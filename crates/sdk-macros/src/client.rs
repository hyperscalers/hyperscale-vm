//! The `client` module: how a package is called.
//!
//! Every fact a wrapper carries is already in the method it wraps — the
//! published name, the parameter kinds, the output count, the gate — so
//! the wrapper is derived rather than maintained beside it. What the
//! emission decides is only the shape those facts take on the calling
//! side.
//!
//! Two shapes, because the protocol has two. A component address folds
//! in the hash of the package serving it, so the wrappers hang off a
//! handle that carries the fact and the target is `self`. A principal's
//! address folds in no package hash — the registry serves the account to
//! every principal by class — so there is nothing a handle could check
//! and the wrappers are free functions over the address itself.

use std::collections::BTreeMap;

use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};

use crate::{Gate, is_named};

/// Which addresses a package's instances sit at, and so how it is
/// called.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Serves {
    /// Instances created from the package, each at an address that
    /// commits to it.
    Instances,
    /// Every principal address, resolved by class. The account, and
    /// nothing else.
    Principals,
}

/// A method's gate, reduced to what the calling side needs of it.
#[derive(Clone, Copy)]
pub enum Shape {
    /// Anyone may name it.
    Public,
    /// A rule over identities the target names. `on_self` is the case
    /// where the rule is the target's own address and nothing else,
    /// which is what lets the call take its target from the proof rather
    /// than from an argument. `threshold` is where meeting it can take
    /// more than one claim, so a caller presents a set.
    Guarded { on_self: bool, threshold: bool },
    /// The target's stored primary, minting the target's identity.
    Authorizing,
    /// One of the target's stored roles, minting nothing.
    RoleGated,
    /// The holder's rule and its possession of a badge, minting that
    /// badge.
    Custodial,
}

impl Shape {
    /// The shape of `gate`, as a caller sees it.
    pub const fn of(gate: &Gate) -> Self {
        match gate {
            Gate::Public => Self::Public,
            Gate::Guarded {
                on_self, threshold, ..
            } => Self::Guarded {
                on_self: *on_self,
                threshold: *threshold,
            },
            Gate::Authorizing(_) => Self::Authorizing,
            Gate::RoleGated(_) => Self::RoleGated,
            Gate::Custodial { .. } => Self::Custodial,
        }
    }

    /// Whether naming the method requires presenting anything.
    const fn requires_evidence(self) -> bool {
        !matches!(self, Self::Public)
    }

    /// Whether the gate judges against a rule the target stores, which
    /// is what the intent's own signature can reach.
    const fn reads_a_rule(self) -> bool {
        matches!(self, Self::Authorizing | Self::RoleGated | Self::Custodial)
    }

    /// Whether naming the method mints evidence for later nodes.
    const fn mints(self) -> bool {
        matches!(self, Self::Authorizing | Self::Custodial)
    }
}

/// Refuse a parameter that would shadow one the wrapper injects.
///
/// Which names those are is the method's own gate and the package's own
/// service class, so the reservation is exactly as wide as the wrapper
/// generated for *this* method: `builder` always, `proof` wherever
/// something is presented, and `who` only where free functions name a
/// principal. A blanket reservation would cost an entrant a good name
/// for the sake of a wrapper that never takes one.
pub fn check_names(params: &[syn::Ident], shape: Shape, serves: Serves) -> syn::Result<()> {
    let injects = |name: &str| match name {
        "builder" => true,
        "proof" | "proofs" => shape.requires_evidence() || shape.reads_a_rule(),
        "who" => {
            serves == Serves::Principals && !matches!(shape, Shape::Guarded { on_self: true, .. })
        }
        _ => false,
    };
    for param in params {
        if injects(&param.to_string()) {
            return Err(syn::Error::new(
                param.span(),
                format!(
                    "`{param}` is what the generated wrapper for this method calls one of its \
                     own parameters, so a parameter of that name would shadow it"
                ),
            ));
        }
    }
    Ok(())
}

/// What one method contributes to the calling surface.
pub struct Method {
    /// The wrapper's own name, which is the method's Rust name.
    pub rust: syn::Ident,
    /// The name the export publishes under.
    pub published: String,
    /// The method's parameters, in order.
    pub params: Vec<(String, syn::Type)>,
    /// The gate, as the calling side needs it.
    pub shape: Shape,
    /// How many value edges the method produces.
    pub outputs: usize,
    /// The method's own documentation, carried onto the wrapper.
    pub docs: Vec<syn::Attribute>,
}

/// A path into the SDK's client surface.
fn sdk(name: &str) -> TokenStream2 {
    let ident = format_ident!("{name}");
    quote!(::hyperscale_vm_sdk::client::#ident)
}

/// The wrapper's parameter and the argument it binds.
///
/// A parameter widens to what the manifest position admits rather than
/// to the guest's own type: a body's `Address` is one class at a time,
/// and which class belongs at a position is the package's business.
fn widen(name: &syn::Ident, ty: &syn::Type) -> (TokenStream2, TokenStream2) {
    let bucket_arg = sdk("BucketArg");
    let address_arg = sdk("AddressArg");
    let value = sdk("ManifestValue");
    if is_named(ty, "Bucket") || is_named(ty, "NfBucket") {
        return (quote!(#name: impl #bucket_arg), quote!(#name));
    }
    if is_named(ty, "Address") {
        return (quote!(#name: impl #address_arg), quote!(#name));
    }
    // A narrower address type stays at the call site: which class
    // belongs at a position is the package's business, and the package
    // answered.
    for (family, _) in crate::ADDRESS_FAMILY {
        if family != "Address" && is_named(ty, family) {
            let narrow = sdk(family);
            return (
                quote!(#name: impl ::core::convert::Into<#narrow>),
                quote!(#name.into()),
            );
        }
    }
    // An id list is a manifest list of `u64`, which no guest type binds
    // as. The slice is what a caller holds, and building the list here
    // is the last place a call site would otherwise reach for `Value`.
    if is_named(ty, "Ids") {
        return (
            quote!(#name: &[u64]),
            quote!(#value::List(
                #name.iter().copied().map(#value::U64).collect()
            )),
        );
    }
    // A quantity is a `u128` at the boundary: the tag is the guest's and
    // erases where a manifest binds a number.
    if is_named(ty, "Quantity") {
        return (quote!(#name: u128), quote!(#name));
    }
    if is_named(ty, "Rule") {
        let rule = sdk("Rule");
        return (quote!(#name: #rule), quote!(#name));
    }
    if is_named(ty, "RoleTable") {
        let roles = sdk("RoleTable");
        return (quote!(#name: #roles), quote!(#name));
    }
    // `u64`, `u128` and the byte vectors bind as themselves.
    (quote!(#name: #ty), quote!(#name))
}

/// The return type and the projection that reaches it.
///
/// The output count is the method's, so the projection is not something
/// a caller states and then has held against it.
fn produced(method: &Method) -> (TokenStream2, TokenStream2) {
    let bucket = sdk("Bucket");
    match method.outputs {
        0 => (quote!(()), quote!(.none())),
        1 => (quote!(#bucket), quote!(.one())),
        n => {
            let n = proc_macro2::Literal::usize_unsuffixed(n);
            (quote!([#bucket; #n]), quote!(.into_array()))
        }
    }
}

/// Whether the call presents a named proof, and so which builder form
/// it takes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Presenting {
    /// The enclosing intent's own signature.
    Signature,
    /// A proof an earlier node minted.
    Proof,
    /// A set of them: what a threshold takes, where one claim is not
    /// enough and the wrapper cannot say which are.
    Proofs,
}

/// One wrapper.
fn wrapper(
    method: &Method,
    serves: Serves,
    presenting: Presenting,
    suffix: Option<&str>,
) -> TokenStream2 {
    let builder = sdk("TypedBuilder");
    let error = sdk("TypedError");
    let proof_ty = sdk("Proof");
    let principal = sdk("PrincipalAddr");

    let name = suffix.map_or_else(
        || method.rust.clone(),
        |suffix| format_ident!("{}_{suffix}", method.rust),
    );
    let published = &method.published;
    let docs = &method.docs;

    let (decls, args): (Vec<_>, Vec<_>) = method
        .params
        .iter()
        .map(|(param, ty)| widen(&format_ident!("{param}"), ty))
        .unzip();

    // Whose address the call is made against. A handle is the target;
    // a principal package names one, except where the gate is the
    // target's own identity and the proof is therefore the actor.
    let from_proof = presenting == Presenting::Proof
        && matches!(method.shape, Shape::Guarded { on_self: true, .. });
    let (receiver, target) = match (serves, from_proof) {
        (Serves::Instances, _) => (quote!(self,), quote!(self.0)),
        (Serves::Principals, true) => (quote!(), quote!(proof.target())),
        (Serves::Principals, false) => (quote!(), quote!(who)),
    };
    let who = matches!((serves, from_proof), (Serves::Principals, false))
        .then(|| quote!(who: #principal,));
    let proof = match presenting {
        Presenting::Proof => Some(quote!(proof: #proof_ty,)),
        Presenting::Proofs => Some(quote!(proofs: &[#proof_ty],)),
        Presenting::Signature => None,
    };

    let (returns, body) = if method.shape.mints() {
        let call = match presenting {
            Presenting::Signature => {
                quote!(builder.call_minting(#target, #published, (#(#args,)*)))
            }
            Presenting::Proof => {
                quote!(builder.call_minting_as(proof, #target, #published, (#(#args,)*)))
            }
            // A minting gate reads a rule, so it is never a threshold.
            Presenting::Proofs => unreachable!("a minting gate presents one proof"),
        };
        (quote!(#proof_ty), call)
    } else {
        let (returns, projection) = produced(method);
        let call = match presenting {
            Presenting::Signature => quote!(builder.call(#target, #published, (#(#args,)*))),
            Presenting::Proof => quote!(builder.call_as(proof, #target, #published, (#(#args,)*))),
            Presenting::Proofs => {
                quote!(builder.call_presenting(proofs, #target, #published, (#(#args,)*)))
            }
        };
        (returns, quote!(#call? #projection))
    };

    quote!(
        #(#docs)*
        ///
        /// # Errors
        ///
        /// Any refusal the call does not type against the method's own
        /// declaration.
        pub fn #name(
            #receiver
            builder: &mut #builder<'_>,
            #proof
            #who
            #(#decls,)*
        ) -> ::core::result::Result<#returns, #error> {
            #body
        }
    )
}

/// Every wrapper one method takes.
///
/// A gate that reads a rule can be satisfied by the intent's own
/// signature or by a proof minted earlier, so it takes both forms; one
/// that names an identity takes the proof alone, and a public method
/// presents nothing at all.
fn wrappers(method: &Method, serves: Serves) -> Vec<TokenStream2> {
    let shape = method.shape;
    if shape.reads_a_rule() {
        return vec![
            wrapper(method, serves, Presenting::Signature, None),
            wrapper(method, serves, Presenting::Proof, Some("as")),
        ];
    }
    let presenting = match shape {
        Shape::Guarded {
            threshold: true, ..
        } => Presenting::Proofs,
        _ if shape.requires_evidence() => Presenting::Proof,
        _ => Presenting::Signature,
    };
    vec![wrapper(method, serves, presenting, None)]
}

/// The `ConfigValues` impl over a package's configuration struct.
///
/// The slot order is the field order, which is what fixes each slot's
/// index — so the struct a caller writes and the list the kernel holds
/// are one declaration read twice rather than two.
fn config_values(config: &syn::Ident, fields: &[(String, syn::Type)]) -> TokenStream2 {
    let trait_path = sdk("ConfigValues");
    let value = sdk("ManifestValue");
    let slot = sdk("IntoSlot");
    let names = fields.iter().map(|(name, _)| format_ident!("{name}"));
    quote!(
        impl #trait_path for super::#config {
            fn values(self) -> ::std::vec::Vec<#value> {
                ::std::vec![
                    #(#slot::into_slot(self.#names),)*
                ]
            }
        }
    )
}

/// One `pub const` per declared state field, at the slot the numbering
/// gave it.
///
/// A consumer keying a leaf under a package names the field it belongs
/// to. The alternative is the number, written out beside the package and
/// agreeing with it until it does not — which is the drift the whole
/// derivation exists to remove, and the reason the slot is emitted rather
/// than documented.
fn slots(fields: &BTreeMap<String, u16>) -> Vec<TokenStream2> {
    let slot_id = sdk("SlotId");
    fields
        .iter()
        .map(|(name, slot)| {
            let konst = format_ident!("{}", name.to_uppercase());
            let doc = format!("The slot `{name}` sits under.");
            quote!(
                #[doc = #doc]
                pub const #konst: #slot_id = #slot_id(#slot);
            )
        })
        .collect()
}

/// The package's calling surface.
pub fn module(
    handle: &syn::Ident,
    config: Option<&syn::Ident>,
    config_fields: &[(String, syn::Type)],
    fields: &BTreeMap<String, u16>,
    serves: Serves,
    methods: &[&Method],
) -> TokenStream2 {
    let slots = slots(fields);
    let calls: Vec<_> = methods
        .iter()
        .flat_map(|method| wrappers(method, serves))
        .collect();

    let component = sdk("Component");
    let metadata = sdk("PackageMetadata");
    let address = sdk("ComponentAddr");
    let any_address = sdk("Address");
    let call_target = sdk("CallTarget");

    // The configuration struct is re-exported beside the handle, so a
    // caller reaches the package's whole calling surface — what to
    // create one under, and what to call on it — through one path.
    let (config_ty, config_impl) = config.map_or_else(
        || (quote!(()), None),
        |config| {
            let values = config_values(config, config_fields);
            (
                quote!(super::#config),
                Some(quote!(
                    pub use super::#config;

                    #values
                )),
            )
        },
    );

    // The account answers an address class rather than instances of
    // itself, so there is no handle to hang the calls off and no
    // configuration to create one under.
    let surface = match serves {
        Serves::Principals => quote!(#(#calls)*),
        Serves::Instances => quote!(
            /// A component known to run this package.
            ///
            /// Reached by creating the instance or by adopting an
            /// address something checked, never by asserting one — which
            /// is what makes a call to another package's method a
            /// compile error rather than a lookup that comes back empty.
            #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct #handle(#address);

            impl #component for #handle {
                type Config = #config_ty;

                fn metadata() -> #metadata {
                    super::blueprint().metadata()
                }

                fn at(address: #address) -> Self {
                    Self(address)
                }

                fn address(self) -> #address {
                    self.0
                }
            }

            impl ::core::convert::From<#handle> for #address {
                fn from(handle: #handle) -> Self {
                    handle.0
                }
            }

            impl ::core::convert::From<#handle> for #any_address {
                fn from(handle: #handle) -> Self {
                    handle.0.into()
                }
            }

            impl ::core::convert::From<#handle> for #call_target {
                fn from(handle: #handle) -> Self {
                    handle.0.into()
                }
            }

            #config_impl

            impl #handle {
                /// The handle at `address`, taken on trust.
                ///
                /// For a holder that established the fact some other way
                /// — a chain that just created the instance, or a test
                /// that wrote the registry. A caller starting from an
                /// address somebody else chose wants the checked
                /// adoption its host tier offers instead.
                #[must_use]
                pub const fn at(address: #address) -> Self {
                    Self(address)
                }

                #(#calls)*
            }
        ),
    };

    quote!(
        /// How this package is called.
        ///
        /// One wrapper per method, derived from the method itself: the
        /// published name, the parameter kinds, the output count and the
        /// gate are all facts the declaration already carries — and one
        /// constant per state field, at the slot the numbering gave it.
        #[cfg(not(target_arch = "wasm32"))]
        pub mod client {
            #(#slots)*

            #surface
        }
    )
}

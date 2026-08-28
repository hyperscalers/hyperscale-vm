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

use hyperscale_vm_effects::ResourceKind;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};

use crate::gate::Gate;
use crate::resource::Resource;
use crate::{INSTANTIATE, is_named, kebab};

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
    /// A rule over identities the target names. What satisfies it is
    /// the call's own business at compose time: the builder proves what
    /// the signer's account can, and an enclosing `presenting` scope
    /// carries the rest.
    Guarded,
    /// The target's stored primary, proving the target's identity.
    Authorizing,
    /// A rule the target stores beside its primary, proving nothing.
    Governed,
    /// The holder's rule and its possession of a badge, proving that
    /// badge.
    Custodial,
}

impl Shape {
    /// The shape of `gate`, as a caller sees it.
    pub const fn of(gate: &Gate) -> Self {
        match gate {
            Gate::Public => Self::Public,
            Gate::Guarded { .. } => Self::Guarded,
            Gate::Authorizing(_) => Self::Authorizing,
            Gate::Governed(_) => Self::Governed,
            Gate::Custodial { .. } => Self::Custodial,
        }
    }

    /// Whether naming the method proves evidence for later nodes.
    const fn proves(self) -> bool {
        matches!(self, Self::Authorizing | Self::Custodial)
    }
}

/// Refuse a parameter that would shadow one the generated code binds.
///
/// The wrapper's own parameters are `builder` on every method and `who`
/// where a principal package's free functions name the caller — never a
/// proof, because evidence is the builder's to resolve and the scope's
/// to carry. A blanket reservation would cost an entrant a good name
/// for the sake of a wrapper that never takes one.
///
/// The `__`-prefixed names are a whole namespace rather than a list: the
/// lowering emits `__value_N`, `__capability_N`, `__records` and their
/// kin into the guest body, and a parameter wearing one shadows the
/// binding the body reads — a type error inside generated code, spanning
/// nothing. Rust convention already frowns on `__` identifiers, so
/// reserving the prefix costs an author nothing.
pub fn check_names(params: &[syn::Ident], shape: Shape, serves: Serves) -> syn::Result<()> {
    let _ = shape;
    let injects = |name: &str| match name {
        "builder" => true,
        "who" => serves == Serves::Principals,
        _ => false,
    };
    for param in params {
        let name = param.to_string();
        if name.starts_with("__") {
            return Err(syn::Error::new(
                param.span(),
                format!(
                    "`{param}` starts with `__`, which the generated code reserves for its own \
                     bindings — name the parameter without the leading underscores"
                ),
            ));
        }
        if injects(&name) {
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
    /// What the method answers with beside them, where it answers.
    ///
    /// The Rust type its own signature names, so a caller reading the
    /// answer back off a receipt names neither the type nor the node.
    pub answers: Option<syn::Type>,
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
    // A quantity and an order key are a `u128` where a manifest binds a
    // number, and the vocabulary's type at the wrapper: the conversion
    // target is spelled by absolute path, so a caller holding the typed
    // value passes it as itself, a literal still converts, and a local
    // type wearing the name fails to convert instead of silently
    // binding.
    if is_named(ty, "Quantity") {
        let quantity = quote!(::hyperscale_vm_sdk::state::Quantity);
        return (
            quote!(#name: impl ::core::convert::Into<#quantity>),
            quote!(::core::convert::Into::<#quantity>::into(#name).subunits()),
        );
    }
    if is_named(ty, "OrderKey") {
        let order = quote!(::hyperscale_vm_sdk::state::OrderKey);
        return (
            quote!(#name: impl ::core::convert::Into<#order>),
            quote!(::core::convert::Into::<#order>::into(#name).bits()),
        );
    }
    // A stored rate binds as its scaled integer, at the width a rate has,
    // and the caller writes the rate — so the scale is the type's and
    // never a number a call site has to agree with.
    if is_named(ty, "Fixed") || is_named(ty, "SignedFixed") {
        return (
            quote!(#name: #ty),
            quote!(#value::U256(#name.to_le_bytes())),
        );
    }
    // `u64`, `u128` and the byte vectors bind as themselves.
    (quote!(#name: #ty), quote!(#name))
}

/// The return type, and the discharge that reaches it over an `outputs`
/// the wrapper has already bound.
///
/// The output count is the method's, so the discharge is not something a
/// caller states and then has held against it.
fn produced(method: &Method) -> (TokenStream2, TokenStream2) {
    let bucket = sdk("Bucket");
    let (edges, discharge) = match method.outputs {
        0 => (quote!(()), quote!(none())),
        1 => (quote!(#bucket), quote!(one())),
        n => {
            let n = proc_macro2::Literal::usize_unsuffixed(n);
            (quote!([#bucket; #n]), quote!(into_array()))
        }
    };
    // An answer rides beside the edges rather than instead of them: a
    // method hands back at most one value and any number of edges, and
    // the signature says both independently. A method that answers and
    // yields nothing hands back the handle alone, because a unit beside
    // it would be a tuple whose second half never says anything.
    let Some(answer) = &method.answers else {
        return (edges, quote!(outputs.#discharge));
    };
    let answered = sdk("Answered");
    if method.outputs == 0 {
        return (
            quote!(#answered<#answer>),
            quote!({
                let (answer, outputs) = outputs.answering()?;
                outputs.none().map(|()| answer)
            }),
        );
    }
    (
        quote!((#answered<#answer>, #edges)),
        quote!({
            let (answer, outputs) = outputs.answering()?;
            outputs.#discharge.map(|edges| (answer, edges))
        }),
    )
}

/// One wrapper.
fn wrapper(method: &Method, serves: Serves) -> TokenStream2 {
    let builder = sdk("TypedBuilder");
    let error = sdk("TypedError");
    let proof_ty = sdk("Proof");
    let principal = sdk("PrincipalAddr");

    let name = method.rust.clone();
    let published = &method.published;
    let docs = &method.docs;

    let (decls, args): (Vec<_>, Vec<_>) = method
        .params
        .iter()
        .map(|(param, ty)| widen(&format_ident!("{param}"), ty))
        .unzip();

    // Whose address the call is made against: a handle is the target,
    // and a principal package names one.
    let (receiver, target) = match serves {
        Serves::Instances => (quote!(self,), quote!(self.0)),
        Serves::Principals => (quote!(), quote!(who)),
    };
    let who = (serves == Serves::Principals).then(|| quote!(who: #principal,));

    let (returns, body) = if method.shape.proves() {
        let call = quote!(builder.call_proving(#target, #published, (#(#args,)*)));
        (quote!(#proof_ty), call)
    } else {
        let (returns, projection) = produced(method);
        let call = quote!(builder.call(#target, #published, (#(#args,)*)));
        (
            returns,
            quote!({
                let outputs = #call?;
                #projection
            }),
        )
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
            #who
            #(#decls,)*
        ) -> ::core::result::Result<#returns, #error> {
            #body
        }
    )
}

/// The one wrapper a method takes.
///
/// Never a proof parameter: evidence is the builder's to resolve — the
/// signer's own account answers what it can — and an enclosing
/// `presenting` scope carries what it cannot. How many claims a gate
/// takes, and whose, stays the gate's own business rather than a shape
/// the wrapper spells.
fn wrappers(method: &Method, serves: Serves) -> Vec<TokenStream2> {
    vec![wrapper(method, serves)]
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
fn slots(fields: &BTreeMap<String, u16>, vaults: &[(String, u16, u32)]) -> Vec<TokenStream2> {
    let slot_id = sdk("SlotId");
    fields
        .iter()
        // A declared vault's typed marker carries its slot, so the raw
        // constant would be a second name for the same number — and the
        // marker's unit value would collide with it.
        .filter(|(name, _)| !vaults.iter().any(|(vault, ..)| vault == *name))
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

/// One address helper per declared resource: what the instance issues
/// under that mark, at the address its own declaration derives.
///
/// Generated because every call site otherwise restates four facts the
/// declaration already carries — the hasher, the instance, the kind and
/// the mark — and a fifth it cannot state at all: the rules the address
/// folds. A site that got any of them wrong would name a vacant sibling
/// address rather than fail.
///
/// A resource whose rules name configuration takes it, because an
/// address is a hash and a handle cannot be read backwards to recover
/// what it commits.
fn issued(resources: &[Resource], config: Option<&syn::Ident>) -> Vec<TokenStream2> {
    let resource_addr = sdk("ResourceAddr");
    let kind_ty = quote!(::hyperscale_vm_sdk::ResourceKind);
    resources
        .iter()
        .map(|resource| {
            // Prefixed the way a gate names one — `issued(Seat)` — so
            // the helper cannot collide with the wrapper for a method
            // the package happens to name after its own resource, and a
            // call site reads which of the two it is.
            let name = format_ident!("issued_{}", kebab(&resource.name).replace('-', "_"));
            let mark = syn::LitByteStr::new(&resource.mark, Span::call_site());
            let kind = match resource.kind {
                ResourceKind::Fungible => quote!(#kind_ty::Fungible),
                ResourceKind::NonFungible => quote!(#kind_ty::NonFungible),
            };
            let grants = &resource.grants.rendered;
            let doc = format!(
                "The address of the `{}` this instance issues.",
                resource.name
            );
            let (param, config_values) = match (resource.grants.reads_config, config) {
                (true, Some(config)) => (
                    quote!(config: super::#config,),
                    quote!(&::hyperscale_vm_sdk::client::ConfigValues::values(config)),
                ),
                _ => (quote!(), quote!(&[])),
            };
            quote!(
                #[doc = #doc]
                #[must_use]
                pub fn #name(
                    self,
                    hasher: &dyn ::hyperscale_vm_sdk::client::Hasher,
                    #param
                ) -> #resource_addr {
                    ::hyperscale_vm_sdk::client::issued_at(
                        hasher,
                        self.0,
                        #kind,
                        #mark,
                        &#grants,
                        #config_values,
                    )
                }
            )
        })
        .collect()
}

/// Everything the calling surface is derived from, which is everything
/// the package already declared.
///
/// A struct rather than an argument list because these are one package's
/// facts read from one module, and a caller assembling them positionally
/// would be restating an order that means nothing.
pub struct Surface<'a> {
    /// The state struct's name, which the handle takes.
    pub handle: &'a syn::Ident,
    /// The configuration struct, where the package has one.
    pub config: Option<&'a syn::Ident>,
    /// Its fields, in the order that fixes their slots.
    pub config_fields: &'a [(String, syn::Type)],
    /// Each state field's slot, for the constants a consumer keys by.
    pub fields: &'a BTreeMap<String, u16>,
    /// Which addresses the package's instances sit at.
    pub serves: Serves,
    /// The methods to wrap.
    pub methods: &'a [&'a Method],
    /// The resources the package issues.
    pub resources: &'a [Resource],
    /// The declared vaults holding configured resources: field name,
    /// slot, and the configuration slot naming the resource.
    pub vaults: &'a [(String, u16, u32)],
}

/// One marker type per issued resource: the mark as a type, tied to the
/// handle of the package that issues under it. What lets a chain answer
/// `chain.issued(pool, client::Share)` from its records, with a foreign
/// marker refused where the handle's type is named.
fn marks(resources: &[Resource], handle: &syn::Ident) -> Vec<TokenStream2> {
    let kind_ty = quote!(::hyperscale_vm_sdk::ResourceKind);
    resources
        .iter()
        .map(|resource| {
            let name = syn::Ident::new(&resource.name, Span::call_site());
            let mark = syn::LitByteStr::new(&resource.mark, Span::call_site());
            let kind = match resource.kind {
                ResourceKind::Fungible => quote!(#kind_ty::Fungible),
                ResourceKind::NonFungible => quote!(#kind_ty::NonFungible),
            };
            let doc = format!(
                "The `{}` this package issues, named as a type.",
                resource.name
            );
            quote!(
                #[doc = #doc]
                #[derive(Clone, Copy, Debug)]
                pub struct #name;

                impl ::hyperscale_vm_sdk::client::Mark for #name {
                    type Of = #handle;
                    const MARK: &'static [u8] = #mark;
                    const KIND: #kind_ty = #kind;
                }
            )
        })
        .collect()
}

/// One marker type per declared vault holding a configured resource,
/// so a chain funds and reads a component's balance sheet by the field:
/// `chain.fund(pool, client::X, 1_000)`.
fn vault_fields(vaults: &[(String, u16, u32)], handle: &syn::Ident) -> Vec<TokenStream2> {
    vaults
        .iter()
        .map(|(name, slot, config)| {
            let ident = format_ident!("{}", crate::pascal(name));
            let doc = format!("The `{name}` vault, named as a type.");
            quote!(
                #[doc = #doc]
                #[derive(Clone, Copy, Debug)]
                pub struct #ident;

                impl ::hyperscale_vm_sdk::client::VaultField for #ident {
                    type Of = #handle;
                    const SLOT: u16 = #slot;
                    const HOLDS: u32 = #config;
                }
            )
        })
        .collect()
}

/// The package's calling surface.
pub fn module(surface: &Surface<'_>) -> TokenStream2 {
    let &Surface {
        handle,
        config,
        config_fields,
        fields,
        serves,
        methods,
        resources,
        vaults,
    } = surface;
    let slots = slots(fields, vaults);
    let issued = issued(resources, config);
    let marks = marks(resources, handle);
    let vault_fields = vault_fields(vaults, handle);
    // The seal is composed rather than called: what a bring-up carries
    // beside it — the sign-in a gated package asks for, the account the
    // supply is filed in — is read off the declaration by the stdlib's
    // own composition, and a bare wrapper would let a caller write the
    // node without them and learn so at admission.
    let calls: Vec<_> = methods
        .iter()
        .filter(|method| !matches!(serves, Serves::Instances) || method.published != INSTANTIATE)
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

                #(#issued)*
            }

            #(#marks)*

            #(#vault_fields)*
        ),
    };

    quote!(
        /// How this package is called.
        ///
        /// One wrapper per method, derived from the method itself: the
        /// published name, the parameter kinds, the output count and the
        /// gate are all facts the declaration already carries — and one
        /// constant per state field, at the slot the numbering gave it.
        pub mod client {
            // Everything the module has, so a wrapper names a
            // parameter's type the way the method that declared it does
            // — the author's own imports included, which a child module
            // sees whether or not they were public. Without them a
            // signature could only speak in what a manifest binds, and a
            // rate would arrive as thirty-two bytes rather than as a
            // rate.
            #[allow(unused_imports)]
            use super::*;

            #(#slots)*

            #surface
        }
    )
}

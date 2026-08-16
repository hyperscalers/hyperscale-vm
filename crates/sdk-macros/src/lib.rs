//! The `#[blueprint]` macro: one module is the package.
//!
//! Applied to a module, so the macro sees the component's state, its
//! configuration, and every method together — which is what lets a body
//! written as ordinary Rust yield the access declaration routing needs
//! *and* the component that executes it, without the author writing
//! either.
//!
//! ```ignore
//! #[blueprint]
//! mod account {
//!     #[state]
//!     struct Account {
//!         #[role(1)] vaults: Keyed<Amount>,
//!         #[role(2)] claims: Keyed<Amount>,
//!     }
//!
//!     impl Account {
//!         pub fn deposit(&mut self, funds: Bucket) {
//!             self.vaults.at(funds.resource()).add(funds.amount());
//!             self.claims.at(funds.resource()).add(0);
//!         }
//!     }
//! }
//! ```
//!
//! The two deltas above are declared because `add` is a commutative
//! movement and the key is `ResourceOf(Arg(0))` — both read off the body.
//! Nothing was written twice.
//!
//! # The two halves
//!
//! A host build gets `blueprint()`: the declaration, traced. A
//! `wasm32` build gets the world, the bindings, and the `impl Guest`
//! whose bodies are the bodies above with each state access rewritten to
//! the kernel call its mode names. The export's parameter list and the
//! signature's ABI binding are the same object seen from two sides, which
//! is why neither is authored: what reaches an export is what the body
//! could not compute, and that is a residue of the body rather than a
//! second declaration of it.
//!
//! # What the macro refuses
//!
//! Routing evaluates a declaration before execution and never reads state,
//! so a key the body computes from a substate value arrives too late to
//! route on. That is not a limitation the macro could engineer away, and
//! the macro stops with an error on the offending line rather than
//! guessing. The same applies to a loop whose trip count is not a
//! configured collection, and to a range whose entry cap is not a literal.
//!
//! The walk is exhaustive: an expression form the lowering does not model
//! is a compile error, never a skip, because a skipped form is a
//! declaration missing whatever the body did inside it. Concretely that
//! refuses closures, macros outside the assert and panic family (whose
//! arguments are walked like any expression), calls that pass the
//! component on — including `self.other_method(…)` — and an early `return`
//! carrying a produced value edge, which the tail's exact output list
//! cannot absorb. Reassigning a local forgets what it held, so a key used
//! after a conditional reassignment is refused at the use site. One handle
//! declares one mode: a read beside a movement, or a second reservation,
//! is refused where it is recorded.
//!
//! Conditionals — `if` and `match` alike — are fine: every arm is
//! declared, giving a superset of what any one execution touches. The VM
//! prices that superset through `footprint` rather than rejecting it.
//!
//! A body whose *declaration* is sound but whose executing half the
//! emission cannot write — a `for-each`, whose handle count depends on
//! configuration, or an unordered entry, which sits at a hash the kernel
//! derives — is a compile error on the guest build alone. The declaration
//! still stands, and the package's component is then written the long way:
//! the publish gate judges artifacts, never authorship.
//!
//! # What it does not do
//!
//! It does not build `Expr` literals. Every declaration it derives is
//! emitted as calls into `hyperscale_vm_sdk::Trace`, so the tracer stays
//! the single implementation of what a declaration means and the macro's
//! correctness reduces to whether it called the tracer the way a human
//! would.

// `syn`'s AST is matched by fully-qualified variant path throughout. Pulling
// `Expr::`, `Item::`, or `Type::` into scope would collide with this crate's
// own `Term` and `Val` variants and, worse, read as though it were them —
// the prefix is the only thing distinguishing "the contract's syntax" from
// "the macro's model of it".
#![allow(clippy::absolute_paths)]

mod emit;
mod guest;
mod lower;
mod term;
mod wit;

use std::collections::BTreeMap;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;

use crate::lower::{Field, FieldKind, Lowerer, Target};

/// Derive a contract's package from its module: the declaration routing
/// reads, and the component that executes it.
///
/// See the crate docs for the shape and for what the lowering refuses.
///
/// # Panics
///
/// Never; every rejection is a `compile_error!` on the offending span.
#[proc_macro_attribute]
pub fn blueprint(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let module = syn::parse_macro_input!(item as syn::ItemMod);
    match expand(module) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// A Rust name as the protocol spells it: the published form of a method,
/// an event, or an error code.
fn kebab(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.char_indices() {
        if ch == '_' {
            out.push('-');
        } else if ch.is_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// The single type argument of a generic state field, which is the value
/// its leaves hold.
fn element_of(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let syn::PathArguments::AngleBracketed(args) = &path.path.segments.last()?.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty.clone()),
        _ => None,
    })
}

/// The state field's role and shape, read off its declaration.
fn parse_field(field: &syn::Field) -> syn::Result<(String, Field)> {
    let name = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new(field.span(), "a state field must be named"))?
        .to_string();

    let mut role = None;
    for attr in &field.attrs {
        if attr.path().is_ident("role") {
            let literal: syn::LitInt = attr.parse_args()?;
            role = Some(literal.base10_parse::<u16>()?);
        }
    }
    // Roles are explicit rather than positional: they are part of every key
    // the field ever names, so a field reorder must not silently move an
    // instance's whole state.
    let role = role.ok_or_else(|| {
        syn::Error::new(
            field.span(),
            "a state field needs an explicit `#[role(n)]` — the role is hashed into every \
             key under this field, so it cannot be positional",
        )
    })?;

    let syn::Type::Path(path) = &field.ty else {
        return Err(syn::Error::new(field.ty.span(), "unsupported state type"));
    };
    let outer = path
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    let kind = match outer.as_str() {
        "Locked" => FieldKind::Locked,
        "Cell" => FieldKind::Cell,
        "Keyed" => FieldKind::Keyed,
        "Ordered" => FieldKind::Ordered,
        "Unordered" => FieldKind::Unordered,
        _ => {
            return Err(syn::Error::new(
                field.ty.span(),
                "a state field must be `Locked<_>`, `Cell<_>`, `Keyed<_>`, `Ordered<_>`, or \
                 `Unordered<_>` — state is reachable only through these, which is what makes \
                 the access mode derivable from the body",
            ));
        }
    };
    Ok((
        name,
        Field {
            role,
            kind,
            element: element_of(&field.ty),
        },
    ))
}

/// The parameter kind a Rust type binds as in a manifest.
fn param_type(ty: &syn::Type) -> syn::Result<TokenStream2> {
    let syn::Type::Path(path) = ty else {
        return Err(syn::Error::new(ty.span(), "unsupported parameter type"));
    };
    let name = path
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    let variant = match name.as_str() {
        "Bucket" => quote!(Bucket),
        "u128" => quote!(U128),
        "u64" => quote!(U64),
        "Address" => quote!(Address),
        "Vec" | "Bytes" => quote!(Bytes),
        "Rule" => quote!(Rule),
        "RoleSet" => quote!(RoleSet),
        _ => {
            return Err(syn::Error::new(
                ty.span(),
                "a contract parameter must be one of `Bucket`, `u128`, `u64`, `Address`, or \
                 bytes — these are the kinds a manifest can bind",
            ));
        }
    };
    Ok(quote!(::hyperscale_vm_sdk::ParamType::#variant))
}

/// The published name of a method: its Rust name unless `#[name("…")]`
/// says otherwise.
fn method_name(method: &syn::ImplItemFn) -> syn::Result<String> {
    for attr in &method.attrs {
        if attr.path().is_ident("name") {
            let literal: syn::LitStr = attr.parse_args()?;
            return Ok(literal.value());
        }
    }
    Ok(method.sig.ident.to_string())
}

/// The macro's own attributes, which are read and then removed so what it
/// emits is ordinary Rust.
const OWN: &[&str] = &[
    "role",
    "state",
    "config",
    "name",
    "event",
    "error",
    "guarded",
    "authorizing",
    "role_gated",
    "custodial",
];

fn strip(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|attr| !OWN.iter().any(|own| attr.path().is_ident(own)));
}

/// Whose authority naming a method requires, as its own attribute says.
enum Gate {
    /// Anyone may name it.
    Public,
    /// The identity the target itself names.
    Guarded(TokenStream2),
    /// The target's own stored rule, read at the named field's cell.
    Authorizing(u16),
    /// One of the target's stored roles.
    RoleGated(TokenStream2),
    /// The target's rule and its possession of the badge a parameter
    /// names.
    Custodial(u32),
}

/// Read a method's gate off its attributes.
fn parse_gate(
    method: &syn::ImplItemFn,
    fields: &BTreeMap<String, Field>,
    params: &[(String, syn::Type)],
) -> syn::Result<Gate> {
    for attr in &method.attrs {
        if attr.path().is_ident("guarded") {
            let identity: syn::Expr = attr.parse_args()?;
            // Every identity a method can require is one the target itself
            // names; a caller who names the identity they must present can
            // always present it, so the gate would admit everyone.
            let tokens = match &identity {
                syn::Expr::Path(path) if path.path.is_ident("self") => {
                    quote!(__t.self_addr())
                }
                syn::Expr::Path(path) if path.path.get_ident().is_some() => {
                    let name = path.path.get_ident().expect("checked").to_string();
                    if params.iter().any(|(p, _)| *p == name) {
                        return Err(syn::Error::new(
                            identity.span(),
                            "the authority this method requires is one its caller names, \
                             so the gate would admit everyone — name `self` or a \
                             configuration field instead",
                        ));
                    }
                    return Err(syn::Error::new(
                        identity.span(),
                        "a guarded method names `self` or one of the component's \
                         configuration fields",
                    ));
                }
                _ => {
                    return Err(syn::Error::new(
                        identity.span(),
                        "a guarded method names `self` or one of the component's \
                         configuration fields",
                    ));
                }
            };
            return Ok(Gate::Guarded(tokens));
        }
        if attr.path().is_ident("authorizing") {
            let field: syn::Ident = attr.parse_args()?;
            let role = fields
                .get(&field.to_string())
                .map(|f| f.role)
                .ok_or_else(|| {
                    syn::Error::new(
                        field.span(),
                        "not a declared field of the component's state",
                    )
                })?;
            return Ok(Gate::Authorizing(role));
        }
        if attr.path().is_ident("role_gated") {
            let role: syn::Ident = attr.parse_args()?;
            let variant = match role.to_string().as_str() {
                "primary" => quote!(Primary),
                "recovery" => quote!(Recovery),
                "confirmation" => quote!(Confirmation),
                _ => {
                    return Err(syn::Error::new(
                        role.span(),
                        "a stored role is `primary`, `recovery`, or `confirmation`",
                    ));
                }
            };
            return Ok(Gate::RoleGated(
                quote!(::hyperscale_vm_sdk::AuthRole::#variant),
            ));
        }
        if attr.path().is_ident("custodial") {
            let badge: syn::Ident = attr.parse_args()?;
            let index = params
                .iter()
                .position(|(p, _)| badge == p.as_str())
                .ok_or_else(|| syn::Error::new(badge.span(), "not a parameter of this method"))?;
            return Ok(Gate::Custodial(u32::try_from(index).unwrap_or(0)));
        }
    }
    Ok(Gate::Public)
}

/// The `#[state]` struct: its name, its fields by role and shape, and the
/// configuration struct its `Locked<_>` field names, if it has one.
fn parse_state(
    items: &[syn::Item],
    span: proc_macro2::Span,
) -> syn::Result<(syn::Ident, BTreeMap<String, Field>, Option<syn::Ident>)> {
    let mut fields = BTreeMap::new();
    let mut state_name = None;
    let mut config_name = None;
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if !item.attrs.iter().any(|a| a.path().is_ident("state")) {
            continue;
        }
        state_name = Some(item.ident.clone());
        for field in &item.fields {
            let (name, parsed) = parse_field(field)?;
            if parsed.kind == FieldKind::Locked
                && let syn::Type::Path(path) = &field.ty
                && let Some(syn::PathArguments::AngleBracketed(args)) =
                    path.path.segments.last().map(|s| &s.arguments)
                && let Some(syn::GenericArgument::Type(syn::Type::Path(inner))) = args.args.first()
            {
                config_name = inner.path.get_ident().cloned();
            }
            fields.insert(name, parsed);
        }
    }
    let state_name = state_name.ok_or_else(|| {
        syn::Error::new(
            span,
            "`#[blueprint]` needs one `#[state]` struct — it names the roles every key in \
             the package sits under",
        )
    })?;
    Ok((state_name, fields, config_name))
}

/// The configuration struct's fields in declaration order — which is what
/// fixes each one's config slot index, and what a guest reading one gets
/// handed.
fn config_slots(items: &[syn::Item], config_name: Option<&syn::Ident>) -> Vec<(String, syn::Type)> {
    let Some(config_name) = config_name else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == *config_name => Some(&item.fields),
            _ => None,
        })
        .flatten()
        .filter_map(|field| {
            field
                .ident
                .as_ref()
                .map(|name| (name.to_string(), field.ty.clone()))
        })
        .collect()
}

/// The package's event names, in the declaration order an emitted index
/// refers to.
fn event_names(items: &[syn::Item]) -> Vec<(syn::Ident, String)> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.attrs.iter().any(|a| a.path().is_ident("event")) => {
                Some((item.ident.clone(), kebab(&item.ident.to_string())))
            }
            _ => None,
        })
        .collect()
}

/// The package's error names, in the order a declined invocation's code
/// refers to.
fn error_names(items: &[syn::Item]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Enum(item) if item.attrs.iter().any(|a| a.path().is_ident("error")) => {
                Some(&item.variants)
            }
            _ => None,
        })
        .flatten()
        .map(|variant| kebab(&variant.ident.to_string()))
        .collect()
}

/// Whether a method's return type carries an error arm, which is the whole
/// of what its totality mark is.
fn declines(method: &syn::ImplItemFn) -> bool {
    let syn::ReturnType::Type(_, ty) = &method.sig.output else {
        return false;
    };
    matches!(&**ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "Result"))
}

/// One public method, lowered to its declaration and its export.
struct Lowered {
    /// The `.method(…)` builder call.
    declaration: TokenStream2,
    /// The export and the `impl Guest` body behind it, or why there is
    /// none.
    guest: Result<guest::Method, TokenStream2>,
}

#[allow(clippy::too_many_lines)] // one pass over a method: name, params, gate, body, export
fn lower_method(
    method: &syn::ImplItemFn,
    fields: &BTreeMap<String, Field>,
    config_fields: &[(String, syn::Type)],
) -> syn::Result<Lowered> {
    let published = method_name(method)?;
    let mut params = Vec::new();
    let mut kinds = Vec::new();
    for arg in &method.sig.inputs {
        let syn::FnArg::Typed(arg) = arg else {
            continue; // the receiver
        };
        let syn::Pat::Ident(ident) = &*arg.pat else {
            return Err(syn::Error::new(
                arg.pat.span(),
                "a contract parameter must be a plain name — the declaration refers \
                 to arguments positionally, and a pattern has no one position",
            ));
        };
        params.push((ident.ident.to_string(), (*arg.ty).clone()));
        kinds.push(param_type(&arg.ty)?);
    }

    let gate = parse_gate(method, fields, &params)?;
    let lowered = Lowerer::new(fields, config_fields, &params)
        .run(&method.block)
        .map_err(|errors| {
            errors
                .into_iter()
                .reduce(|mut all, error| {
                    all.combine(error);
                    all
                })
                .unwrap_or_else(|| syn::Error::new(method.span(), "lowering failed"))
        })?;
    check_gate_shape(&gate, &lowered, method)?;

    let declining = declines(method);
    let closure = emit::declaration(&lowered, &gate_calls(&gate), declining);
    let declaration = quote!(
        .method(#published, &[#(#kinds),*], #closure)
    );

    let guest = lowered.refusal.as_ref().map_or_else(
        || {
            Ok(guest::method(
                &published,
                &lowered,
                &params,
                config_fields,
                declining,
            ))
        },
        |why| Err(guest::refusal(&published, why)),
    );
    Ok(Lowered { declaration, guest })
}

/// The tracer calls a gate becomes.
///
/// An authorizing method's clause is the gate's, not the body's: the
/// kernel reads the stored rule before the export runs, so the read is
/// declared here and no handle is bound for it.
fn gate_calls(gate: &Gate) -> TokenStream2 {
    match gate {
        Gate::Public => quote!(),
        Gate::Guarded(identity) => quote!({
            let __identity = #identity;
            __t.guarded(&__identity);
        }),
        Gate::Authorizing(role) => quote!({
            let __owner = __t.self_addr();
            let __key = __owner.child(::hyperscale_vm_sdk::RoleId(#role), &[]);
            __t.point(&__key).read();
            __t.authorizing();
        }),
        Gate::RoleGated(role) => quote!(__t.role_gated(#role);),
        Gate::Custodial(index) => quote!({
            let __badge = __t.arg::<::hyperscale_vm_sdk::Addr>(#index);
            __t.custodial(&__badge);
        }),
    }
}

/// Hold a gate to the declaration shape the publish gate pins for it.
///
/// The same rules `hyperscale_vm_effects::check_abi` applies to a
/// published artifact, applied to the body that would produce one — so an
/// author hears about it on the offending line rather than at the moment
/// they try to publish.
fn check_gate_shape(
    gate: &Gate,
    lowered: &lower::Lowered,
    method: &syn::ImplItemFn,
) -> syn::Result<()> {
    let refuse = |message: &str| Err(syn::Error::new(method.sig.ident.span(), message));
    match gate {
        Gate::Public | Gate::Guarded(_) => Ok(()),
        Gate::Authorizing(_) => {
            if lowered.sites.is_empty() {
                Ok(())
            } else {
                refuse(
                    "an authorizing method declares exactly one point read — the cell its \
                     stored rule lives in, which the kernel reads before the export runs. \
                     The body has nothing left to say, so it must be empty",
                )
            }
        }
        Gate::RoleGated(_) => match lowered.sites.as_slice() {
            [site]
                if matches!(site.target, Target::Point { .. })
                    && site.resource() == Some("write-cell") =>
            {
                Ok(())
            }
            _ => refuse(
                "a role-gated method declares exactly one point write — the cell its \
                 stored roles live in. The write is where the gate's cell comes from, \
                 and it serializes role rewrites against concurrent sign-ins",
            ),
        },
        Gate::Custodial(_) => match lowered.sites.as_slice() {
            [rule, vault, holdings]
                if rule.resource() == Some("read-cell")
                    && vault.resource() == Some("read-cell")
                    && holdings.resource() == Some("range-read") =>
            {
                Ok(())
            }
            _ => refuse(
                "a custodial method declares three reads: its rule cell, the \
                 badge-keyed vault, and the badge-keyed holdings interval",
            ),
        },
    }
}

/// Every public method of the state struct's inherent impls, lowered.
fn lower_methods(
    items: &[syn::Item],
    state_name: &syn::Ident,
    fields: &BTreeMap<String, Field>,
    config_fields: &[(String, syn::Type)],
) -> syn::Result<Vec<Lowered>> {
    let mut lowered = Vec::new();
    for item in items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        if !matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name)) {
            continue;
        }
        for item in &block.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if matches!(method.vis, syn::Visibility::Public(_)) {
                lowered.push(lower_method(method, fields, config_fields)?);
            }
        }
    }
    Ok(lowered)
}

/// Remove the macro's own attributes, so what it emits is ordinary Rust.
///
/// The state struct's inherent impl is also held to the host build. Its
/// bodies are what the export bodies were rewritten from, so they are
/// read on every target and run on none — and compiling them on a guest
/// build would ask for the authoring half of a vocabulary that has only
/// its executing half there.
fn strip_macro_attrs(items: &mut [syn::Item], state_name: &syn::Ident) {
    for item in items {
        if let syn::Item::Impl(block) = item
            && matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name))
        {
            block
                .attrs
                .push(syn::parse_quote!(#[cfg(not(target_arch = "wasm32"))]));
        }
        match item {
            syn::Item::Struct(item) => {
                strip(&mut item.attrs);
                for field in &mut item.fields {
                    strip(&mut field.attrs);
                }
            }
            syn::Item::Enum(item) => {
                strip(&mut item.attrs);
                for variant in &mut item.variants {
                    strip(&mut variant.attrs);
                }
            }
            syn::Item::Impl(block) => {
                for item in &mut block.items {
                    if let syn::ImplItem::Fn(method) = item {
                        strip(&mut method.attrs);
                    }
                }
            }
            _ => {}
        }
    }
}

/// One inherent `emit` per event type, at the index the name table fixes.
///
/// The index is the macro's, never the author's: a constant beside a name
/// table is the one thing in the old four-document shape that nothing
/// checked.
fn event_emitters(events: &[(syn::Ident, String)]) -> Vec<syn::Item> {
    events
        .iter()
        .enumerate()
        .map(|(index, (ident, _))| {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            syn::parse_quote!(
                impl #ident {
                    /// Record that this happened, with an opaque payload.
                    ///
                    /// The type index is this package's own, fixed by the
                    /// declaration order of its event structs.
                    pub fn emit(payload: &[u8]) {
                        let _ = payload;
                        #[cfg(target_arch = "wasm32")]
                        ::hyperscale_vm_sdk::guest::emit(#index, payload);
                    }
                }
            )
        })
        .collect()
}

fn expand(mut module: syn::ItemMod) -> syn::Result<TokenStream2> {
    let span = module.span();
    let world = kebab(&module.ident.to_string());
    let Some((_, items)) = &mut module.content else {
        return Err(syn::Error::new(
            span,
            "`#[blueprint]` needs the module's body — it reads the state, the configuration, \
             and every method together",
        ));
    };

    let (state_name, fields, config_name) = parse_state(items, span)?;
    let config_fields = config_slots(items, config_name.as_ref());
    let events = event_names(items);
    let errors = error_names(items);
    let methods = lower_methods(items, &state_name, &fields, &config_fields)?;

    let declarations = methods.iter().map(|m| &m.declaration);
    let event_table = events.iter().map(|(_, name)| quote!(.event(#name)));
    let error_table = errors.iter().map(|name| quote!(.error(#name)));

    let (exports, refusals): (Vec<_>, Vec<_>) =
        methods
            .iter()
            .fold((Vec::new(), Vec::new()), |(mut ok, mut no), method| {
                match &method.guest {
                    Ok(built) => ok.push(built),
                    Err(refusal) => no.push(refusal),
                }
                (ok, no)
            });
    let component = if refusals.is_empty() {
        let shapes: Vec<_> = exports.iter().map(|m| m.export.clone()).collect();
        let document = wit::document(&world, &shapes);
        guest::component(&world, &document, &exports)
    } else {
        quote!(#(#refusals)*)
    };

    strip_macro_attrs(items, &state_name);
    // Nothing in a package constructs its own state: the struct names
    // the roles the kernel materializes storage under, and the
    // configuration record is an instance's, not the code's. On a guest
    // build the authoring half is held back too, so the vocabulary those
    // are written against is read by nothing there either.
    module.attrs.push(syn::parse_quote!(#[allow(dead_code)]));
    module.attrs.push(syn::parse_quote!(
        #[cfg_attr(target_arch = "wasm32", allow(unused_imports))]
    ));
    items.extend(event_emitters(&events));
    items.push(syn::parse_quote!(
        /// This package's metadata, as routing consumes it.
        ///
        /// Derived from the method bodies above; see the `#[blueprint]`
        /// docs for the grammar the derivation admits.
        #[cfg(not(target_arch = "wasm32"))]
        #[must_use]
        pub fn blueprint() -> ::hyperscale_vm_sdk::Blueprint {
            ::hyperscale_vm_sdk::Blueprint::builder()
                #(#declarations)*
                #(#event_table)*
                #(#error_table)*
                .build()
        }
    ));
    items.push(syn::Item::Verbatim(component));

    Ok(quote!(#module))
}

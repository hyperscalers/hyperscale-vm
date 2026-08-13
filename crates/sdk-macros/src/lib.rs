//! The `#[blueprint]` macro: contract bodies lowered to effect
//! declarations.
//!
//! Applied to a module, so the macro sees the component's state, its
//! configuration, and every method together — which is what lets a body
//! written as ordinary Rust yield the access declaration routing needs
//! without the author writing one.
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
mod lower;
mod term;

use std::collections::BTreeMap;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned;

use crate::lower::{Field, FieldKind, Lowerer};

/// Derive a contract's package metadata from its module.
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
        _ => {
            return Err(syn::Error::new(
                field.ty.span(),
                "a state field must be `Locked<_>`, `Cell<_>`, `Keyed<_>`, or `Ordered<_>` — \
                 state is reachable only through these, which is what makes the access mode \
                 derivable from the body",
            ));
        }
    };
    Ok((name, Field { role, kind }))
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

fn strip(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|attr| {
        !(attr.path().is_ident("role")
            || attr.path().is_ident("state")
            || attr.path().is_ident("config")
            || attr.path().is_ident("name"))
    });
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

/// The configuration struct's field names in declaration order — which is
/// what fixes each one's config slot index.
fn config_slots(items: &[syn::Item], config_name: Option<&syn::Ident>) -> Vec<String> {
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
        .filter_map(|field| field.ident.as_ref().map(ToString::to_string))
        .collect()
}

/// One public method's `.method(…)` builder call.
fn lower_method(
    method: &syn::ImplItemFn,
    fields: &BTreeMap<String, Field>,
    config_fields: &[String],
) -> syn::Result<TokenStream2> {
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
        params.push(ident.ident.to_string());
        kinds.push(param_type(&arg.ty)?);
    }

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
    let closure = emit::declaration(&lowered);
    Ok(quote!(
        .method(#published, &[#(#kinds),*], #closure)
    ))
}

/// Every public method of the state struct's inherent impls, lowered.
fn lower_methods(
    items: &[syn::Item],
    state_name: &syn::Ident,
    fields: &BTreeMap<String, Field>,
    config_fields: &[String],
) -> syn::Result<Vec<TokenStream2>> {
    let mut declarations = Vec::new();
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
                declarations.push(lower_method(method, fields, config_fields)?);
            }
        }
    }
    Ok(declarations)
}

/// Remove the macro's own attributes, so what it emits is ordinary Rust.
fn strip_macro_attrs(items: &mut [syn::Item]) {
    for item in items {
        match item {
            syn::Item::Struct(item) => {
                strip(&mut item.attrs);
                for field in &mut item.fields {
                    strip(&mut field.attrs);
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

fn expand(mut module: syn::ItemMod) -> syn::Result<TokenStream2> {
    let span = module.span();
    let Some((_, items)) = &mut module.content else {
        return Err(syn::Error::new(
            span,
            "`#[blueprint]` needs the module's body — it reads the state, the configuration, \
             and every method together",
        ));
    };

    let (state_name, fields, config_name) = parse_state(items, span)?;
    let config_fields = config_slots(items, config_name.as_ref());
    let declarations = lower_methods(items, &state_name, &fields, &config_fields)?;

    strip_macro_attrs(items);
    items.push(syn::parse_quote!(
        /// This package's metadata, as routing consumes it.
        ///
        /// Derived from the method bodies above; see the `#[blueprint]`
        /// docs for the grammar the derivation admits.
        #[must_use]
        pub fn blueprint() -> ::hyperscale_vm_sdk::Blueprint {
            ::hyperscale_vm_sdk::Blueprint::builder()
                #(#declarations)*
                .build()
        }
    ));

    Ok(quote!(#module))
}

//! Codegen: a lowered body becomes the component's executing export.
//!
//! The counterpart of [`crate::emit`], which produces the declaration. The
//! two come out of one walk because they are two readings of one text: the
//! handle a `self.vaults.at(k)` resolves to is the declaration's answer,
//! and the call it is rewritten to is this module's.
//!
//! What arrives at an export is what the body could not compute — the
//! materialized capabilities, a bucket's amount, a fresh id, a
//! configuration slot — so the parameter list is a residue of the body
//! rather than a second declaration of it. Everything else the author
//! wrote passes through unchanged, which is what keeps the grammar the
//! cost of A3 and nothing more.

use proc_macro2::TokenStream;
use quote::quote;

use crate::lower::{Lowered, Need, handle_ident, handle_variant, value_ident};
use crate::term::Term;
use crate::wit::{Export, Param, Shape};

/// One method's generated export, and the `impl Guest` body behind it.
pub struct Method {
    /// The export's shape, which the world is written from.
    pub export: Export,
    /// The `fn` the `impl Guest` block carries.
    pub function: TokenStream,
}

/// The Rust name wit-bindgen gives a kebab-cased export.
fn rust_name(published: &str) -> syn::Ident {
    syn::Ident::new(&published.replace('-', "_"), proc_macro2::Span::call_site())
}

/// The generated Rust type of a borrowed kernel resource.
fn resource_type(resource: &str) -> syn::Ident {
    let camel: String = resource
        .split('-')
        .map(|word| {
            let mut chars = word.chars();
            chars.next().map_or_else(String::new, |first| {
                first.to_uppercase().collect::<String>() + chars.as_str()
            })
        })
        .collect();
    syn::Ident::new(&camel, proc_macro2::Span::call_site())
}

/// How the guest reads the value carrying `need`.
///
/// A `u64` crosses as itself; everything else crosses as the kernel's
/// cell representation and is decoded through [`Cellular`], which is the
/// same vocabulary a substate value uses.
///
/// [`Cellular`]: hyperscale_vm_sdk::state::Cellular
fn value_shape(
    need: &Need,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
) -> Shape {
    let scalar = |ty: &syn::Type| matches!(ty, syn::Type::Path(p) if p.path.is_ident("u64"));
    match need {
        // A bucket crosses as its amount alone, at the kernel's cell
        // width.
        // Both cross at the kernel's own 128-bit cell width: an edge's
        // amount because that is what an amount is, an order key whatever
        // the logical key it was derived from.
        Need::Amount(_) | Need::Derived(Term::OrderKey { .. }) => Shape::Cell(Box::new(
            syn::parse_quote!(::hyperscale_vm_sdk::state::Amount),
        )),
        // A resource is an address however it was derived.
        Need::Derived(Term::SelfResource(_) | Term::ResourceOf(_)) => {
            Shape::Cell(Box::new(syn::parse_quote!(::hyperscale_vm_sdk::Address)))
        }
        Need::Derived(Term::Arg(index)) => {
            params
                .get(*index as usize)
                .map_or(Shape::Scalar, |(_, ty)| {
                    if scalar(ty) {
                        Shape::Scalar
                    } else {
                        Shape::Cell(Box::new(ty.clone()))
                    }
                })
        }
        Need::Derived(Term::Config(index)) => {
            config
                .get(*index as usize)
                .map_or(Shape::Scalar, |(_, ty)| {
                    if scalar(ty) {
                        Shape::Scalar
                    } else {
                        Shape::Cell(Box::new(ty.clone()))
                    }
                })
        }
        // A fresh id is a `u64`, and so is anything else the evaluator
        // reduces to a scalar.
        Need::Derived(_) => Shape::Scalar,
    }
}

/// The author's own name for the `index`-th declared parameter.
fn param_ident(index: u32, params: &[(String, syn::Type)]) -> syn::Ident {
    params.get(index as usize).map_or_else(
        || syn::Ident::new("__edge", proc_macro2::Span::call_site()),
        |(name, _)| syn::Ident::new(name, proc_macro2::Span::call_site()),
    )
}

/// One method's export and its executing body.
///
/// `declines` is the export's error arm, which is what the totality mark
/// is judged against at publish; a body that returns `Err` on it aborts
/// its transaction as a declared refusal rather than as a defect, so the
/// arm is threaded out through the code the package's error table names.
pub fn method(
    published: &str,
    lowered: &Lowered,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
    declines: bool,
) -> Method {
    let mut export = Export {
        name: published.to_owned(),
        params: Vec::new(),
        returns: lowered.returns,
        declines,
    };
    let mut signature = Vec::new();
    let mut prologue = Vec::new();

    for (position, site) in lowered.handles.iter().enumerate() {
        let resource = lowered
            .sites
            .get(*site)
            .and_then(crate::lower::Site::resource)
            .unwrap_or("read-cell");
        export.params.push(Param {
            name: format!("handle-{position}"),
            shape: Shape::Handle(resource),
        });
        let ident = handle_ident(position);
        let ty = resource_type(resource);
        let variant = handle_variant(resource);
        signature.push(quote!(#ident: &#ty));
        // The rep is a borrow for one call and no longer; the mode is the
        // resource type it arrived as, so the variant is a fact about the
        // parameter rather than an assumption at the accessor.
        prologue.push(quote!(
            let #ident = ::hyperscale_vm_sdk::guest::Handle::#variant(#ident.handle());
        ));
    }

    for (position, need) in lowered.values.iter().enumerate() {
        let shape = value_shape(need, params, config);
        export.params.push(Param {
            name: format!("value-{position}"),
            shape: shape.clone(),
        });
        let ident = value_ident(position);
        // A value edge is rebuilt under the name the author gave it, so
        // the body reads it as written. Its amount is what crossed; its
        // resource is the declaration's, and a body that reads one binds
        // it separately.
        if let Need::Amount(param) = need {
            let name = param_ident(*param, params);
            signature.push(quote!(#ident: ::std::vec::Vec<u8>));
            prologue.push(quote!(
                let #name = ::hyperscale_vm_sdk::state::Bucket::carrying(
                    ::hyperscale_vm_sdk::state::Cellular::from_cell(&#ident),
                );
            ));
            continue;
        }
        match shape {
            Shape::Scalar => signature.push(quote!(#ident: u64)),
            Shape::Cell(ty) => {
                signature.push(quote!(#ident: ::std::vec::Vec<u8>));
                prologue.push(quote!(
                    let #ident: #ty =
                        ::hyperscale_vm_sdk::state::Cellular::from_cell(&#ident);
                ));
            }
            Shape::Handle(_) => unreachable!("a value binding is never a capability"),
        }
    }

    let name = rust_name(published);
    let body = &lowered.body;
    let tail = &lowered.result;
    let (result, outcome) = match (lowered.returns, declines) {
        (true, true) => (
            quote!(::core::result::Result<::std::vec::Vec<u8>, u32>),
            quote!(::core::result::Result::Ok(#tail)),
        ),
        (true, false) => (quote!(::std::vec::Vec<u8>), quote!(#tail)),
        (false, true) => (
            quote!(::core::result::Result<(), u32>),
            quote!(::core::result::Result::Ok(())),
        ),
        (false, false) => (quote!(()), quote!()),
    };
    // The author's body runs in a closure so an early `return` on the
    // error arm is the method's own refusal rather than the export's, and
    // the code it carries is mapped to the index the package's error table
    // names in exactly one place.
    let function = if declines {
        quote!(
            fn #name(#(#signature),*) -> #result {
                #(#prologue)*
                match (|| { #body #outcome })() {
                    ::core::result::Result::Ok(__value) => ::core::result::Result::Ok(__value),
                    ::core::result::Result::Err(__code) => {
                        ::core::result::Result::Err(__code as u32)
                    }
                }
            }
        )
    } else {
        quote!(
            fn #name(#(#signature),*) -> #result {
                #(#prologue)*
                #body
                #outcome
            }
        )
    };
    Method { export, function }
}

/// The guest half of a package: its bindings, its exports, and the
/// component registration.
///
/// Emitted under `cfg(target_arch = "wasm32")` alone. A host build reads
/// the same bodies to derive the declaration and never runs them, so
/// generating the imports there would be asking for a kernel that is not
/// present.
pub fn component(world: &str, document: &str, methods: &[&Method]) -> TokenStream {
    let functions = methods.iter().map(|m| &m.function);
    let _ = world;
    quote!(
        // The kernel interfaces are bound in the SDK, once. Generating
        // them again here would produce a second set of Rust types for
        // the same resources, and the accessors could not be called with
        // them.
        //
        // At module scope rather than inside a block: `export!` names the
        // generated types through `self`, so the bindings have to sit
        // where the module's own path reaches them.
        #[cfg(target_arch = "wasm32")]
        ::wit_bindgen::generate!({
            inline: #document,
            world: #world,
            with: {
                "hyperscale:kernel/state": ::hyperscale_vm_sdk::guest::kernel::state,
                "hyperscale:kernel/env": ::hyperscale_vm_sdk::guest::kernel::env,
                "hyperscale:kernel/crypto": ::hyperscale_vm_sdk::guest::kernel::crypto,
                "hyperscale:kernel/events": ::hyperscale_vm_sdk::guest::kernel::events,
            },
        });

        #[cfg(target_arch = "wasm32")]
        struct Component;

        #[cfg(target_arch = "wasm32")]
        impl Guest for Component {
            #(#functions)*
        }

        #[cfg(target_arch = "wasm32")]
        export!(Component);
    )
}

/// The guest half's refusal: a body the emission cannot execute.
///
/// A compile error rather than a silently absent export, and one scoped to
/// the guest build: the declaration the same body yields is sound, and a
/// package whose executing half is written the long way publishes exactly
/// as it does today.
pub fn refusal(method: &str, why: &str) -> TokenStream {
    let message = format!(
        "`#[blueprint]` cannot emit a guest body for `{method}`: {why}. Write this \
         package's component by hand — the publish gate judges artifacts, not \
         authorship"
    );
    quote!(
        #[cfg(target_arch = "wasm32")]
        ::core::compile_error!(#message);
    )
}

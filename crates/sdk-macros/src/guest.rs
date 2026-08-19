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

use proc_macro2::{Span, TokenStream};
use quote::quote;

use crate::bind::{Binding, Carries, bindings};
use crate::lower::Lowered;
use crate::wit::{Export, Shape};

/// One method's generated export, and the `impl Guest` body behind it.
pub struct Method {
    /// The export's shape, which the world is written from.
    pub export: Export,
    /// The `fn` the `impl Guest` block carries.
    pub function: TokenStream,
}

/// The Rust name wit-bindgen gives a kebab-cased export.
fn rust_name(published: &str) -> syn::Ident {
    syn::Ident::new(&published.replace('-', "_"), Span::call_site())
}

/// One method's export and its executing body.
///
/// `declines` is the export's error arm, which is what the totality mark
/// is judged against at publish; a body that returns `Err` on it aborts
/// its transaction as a declared refusal rather than as a defect, so the
/// arm is threaded out through the code the package's error table names.
#[allow(clippy::too_many_lines)] // one pass: parameters, prologue, body, result
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
        outputs: lowered.outputs.len(),
        declines,
    };
    let mut signature = Vec::new();
    let mut prologue = Vec::new();

    for Binding {
        param,
        ident,
        carries,
    } in bindings(lowered, params, config)
    {
        let shape = param.shape.clone();
        export.params.push(param);
        match carries {
            // The rep is a borrow for one call and no longer; the mode is
            // the resource type it arrived as, so the variant is a fact
            // about the parameter rather than an assumption at the
            // accessor.
            // The declaration's own verdict, arriving as itself: the
            // guest branches on it rather than on the condition, so the
            // two cannot disagree.
            Carries::Flag => signature.push(quote!(#ident: bool)),
            Carries::Handle(resource) => {
                let ty = resource.guest_type();
                let variant = resource.handle_variant();
                signature.push(quote!(#ident: &#ty));
                prologue.push(quote!(
                    let #ident = ::hyperscale_vm_sdk::guest::Handle::#variant(#ident.handle());
                ));
            }
            // A value edge is rebuilt under the name and the kind the
            // author gave it, so the body reads it as written. Mutable
            // because a body may split it, and whether one does is not
            // worth a second pass over the text to find out.
            Carries::Edge { name, nf } => {
                signature.push(quote!(#ident: KernelBucket));
                let kind = if nf { quote!(NfBucket) } else { quote!(Bucket) };
                prologue.push(quote!(
                    #[allow(unused_mut)]
                    let mut #name = ::hyperscale_vm_sdk::state::#kind::held(#ident);
                ));
            }
            Carries::Issuer => {
                signature.push(quote!(#ident: &Issuer));
                prologue.push(quote!(let __issuer = #ident.handle();));
            }
            Carries::Value { narrow } => match shape {
                Shape::Scalar => signature.push(quote!(#ident: u64)),
                Shape::Flag => signature.push(quote!(#ident: bool)),
                // Named through the world's own alias, so the generated
                // type cannot collide with the vocabulary's `Address`
                // that the author's module already imports; the words
                // come out at the call site, where both are in scope.
                Shape::Address => {
                    signature.push(quote!(#ident: KernelAddress));
                    let rebuilt = quote!(::hyperscale_vm_sdk::guest::address_of(
                        #ident.a, #ident.b, #ident.c, #ident.d,
                    ));
                    prologue.push(narrow.as_ref().map_or_else(
                        || quote!(let #ident = #rebuilt;),
                        |ty| {
                            quote!(
                                let #ident: #ty =
                                    ::hyperscale_vm_sdk::guest::narrowed(#rebuilt);
                            )
                        },
                    ));
                }
                Shape::Cell(ty) => {
                    signature.push(quote!(#ident: ::std::vec::Vec<u8>));
                    prologue.push(quote!(
                        let #ident: #ty =
                            ::hyperscale_vm_sdk::state::Cellular::from_cell(&#ident);
                    ));
                }
                Shape::Ids => {
                    signature.push(quote!(#ident: ::std::vec::Vec<u64>));
                    prologue.push(quote!(
                        let #ident = ::hyperscale_vm_sdk::state::Ids(#ident);
                    ));
                }
                Shape::Handle(_) | Shape::Bucket | Shape::Issuer => {
                    unreachable!("a value binding is never a handle")
                }
            },
        }
    }

    let name = rust_name(published);
    let body = &lowered.body;
    // A guest hands each edge back as the handle the kernel lends it:
    // one on its own, more than one as the tuple the profile admits for
    // exactly this, so an edge's slot is the order the body produced it.
    let edges = &lowered.edges;
    let tail = match edges.as_slice() {
        [] => quote!(),
        [one] => quote!((#one).into_handle()),
        many => quote!((#((#many).into_handle()),*)),
    };
    let outputs = lowered.outputs.len();
    let edge_type = match outputs {
        0 => quote!(()),
        1 => quote!(KernelBucket),
        n => {
            let each = std::iter::repeat_n(quote!(KernelBucket), n);
            quote!((#(#each),*))
        }
    };
    let (result, outcome) = match (outputs > 0, declines) {
        (true, true) => (
            quote!(::core::result::Result<#edge_type, u32>),
            quote!(::core::result::Result::Ok(#tail)),
        ),
        (true, false) => (edge_type, quote!(#tail)),
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
                "hyperscale:kernel/math": ::hyperscale_vm_sdk::guest::kernel::math,
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
/// as it does today. The error lands on the line that wrote what the
/// emission cannot execute, not on the macro invocation.
pub fn refusal(method: &str, span: Span, why: &str) -> TokenStream {
    let message = format!(
        "`#[blueprint]` cannot emit a guest body for `{method}`: {why}. Write this \
         package's component by hand — the publish gate judges artifacts, not \
         authorship"
    );
    let error = syn::Error::new(span, message).to_compile_error();
    quote!(
        #[cfg(target_arch = "wasm32")]
        const _: () = { #error };
    )
}

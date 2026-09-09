//! Codegen: a lowered body becomes the module's executing export.
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
//!
//! The export is the boundary's own shape: an `extern "C"` function under
//! the published name, scalars and indices as they are, every byte-shaped
//! argument as the length of the input register the prologue collects,
//! and an epilogue that replies with the edges the body produced and the
//! answer it gave. A fallible export returns the decline code plus one,
//! and zero where it completed.

use proc_macro2::{Span, TokenStream};
use quote::quote;

use crate::abi::Shape;
use crate::bind::{Binding, Carries, bindings};
use crate::lower::Lowered;

/// One method's generated export.
pub struct Method {
    /// The `extern "C"` function under the published name.
    pub function: TokenStream,
}

/// The Rust name a kebab-cased export is defined under.
fn rust_name(published: &str) -> syn::Ident {
    syn::Ident::new(&published.replace('-', "_"), Span::call_site())
}

/// One method's export and its executing body.
///
/// `declines` is the export's error arm, which is what the totality mark
/// is judged against at publish; a body that returns `Err` on it aborts
/// its transaction as a declared refusal rather than as a defect, so the
/// arm is threaded out through the code the package's error table names.
/// It is the arm's type rather than the fact of one because the closure
/// the body runs in is annotated with it.
#[allow(clippy::too_many_lines)] // one pass: parameters, prologue, body, epilogue
pub fn method(
    published: &str,
    lowered: &Lowered,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
    declines: Option<&syn::Type>,
) -> Method {
    let mut signature = Vec::new();
    let mut prologue = Vec::new();

    for (
        position,
        Binding {
            param,
            ident,
            carries,
        },
    ) in bindings(lowered, params, config).into_iter().enumerate()
    {
        let position = u32::try_from(position).expect("few parameters");
        let core = param.core();
        signature.push(quote!(#ident: #core));
        // What the export receives for a register argument is its
        // length; the bytes wait in the register at this parameter's
        // position until the prologue collects them.
        let collected = quote!(::hyperscale_vm_sdk::guest::arg(#position, #ident));
        match carries {
            // The declaration's own verdict, arriving as itself: the
            // guest branches on it rather than on the condition, so the
            // two cannot disagree.
            Carries::Flag => prologue.push(quote!(let #ident = #ident != 0;)),
            // One site per declared handle parameter, walked by the
            // element the access names.
            Carries::Handle => prologue.push(quote!(
                let #ident = ::hyperscale_vm_sdk::state::Site::at(#ident);
            )),
            // A value edge is rebuilt under the name and the kind the
            // author gave it, so the body reads it as written. Mutable
            // because a body may split it, and whether one does is not
            // worth a second pass over the text to find out.
            Carries::Edge { name, nf } => {
                let kind = if nf { quote!(NfBucket) } else { quote!(Bucket) };
                prologue.push(quote!(
                    #[allow(unused_mut)]
                    let mut #name = ::hyperscale_vm_sdk::state::#kind::held(
                        ::hyperscale_vm_sdk::guest::BucketHandle::from_rep(#ident),
                    );
                ));
            }
            Carries::Value { narrow } => match param {
                Shape::Scalar => {}
                Shape::Flag => prologue.push(quote!(let #ident = #ident != 0;)),
                Shape::Address => {
                    let rebuilt = quote!(::hyperscale_vm_sdk::guest::address_from(&#collected));
                    prologue.push(narrow.as_ref().map_or_else(
                        || quote!(let #ident = #rebuilt;),
                        |ty| {
                            quote!(
                                let #ident: #ty =
                                    ::hyperscale_vm_sdk::narrowed(#rebuilt);
                            )
                        },
                    ));
                }
                Shape::Cell(ty) => prologue.push(quote!(
                    let #ident: #ty =
                        ::hyperscale_vm_sdk::state::Cellular::from_cell(&#collected);
                )),
                Shape::Ids(ty) => prologue.push(quote!(
                    let #ident: #ty = ::core::convert::Into::into(
                        ::hyperscale_vm_sdk::guest::arg_ids(#position, #ident),
                    );
                )),
                Shape::Handle | Shape::Bucket => {
                    unreachable!("a value binding is never a handle")
                }
            },
        }
    }

    let name = rust_name(published);
    let body = &lowered.body;
    // A guest hands its answer back as the bytes it encoded to, and each
    // edge as the index the kernel holds it at, in the order the body
    // produced them. The answer is evaluated first, as the binding
    // orders it, and every handle is consumed rather than dropped: what
    // is replied is the kernel's to hold again.
    let answered = lowered
        .answer
        .as_ref()
        .map(|answer| quote!(::hyperscale_vm_sdk::guest::answer(&(#answer));));
    let edges = lowered
        .edges
        .iter()
        .map(|edge| quote!((#edge).into_handle().into_rep()));
    let epilogue = quote!(
        #answered
        ::hyperscale_vm_sdk::guest::reply(&[#(#edges),*]);
    );
    // The author's body runs in a closure so an early `return` on the
    // error arm is the method's own refusal rather than the export's, and
    // the code it carries is mapped to the index the package's error table
    // names in exactly one place. The closure names the arm, because a
    // body that only ever propagates one never does. A decline replies
    // with nothing: the return value is the whole of it.
    let function = declines.map_or_else(
        || {
            quote!(
                #[unsafe(export_name = #published)]
                pub extern "C" fn #name(#(#signature),*) {
                    #(#prologue)*
                    #body
                    #epilogue
                }
            )
        },
        |arm| {
            quote!(
                #[unsafe(export_name = #published)]
                pub extern "C" fn #name(#(#signature),*) -> u32 {
                    #(#prologue)*
                    let __declined = || -> ::core::result::Result<(), #arm> {
                        #body
                        #epilogue
                        ::core::result::Result::Ok(())
                    };
                    match __declined() {
                        ::core::result::Result::Ok(()) => 0,
                        ::core::result::Result::Err(__code) => {
                            ::hyperscale_vm_sdk::Declines::code(&__code) + 1
                        }
                    }
                }
            )
        },
    );
    Method { function }
}

/// The guest half of a package: its exports, under the published names.
///
/// Emitted only for the crate that publishes this package, and there
/// only on the build that produces the artifact. Every other build reads
/// the same bodies to derive the declaration and never runs them, so
/// generating the exports would be asking for a kernel that is not
/// present.
pub fn module(methods: &[&Method]) -> TokenStream {
    let functions = methods.iter().map(|m| &m.function);
    quote!(
        #(
            #[cfg(target_arch = "wasm32")]
            #functions
        )*
    )
}

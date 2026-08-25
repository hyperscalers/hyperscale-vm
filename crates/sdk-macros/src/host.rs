//! Codegen: the same lowered bodies, dispatched natively.
//!
//! The sibling of [`crate::guest`], from one [`Lowered`] and one binding
//! walk. What differs is only how a parameter arrives — a handle as the
//! rep the kernel materialized rather than a resource the canonical ABI
//! lent, a value as an assembled argument rather than a lifted one — and
//! what an edge goes back as. Everything between is the author's text,
//! unchanged, which is the whole reason this is worth having.
//!
//! Emitted for every crate that reads this package, and for a publisher
//! on every build but the one that emits its artifact: a component has an
//! engine to be called by and needs no dispatch of its own.

use proc_macro2::TokenStream;
use quote::quote;

use crate::bind::{Binding, Carries, bindings};
use crate::lower::Lowered;
use crate::role::Role;
use crate::wit::Shape;

/// One method's arm of the package's dispatch.
///
/// The prologue reads each parameter out of the assembled arguments at
/// the position the binding walk fixed, so what the body sees is what a
/// guest export's own prologue would have bound.
#[allow(clippy::too_many_lines)] // one prologue arm per parameter shape
pub fn arm(
    published: &str,
    lowered: &Lowered,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
    declines: Option<&syn::Type>,
) -> TokenStream {
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
        prologue.push(match carries {
            Carries::Flag => quote!(
                let #ident = ::hyperscale_vm_sdk::host::flag(__args, #position);
            ),
            Carries::Handle => quote!(
                let #ident = ::hyperscale_vm_sdk::host::handle(__args, #position);
            ),
            Carries::Run => quote!(
                let #ident = ::hyperscale_vm_sdk::state::Run::at(
                    ::hyperscale_vm_sdk::host::run(__args, #position),
                );
            ),
            Carries::Edge { name, nf } => {
                let reader = if nf { quote!(nf_edge) } else { quote!(edge) };
                quote!(
                    #[allow(unused_mut)]
                    let mut #name = ::hyperscale_vm_sdk::host::#reader(__args, #position);
                )
            }
            Carries::Issuer => quote!(
                let __issuer = ::hyperscale_vm_sdk::host::issuer(__args, #position);
            ),
            Carries::Value { narrow } => match param.shape {
                Shape::Scalar => quote!(
                    let #ident = ::hyperscale_vm_sdk::host::scalar(__args, #position);
                ),
                Shape::Flag => quote!(
                    let #ident = ::hyperscale_vm_sdk::host::flag(__args, #position);
                ),
                Shape::Address => {
                    let rebuilt = quote!(::hyperscale_vm_sdk::host::address(__args, #position));
                    narrow.as_ref().map_or_else(
                        || quote!(let #ident = #rebuilt;),
                        |ty| {
                            quote!(
                                let #ident: #ty = ::hyperscale_vm_sdk::narrowed(#rebuilt);
                            )
                        },
                    )
                }
                Shape::Cell(ty) => quote!(
                    let #ident: #ty = ::hyperscale_vm_sdk::state::Cellular::from_cell(
                        ::hyperscale_vm_sdk::host::cell(__args, #position),
                    );
                ),
                Shape::Ids(ty) => quote!(
                    let #ident: #ty = ::core::convert::Into::into(
                        ::hyperscale_vm_sdk::host::ids(__args, #position).to_vec(),
                    );
                ),
                Shape::Handle | Shape::Run | Shape::Bucket | Shape::Issuer => {
                    unreachable!("a value binding is never a handle")
                }
            },
        });
    }

    let body = &lowered.body;
    // A host hands each edge back as the table position the kernel holds
    // it at, which is what the walk's `Produced` carries — the one thing
    // in the tail that is not the guest's. The answer is the guest's
    // own expression, encoded the same way on both halves.
    let edges = &lowered.edges;
    let answer = lowered.answer.as_ref().map_or_else(
        || quote!(::core::option::Option::None),
        |answer| quote!(::core::option::Option::Some(#answer)),
    );
    let produced = quote!(::hyperscale_vm_sdk::host::Invoked::Produced {
        edges: ::std::vec![#((#edges).rep()),*],
        answer: #answer,
    });
    // The author's body runs in a closure so an early `return` on the
    // error arm is the method's own refusal rather than the dispatch's.
    // The closure names the arm, because a body that only ever propagates
    // one — `?` on a helper that made the judgment — never does.
    let running = if edges.is_empty() && lowered.answer.is_none() {
        // A body that yields nothing still runs in a closure of its own,
        // so a bare `return` leaves the method rather than the dispatch —
        // which is what it does in the guest, where each export is its
        // own function.
        quote!({
            (|| { #body })();
            #produced
        })
    } else {
        quote!((|| { #body #produced })())
    };
    let outcome = declines.map_or(running, |arm| {
        quote!({
            let __declined = || -> ::core::result::Result<_, #arm> {
                #body
                ::core::result::Result::Ok(#produced)
            };
            match __declined() {
                ::core::result::Result::Ok(__produced) => __produced,
                ::core::result::Result::Err(__code) => {
                    ::hyperscale_vm_sdk::host::Invoked::Declined(__code as u32)
                }
            }
        })
    });

    quote!(#published => {
        #(#prologue)*
        #outcome
    })
}

/// The package's native dispatch: one export name to one lowered body.
///
/// Generic over the kernel rather than naming one, because the SDK has
/// no session to name — an embedder brings its own host and gets the
/// same one back, which is what lets this sit behind the kernel's own
/// backend seam without the package crate depending on the kernel.
pub fn dispatch(arms: &[TokenStream], role: Role) -> TokenStream {
    let reading = role.reading();
    quote!(
        /// Invoke one of this package's exports against `kernel`.
        ///
        /// Called by a test harness through the kernel's backend seam,
        /// never by an author: what the arguments are is the manifest's
        /// answer, and what they mean is the declaration's.
        #reading
        #[must_use]
        // A rewritten body is not the author's text: a binding the
        // lowering resolved away is unused here and used there, and a
        // lint about it would name a line nobody wrote.
        #[allow(unused_mut, unused_variables)]
        pub fn invoke<__K: ::hyperscale_vm_sdk::host::Kernel>(
            export: &str,
            kernel: __K,
            args: &[::hyperscale_vm_sdk::host::GuestArg<'_>],
        ) -> (__K, ::hyperscale_vm_sdk::host::Invoked) {
            let __args = args;
            ::hyperscale_vm_sdk::host::dispatch(kernel, move || match export {
                #(#arms)*
                _ => ::hyperscale_vm_sdk::host::no_such_export(),
            })
        }
    )
}

//! Codegen: the same lowered bodies, dispatched natively.
//!
//! The sibling of [`crate::guest`], from one [`Lowered`] and one binding
//! walk. What differs is only how a parameter arrives — a handle as the
//! rep the kernel materialized rather than a resource the canonical ABI
//! lent, a value as an assembled argument rather than a lifted one — and
//! what an edge goes back as. Everything between is the author's text,
//! unchanged, which is the whole reason this is worth having.
//!
//! Emitted under `cfg(not(target_arch = "wasm32"))` alone: the guest
//! build has an engine to be called by and needs no dispatch of its own.

use proc_macro2::TokenStream;
use quote::quote;

use crate::bind::{Binding, Carries, bindings};
use crate::lower::Lowered;
use crate::wit::Shape;

/// One method's arm of the package's dispatch.
///
/// The prologue reads each parameter out of the assembled arguments at
/// the position the binding walk fixed, so what the body sees is what a
/// guest export's own prologue would have bound.
pub fn arm(
    published: &str,
    lowered: &Lowered,
    params: &[(String, syn::Type)],
    config: &[(String, syn::Type)],
    declines: bool,
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
            Carries::Handle(resource) => {
                let kind = resource.cell_kind();
                quote!(
                    let #ident = ::hyperscale_vm_sdk::host::handle(
                        __args,
                        #position,
                        ::hyperscale_vm_sdk::host::CellKind::#kind,
                    );
                )
            }
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
            Carries::Value => match param.shape {
                Shape::Scalar => quote!(
                    let #ident = ::hyperscale_vm_sdk::host::scalar(__args, #position);
                ),
                Shape::Flag => quote!(
                    let #ident = ::hyperscale_vm_sdk::host::flag(__args, #position);
                ),
                Shape::Address => quote!(
                    let #ident = ::hyperscale_vm_sdk::host::address(__args, #position);
                ),
                Shape::Cell(ty) => quote!(
                    let #ident: #ty = ::hyperscale_vm_sdk::state::Cellular::from_cell(
                        ::hyperscale_vm_sdk::host::cell(__args, #position),
                    );
                ),
                Shape::Ids => quote!(
                    let #ident = ::hyperscale_vm_sdk::state::Ids(
                        ::hyperscale_vm_sdk::host::ids(__args, #position).to_vec(),
                    );
                ),
                Shape::Handle(_) | Shape::Bucket | Shape::Issuer => {
                    unreachable!("a value binding is never a handle")
                }
            },
        });
    }

    let body = &lowered.body;
    // A host hands each edge back as the table position the kernel holds
    // it at, which is what the walk's `Produced` carries — the one thing
    // in the tail that is not the guest's.
    let edges = &lowered.edges;
    let produced = quote!(::std::vec![#((#edges).rep()),*]);
    // The author's body runs in a closure so an early `return` on the
    // error arm is the method's own refusal rather than the dispatch's.
    let outcome = if declines {
        quote!(
            match (|| { #body ::core::result::Result::Ok(#produced) })() {
                ::core::result::Result::Ok(__edges) => {
                    ::hyperscale_vm_sdk::host::Invoked::Produced(__edges)
                }
                ::core::result::Result::Err(__code) => {
                    ::hyperscale_vm_sdk::host::Invoked::Declined(__code as u32)
                }
            }
        )
    } else if edges.is_empty() {
        // A body that yields nothing still runs in a closure of its own,
        // so a bare `return` leaves the method rather than the dispatch —
        // which is what it does in the guest, where each export is its
        // own function.
        quote!({
            (|| { #body })();
            ::hyperscale_vm_sdk::host::Invoked::Produced(::std::vec![])
        })
    } else {
        quote!(::hyperscale_vm_sdk::host::Invoked::Produced(
            (|| { #body #produced })()
        ))
    };

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
pub fn dispatch(arms: &[TokenStream]) -> TokenStream {
    quote!(
        /// Invoke one of this package's exports against `kernel`.
        ///
        /// Called by a test harness through the kernel's backend seam,
        /// never by an author: what the arguments are is the manifest's
        /// answer, and what they mean is the declaration's.
        #[cfg(not(target_arch = "wasm32"))]
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

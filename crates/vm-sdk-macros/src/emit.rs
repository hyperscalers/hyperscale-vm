//! Codegen: a lowered body becomes calls into the tracer.
//!
//! Deliberately the *only* thing the macro emits for declarations. It does
//! not build `Expr` literals, so every property the tracer already carries
//! — de Bruijn conversion, fresh-slot uniqueness, the structural bounds —
//! applies to macro output without being restated, and the macro's own
//! correctness reduces to "did it call the tracer the way a human would".
//! That reduction is what the parity test checks.

use proc_macro2::TokenStream;
use quote::quote;

use crate::lower::{Lowered, Node, Site, Target};
use crate::term::{Op, Term, binding_ident};

/// The mode a site's operations fold to.
///
/// Read off the lattice rather than tabulated: a cell a body both reads and
/// writes is an exclusive read-modify-write, because `Write` subsumes
/// `Read`. Everything else names its own point.
/// A mode's parameter is evaluated before the access opens.
///
/// `Access` borrows the tracer mutably for as long as it is alive, and
/// building a reserve amount reads the tracer to
/// resolve arguments. Emitting the parameter into the call site would put
/// both borrows on one expression; hoisting it is what keeps the generated
/// code compiling for every declaration rather than only the ones with no
/// mode parameter.
fn mode(site: &Site) -> Option<(TokenStream, TokenStream)> {
    let has = |op: Op| site.ops.iter().find(|(o, _)| *o == op);
    let param = |op: Op| has(op).and_then(|(_, p)| p.clone());
    let nothing = quote!();

    if has(Op::Set).is_some() {
        Some((nothing, quote!(.write())))
    } else if has(Op::Get).is_some() {
        Some((nothing, quote!(.read())))
    } else if let Some(amount) = param(Op::Reserve) {
        let amount = amount.emit();
        Some((
            quote!(let __param = #amount.cast::<::hyperscale_vm_sdk::Amount>();),
            quote!(.reserve(&__param)),
        ))
    } else if has(Op::Delta).is_some() {
        Some((nothing, quote!(.delta())))
    } else if has(Op::Locked).is_some() {
        Some((nothing, quote!(.locked())))
    } else {
        // A handle opened and never used declares nothing. Correct rather
        // than lenient: the body did not touch the substate.
        None
    }
}

fn target(target: &Target) -> TokenStream {
    match target {
        Target::Point { role, material } => {
            let material = material.iter().map(Term::emit);
            quote!(
                let __owner = __t.self_addr();
                let __key = __owner.child(
                    ::hyperscale_vm_sdk::RoleId(#role),
                    &[#(#material),*],
                );
                let __access = __t.point(&__key);
            )
        }
        Target::Entry { role, order } => {
            let order = order.emit();
            quote!(
                let __owner = __t.self_addr();
                let __order = #order.cast::<::hyperscale_vm_sdk::Amount>();
                let __access = __t.entry(
                    &__owner,
                    ::hyperscale_vm_sdk::RoleId(#role),
                    &__order,
                );
            )
        }
        Target::Range { role, lo, hi, cap } => {
            let lo = lo.emit();
            let hi = hi.emit();
            quote!(
                let __owner = __t.self_addr();
                let __lo = #lo.cast::<::hyperscale_vm_sdk::Amount>();
                let __hi = #hi.cast::<::hyperscale_vm_sdk::Amount>();
                let __access = __t.range(
                    &__owner,
                    ::hyperscale_vm_sdk::RoleId(#role),
                    &__lo,
                    &__hi,
                    #cap,
                );
            )
        }
    }
}

fn node(node: &Node, lowered: &Lowered) -> TokenStream {
    match node {
        Node::Site(index) => {
            let Some(site) = lowered.sites.get(*index) else {
                return quote!();
            };
            let Some((prelude, call)) = mode(site) else {
                return quote!();
            };
            let target = target(&site.target);
            quote!({ #prelude #target __access #call; })
        }
        Node::ForEach { list, depth, body } => {
            let list = list.emit();
            let element = binding_ident(*depth);
            let body = body.iter().map(|n| self::node(n, lowered));
            quote!({
                let __list = #list.cast::<::hyperscale_vm_sdk::Seq>();
                __t.for_each(&__list, |__t, #element| {
                    #(#body)*
                });
            })
        }
    }
}

/// The declaration closure for one lowered method.
pub fn declaration(lowered: &Lowered) -> TokenStream {
    let nodes = lowered.nodes.iter().map(|n| node(n, lowered));
    let outputs = lowered.outputs.iter().map(|term| {
        let term = term.emit();
        quote!(__t.output(&#term.cast::<::hyperscale_vm_sdk::Addr>());)
    });
    quote!(
        |__t: &mut ::hyperscale_vm_sdk::Trace| {
            #(#nodes)*
            #(#outputs)*
        }
    )
}

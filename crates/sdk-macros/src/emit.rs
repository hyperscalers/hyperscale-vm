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

use crate::lower::{Lowered, Need, Node, Site, Target};
use crate::term::{Op, Term, binding_ident, emit_behaviour, emit_issued, emit_kind, fresh_ident};

/// The mode a site's operations fold to.
///
/// Read off the lattice rather than tabulated: a cell a body both reads and
/// writes is an exclusive read-modify-write, because `Write` subsumes
/// `Read`. Every other mix was refused when the operation was recorded, so
/// by the time a site reaches emission its operations name one mode.
/// A mode's parameter is evaluated before the access opens.
///
/// `Capability` borrows the tracer mutably for as long as it is alive, and
/// building a reserve amount reads the tracer to
/// resolve arguments. Emitting the parameter into the call site would put
/// both borrows on one expression; hoisting it is what keeps the generated
/// code compiling for every declaration rather than only the ones with no
/// mode parameter.
pub fn mode(site: &Site) -> Option<(TokenStream, TokenStream)> {
    let has = |op: Op| site.ops.iter().find(|(o, _)| *o == op);
    let param = |op: Op| has(op).and_then(|(_, p)| p.clone());
    let nothing = quote!();

    // An interval has no commutative mode: the kernel materializes one
    // capability over the whole span, so a body that moves value through
    // one holds it exclusively rather than queuing against it.
    if matches!(
        site.target,
        Target::Entry { .. }
            | Target::Range { .. }
            | Target::KeyedEntry { .. }
            | Target::Sweep { .. }
    ) {
        return match (
            has(Op::Set).is_some() || has(Op::Move).is_some() || has(Op::Credit).is_some(),
            has(Op::Get).is_some(),
        ) {
            (true, _) => Some((nothing, quote!(.write()))),
            (false, true) => Some((nothing, quote!(.read()))),
            (false, false) => None,
        };
    }

    // A presence requirement is the exclusive mode carrying what it
    // requires of the leaf, so it answers before the unqualified write
    // rather than beside it. No two of these can be recorded on one site
    // — the lowering refuses every pair, in either order — so this
    // states a precedence rather than resolving a conflict.
    if has(Op::Create).is_some() {
        return Some((nothing, quote!(.create())));
    }
    if has(Op::Existing).is_some() {
        return Some((nothing, quote!(.existing())));
    }
    if has(Op::Vacant).is_some() {
        return Some((nothing, quote!(.vacant())));
    }

    // The same order the resource derivation reads: an assignment or a
    // read makes the mode exclusive, and a movement without either
    // commutes.
    let moves = has(Op::Move).is_some() || has(Op::Credit).is_some();
    if has(Op::Set).is_some() || (moves && has(Op::Get).is_some()) {
        Some((nothing, quote!(.write())))
    } else if has(Op::Get).is_some() {
        Some((nothing, quote!(.read())))
    } else if let Some(amount) = param(Op::Reserve) {
        let amount = amount.emit();
        Some((
            quote!(let __param = #amount.cast::<::hyperscale_vm_sdk::U128>();),
            quote!(.reserve(&__param)),
        ))
    } else if has(Op::Move).is_some() {
        Some((nothing, quote!(.delta())))
    } else if has(Op::Credit).is_some() {
        // Only the crediting half, so the declaration says so and is
        // judged on that alone. A body that also takes reached the arm
        // above, where the direction is no longer something to state.
        Some((nothing, quote!(.credit())))
    } else {
        // A handle opened and never used declares nothing. Correct rather
        // than lenient: the body did not touch the substate.
        None
    }
}

/// Whose prefix a site's leaf sits under.
///
/// A reaching access names it; every other one lands under the declaring
/// instance's, which is the only owner a declaration can name without an
/// authority behind it. A reached owner arrives as whatever the body
/// named it, which the DSL types opaquely — the evaluator checks the
/// real kind where the key is derived, so a wrong one is a refused call
/// rather than an unsound declaration.
fn owning(owner: Option<&Term>) -> TokenStream {
    owner.map_or_else(
        || quote!(let __owner = __t.self_addr();),
        |whose| {
            let whose = whose.emit();
            quote!(
                let __owner: ::hyperscale_vm_sdk::sym::Sym<::hyperscale_vm_sdk::sym::Addr> =
                    #whose.cast();
            )
        },
    )
}

fn target(site: &Site) -> TokenStream {
    match &site.target {
        Target::Point {
            slot,
            material,
            owner,
        } => {
            let material = material.iter().map(Term::emit);
            let owner = owning(owner.as_ref());
            quote!(
                #owner
                let __key = __owner.child(
                    ::hyperscale_vm_sdk::SlotId(#slot),
                    &[#(#material),*],
                );
                let __access = __t.point(&__key);
            )
        }
        Target::Entry {
            slot,
            material,
            order,
        } => {
            let material = material.iter().map(Term::emit);
            let order = order.emit();
            quote!(
                let __owner = __t.self_addr();
                let __material = [#(#material),*];
                let __order = #order.cast::<::hyperscale_vm_sdk::U128>();
                let __access = __t.entry(
                    &__owner,
                    ::hyperscale_vm_sdk::SlotId(#slot),
                    &__material,
                    &__order,
                );
            )
        }
        Target::KeyedEntry { slot, key } => {
            let key = key.emit();
            quote!(
                let __owner = __t.self_addr();
                let __key = #key;
                let __access = __t.keyed_entry(
                    &__owner,
                    ::hyperscale_vm_sdk::SlotId(#slot),
                    &__key,
                );
            )
        }
        Target::Sweep { slot, cursor, cap } => {
            let cursor = cursor.emit();
            let cap = cap.emit();
            quote!(
                let __owner = __t.self_addr();
                let __cursor = #cursor.cast::<::hyperscale_vm_sdk::U128>();
                let __cap = #cap.cast::<::hyperscale_vm_sdk::U64>();
                let __access = __t.sweep(
                    &__owner,
                    ::hyperscale_vm_sdk::SlotId(#slot),
                    &__cursor,
                    &__cap,
                );
            )
        }
        Target::Range {
            slot,
            material,
            lo,
            hi,
            cap,
        } => {
            let material = material.iter().map(Term::emit);
            let lo = lo.emit();
            let hi = hi.emit();
            // An authored cap, or the one the site's move derived. The
            // lowering refuses a capless interval nothing moves through,
            // so the fallback stands only beside an error already
            // reported.
            let cap = cap
                .clone()
                .or_else(|| site.moved.clone())
                .unwrap_or(Term::LitU64(0))
                .emit();
            quote!(
                let __owner = __t.self_addr();
                let __material = [#(#material),*];
                let __lo = #lo.cast::<::hyperscale_vm_sdk::U128>();
                let __hi = #hi.cast::<::hyperscale_vm_sdk::U128>();
                let __cap = #cap.cast::<::hyperscale_vm_sdk::U64>();
                let __access = __t.range(
                    &__owner,
                    ::hyperscale_vm_sdk::SlotId(#slot),
                    &__material,
                    &__lo,
                    &__hi,
                    &__cap,
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
            let target = target(site);
            // What the cell holds, stated on the clause that names it, so
            // execution can refuse a movement across two resources without
            // consulting anything a caller wrote. Resolved before the
            // access opens, because the term reads the tracer and the open
            // access is holding it.
            let held = site.denomination.as_ref().map(|resource| {
                let resource = resource.emit();
                quote!(let __held = #resource.cast::<::hyperscale_vm_sdk::Addr>();)
            });
            let holding = site
                .denomination
                .as_ref()
                .map(|_| quote!(.holding(&__held)));
            // A handle parameter names the clause just declared, so the
            // binding rides beside the declaration rather than being
            // recomputed from it. A site inside a loop names its position
            // in the loop's body instead, which is the one thing about
            // the binding that a `for-each` changes.
            let bind = lowered.handles.contains(index).then(|| {
                if lowered.looped.contains(index) {
                    quote!(__t.bind_looped();)
                } else {
                    quote!(__t.bind_handle();)
                }
            });
            // A reaching access says which authority lets it name the
            // prefix it named, and the entry that authority holds is
            // injected where the declaration is evaluated.
            let reaching = site.reach.map(|behaviour| {
                let behaviour = emit_behaviour(behaviour);
                quote!(.reaching(#behaviour))
            });
            let declare =
                quote!({ #prelude #held #target __access #reaching #holding #call; #bind });
            // The condition the clause is declared under, where the cell
            // is only ever reached under one. It wraps the declaration
            // rather than nesting it: the tracer conjoins conditions and
            // leaves every clause where it was, so a guard changes what a
            // clause says and never where it sits.
            match &site.guard {
                None => declare,
                Some(cond) => {
                    let cond = cond.emit();
                    quote!({
                        let __cond = #cond.cast::<::hyperscale_vm_sdk::Flag>();
                        __t.when(&__cond, |__t| #declare);
                    })
                }
            }
        }
        // The flag names the clause just declared, which the tracer knows
        // as the last one emitted — so the binding rides in the emission
        // order rather than being recovered by counting a clause list.
        Node::BindGuard => quote!(__t.bind_guard();),
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
///
/// `gate` is the accessibility the method's own attribute names, which
/// may declare a clause of its own: an authorizing gate's rule read
/// happens before the export runs, so it is the gate's to declare and
/// no handle is bound for it.
pub fn declaration(
    lowered: &Lowered,
    gate: &TokenStream,
    declines: bool,
    total: bool,
    grants: &TokenStream,
) -> TokenStream {
    // One draw per call site: the entry key derived from a fresh id and
    // the parameter carrying that id have to name the same slot.
    let fresh = (0..lowered.fresh).map(|site| {
        let ident = fresh_ident(site);
        quote!(let #ident = __t.fresh_id();)
    });
    let nodes = lowered.nodes.iter().map(|n| node(n, lowered));
    let outputs = lowered.outputs.iter().map(|term| {
        let term = term.emit();
        quote!(__t.output(&#term.cast::<::hyperscale_vm_sdk::Addr>());)
    });
    let denominations = lowered.denominations.iter().map(|(param, term)| {
        let term = term.emit();
        quote!(__t.denomination(#param, &#term.cast::<::hyperscale_vm_sdk::Addr>());)
    });
    // Values bind after the handles for a reason the export's own
    // signature shows: a reader of the binding wants the capabilities
    // together, not interleaved with wherever each value was first
    // needed.
    let values = lowered.values.iter().map(|need| match need {
        Need::Amount(param) => quote!(__t.bind_bucket(#param);),
        Need::Derived(term) => {
            let term = term.emit();
            quote!(__t.bind_derived(&#term);)
        }
    });
    // The grant binds after the values, which is where the export takes
    // it: the binding's order is the export's parameter order.
    // One binding per mark, in the order the lowering reached them —
    // which is the index each of the body's own calls passes.
    let issuer = lowered.issues.iter().map(|(kind, mark, direction)| {
        let kind = emit_kind(*kind);
        let direction = emit_issued(*direction);
        let bytes = syn::LitByteStr::new(mark, proc_macro2::Span::call_site());
        quote!(__t.bind_issuer(#kind, #bytes, #direction);)
    });
    // One binding per bucket the body retires on somebody else's behalf.
    let destroyer = lowered
        .destroys
        .iter()
        .map(|param| quote!(__t.bind_destroyer(#param);));
    let fallible = declines.then(|| quote!(__t.fallible();));
    let answers = lowered.answer.is_some().then(|| quote!(__t.answers();));
    let total = total.then(|| quote!(__t.total();));
    quote!(
        |__t: &mut ::hyperscale_vm_sdk::Trace| {
            #grants
            #(#fresh)*
            #gate
            #fallible
            #total
            #answers
            #(#nodes)*
            #(#outputs)*
            #(#denominations)*
            #(#values)*
            #(#issuer)*
            #(#destroyer)*
        }
    )
}

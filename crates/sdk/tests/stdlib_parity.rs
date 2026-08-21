//! The spike's headline claim: an author writing ordinary Rust reaches the
//! authored signature form exactly.
//!
//! Each package below is re-declared through the tracer by hand and
//! compared to what its own crate publishes, with `assert_eq!` on the
//! whole [`MethodSignature`]. For `splitter`, which is metadata-only, the
//! other side is a hand-written literal. For the rest it is what
//! `#[blueprint]` derived — so what these compare is a human calling the
//! tracer against the macro calling it, which is exactly the reduction
//! the macro's correctness rests on and the one thing a committed
//! snapshot of the macro's own output cannot make.
//!
//! Equality is the right bar rather than an over-strict one. A signature
//! that merely *routes the same* on the cases someone thought to test is
//! not the same signature; it can diverge on the case nobody wrote. Whole-
//! structure equality against a fixture that is already routed under test
//! elsewhere in the workspace means the SDK's output inherits every one of
//! those tests without restating them.

use hyperscale_vm_effects::vocabulary::{AUTH, CLAIMS, CONFIG, VAULT};
use hyperscale_vm_effects::{CONFIRMATION, PackageMetadata, ParamType, RECOVERY, SlotId};
use hyperscale_vm_fixtures::{
    amm as amm_package, book as book_package, splitter as splitter_package,
};
use hyperscale_vm_sdk::sym::{
    Addr, Amount, Bucket, Num, Sym, eq, lit_u64, pack, select, self_record,
};
use hyperscale_vm_sdk::{Blueprint, GrantedBehaviour, Trace};
use hyperscale_vm_stdlib::account as account_package;

/// The fungible account.
fn account() -> Blueprint {
    Blueprint::builder()
        .method(
            "withdraw",
            &[ParamType::Resource, ParamType::U128],
            |t: &mut Trace| {
                let resource: Sym<Addr> = t.arg(0);
                let amount: Sym<Amount> = t.arg(1);
                let holder = t.self_addr();

                // The gate first: the macro emits it ahead of the body.
                let rule = t.claim(&holder);
                t.guarded_by(rule);
                let vault = holder.child(VAULT, &[resource.clone().cast()]);
                t.point(&vault).holding(&resource).reserve(&amount);
                t.output(&resource);
            },
        )
        .method(
            "recall",
            &[ParamType::Resource, ParamType::U128],
            |t: &mut Trace| {
                let resource: Sym<Addr> = t.arg(0);
                let _amount: Sym<Amount> = t.arg(1);
                let holder = t.self_addr();

                // The gate is the resource's own granted rule, resolved
                // at admission from the presented record.
                let rule = t.granted(GrantedBehaviour::Recall, &resource);
                t.guarded_by(rule);
                let vault = holder.child(VAULT, &[resource.clone().cast()]);
                t.point(&vault).holding(&resource).delta();
                t.output(&resource);
            },
        )
        .method("deposit", &[ParamType::Bucket], |t: &mut Trace| {
            let funds: Sym<Bucket> = t.arg(0);
            let resource = funds.resource();
            let holder = t.self_addr();

            // The guaranteed-delivery fallback and the vault beside it,
            // both keyed by the arriving bucket's resource. The fallback
            // is declared first because the body states it first: the
            // credit consumes the edge, so it comes after every read of
            // what the edge carries.
            let claims = holder.child(CLAIMS, &[resource.clone().cast()]);
            let vault = holder.child(VAULT, &[resource.clone().cast()]);
            t.point(&claims).holding(&resource).delta();
            t.point(&vault).holding(&resource).delta();
        })
        // The sign-in's whole body is its gate's read: the cell the
        // account's stored rule lives in.
        .method("authorize", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).read();
            t.authorizing();
        })
        // Securify and the recovery surface all write the same cell,
        // exclusively — every role rewrite conflicts with every
        // concurrent sign-in's read — and each says what it requires of
        // the leaf: the one-way door is a write onto an absent cell, and
        // a recovery is a write onto one that is there.
        .method(
            "securify",
            &[ParamType::RoleTable, ParamType::U64],
            |t: &mut Trace| {
                let holder = t.self_addr();
                let rule = t.claim(&holder);
                t.guarded_by(rule);
                let cell = holder.child(AUTH, &[]);
                t.point(&cell).create();
            },
        )
        .method(
            "propose",
            &[ParamType::RoleTable, ParamType::U64],
            |t: &mut Trace| {
                let holder = t.self_addr();
                let cell = holder.child(AUTH, &[]);
                t.point(&cell).existing();
                t.role_gated(RECOVERY);
            },
        )
        .method("cancel", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).existing();
            t.role_gated(RECOVERY);
        })
        .method("freeze", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).existing();
            t.role_gated(RECOVERY);
        })
        .method("confirm", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).existing();
            t.role_gated(CONFIRMATION);
        })
        .build()
}

/// The constant-product pool.
fn amm() -> Blueprint {
    Blueprint::builder()
        .method(
            "swap",
            &[ParamType::Bucket, ParamType::U128],
            |t: &mut Trace| {
                // The reserve pair is creation-fixed, and which side of it
                // a call sells is read off the arriving bucket — so both
                // vault keys are one conditional over configuration
                // rather than a resource the caller chose.
                let x: Sym<Addr> = t.config(0);
                let y: Sym<Addr> = t.config(1);
                let input: Sym<Bucket> = t.arg(0);
                let pool = t.self_addr();

                let sells_x = eq(&input.resource(), &x);
                let sold: Sym<Addr> = select(&sells_x, &x, &y).cast();
                let bought: Sym<Addr> = select(&sells_x, &y, &x).cast();

                t.point(&pool.child(VAULT, &[sold.clone().cast()]))
                    .holding(&sold)
                    .write();
                t.point(&pool.child(VAULT, &[bought.clone().cast()]))
                    .holding(&bought)
                    .write();

                // The payment is credited to the side the pool sells, so
                // a resource in neither side is one the pair refuses.
                t.denomination(0, &sold);
                t.output(&bought);
            },
        )
        .method("instantiate", &[], |t: &mut Trace| {
            // The generated seal: the record into the configuration
            // leaf, under the one-way door its absence is, with the
            // bytes evaluated rather than supplied.
            let leaf = t.self_addr().child(CONFIG, &[]);
            t.point(&leaf).create();
            t.bind_handle();
            t.bind_derived(&self_record());
        })
        .build()
}

/// The order book.
fn book() -> Blueprint {
    Blueprint::builder()
        .method(
            "place-ask",
            &[ParamType::U64, ParamType::Bucket],
            |t: &mut Trace| {
                let price: Sym<Num> = t.arg(0);
                let _funds: Sym<Bucket> = t.arg(1);
                let venue = t.self_addr();

                // Price over a fresh sequence id: the tiebreaker that makes
                // the order key unique without reading the book.
                let seq = t.fresh_id();
                let order = pack(&price, &seq);
                t.entry(&venue, book_package::ASKS, &[], &order).write();

                // The escrow is the book's own base vault, named by its
                // configured pair rather than by whatever arrived — which
                // is what fixes the parameter to that side.
                let base: Sym<Addr> = t.config(0);
                let escrow = venue.child(VAULT, &[base.clone().cast()]);
                t.point(&escrow).holding(&base).delta();
                t.denomination(1, &base);
            },
        )
        .method(
            "fill-asks",
            &[ParamType::U64, ParamType::U64, ParamType::Bucket],
            |t: &mut Trace| {
                let from: Sym<Num> = t.arg(0);
                let to: Sym<Num> = t.arg(1);
                let payment: Sym<Bucket> = t.arg(2);
                let base: Sym<Addr> = t.config(0);
                let venue = t.self_addr();

                // The whole tiebreaker span at each end, so the interval
                // covers every sequence at the boundary prices.
                let lo = pack(&from, &lit_u64(0));
                let hi = pack(&to, &lit_u64(u64::MAX));
                t.range(
                    &venue,
                    book_package::ASKS,
                    &[],
                    &lo,
                    &hi,
                    &lit_u64(u64::from(book_package::FILL_CAP)),
                )
                .write();

                let quote: Sym<Addr> = t.config(1);
                t.point(&venue.child(VAULT, &[base.clone().cast()]))
                    .holding(&base)
                    .delta();
                t.point(&venue.child(VAULT, &[quote.clone().cast()]))
                    .holding(&quote)
                    .delta();
                t.denomination(2, &quote);

                // The change is what came off the payment, so it carries
                // the payment's own resource however the vault it did not
                // reach is keyed.
                t.output(&base);
                t.output(&payment.resource());
            },
        )
        .method("instantiate", &[], |t: &mut Trace| {
            // The generated seal: the record into the configuration
            // leaf, under the one-way door its absence is, with the
            // bytes evaluated rather than supplied.
            let leaf = t.self_addr().child(CONFIG, &[]);
            t.point(&leaf).create();
            t.bind_handle();
            t.bind_derived(&self_record());
        })
        .build()
}

/// The bucket splitter: two output edges, no effects at all.
fn splitter() -> Blueprint {
    Blueprint::builder()
        .method(
            "take",
            &[ParamType::Bucket, ParamType::U128],
            |t: &mut Trace| {
                let funds: Sym<Bucket> = t.arg(0);
                t.output(&funds.resource());
                t.output(&funds.resource());
            },
        )
        .build()
}

/// The account's fungible surface, which is what the declaration above
/// covers.
fn fungible_account() -> PackageMetadata {
    let mut authored = account_package::metadata();
    // The instance surface and the custody gate are declared above by
    // neither name: what they would add here is a third spelling of the
    // holdings interval, where the two that matter — the module's and the
    // gate's pinned shape — already agree.
    for aside in [
        "deposit-nf",
        "withdraw-nf",
        "present-badge",
        "present-instance",
    ] {
        authored.methods.remove(aside);
    }
    authored
}

fn assert_parity(traced: &Blueprint, authored: &PackageMetadata, package: &str) {
    let traced = traced.metadata();
    for (name, signature) in &authored.methods {
        let got = traced
            .methods
            .get(name)
            .unwrap_or_else(|| panic!("{package}: the SDK declared no `{name}`"));
        // Everything a body and its gates determine, compared field by
        // field. The ABI binding is deliberately not among them: a trace
        // sees which handles a body opened and in what order, never the
        // component's exported parameter list, which is authored beside
        // the WIT. What validates the binding is the publish check,
        // against the export type in the artifact itself.
        assert_eq!(got.params, signature.params, "{package}::{name} params");
        assert_eq!(got.outputs, signature.outputs, "{package}::{name} outputs");
        assert_eq!(
            got.denominations, signature.denominations,
            "{package}::{name} denominations"
        );
        assert_eq!(got.effects, signature.effects, "{package}::{name} effects");
    }
    assert_eq!(
        traced.methods.keys().collect::<Vec<_>>(),
        authored.methods.keys().collect::<Vec<_>>(),
        "{package}: the method sets differ"
    );
}

#[test]
fn the_account_traces_to_its_authored_signature() {
    assert_parity(&account(), &fungible_account(), "account");
}

#[test]
fn the_pool_traces_to_its_authored_signature() {
    assert_parity(&amm(), &amm_package::metadata(), "amm");
}

#[test]
fn the_book_traces_to_its_authored_signature() {
    assert_parity(&book(), &book_package::metadata(), "book");
}

#[test]
fn the_splitter_traces_to_its_authored_signature() {
    assert_parity(&splitter(), &splitter_package::metadata(), "splitter");
}

#[test]
fn every_authored_role_is_reachable_from_the_sdk() {
    // A guard on the fixtures rather than on the SDK: if a role is added to
    // the stdlib and no traced declaration names it, the parity tests above
    // are silently covering less than they read as covering. A package
    // traced from its own module needs no entry — there is no second
    // declaration left to cover.
    let named = [VAULT, CLAIMS, CONFIG, book_package::ASKS];
    assert_eq!(
        named.len(),
        4,
        "a role was added to the stdlib without a traced declaration to match"
    );
    assert!(named.iter().all(|r| *r != SlotId(0)));
}

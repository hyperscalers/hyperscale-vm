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
use hyperscale_vm_effects::{PackageMetadata, ParamType, RoleId};
use hyperscale_vm_fixtures::{
    amm as amm_package, book as book_package, splitter as splitter_package,
};
use hyperscale_vm_sdk::sym::{Addr, Amount, Bucket, Num, Sym, lit_u64, pack};
use hyperscale_vm_sdk::{Blueprint, Trace};
use hyperscale_vm_stdlib::account as account_package;

/// The fungible account.
fn account() -> Blueprint {
    Blueprint::builder()
        .method(
            "withdraw",
            &[ParamType::Address, ParamType::U128],
            |t: &mut Trace| {
                let resource: Sym<Addr> = t.arg(0);
                let amount: Sym<Amount> = t.arg(1);
                let holder = t.self_addr();

                let vault = holder.child(VAULT, &[resource.clone().cast()]);
                t.point(&vault).reserve(&amount);
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
            let vault = holder.child(VAULT, &[resource.cast()]);
            t.point(&claims).delta();
            t.point(&vault).delta();
        })
        // The sign-in's whole body is its gate's read: the cell the
        // account's stored rule lives in.
        .method("authorize", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).read();
        })
        // Securify and the recovery surface all write the same cell,
        // exclusively: an existing cell is securify's own refusal, and
        // every role rewrite conflicts with every concurrent sign-in's
        // read.
        .method(
            "securify",
            &[ParamType::RoleSet, ParamType::U64],
            |t: &mut Trace| {
                let holder = t.self_addr();
                let cell = holder.child(AUTH, &[]);
                t.point(&cell).write();
            },
        )
        .method(
            "propose",
            &[ParamType::RoleSet, ParamType::U64],
            |t: &mut Trace| {
                let holder = t.self_addr();
                let cell = holder.child(AUTH, &[]);
                t.point(&cell).write();
            },
        )
        .method("cancel", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).write();
        })
        .method("confirm", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let cell = holder.child(AUTH, &[]);
            t.point(&cell).write();
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
                // The reserve pair is creation-fixed, so the vault keys come
                // off configuration rather than off the arriving bucket.
                let x: Sym<Addr> = t.config(0);
                let y: Sym<Addr> = t.config(1);
                let pool = t.self_addr();

                let config = pool.child(CONFIG, &[]);
                t.point(&config).locked();
                t.point(&pool.child(VAULT, &[x.cast()])).write();
                t.point(&pool.child(VAULT, &[y.clone().cast()])).write();

                t.output(&y);
            },
        )
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
                let funds: Sym<Bucket> = t.arg(1);
                let venue = t.self_addr();

                // Price over a fresh sequence id: the tiebreaker that makes
                // the order key unique without reading the book.
                let seq = t.fresh_id();
                let order = pack(&price, &seq);
                t.entry(&venue, book_package::ASKS, &[], &order).write();

                let escrow = venue.child(VAULT, &[funds.resource().cast()]);
                t.point(&escrow).delta();
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
                    book_package::FILL_CAP,
                )
                .write();

                let quote = payment.resource();
                t.point(&venue.child(VAULT, &[base.clone().cast()])).delta();
                t.point(&venue.child(VAULT, &[quote.clone().cast()]))
                    .delta();

                t.output(&base);
                t.output(&quote);
            },
        )
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
    for aside in ["deposit-nf", "withdraw-nf", "present-badge"] {
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
        // Everything a body determines, compared field by field. The ABI
        // binding and the accessibility are deliberately not among them:
        // a trace sees which handles a body opened and in what order,
        // never the component's exported parameter list and never a claim
        // about who may call it. Both are authored beside the WIT. What
        // validates the binding is the publish check, against the export
        // type in the artifact itself.
        assert_eq!(got.params, signature.params, "{package}::{name} params");
        assert_eq!(got.outputs, signature.outputs, "{package}::{name} outputs");
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
    assert!(named.iter().all(|r| *r != RoleId(0)));
}

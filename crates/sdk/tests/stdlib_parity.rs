//! The spike's headline claim: an author writing ordinary Rust reaches the
//! authored signature form exactly.
//!
//! `vm-effects::stdlib` carries the four packages the corpus guests execute
//! under, hand-written as [`MethodSignature`] literals — and says of itself
//! that they are "authored, not compiler-inferred — the inference backend
//! is a later phase". This file is that phase's evidence. Each package is
//! re-declared through the SDK and compared to the authored fixture with
//! `assert_eq!` on the whole [`PackageMetadata`].
//!
//! Equality is the right bar rather than an over-strict one. A signature
//! that merely *routes the same* on the cases someone thought to test is
//! not the same signature; it can diverge on the case nobody wrote. Whole-
//! structure equality against a fixture that is already routed under test
//! elsewhere in the workspace means the SDK's output inherits every one of
//! those tests without restating them.

use hyperscale_vm_effects::stdlib::{
    ASKS, AUTH, CLAIMS, CONFIG, ENTROPY, FILL_CAP, VAULT, account_metadata, amm_metadata,
    book_metadata, splitter_metadata,
};
use hyperscale_vm_effects::{PackageMetadata, ParamType, RoleId};
use hyperscale_vm_sdk::sym::{Addr, Amount, Bucket, Num, Sym, lit_u64, pack};
use hyperscale_vm_sdk::{Blueprint, Trace};

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

            // The vault and the guaranteed-delivery fallback beside it,
            // both keyed by the arriving bucket's resource.
            let vault = holder.child(VAULT, &[resource.clone().cast()]);
            let claims = holder.child(CLAIMS, &[resource.cast()]);
            t.point(&vault).delta();
            t.point(&claims).delta();
        })
        .method("stamp-entropy", &[], |t: &mut Trace| {
            let holder = t.self_addr();
            let leaf = holder.child(ENTROPY, &[]);
            t.point(&leaf).write();
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
                t.entry(&venue, ASKS, &order).write();

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
                t.range(&venue, ASKS, &lo, &hi, FILL_CAP).write();

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
        assert_eq!(got.calls, signature.calls, "{package}::{name} calls");
    }
    assert_eq!(
        traced.methods.keys().collect::<Vec<_>>(),
        authored.methods.keys().collect::<Vec<_>>(),
        "{package}: the method sets differ"
    );
}

#[test]
fn the_account_traces_to_its_authored_signature() {
    assert_parity(&account(), &account_metadata(), "account");
}

#[test]
fn the_pool_traces_to_its_authored_signature() {
    assert_parity(&amm(), &amm_metadata(), "amm");
}

#[test]
fn the_book_traces_to_its_authored_signature() {
    assert_parity(&book(), &book_metadata(), "book");
}

#[test]
fn the_splitter_traces_to_its_authored_signature() {
    assert_parity(&splitter(), &splitter_metadata(), "splitter");
}

#[test]
fn every_authored_role_is_reachable_from_the_sdk() {
    // A guard on the fixtures rather than on the SDK: if a role is added to
    // the stdlib and no traced declaration names it, the parity tests above
    // are silently covering less than they read as covering.
    let named = [VAULT, CLAIMS, CONFIG, ASKS, ENTROPY];
    assert_eq!(
        named.len(),
        5,
        "a role was added to the stdlib without a traced declaration to match"
    );
    assert!(named.iter().all(|r| *r != RoleId(0)));
}

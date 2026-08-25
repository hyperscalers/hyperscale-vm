//! What a transaction is bound by, and why one refused — neither of
//! which anything a reader already has will tell them.
//!
//! Both gaps are the same gap. A requirement the protocol injects comes
//! from a resource rather than from a signature, so a reader of every
//! package a transaction calls concludes it is bound by nothing; and the
//! verdict that fires when one fails carries no rule, because the
//! declaration is content-addressed with its package and restating it in
//! a receipt would pay to say twice what a reader can derive.
//!
//! What the verdict does carry is a key, and a key is a hash of the
//! party and the badge that inverts to neither. So the receipt says some
//! leaf was missing and can never say whose or of what. The derivation
//! that reads it back is the injection itself: every requirement was
//! built from something, and that something is kept beside it.

use std::fmt::Write as _;

use hyperscale_vm_effects::{Hash32, ManifestGraph, explain_refusal, explain_requirements};
use hyperscale_vm_harness::driver::vault;
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{Address, Outcome, TxHash, encode_amount};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// An address as the rendering spells one: its class, then its bytes.
fn addr(address: impl Into<Address>) -> String {
    let address = address.into();
    let hex = address
        .to_bytes()
        .iter()
        .fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        });
    format!("{}:{hex}", address.class())
}

/// Alice pays X into the register-mode pool and is paid in shares.
fn trade() -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 500)?;
        let out = register_pool().swap(b, funds, 300u128)?;
        account::deposit(b, ALICE, out)
    })
}

/// The reserves and the buyer's credential, with the venue's optional.
fn store(venue_admitted: bool) -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store.write(vault(ALICE, registered()), encode_amount(1).to_vec());
    store.write(vault(register_pool(), RES_X), encode_amount(1_000).to_vec());
    store.write(
        vault(register_pool(), share()),
        encode_amount(1_000).to_vec(),
    );
    if venue_admitted {
        store.write(
            vault(register_pool(), registered()),
            encode_amount(1).to_vec(),
        );
    }
    store
}

/// Every requirement the protocol put on the transaction, marked as the
/// protocol's and naming the entry it came from.
///
/// Not one of these appears in any package's declaration. The pool's
/// author never read the share class's rules; the account's author never
/// heard of this resource. Both are bound, and this is the only place a
/// sender learns it before signing.
#[test]
fn a_transaction_says_what_the_protocol_asked_of_it() {
    let world = world();
    let text = explain_requirements(&admit_here(&trade(), ALICE, &world).expect("admits"));

    // The sign-in and the plain withdrawal move nothing governed, and
    // say so — an omitted line would read as a node this forgot.
    assert!(
        text.contains("nothing — no resource this node moves governs it"),
        "{text}"
    );

    // The venue's own two movements, each naming the entry that demands
    // it and the stage that answers it.
    let share = addr(share());
    assert!(
        text.contains(&format!(
            "withdraw of {share} — the moving party holds a balance of"
        )),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "deposit of {share} — the moving party holds a balance of"
        )),
        "{text}"
    );
    assert!(text.contains("heard before any body runs"), "{text}");

    // And the fence a `Freeze` entry puts on every movement of it, which
    // is stated by no entry at all — once per party and resource,
    // however many directions the access moves in.
    assert_eq!(
        text.matches("the moving party is not halted").count(),
        2,
        "one fence for the venue and one for the buyer: {text}"
    );
}

/// A refusal, read back into the entry that caused it.
///
/// The receipt names `Holds { target: Point(SubstateKey { .. }) }` and
/// nothing else — an owner and sixteen bytes of hash. What that leaf is
/// about is recoverable only from the requirement it came from, which is
/// what makes this the difference between a debuggable refusal and a
/// hash.
#[test]
fn a_refusal_names_the_resource_and_the_behaviour_behind_it() {
    let world = world();
    let graph = trade();
    let (results, _) = run_both(
        &world,
        &store(false),
        &[(&graph, TxHash(Hash32([0x78; 32])))],
    );
    let TxResult::Refused(Outcome::ConditionUnmet { condition }) = &results[0] else {
        panic!("the venue is off the register: {:?}", results[0]);
    };

    let text = explain_refusal(
        &admit_here(&graph, ALICE, &world).expect("admits"),
        condition,
    );
    // The node, the entry, and the question — none of which the verdict
    // carries.
    assert!(text.contains("node 2"), "{text}");
    assert!(text.contains("swap"), "{text}");
    assert!(
        text.contains(&format!("withdraw of {}", addr(share()))),
        "{text}"
    );
    assert!(
        text.contains(&format!(
            "the moving party holds a balance of {}",
            addr(registered())
        )),
        "{text}"
    );
    // And that nobody declared it, which is what separates this from a
    // gate the package's own author wrote and a reader can go and find.
    assert!(text.contains("Nothing declared this"), "{text}");
}

/// The control: a transaction that succeeds was bound by exactly the
/// same requirements, so the rendering is about the transaction rather
/// than about the refusal.
#[test]
fn what_bound_a_settled_transaction_reads_the_same() {
    let world = world();
    let graph = trade();
    let (results, _) = run_both(
        &world,
        &store(true),
        &[(&graph, TxHash(Hash32([0x79; 32])))],
    );
    assert!(
        matches!(results[0], TxResult::Completed(_)),
        "{:?}",
        results[0]
    );
    let text = explain_requirements(&admit_here(&graph, ALICE, &world).expect("admits"));
    assert!(
        text.contains(&format!("withdraw of {}", addr(share()))),
        "{text}"
    );
}

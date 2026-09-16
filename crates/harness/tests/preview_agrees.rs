//! A preview of a transaction is the run the chain would do.
//!
//! The library reads its state through a source and holds no other
//! transaction's reservations, which is the one thing it does
//! differently. For a transaction nothing else is touching, that must
//! change no answer: the same entry over the same store has to spend
//! the same fuel at the same nodes and move the same value, or a wallet
//! is being shown something the chain will not do.

use std::sync::Arc;

use hyperscale_vm_effects::{
    EnvelopeTree, IntentDecl, IntentHeader, ManifestGraph, TestHasher, admit_tree, explain_refusal,
};
use hyperscale_vm_harness::driver::{test_hash, vault};
use hyperscale_vm_kernel::{MemoryStore, OwnerSet, Substates};
use hyperscale_vm_preview::{Slack, preview};
use hyperscale_vm_types::{NetworkId, Outcome, PrincipalAddr, UnmetCondition, encode_amount};
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// Any window; this lane never validates one against a clock.
const HEADER: IntentHeader = IntentHeader {
    network: NetworkId(242),
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

fn single_intent(account: PrincipalAddr, graph: ManifestGraph) -> EnvelopeTree {
    EnvelopeTree::of_one(
        account,
        IntentDecl {
            header: HEADER,
            graph,
            sockets: Vec::new(),
        },
    )
}

/// Alice funded, every genesis component sealed.
fn funded() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store
}

#[test]
fn a_preview_spends_what_the_run_spends() -> Result<()> {
    let world = world();
    let store = funded();
    let tree = single_intent(ALICE, transfer_graph());

    // What the chain would do with it.
    let (outcome, _end) =
        run_both_tree(&world, &store, &tree).expect("the fixture transfer admits");
    let entry = batch_entry(&world, &tree, env())?;
    let receipt = &outcome.receipts[&entry.tx];
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "the fixture transfer completes: {:?}",
        receipt.outcome
    );

    // What a wallet would be shown, over the same state through the
    // source seam.
    let source: Arc<dyn Substates> = Arc::new(store);
    let [blessed, _reference] = LANES.engine_backends();
    let report = preview(&entry, None, source, blessed, test_hash, Slack::NONE);

    assert!(report.completed(), "{:?}", report.outcome);
    assert_eq!(
        report.spent, receipt.fuel_by_node,
        "the preview spends what the run spends, node for node"
    );
    let whole = OwnerSet::whole();
    assert_eq!(
        report.movements,
        receipt.delta.owned(&whole).movements().collect::<Vec<_>>(),
        "and moves what the run moves"
    );
    Ok(())
}

/// A refused preview prints what the refusal prints anywhere else.
///
/// The text is the declaration's, not the outcome's: which node asked
/// for what is a fact about the manifest, and a wallet reading a
/// refusal wants the same sentence a corpus lane would print.
#[test]
fn a_refused_preview_prints_the_refusal() -> Result<()> {
    let world = world();
    let store = funded();
    // Bob composing a transfer out of Alice's account: her own gate
    // refuses the authorizing node, and the withdrawal never runs.
    let tree = single_intent(BOB, authorized_transfer_by(BOB));
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(
        &tree,
        &tree.assume_self_attested(),
        identity,
        &world,
        &TestHasher,
    )
    .expect("it admits");
    let entry = batch_entry(&world, &tree, env())?;

    let source: Arc<dyn Substates> = Arc::new(store);
    let [blessed, _reference] = LANES.engine_backends();
    let report = preview(
        &entry,
        Some(&admitted.admitted),
        source,
        blessed,
        test_hash,
        Slack::NONE,
    );

    let condition = UnmetCondition::Satisfies { node: 1 };
    assert_eq!(
        report.outcome,
        Outcome::ConditionUnmet {
            condition: condition.clone()
        },
        "the fixture refuses at the authorizing node"
    );
    assert_eq!(
        report.refusal,
        Some(explain_refusal(&admitted.admitted, &condition)),
        "and prints what the refusal prints anywhere else"
    );
    Ok(())
}

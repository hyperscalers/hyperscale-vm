//! A preview of a transaction is the run the chain would do.
//!
//! The library reads its state through a source and holds no other
//! transaction's reservations, which is the one thing it does
//! differently. For a transaction nothing else is touching, that must
//! change no answer: the same entry over the same store has to spend
//! the same fuel at the same nodes and move the same value, or a wallet
//! is being shown something the chain will not do.

use std::sync::Arc;

use hyperscale_vm_effects::{EnvelopeTree, IntentDecl, IntentHeader, ManifestGraph, ShardId};
use hyperscale_vm_harness::driver::{test_hash, vault};
use hyperscale_vm_kernel::{MemoryStore, OwnerSet};
use hyperscale_vm_preview::{CellSource, Local, Slack, preview};
use hyperscale_vm_types::{NetworkId, Outcome, encode_amount};
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

const fn single_intent(graph: ManifestGraph) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            header: HEADER,
            graph,
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    }
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
    let tree = single_intent(transfer_graph());

    // What the chain would do with it.
    let (outcome, _end) =
        run_both_tree(&world, &store, &tree, ALICE).expect("the fixture transfer admits");
    let entry = batch_entry(&world, &tree, ALICE, env())?;
    let receipt = &outcome.receipts[&entry.tx];
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "the fixture transfer completes: {:?}",
        receipt.outcome
    );

    // What a wallet would be shown, over the same state through the
    // source seam.
    let source: Arc<dyn CellSource> = Arc::new(Local::at(store, ShardId(0), env().clock_ms));
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

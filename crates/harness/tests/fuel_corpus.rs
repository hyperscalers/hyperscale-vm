//! What the corpus costs, method by method.
//!
//! The per-node compute ceiling is derived in the fee plan from a
//! measured rate and an assumed window, and sanity-checked against "a
//! transfer is about a hundred thousand fuel". This lane is where that
//! figure stops being a remembered one: every shape the shared world
//! builds is run and its fuel pinned, so the heaviest legitimate
//! transaction is a number a reviewer can read rather than a guess, and
//! a change that doubles a method's cost shows up here rather than in a
//! ceiling nobody re-derived.
//!
//! The figures are exact because fuel is consensus content: both
//! engines are held to the same total, so a pin that drifts is a
//! schedule change and should be read as one.

use hyperscale_vm_effects::{EnvelopeTree, IntentDecl, IntentHeader, ManifestGraph};
use hyperscale_vm_fixtures::amm;
use hyperscale_vm_harness::driver::{declared_vault, vault};
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_types::{MAX_GAS_LIMIT, NetworkId, Outcome, PrincipalAddr, encode_amount};
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

/// Run `graph` composed by `signer` over `store`, and report what each
/// node spent.
fn spent(store: &MemoryStore, graph: ManifestGraph, signer: PrincipalAddr) -> Vec<u64> {
    let world = world();
    let tree = single_intent(signer, graph);
    let (outcome, _end) = run_both_tree(&world, store, &tree).expect("every shape here admits");
    let receipt = outcome
        .receipts
        .values()
        .next()
        .expect("one transaction, one receipt");
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "a shape this lane prices has to complete: {:?}",
        receipt.outcome
    );
    receipt.fuel_by_node.clone()
}

/// Alice funded, every genesis component sealed.
fn funded() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store
}

/// The same, with the pool's own pair stocked.
fn stocked() -> MemoryStore {
    let mut store = funded();
    store.write(
        declared_vault(pool(), amm::RESERVES, RES_X),
        encode_amount(1_000).to_vec(),
    );
    store.write(
        declared_vault(pool(), amm::RESERVES, RES_Y),
        encode_amount(1_000).to_vec(),
    );
    store
}

#[test]
fn the_corpus_costs_what_it_costs() {
    let priced = [
        (
            "transfer",
            spent(&funded(), transfer_graph(), ALICE),
            99_053,
        ),
        (
            "recovery proposal",
            spent(&funded(), propose_graph(), ALICE),
            80_969,
        ),
        ("swap", spent(&stocked(), swap_graph(1), ALICE), 168_525),
    ];

    for (name, nodes, pinned) in &priced {
        let total: u64 = nodes.iter().sum();
        println!(
            "{name:20} {total:>9} fuel over {} nodes {nodes:?}",
            nodes.len()
        );
        assert_eq!(
            total, *pinned,
            "{name} costs {total} fuel against a pinned {pinned}: a schedule or a guest moved"
        );
    }

    // The claim the per-node ceiling rests on: the heaviest node of the
    // heaviest shape is orders under what one node may sign for, so the
    // ceiling bounds an adversary rather than the corpus.
    let heaviest = priced
        .iter()
        .flat_map(|(_, nodes, _)| nodes.iter().copied())
        .max()
        .expect("the corpus prices something");
    assert!(
        heaviest * 32 < MAX_GAS_LIMIT,
        "the heaviest corpus node is {heaviest} fuel against a {MAX_GAS_LIMIT} ceiling: \
         the ceiling has stopped being an adversary's bound"
    );
}

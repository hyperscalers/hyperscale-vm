//! The corpus catalogue's routed and classified forms: the golden
//! vectors pinning INV-VM-2, the star each pattern's shape implies, and
//! the sweeps that hold across every guest.

use hyperscale_vm_effects::{MAX_STAGED_DEPTH, ManifestGraph, Role, Strategy};
use hyperscale_vm_fixtures::nf;
use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_stdlib::account;
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// INV-VM-2: the routed form is consensus content — every node derives
/// the identical routing from the identical signed form, and it must not
/// drift as the fold is reshaped. The pins were generated from the fold
/// as it stands; a change to any of them is a change to what routing
/// says, and needs a protocol answer rather than a regenerated literal.
/// The digest is over a Debug rendering, so one drift is dischargeable
/// short of a protocol answer: a vocabulary reshape whose rendering diff
/// shows the same addresses under new type names, with the wire bytes —
/// the encoded role sets in the propose vector are the witness —
/// unchanged, is a re-pin of the same routing.
#[test]
fn the_catalogue_routes_to_pinned_vectors() {
    let world = world();
    let pinned = [
        ("transfer", transfer_graph(), PIN_TRANSFER),
        ("swap", swap_graph(300), PIN_SWAP),
        ("fill", fill_graph(), PIN_FILL),
        ("propose", propose_graph(), PIN_PROPOSE),
    ];
    for (name, graph, pin) in pinned {
        let routing = sharded_routing(&world, &graph);
        assert_eq!(
            routing_fingerprint(&routing),
            pin,
            "{name}: routing drifted"
        );
    }
}

const PIN_TRANSFER: &str = "ed061b8186df29a4f31d0e88f2292d965583faf732ba65d1808d934c4a03d3fa";

const PIN_SWAP: &str = "a7f9a9a616a29fbe9a5d43987f5233147976dcd81cb5e6d3a64a10747a0ea17c";

const PIN_FILL: &str = "d73903ab1deaa032dd1cead993b2d51f2f460a9600b62b3e2d02fac7a3314a27";

const PIN_PROPOSE: &str = "8883a55796aa5e929ceb9036649f6552bb1603a5106e6f9e0cb96b791993195e";

/// One catalogue pattern and the star its shape implies.
struct Shape {
    name: &'static str,
    graph: ManifestGraph,
    /// Where each node sits, in node order.
    roles: Vec<Role>,
    /// Every shard change along the longest chain.
    crossings: u32,
    /// Only the crossings something waits on.
    stages: u32,
    strategy: Strategy,
}

/// Every catalogue shape, and the decomposition it implies.
///
/// One table rather than an assertion bolted onto each behavioural test,
/// because what earns its place here is the *contrast* between the rows:
/// the same classifier has to call a transfer a degenerate star, a venue
/// call a one-stage star, a self-governing account nothing at all, and a
/// named-instance move back to replication. A row on its own would say
/// little; the set is the falsifier.
#[test]
fn every_pattern_takes_the_star_its_shape_implies() {
    let world = world();
    let shapes = vec![
        // A core with a leg either side and no venue between them. The
        // one crossing is into the recipient's deposit, which cannot
        // refuse, so nothing waits and no stage is owed.
        Shape {
            name: "transfer",
            graph: transfer_graph(),
            roles: vec![Role::Core, Role::Inbound, Role::Outbound],
            crossings: 1,
            stages: 0,
            strategy: Strategy::LegLocal,
        },
        // The venue star: the withdrawal inbound, the pool a single-shard
        // core, the delivery outbound. Two crossings to reach the venue
        // and return, and only the outbound one is free.
        Shape {
            name: "swap",
            graph: swap_graph(300),
            roles: vec![Role::Core, Role::Inbound, Role::Core, Role::Outbound],
            crossings: 2,
            stages: 1,
            strategy: Strategy::LegLocal,
        },
        // The same star over a range rather than points — an interval's
        // width prices provisioning and never depth — and the first
        // shape with more than one outbound leg, which is what L2's "N
        // outbound legs" was written for: a fill pays out on two edges
        // and the core waits on neither.
        Shape {
            name: "fill",
            graph: fill_graph(),
            roles: vec![
                Role::Core,
                Role::Inbound,
                Role::Core,
                Role::Outbound,
                Role::Outbound,
            ],
            crossings: 2,
            stages: 1,
            strategy: Strategy::LegLocal,
        },
        // An account governing itself reaches no further than itself, so
        // there is no star to take and the two strategies name the same
        // execution.
        Shape {
            name: "propose",
            graph: propose_graph(),
            roles: vec![Role::Core],
            crossings: 0,
            stages: 0,
            strategy: Strategy::Replicated,
        },
    ];

    for shape in shapes {
        let star = star_of(&world, &shape.graph);
        let name = shape.name;
        assert_eq!(star.roles, shape.roles, "{name}: star");
        assert_eq!(star.crossings, shape.crossings, "{name}: crossings");
        assert_eq!(star.stages, shape.stages, "{name}: stages");
        assert_eq!(star.strategy, shape.strategy, "{name}: strategy");
        // The budget is what the verdict is for, so nothing may decompose
        // past it. Read across the table rather than per row: the claim
        // is about the classifier, not about any one shape's depth.
        assert!(
            shape.strategy != Strategy::LegLocal || star.stages <= MAX_STAGED_DEPTH,
            "{name}: decomposed at {} stages, past a budget of {MAX_STAGED_DEPTH}",
            star.stages,
        );
    }
}

/// Named instances moving inside a core do not force replication.
///
/// L11 excludes non-fungible value from *staging*, because the supply
/// delta an escrow certificate attests counts amounts and cannot see
/// which id moved. A core is not staged: its participants agree by
/// unanimity rather than by taking each other's attested values, so
/// nothing inside one is exposed to that gap and the exclusion has no
/// business firing.
///
/// Minting an instance and filing it into an account is exactly that
/// shape — neither node is a leg, since a mint declares no reservation
/// and `deposit-nf` cannot carry the total mark while filing each id is
/// a loop — so the two sit on either side of a multi-shard core and the
/// route still decomposes.
///
/// The reachable-today consequence, worth stating: no catalogue pattern
/// can put a named instance across a *leg*, because no non-fungible
/// method is reservation-shaped or total. L11 guards a shape the
/// vocabulary cannot currently express, which is where a unit test
/// belongs and a catalogue case cannot go.
#[test]
fn named_instances_inside_a_core_still_decompose() {
    let world = world();
    let seat = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, minted)
    });
    let star = star_of(&world, &seat);

    assert!(
        star.crossings > 0,
        "the fixture has to cross, or the verdict below proves nothing",
    );
    assert!(
        star.roles.iter().all(|slot| *slot == Role::Core),
        "neither end is a leg: {:?}",
        star.roles,
    );
    assert_eq!(star.strategy, Strategy::LegLocal);
}

/// One kernel WIT, and no package holds a copy of it.
///
/// Drift used to be checkable only by comparing eight copies against the
/// canonical file; now there is nothing to compare, because a package
/// resolves `hyperscale:kernel` out of the SDK rather than vendoring it.
/// What is left to assert is that the vendoring did not come back — a
/// package with its own copy would compile against a world nothing holds
/// it to.
#[test]
fn no_guest_vendors_its_own_kernel_world() -> Result<()> {
    let canonical = std::fs::read(repo_root().join("crates/runtime/wit/kernel.wit"))?;
    let vendored = std::fs::read(repo_root().join("crates/sdk/wit/deps/kernel/kernel.wit"))?;
    assert_eq!(canonical, vendored, "the SDK's kernel.wit drifted");

    for guest in std::fs::read_dir(repo_root().join("guests"))? {
        let guest = guest?.path();
        assert!(
            !guest.join("wit/deps").exists(),
            "{} vendors its own dependencies",
            guest.display()
        );
    }
    Ok(())
}

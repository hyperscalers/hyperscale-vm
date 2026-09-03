//! The corpus catalogue's routed and classified forms: the golden
//! vectors pinning routing as consensus content, the star each pattern's shape implies, and
//! the sweeps that hold across every guest.

use hyperscale_vm_effects::{LegRole, ManifestGraph, PrefixShardResolver};
use hyperscale_vm_fixtures::{lottery, nf};
use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_stdlib::account;
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// The routed form is consensus content — every node derives
/// the identical routing from the identical signed form, and it must not
/// drift as the fold is reshaped. The pins were generated from the fold
/// as it stands; a change to any of them is a change to what routing
/// says, and needs a protocol answer rather than a regenerated literal.
/// The digest is over a Debug rendering, so one drift is dischargeable
/// short of a protocol answer: a vocabulary reshape whose rendering shows
/// the same addresses under new type names is a re-pin of the same
/// routing. The rendering is the witness, and a drift prints it in full
/// beside the new digest — the encoded role sets, calls, frames, and
/// folded declaration — so the discharge is a read rather than a guess.
///
/// A drift in the addresses themselves is not that. Until a network
/// runs, the protocol answer to one can be that the derivation was
/// deliberately moved: [`Value`]'s variant order is its encoding and its
/// encoding is child-address material, so reorganizing the vocabulary
/// moves every key derived from a literal. After a network runs, no such
/// answer exists.
///
/// Every vector moved once, and the protocol answer is that what governs
/// an address before anything is written for it is now part of the rule
/// rather than something the kernel supplies. A sign-in's gate is the
/// disjunction that says so — the rule stored at the cell, or, while the
/// cell is absent, the identity that address derives — and every vector
/// reaching an account carries one. The propose vector moved further,
/// because the surface that replaces those rules is the account's own
/// policy now and takes three rules where it took a role table.
///
/// A sealed rule's leaf also says which side it asks about: a claim
/// somebody presents, or a badge the rule's own subject holds. That is
/// what lets one rule vocabulary serve both an authority and a movement.
///
/// And a claim is a subject rather than a kind, so every vector's
/// rendering names an address where it named a case. For transfer, swap
/// and fill that is the whole of it — the same addresses under a shape
/// that no longer decides what they are. The propose vector carries
/// encoded claims, so its bytes moved with them.
///
/// Every vector moved again, and the answer is a derivation move rather
/// than a routing one. A method declares a *list* of issuances rather
/// than at most one, so a component founds every resource it declares;
/// it names the buckets it destroys on somebody else's behalf; and a
/// clause says which authority lets it reach a prefix that is not its
/// own. Each is a field on a declaration, so every package's declaration
/// encodes differently, every declaration hash moves, and every instance
/// address derived from one moves with it. The addresses under the
/// rendering changed; what each shard is asked to provision did not.
///
/// And again, this time because the vocabulary shrank rather than grew:
/// the delivery cell beside a vault is gone, so every slot above it
/// renumbers and every key derived from one moves. What replaces it is
/// the account's own — a flag saying where a deposit lands and a
/// quarantine for what it refuses — which is a package's cell rather
/// than the protocol's, since only the account itself reaches it.
///
/// Three of the four moved, and this one is the dischargeable drift the
/// paragraph above admits rather than a routing change. An exclusive
/// write now carries which directions value moves under it, so the
/// rendering reads `Write { moves: Both }` where it read `Write`, and
/// `Both` is exactly what a bare write meant. The whole diff between the
/// old rendering and the new is those four words: the same addresses,
/// the same effect sets, the same shards asked for the same leaves, and
/// no byte array anywhere in it moved. Transfer did not move at all,
/// because a transfer's routing holds no exclusive write — it credits
/// and it reserves.
///
/// Three of the four moved again when the commutative modes joined the
/// exclusive one in saying their direction by field: a credit renders as
/// `Delta { moves: In }` where it was a variant of its own, and a
/// bidirectional movement as `Delta { moves: Both }` where it read
/// `Delta`. Dischargeable on the same terms as the write's field —
/// nothing about which shard provisions which leaf moved. Propose alone
/// holds no commutative movement, so it alone stood still.
///
/// Swap and fill moved once more when the lowering learned to keep the
/// direction a body's own operations settle: a reserve vault that only
/// receives or only pays declares `In` or `Out` where it declared
/// `Both`. The narrowing is what each site is judged on; the targets,
/// the shards and the provisioned leaves are the ones already pinned.
/// Transfer's withdrawal is a reservation, whose direction was always
/// its own, so it stood still beside propose.
///
/// Swap and fill moved again when the pool and book declared their
/// vaults: each reserve leaf sits at its field's package slot rather
/// than the protocol vault slot, so the keys under the same shards
/// moved with the declarations.
///
/// The swap and fill pins carry the instantiation fence: admission reads
/// the configuration leaf of every component a node targets, so the
/// owning shard is a participant and provisions the leaf. Transfer and
/// propose reach only principals, which have no creation to finish and
/// take no fence.
///
/// Transfer, swap and fill moved when the account's deposit stopped
/// declaring its two credits by hand: the arms declare them, so the
/// quarantine's clause precedes the vault's in the deposit frame, and
/// the rebuilt artifacts reseat every package hash and every instance
/// address derived from one. The leaves, their modes and the shards
/// asked for them are the ones already pinned — what renumbered is one
/// frame's clause order and the addresses under it. Propose alone stood
/// still, because its manifest never deposits.
///
/// The fingerprint is over the routing's `Debug` rendering, so it is
/// sensitive to more than routing: renaming a type the declaration holds
/// moves it too. What that costs is a re-record whenever the vocabulary
/// does; what it buys is that nothing about a routing can move without
/// somebody looking at it.
///
/// [`Value`]: hyperscale_vm_effects::Value
#[test]
fn the_catalogue_routes_to_pinned_vectors() {
    let world = world();
    let pinned = [
        ("transfer", transfer_graph(), PIN_TRANSFER),
        ("swap", swap_graph(300), PIN_SWAP),
        ("fill", fill_graph(), PIN_FILL),
        ("propose", propose_graph(), PIN_PROPOSE),
    ];
    let mut drifted = Vec::new();
    for (name, graph, pin) in pinned {
        let routing = sharded_routing(&world, &graph);
        let fingerprint = routing_fingerprint(&routing);
        if fingerprint != pin {
            // The witness the digest is over, printed beside the new hex —
            // so a rendering-only reshape can be discharged by reading it
            // rather than re-pinning blind.
            drifted.push(format!(
                "{name} = {fingerprint}\n{}",
                routing_rendering(&routing)
            ));
        }
    }
    assert!(
        drifted.is_empty(),
        "routing drifted:\n{}",
        drifted.join("\n")
    );
}

const PIN_TRANSFER: &str = "c2540621ed29b6bc4156d70c2cd0e08f1a8ff356c4f137adc59e94a9d624aa5a";

const PIN_SWAP: &str = "e14f63469695b7574ea180cde0a6a84c5994ac3a227db304ef5fe48703b6616a";

const PIN_FILL: &str = "77f730a9471e87df50e8d3b6b73d891ddc47f035706f18718e28e94f7999c23b";

const PIN_PROPOSE: &str = "9034ede521aeb9c053f724d9f95ae126d4e933abe168399ecbb021ae20edcd43";

/// One catalogue pattern and the star its shape implies.
struct Shape {
    name: &'static str,
    graph: ManifestGraph,
    /// Where each node sits, in node order.
    roles: Vec<LegRole>,
    /// How many shards the core's nodes sit on.
    core: usize,
    /// Value edges landing on a shard other than their producer's.
    crossing_edges: u32,
    decomposes: bool,
}

/// Every catalogue shape, and the decomposition it implies.
///
/// One table rather than an assertion bolted onto each behavioural test,
/// because what earns its place here is the *contrast* between the rows:
/// the same classifier has to call a transfer a star with a leg either
/// side, a venue call a star whose core is the venue alone, a
/// self-governing account nothing at all, and a restricted deposit a core
/// of its own. A row on its own would say little; the set is the
/// falsifier.
///
/// Every row's core is size one, and the sign-in node is why that is not
/// automatic: it commits nothing, so it is a leg wherever a venue or a
/// gated deposit bears the verdict, and the core itself wherever nothing
/// else would. A regression that dropped the write-free role shows up
/// here as swap and fill going to core size two.
#[test]
fn every_pattern_takes_the_star_its_shape_implies() {
    let world = world();
    let shapes = vec![
        // A core with a leg either side and no venue between them. The
        // sign-in is the only node that commits nothing *and* has nothing
        // beside it in the core, so it bears the verdict.
        Shape {
            name: "transfer",
            graph: transfer_graph(),
            roles: vec![LegRole::Core, LegRole::Inbound, LegRole::Outbound],
            core: 1,
            crossing_edges: 1,
            decomposes: true,
        },
        // The venue star: the sign-in and the withdrawal on the caller's
        // shard, the pool the whole core, the delivery outbound.
        Shape {
            name: "swap",
            graph: swap_graph(300),
            roles: vec![
                LegRole::Attesting,
                LegRole::Inbound,
                LegRole::Core,
                LegRole::Outbound,
            ],
            core: 1,
            crossing_edges: 2,
            decomposes: true,
        },
        // The same star over a range rather than points — an interval's
        // width prices provisioning and never depth — and the first shape
        // with more than one outbound leg: a fill pays out on two edges
        // and the core waits on neither.
        Shape {
            name: "fill",
            graph: fill_graph(),
            roles: vec![
                LegRole::Attesting,
                LegRole::Inbound,
                LegRole::Core,
                LegRole::Outbound,
                LegRole::Outbound,
            ],
            core: 1,
            crossing_edges: 3,
            decomposes: true,
        },
        // An account governing itself reaches no further than itself, so
        // there is no leg off the core and nothing to divide.
        Shape {
            name: "propose",
            graph: propose_graph(),
            roles: vec![LegRole::Core],
            core: 1,
            crossing_edges: 0,
            decomposes: false,
        },
    ];

    for shape in shapes {
        let (star, legs) = star_and_shape(&world, &shape.graph);
        let name = shape.name;
        assert_eq!(star.roles, shape.roles, "{name}: star");
        assert_eq!(star.core.len(), shape.core, "{name}: core size");
        assert_eq!(
            star.crossing_edges, shape.crossing_edges,
            "{name}: crossing edges",
        );
        assert_eq!(
            star.decomposes(
                &legs,
                &route_owners(&shape.graph),
                &PrefixShardResolver { bits: 8 }
            ),
            shape.decomposes,
            "{name}: decomposes",
        );
    }
}

/// A deposit of a resource whose issuer declares one carries a movement
/// rule judged at materialization, so it can still refuse after the core
/// committed and it is not an outbound leg.
///
/// It does not cost the decomposition, and that is the point: the demoted
/// deposit *becomes* the core, the withdrawal is the leg that escrows to
/// it, and the recipient's own halt fence is what bears the verdict. The
/// grant-free transfer beside it is the contrast — same shape, same
/// nodes, and a role that moves because of what the resource declares.
#[test]
fn a_grant_declaring_deposit_bears_the_verdict() {
    let world = world();
    let plain = star_of(&world, &transfer_graph());
    assert_eq!(plain.roles[2], LegRole::Outbound, "RES_X grants nothing");

    let restricted = graph(|b| {
        let funds = account::withdraw(b, ALICE, share(), 100)?;
        account::deposit(b, BOB, funds)
    });
    let (star, legs) = star_and_shape(&world, &restricted);
    assert_eq!(
        star.roles,
        vec![LegRole::Attesting, LegRole::Inbound, LegRole::Core],
        "the deposit is the only node that can still refuse",
    );
    assert_eq!(star.core.len(), 1, "and it is the whole core");
    assert!(star.decomposes(
        &legs,
        &route_owners(&restricted),
        &PrefixShardResolver { bits: 8 }
    ));
}

/// A declared access reaching a party no node targets leaves that target
/// judged by nobody once execution divides, where a whole execution
/// judged it everywhere.
///
/// A recall is what reaches one: the registrar names the holder's own
/// vault, and the holder targets no node. A deposit's owner is the moving
/// party and usually does, so a reader checking only deposits concludes
/// this cannot happen.
#[test]
fn a_declaration_reaching_a_non_participant_does_not_decompose() {
    let world = world();
    let recall = graph_signed(REGISTRAR, |b| {
        let proof = account::sign_in(b)?;
        let taken = b.presenting(proof, |b| {
            issuer().recall_shares(b, ALICE.address(), 1, 100)
        })?;
        account::deposit(b, REGISTRAR, taken)
    });
    let (star, legs) = star_and_shape(&world, &recall);
    assert!(
        !legs
            .iter()
            .any(|node| shard_of(node.target) == shard_of(ALICE)),
        "the reached holder has to target no node, or the verdict below proves nothing",
    );
    assert!(!star.decomposes(
        &legs,
        &route_owners(&recall),
        &PrefixShardResolver { bits: 8 }
    ));
}

/// Package metadata is content-addressed, so a resolved package cannot
/// differ between frontiers — and every replica derives its own roles, so
/// a disagreement here would be different legs, different crossings and
/// different kernel cells rather than a slow path.
#[test]
fn two_chain_frontiers_give_one_classification() {
    let ahead = world();
    let mut behind = world();
    behind
        .packages
        .publish_unchecked(pkg("lottery"), lottery::metadata());

    for (name, graph) in [
        ("transfer", transfer_graph()),
        ("swap", swap_graph(300)),
        ("fill", fill_graph()),
        ("propose", propose_graph()),
    ] {
        assert_eq!(
            star_of(&ahead, &graph),
            star_of(&behind, &graph),
            "{name}: the frontier moved the classification",
        );
    }
}

/// A named instance moving inside a core is not what stops a shape
/// dividing.
///
/// The non-fungible exclusion is over legs, because the escrow
/// attestation counts amounts and cannot see which id moved. A core is
/// not escrowed: its participants agree by unanimity rather than by
/// taking each other's attested values, so nothing inside one is exposed
/// to that gap and the exclusion has no business firing.
///
/// Minting an instance and filing it into an account is exactly that
/// shape — neither node is a leg, since a mint declares no reservation
/// and `deposit-nf` cannot carry the total mark while filing each id is
/// a loop. What decides it is that the core spans two shards, which
/// replicates; the contrast below is what says so, because the same
/// shape over a fungible edge reaches the same verdict.
///
/// The reachable-today consequence, worth stating: no catalogue pattern
/// can put a named instance across a *leg*, because no non-fungible
/// method is reservation-shaped or total. The exclusion guards a shape
/// the vocabulary cannot currently express, which is where a unit test
/// belongs and a catalogue case cannot go.
#[test]
fn a_named_instance_inside_a_core_is_not_what_refuses_it() {
    let world = world();
    let seat = graph(|b| {
        let minted = nf::mint(b, nf_issuer())?;
        account::deposit_nf(b, ALICE, minted)
    });
    let (star, legs) = star_and_shape(&world, &seat);
    let shards = PrefixShardResolver { bits: 8 };

    assert!(
        star.crossing_edges > 0,
        "the fixture has to cross, or the verdict below proves nothing",
    );
    assert!(
        star.roles.iter().all(|slot| *slot == LegRole::Core),
        "neither end is a leg: {:?}",
        star.roles,
    );
    assert_eq!(
        star.core.len(),
        2,
        "the core spans the issuer and the account"
    );
    assert!(!star.decomposes(&legs, &route_owners(&seat), &shards));

    // Which conjunct refused it, stated rather than assumed: with every
    // node in the core there is no leg off it, and the non-fungible
    // exclusion is over legs — so a shape with none cannot be the one it
    // fires on. The classifier's own tests pin it firing where there is.
    assert!(
        star.roles.iter().all(|slot| *slot == LegRole::Core),
        "no leg means no edge for the exclusion to touch",
    );
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

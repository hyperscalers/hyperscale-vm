//! The crate's whole contract, stated as a property: any graph either
//! builder emits without error passes admission.
//!
//! The two builders are held to it over the same generated transfers,
//! because they promise different halves of it. The untyped one keeps the
//! structural rules and leaves typing to admission; the typed one derives
//! the typing too, so its graphs carry an assertion on every edge that
//! nothing in the test wrote.
//!
//! The world is the stdlib account and the bucket splitter — enough to
//! exercise every shape the builder can produce: literals of each scalar
//! kind, single- and dual-output calls, constrained edges, and chains
//! long enough that index bookkeeping would be the error-prone part by
//! hand.

use hyperscale_vm_effects::{
    Constraint, GraphArg, Hash32, Hasher, InstanceMeta, InstanceRegistry, MetadataCache,
    PackageHash, TestHasher, admit,
};
use hyperscale_vm_fixtures::splitter;
use hyperscale_vm_manifest_builder::{GraphBuilder, TypedBuilder};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr, ResourceAddr};
use proptest::prelude::{Strategy, prop, prop_assert, proptest};

const ACCOUNTS: [PrincipalAddr; 4] = [
    PrincipalAddr::new([0x10; 31]),
    PrincipalAddr::new([0x20; 31]),
    PrincipalAddr::new([0x30; 31]),
    PrincipalAddr::new([0x40; 31]),
];

fn splitter_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("splitter"),
        config: vec![],
        salt: Hash32([2; 32]),
    }
}

/// The splitter instance, at the address its record derives.
fn splitter() -> ComponentAddr {
    splitter_meta().address(&TestHasher)
}
const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account::metadata());
    cache.publish(pkg("splitter"), splitter::metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, splitter_meta());
    (cache, instances)
}

/// One transfer's shape: who pays whom how much, optionally split on the
/// way, optionally bounded by the consumer. Bounds are generated
/// satisfiable — `min <= amount <= max` — because admission's
/// unsatisfiable-constraint check is not what this property is about.
#[derive(Clone, Debug)]
struct Transfer {
    from: usize,
    to: usize,
    amount: u128,
    split: Option<u128>,
    bounds: Option<(u128, u128)>,
}

fn transfer() -> impl Strategy<Value = Transfer> {
    (
        0..ACCOUNTS.len(),
        0..ACCOUNTS.len(),
        100..1000u128,
        prop::option::of(1..100u128),
        prop::option::of((0..100u128, 1000..2000u128)),
    )
        .prop_map(|(from, to, amount, split, bounds)| Transfer {
            from,
            to,
            amount,
            split,
            bounds,
        })
}

proptest! {
    #[test]
    fn built_graphs_admit(transfers in prop::collection::vec(transfer(), 1..12)) {
        let (cache, instances) = world();
        let mut b = GraphBuilder::new();
        for t in &transfers {
            let sign_in = b.len();
            let [] = b.call_signed(ACCOUNTS[t.from], "authorize", ());
            let [funds] = b.call_bearing(ACCOUNTS[t.from], "withdraw", (RES, t.amount), sign_in);
            let mut funds = funds.resource_is(RES);
            if let Some((min, max)) = t.bounds {
                funds = funds.min(min).max(max);
            }
            if let Some(taken) = t.split {
                let [taken, rest] = b.call(splitter(), "take", (funds, taken));
                let [] = b.call(ACCOUNTS[t.to], "deposit", (taken,));
                let [] = b.call(ACCOUNTS[t.from], "deposit", (rest,));
            } else {
                let [] = b.call(ACCOUNTS[t.to], "deposit", (funds,));
            }
        }
        let graph = b.build().expect("every output is consumed");
        admit(&graph, ACCOUNTS[0], &cache, &instances, &TestHasher).expect("a built graph admits");
    }

    #[test]
    fn typed_graphs_admit_and_type_every_edge(transfers in prop::collection::vec(transfer(), 1..12)) {
        let (cache, instances) = world();
        let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
        for t in &transfers {
            // No `resource_is` anywhere below: `withdraw` declares its
            // output's type and `take` carries it, so the assertions are
            // the signatures' rather than the author's.
            let proof = b.call_minting(ACCOUNTS[t.from], "authorize", ()).unwrap();
            let mut funds = b.call_as(proof, ACCOUNTS[t.from], "withdraw", (RES, t.amount)).unwrap().one().unwrap();
            if let Some((min, max)) = t.bounds {
                funds = funds.min(min).max(max);
            }
            if let Some(taken) = t.split {
                let [taken, rest] = b.call(splitter(), "take", (funds, taken)).unwrap().into_array().unwrap();
                b.call(ACCOUNTS[t.to], "deposit", (taken,)).unwrap().none().unwrap();
                b.call(ACCOUNTS[t.from], "deposit", (rest,)).unwrap().none().unwrap();
            } else {
                b.call(ACCOUNTS[t.to], "deposit", (funds,)).unwrap().none().unwrap();
            }
        }
        let graph = b.build().expect("every output is consumed");
        for node in &graph.nodes {
            for arg in &node.args {
                if let GraphArg::Edge { constraints, .. } = arg {
                    prop_assert!(
                        constraints.contains(&Constraint::ResourceIs(RES.into())),
                        "every edge in this world resolves to one resource, and says so"
                    );
                }
            }
        }
        admit(&graph, ACCOUNTS[0], &cache, &instances, &TestHasher).expect("a built graph admits");
    }
}

/// The same contract at a single deliberate point: the walkthrough
/// transfer, admitted and lowered to the node count the graph declares.
#[test]
fn the_walkthrough_transfer_admits() {
    let (cache, instances) = world();
    let mut b = GraphBuilder::new();
    let [] = b.call_signed(ACCOUNTS[0], "authorize", ());
    let [funds] = b.call_bearing(ACCOUNTS[0], "withdraw", (RES, 100u128), 0);
    let [] = b.call(ACCOUNTS[1], "deposit", (funds.resource_is(RES),));
    let graph = b.build().unwrap();
    let admitted = admit(&graph, ACCOUNTS[0], &cache, &instances, &TestHasher).unwrap();
    assert_eq!(admitted.manifest().nodes.len(), 3);
}

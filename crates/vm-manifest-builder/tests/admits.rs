//! The crate's whole contract, stated as a property: any graph the
//! builder emits without error passes admission.
//!
//! The world is the stdlib account and the bucket splitter — enough to
//! exercise every shape the builder can produce: literals of each scalar
//! kind, single- and dual-output calls, constrained edges, and chains
//! long enough that index bookkeeping would be the error-prone part by
//! hand.

use hyperscale_vm_effects::stdlib::{account_metadata, splitter_metadata};
use hyperscale_vm_effects::{
    Address, Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash, TestHasher, admit,
};
use hyperscale_vm_manifest_builder::GraphBuilder;
use proptest::prelude::{Strategy, prop, proptest};

const ACCOUNTS: [Address; 4] = [
    Address([0x10; 16]),
    Address([0x20; 16]),
    Address([0x30; 16]),
    Address([0x40; 16]),
];
const SPLITTER: Address = Address([0x50; 16]);
const RES: Address = Address([0xE1; 16]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("splitter"), splitter_metadata());
    let mut instances = InstanceRegistry::new();
    for account in ACCOUNTS {
        instances.register(
            account,
            InstanceMeta {
                package: pkg("account"),
                config: vec![],
            },
        );
    }
    instances.register(
        SPLITTER,
        InstanceMeta {
            package: pkg("splitter"),
            config: vec![],
        },
    );
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
            let [funds] = b.call(ACCOUNTS[t.from], "withdraw", (RES, t.amount));
            let mut funds = funds.resource_is(RES);
            if let Some((min, max)) = t.bounds {
                funds = funds.min(min).max(max);
            }
            if let Some(taken) = t.split {
                let [taken, rest] = b.call(SPLITTER, "take", (funds, taken));
                let [] = b.call(ACCOUNTS[t.to], "deposit", (taken,));
                let [] = b.call(ACCOUNTS[t.from], "deposit", (rest,));
            } else {
                let [] = b.call(ACCOUNTS[t.to], "deposit", (funds,));
            }
        }
        let graph = b.build().expect("every output is consumed");
        admit(&graph, &cache, &instances, &TestHasher).expect("a built graph admits");
    }
}

/// The same contract at a single deliberate point: the walkthrough
/// transfer, admitted and lowered to the node count the graph declares.
#[test]
fn the_walkthrough_transfer_admits() {
    let (cache, instances) = world();
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ACCOUNTS[0], "withdraw", (RES, 100u128));
    let [] = b.call(ACCOUNTS[1], "deposit", (funds.resource_is(RES),));
    let graph = b.build().unwrap();
    let admitted = admit(&graph, &cache, &instances, &TestHasher).unwrap();
    assert_eq!(admitted.manifest().nodes.len(), 2);
}

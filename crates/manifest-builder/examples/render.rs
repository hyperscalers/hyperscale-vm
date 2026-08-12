//! What a wallet has to show somebody before they sign.
//!
//! Four graphs built through the typed builder, each printed as the
//! surface syntax and summarised by the preflight report — the two
//! client-side reads of one signed form. Run it with
//! `cargo run -p hyperscale-vm-manifest-builder --example render`.

use hyperscale_vm_effects::stdlib::{
    account_metadata, amm_metadata, splitter_metadata, staking_metadata,
};
use hyperscale_vm_effects::{
    ComponentAddr, Hash32, Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache,
    PackageHash, PrefixShardResolver, PrincipalAddr, ResourceAddr, TestHasher, Value,
    resource_address,
};
use hyperscale_vm_manifest_builder::native::{account, amm, splitter, staking};
use hyperscale_vm_manifest_builder::{
    Authority, Names, TypedBuilder, TypedError, preflight, render,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const USDC: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";
const SHARDS: PrefixShardResolver = PrefixShardResolver { bits: 2 };
/// A ceiling a sender might sign for; the report prices against it.
const GAS_LIMIT: u64 = 50_000;

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn instance(package: &str, config: Vec<Value>) -> InstanceMeta {
    InstanceMeta {
        package: pkg(package),
        config,
        salt: Hash32([2; 32]),
    }
}

fn pair() -> Vec<Value> {
    vec![
        Value::Address(XRD.address()),
        Value::Address(USDC.address()),
    ]
}

fn operated() -> Vec<Value> {
    vec![
        Value::Address(XRD.address()),
        Value::Address(OPERATOR.address()),
    ]
}

fn pool() -> ComponentAddr {
    instance("amm", pair()).address(&TestHasher)
}

fn stake_pool() -> ComponentAddr {
    instance("staking", operated()).address(&TestHasher)
}

fn splitter() -> ComponentAddr {
    instance("splitter", vec![]).address(&TestHasher)
}

/// The pool's own stake units, derived from the pool rather than
/// configured — so a wallet can name them without the pool declaring them.
fn units() -> ResourceAddr {
    resource_address(&TestHasher, stake_pool(), &[])
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("splitter"), splitter_metadata());
    cache.publish(pkg("staking"), staking_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg("account"));
    instances.create(&TestHasher, instance("amm", pair()));
    instances.create(&TestHasher, instance("splitter", vec![]));
    instances.create(&TestHasher, instance("staking", operated()));
    (cache, instances)
}

/// What this reader already calls the addresses these graphs name. A
/// wallet's own address book; nothing in the protocol carries it.
fn vocabulary() -> Names {
    Names::none()
        .with(ALICE, "alice")
        .with(BOB, "bob")
        .with(OPERATOR, "operator")
        .with(pool(), "pool")
        .with(stake_pool(), "stake_pool")
        .with(splitter(), "splitter")
        .with(XRD, "xrd")
        .with(USDC, "usdc")
        .with(units(), "stake_units")
}

fn main() {
    let (cache, instances) = world();
    let build = |write: &dyn Fn(&mut TypedBuilder<'_>) -> Result<(), TypedError>| -> ManifestGraph {
        let mut b = TypedBuilder::new(&cache, &instances, &TestHasher);
        write(&mut b).expect("every call types against its signature");
        b.build().expect("every output is consumed")
    };

    let graphs: Vec<(&str, ManifestGraph)> = vec![
        (
            "a transfer",
            build(&|b| {
                let funds = account::withdraw(b, ALICE, XRD, 100)?;
                account::deposit(b, BOB, funds)
            }),
        ),
        (
            "a swap",
            build(&|b| {
                let funds = account::withdraw(b, ALICE, XRD, 100)?;
                let proceeds = amm::swap(b, pool(), funds, 90)?;
                account::deposit(b, ALICE, proceeds)
            }),
        ),
        (
            "a split, with the change routed by policy",
            build(&|b| {
                b.rest_to(ALICE);
                let funds = account::withdraw(b, ALICE, XRD, 100)?;
                let [taken, _change] = splitter::take(b, splitter(), funds, 30)?;
                account::deposit(b, BOB, taken.min(30))
            }),
        ),
        (
            "a delegation, and the operator surface beside it",
            build(&|b| {
                let funds = account::withdraw(b, ALICE, XRD, 1_000)?;
                let position = staking::stake(b, stake_pool(), funds)?;
                account::deposit(b, ALICE, position)?;
                staking::unjail(b, stake_pool(), 42)
            }),
        ),
    ];

    for (title, graph) in &graphs {
        println!("── {title} ──\n");
        print!(
            "{}",
            render(
                graph,
                &cache,
                &instances,
                &TestHasher,
                NETWORK,
                &vocabulary()
            )
            .expect("mainnet is a network word")
        );
        println!();
        summarise(graph, &cache, &instances);
        println!();
    }

    // The same transfer with no address book: the projection degrades to
    // the addresses themselves, which is what an unrecognised counterparty
    // actually looks like.
    println!("── a transfer, to somebody the reader has no name for ──\n");
    print!(
        "{}",
        render(
            &graphs[0].1,
            &cache,
            &instances,
            &TestHasher,
            NETWORK,
            &Names::none()
        )
        .expect("mainnet is a network word")
    );
}

/// The preflight report, as a wallet would read it out.
fn summarise(graph: &ManifestGraph, cache: &MetadataCache, instances: &InstanceRegistry) {
    let report = preflight(graph, cache, instances, &TestHasher, &SHARDS, NETWORK)
        .expect("the graph admits and routes");
    let names = vocabulary();
    let signers: Vec<String> = report
        .signers()
        .iter()
        .map(|signer| {
            names
                .get(*signer)
                .map_or_else(|| signer.address().to_text(NETWORK).unwrap(), str::to_owned)
        })
        .collect();
    let shards: Vec<String> = report.shards().map(|shard| shard.0.to_string()).collect();
    println!("   signers    {}", signers.join(", "));
    println!("   shards     {}", shards.join(", "));
    println!(
        "   footprint  {} over {} shard(s)",
        report.footprint(),
        report.footprints.len()
    );
    println!(
        "   work       {} at a {GAS_LIMIT} gas ceiling",
        report.declared_work(GAS_LIMIT)
    );
    for required in report.unsatisfiable() {
        let reason = match required.authority {
            Authority::TargetHasNoKey => "its target's own authority, which no key holds",
            Authority::NoPrincipalConfigured { .. } => "a configured slot naming no principal",
            Authority::Anyone | Authority::Signature(_) => unreachable!("satisfiable"),
        };
        println!(
            "   UNSIGNABLE `{}` on node {} needs {reason}",
            required.method, required.node
        );
    }
}

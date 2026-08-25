//! What a wallet has to show somebody before they sign.
//!
//! Four graphs built through the typed builder, each printed as the
//! surface syntax and summarised by the preflight report — the two
//! client-side reads of one signed form. Run it with
//! `cargo run -p hyperscale-vm-manifest-builder --example render`.

use hyperscale_vm_effects::{
    Hash32, Hasher, InstanceMeta, ManifestGraph, PackageHash, PrefixShardResolver, Records,
    ResourceKind, TestHasher, Value, issued_resource,
};
use hyperscale_vm_fixtures::{amm, payouts};
use hyperscale_vm_manifest_builder::{
    Authority, Names, TypedBuilder, TypedError, preflight, render,
};
use hyperscale_vm_stdlib::{account, staking};
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr, ResourceAddr, SchemeId};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const OPERATOR: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const USDC: ResourceAddr = ResourceAddr::new([0xE2; 31]);
const NETWORK: &str = "mainnet";
const SHARDS: PrefixShardResolver = PrefixShardResolver { bits: 2 };
/// A ceiling a sender might sign for; the report prices against it.
const GAS_LIMIT: u64 = 50_000;

/// A quarter, at the scale a bounded configuration number holds.
const QUARTER: u128 = 1_000_000_000_000_000_000 / 4;

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

fn pool() -> amm::Amm {
    amm::Amm::at(instance("amm", pair()).address(&TestHasher))
}

fn stake_pool() -> staking::Staking {
    staking::Staking::at(instance("staking", operated()).address(&TestHasher))
}

fn splitter_config() -> Vec<Value> {
    vec![
        Value::Address(XRD.address()),
        Value::U128(QUARTER),
        Value::U128(QUARTER),
        Value::U128(2 * QUARTER),
    ]
}

fn splitter() -> ComponentAddr {
    instance("payouts", splitter_config()).address(&TestHasher)
}

/// The pool's own stake units, derived from the pool and its declared
/// mark rather than configured — so a wallet names them off the pool's
/// address without asking the pool anything.
fn units() -> ResourceAddr {
    issued_resource(
        &TestHasher,
        stake_pool(),
        ResourceKind::Fungible,
        staking::STAKE_UNIT,
    )
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("amm"), amm::metadata());
    chain
        .packages
        .publish_unchecked(pkg("payouts"), payouts::metadata());
    chain
        .packages
        .publish_unchecked(pkg("staking"), staking::metadata());
    chain.instances.serve_principals(pkg("account"));
    chain.instances.create(&TestHasher, instance("amm", pair()));
    chain
        .instances
        .create(&TestHasher, instance("payouts", splitter_config()));
    chain
        .instances
        .create(&TestHasher, instance("staking", operated()));
    chain
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
    let chain = world();
    let build = |write: &dyn Fn(&mut TypedBuilder<'_>) -> Result<(), TypedError>| -> ManifestGraph {
        let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
        write(&mut b).expect("every call types against its signature");
        b.build().expect("every output is consumed")
    };

    let graphs: Vec<(&str, ManifestGraph)> = vec![
        (
            "a transfer",
            build(&|b| {
                let alice = account::authorize(b, ALICE)?;
                let funds = account::withdraw(b, alice, XRD, 100)?;
                account::deposit(b, BOB, funds)
            }),
        ),
        (
            "a swap",
            build(&|b| {
                let alice = account::authorize(b, ALICE)?;
                let funds = account::withdraw(b, alice, XRD, 100)?;
                let proceeds = pool().swap(b, funds, 90)?;
                account::deposit(b, ALICE, proceeds)
            }),
        ),
        (
            "a split, with the change routed by policy",
            build(&|b| {
                b.rest_to(ALICE);
                let alice = account::authorize(b, ALICE)?;
                let funds = account::withdraw(b, alice, XRD, 100)?;
                let [taken, _change] =
                    payouts::Payouts::at(splitter()).in_lots(b, funds, 30u128)?;
                account::deposit(b, BOB, taken.min(30))
            }),
        ),
        (
            "a delegation, and the operator surface beside it",
            build(&|b| {
                let alice = account::authorize(b, ALICE)?;
                let funds = account::withdraw(b, alice, XRD, 1_000)?;
                let position = stake_pool().stake(b, funds)?;
                account::deposit(b, ALICE, position)?;
                // The operator surface is the configured operator's, so
                // it acts under the operator's own sign-in beside
                // Alice's.
                let operator = account::authorize(b, OPERATOR)?;
                stake_pool().unjail(b, operator, 42)
            }),
        ),
    ];

    for (title, graph) in &graphs {
        println!("── {title} ──\n");
        print!(
            "{}",
            render(graph, &chain, &TestHasher, NETWORK, &vocabulary())
                .expect("mainnet is a network word")
        );
        println!();
        summarise(graph, &chain);
        println!();
    }

    // The same transfer with no address book: the projection degrades to
    // the addresses themselves, which is what an unrecognised counterparty
    // actually looks like.
    println!("── a transfer, to somebody the reader has no name for ──\n");
    print!(
        "{}",
        render(&graphs[0].1, &chain, &TestHasher, NETWORK, &Names::none())
            .expect("mainnet is a network word")
    );
}

/// The preflight report, as a wallet would read it out.
fn summarise(graph: &ManifestGraph, chain: &Records) {
    let report = preflight(graph, ALICE, chain, &TestHasher, &SHARDS, NETWORK)
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
        "   work       {} at a {GAS_LIMIT} gas ceiling, signed under ed25519",
        report.declared_work(GAS_LIMIT, &[SchemeId::ED25519])
    );
    for required in report.unsatisfiable() {
        let reason = match required.authority {
            Authority::TargetHasNoKey => "an identity no key derives",
            Authority::Anyone
            | Authority::Signature(_)
            | Authority::StoredRule
            | Authority::Held
            | Authority::Badge { .. }
            | Authority::Threshold { .. } => {
                unreachable!("satisfiable")
            }
        };
        println!(
            "   UNSIGNABLE `{}` on node {} needs {reason}",
            required.method, required.node
        );
    }
}

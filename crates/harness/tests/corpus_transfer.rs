//! The transfer pattern end to end on both runtimes: profile and
//! provision shape, edge bounds, minted proofs, runtime-published
//! packages, and the stdlib deposit's mark.

use std::collections::BTreeMap;

use hyperscale_vm_effects::vocabulary::{CLAIMS, VAULT};
use hyperscale_vm_effects::{
    AbiParam, Clause, Constraint, Expr, Hash32, InstanceMeta, ManifestGraph, MethodSignature,
    ModeExpr, PackageMetadata, ParamType, ShardId, SlotId, TargetExpr, TestHasher, Totality,
};
use hyperscale_vm_harness::driver::{amount_of, vault};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_manifest_builder::TypedBuilder;
use hyperscale_vm_runtime::check_method;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{EffectSet, EffectTarget, Event, Mode, Outcome, TxHash, encode_amount};
use wasmtime::Result;

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

fn mirror_meta() -> InstanceMeta {
    InstanceMeta {
        package: pkg("mirror"),
        config: vec![],
        salt: Hash32([4; 32]),
    }
}

/// A package the authored stdlib table does not describe: the same
/// account code under its own content address, with metadata written
/// here and published at runtime.
///
/// `deposit` declares its two delta clauses in the opposite order to the
/// stdlib account's and binds the ABI handle to the second one. Nothing
/// about the resulting call can come from a table of known method names,
/// and nothing can come from a convention that a method's first clause is
/// its first handle: if either were true the credit would land on the
/// claims cell instead of the vault.
fn mirror_metadata() -> PackageMetadata {
    let self_child = |slot: SlotId, material: Vec<Expr>| Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot,
        material,
    };
    let resource_of_arg0 = || Expr::ResourceOf(Box::new(Expr::Arg(0)));
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "deposit".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(1), AbiParam::Bucket(0)],
            effects: vec![
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(self_child(CLAIMS, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(resource_of_arg0())),
                },
                Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(self_child(VAULT, vec![resource_of_arg0()])),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(resource_of_arg0())),
                },
            ],
            ..MethodSignature::default()
        },
    );
    metadata.events = vec!["withdrawn".into(), "deposited".into()];
    metadata
}

#[test]
fn a_package_published_at_runtime_is_callable_through_the_same_walk() {
    let mut world = world();
    world
        .packages
        .publish_unchecked(pkg("mirror"), mirror_metadata());
    let dana = world.instances.create(&TestHasher, mirror_meta());

    let mut store = MemoryStore::new();
    seal(&mut store, &mirror_meta());
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    let graph = {
        // Not a wrapper call: `dana` runs the mirror package, so its
        // deposit is the one this test published rather than the account's.
        let mut b = TypedBuilder::new(&world, &TestHasher);
        let alice = account::authorize(&mut b, ALICE).unwrap();
        let funds = account::withdraw(&mut b, alice, RES_X, 100).unwrap();
        b.call(dana, "deposit", (funds,)).unwrap().none().unwrap();
        b.build().expect("every output is consumed")
    };
    let (results, _) = run_both(&world, &store, &[(&graph, TxHash(Hash32([0x0D; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the published package must complete");
    };
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(dana, RES_X))
            .map(|movement| movement.credit),
        Some(100),
        "the bound clause's cell takes the credit"
    );
    assert!(
        receipt.delta.movements.get(&claims(dana, RES_X)).is_none(),
        "the unbound clause is declared and untouched"
    );
}

/// A transfer whose recipient signs a bound the sender's withdrawal
/// cannot meet.
fn bounded_transfer_graph(constraint: Constraint) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
        account::deposit(b, BOB, funds.constrain(constraint))
    })
}

#[test]
fn a_missed_edge_bound_aborts_identically_on_both_runtimes() {
    let world = world();
    let mut store = MemoryStore::new();
    store.write(vault(ALICE, RES_X), encode_amount(500).to_vec());

    // The withdrawal is feasible and the guest is honest — it returns
    // exactly the 100 it reserved. What fails is the manifest's own
    // guarantee, asserted independently of the callee, so neither the
    // producer's code nor the consumer's had to check anything.
    for (constraint, name) in [
        (Constraint::MinAmount(150), "under the floor"),
        (Constraint::MaxAmount(50), "over the ceiling"),
    ] {
        let graph = bounded_transfer_graph(constraint);
        let (results, after) = run_both(&world, &store, &[(&graph, TxHash(Hash32([0x0E; 32])))]);
        assert_eq!(
            results[0],
            TxResult::Refused(Outcome::ConstraintUnmet {
                node: 2,
                param: 0,
                amount: 100,
            }),
            "{name}"
        );
        // The abort is the whole of it: nothing the sender declared
        // applied, so the reservation never settled.
        assert_eq!(
            after
                .cells()
                .map(|(key, value)| (key, value.to_vec()))
                .collect::<BTreeMap<_, _>>(),
            store
                .cells()
                .map(|(key, value)| (key, value.to_vec()))
                .collect::<BTreeMap<_, _>>(),
            "{name}"
        );
    }

    // The same manifest inside the bound completes, so the refusal is
    // the bound and not the shape.
    let graph = bounded_transfer_graph(Constraint::MinAmount(100));
    let (results, _) = run_both(&world, &store, &[(&graph, TxHash(Hash32([0x0F; 32])))]);
    assert!(matches!(results[0], TxResult::Completed(_)));
}

#[test]
fn transfer_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &transfer_graph());

    // The walkthrough's profile: the sign-in's rule-cell read and one
    // reservation at the sender, the vault and claims deltas at the
    // recipient.
    let expected: BTreeMap<ShardId, EffectSet> = BTreeMap::from([
        (
            shard_of(ALICE),
            set(&[
                point(auth(ALICE), Mode::Read),
                point(vault(ALICE, RES_X), Mode::Reserve { amount: 100 }),
            ]),
        ),
        (
            shard_of(BOB),
            set(&[
                point(vault(BOB, RES_X), Mode::Delta),
                point(claims(BOB, RES_X), Mode::Delta),
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);

    // The acceptance test, executable: the balance movement stays
    // commutative on both sides, and what provisions is exactly the
    // sender's rule cell — absent for a virtual account, and the read
    // is what carries that absence to the counterpart.
    assert_eq!(
        routing.per_shard[&shard_of(ALICE)].provision_targets(),
        std::iter::once(EffectTarget::Point(auth(ALICE))).collect()
    );
    assert!(
        routing.per_shard[&shard_of(BOB)]
            .provision_targets()
            .is_empty()
    );
}

#[test]
fn transfer_executes_end_to_end_on_both_runtimes() {
    let world = world();
    let mut store = MemoryStore::new();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    let graph = transfer_graph();
    let (results, final_store) = run_both(&world, &store, &[(&graph, TxHash(Hash32([0x01; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("transfer must complete");
    };
    assert_eq!(
        receipt
            .delta
            .settles
            .get(&vault(ALICE, RES_X))
            .map(|moved| moved.debit),
        Some(100)
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(BOB, RES_X))
            .unwrap()
            .credit,
        100
    );
    assert!(receipt.delta.cells.is_empty());
    // Both nodes emitted, and each event carries the address of the node
    // that ran rather than anything the guest could have named — the two
    // legs of a transfer live on different shards, so this is what decides
    // which receipt each event lands on.
    assert_eq!(
        receipt.events,
        vec![
            Event {
                emitter: ALICE.address(),
                event_type: 0,
                payload: encode_amount(100).to_vec(),
            },
            Event {
                emitter: BOB.address(),
                event_type: 1,
                payload: encode_amount(100).to_vec(),
            },
        ],
    );
    // Nothing on the execution path resolves an index, so the guest's
    // constants and the package's table are two halves of one contract
    // that only a test holds together.
    let table = account::metadata().events;
    assert_eq!(table, vec!["withdrawn", "deposited"]);
    for event in &receipt.events {
        assert!(
            table.get(event.event_type as usize).is_some(),
            "event type {} resolves in its emitter's package",
            event.event_type,
        );
    }
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 100);
}

#[test]
fn a_transfer_on_a_minted_proof_settles_like_one_on_the_signature() {
    let world = world();
    let mut store = MemoryStore::new();
    store.write(vault(ALICE, RES_X), encode_amount(150).to_vec());

    let graph = authorized_transfer_graph();
    let (results, final_store) = run_both(&world, &store, &[(&graph, TxHash(Hash32([0x0A; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the authorized transfer must complete");
    };
    // The proof changes where the withdrawal's authority came from and
    // nothing about what it did.
    assert_eq!(
        receipt
            .delta
            .settles
            .get(&vault(ALICE, RES_X))
            .map(|moved| moved.debit),
        Some(100)
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(BOB, RES_X))
            .unwrap()
            .credit,
        100
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&final_store, vault(BOB, RES_X)), 100);
}

/// The stdlib's own total mark, checked against the code that carries it.
///
/// `account_metadata` declares `deposit` total, and a claim a package
/// makes about itself is worth nothing unless something reads the
/// artifact back. This is that reading: the guest as it deploys, the
/// method as routing names it, and the same walk a publish-time check
/// would run.
///
/// `withdraw` rides along as the contrast, and the two facts behind the
/// mark come apart on it. Its export carries no error arm either, so it
/// is infallible by the same reading — and the checker still refuses it
/// the upgrade, which is the proof that the scan answers per method
/// rather than per package: the two live in one module and only one of
/// them passes.
#[test]
fn the_stdlib_deposit_earns_the_mark_it_claims() -> Result<()> {
    let artifact = build_guest("account")?;

    assert_eq!(
        account::metadata().methods["deposit"].totality,
        Totality::Total,
        "the fixture under test is the claim itself",
    );
    assert_eq!(
        check_method(&artifact, "deposit"),
        Ok(()),
        "the claim has to survive the artifact, or it is not a claim",
    );

    assert_eq!(
        account::metadata().methods["withdraw-nf"].totality,
        Totality::Infallible,
    );
    assert!(
        check_method(&artifact, "withdraw-nf").is_err(),
        "one module, two verdicts — the check is per method",
    );
    Ok(())
}

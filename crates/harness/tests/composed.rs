//! The composed-transaction fixture: a two-signer envelope tree —
//! composer and subintent trading across yield edges — admitted,
//! routed, and executed through the batch executor on both runtimes,
//! with the nullifier making the subintent once-only.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::stdlib::{VAULT, account_metadata};
use hyperscale_vm_effects::{
    Address, AdmittedTree, Constraint, EnvelopeTree, Hasher, InstanceRegistry, MetadataCache,
    PackageHash, PrefixShardResolver, PrincipalAddr, ResourceAddr, SubstateKey, TestHasher, Value,
    admit_tree, child_key, route_tree,
};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, CellKind, EnvInputs, ExecutionMode, GuestArg, GuestBackend, GuestCall,
    InvokeResult, KernelSession, Locality, ManifestWalk, MemoryStore, OUT_OF_GAS, Outcome,
    SubstateStore, TxHash, decode_amount, encode_amount, execute_batch,
};
use hyperscale_vm_manifest_builder::EnvelopeBuilder;
use hyperscale_vm_manifest_builder::native::account;
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, ResourceKind, Trap as RefTrap,
};
use hyperscale_vm_runtime::{
    CellKind as HostCellKind, HostArg, add_kernel_to_linker, blessed_engine, call_export,
    validate_component,
};
use wasmtime::component::{Component, Linker};
use wasmtime::error::{Context, ensure};
use wasmtime::{Engine, Result, Store};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const CAROL: PrincipalAddr = PrincipalAddr::new([0x30; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 3_000,
        randomness: [6; 32],
    }
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg());
    (cache, instances)
}

fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The composition: the composer pays `pay` of X for the subintent's 10
/// Y — each side withdraws its leg, exports it, and deposits the other's
/// yield. Neither graph names the other; the envelope is the two edges
/// between them.
fn composed_tree(composer: PrincipalAddr, pay: u128) -> EnvelopeTree {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);

    let (taken, wants_y) = root.declare(RES_Y, [Constraint::MinAmount(10)]);
    let funds = account::withdraw(&mut root, composer, RES_X, pay).expect("withdraw types");
    let paid_x = root.export(funds);
    account::deposit(&mut root, composer, taken).expect("deposit types");

    let mut sub = env.subintent(BOB);
    let (taken, wants_x) = sub.declare(RES_X, [Constraint::MinAmount(100)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, 10).expect("withdraw types");
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken).expect("deposit types");

    env.seal(root).expect("the root discharges its declaration");
    env.seal(sub)
        .expect("the subintent discharges its declaration");
    env.bind(wants_y, paid_y);
    env.bind(wants_x, paid_x);
    env.build().expect("every hole is bound")
}

/// Admit and route one envelope into its batch entry, plus the manifest
/// its runner walks.
fn batch_entry(
    world: &(MetadataCache, InstanceRegistry),
    tree: &EnvelopeTree,
) -> Result<(BatchTx, AdmittedTree)> {
    let (cache, instances) = world;
    let identity = tree.hash(&TestHasher);
    let admitted =
        admit_tree(tree, identity, cache, instances, &TestHasher).context("admission")?;
    let routing = route_tree(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )
    .context("routing")?;
    // The null resolver puts every effect on one shard, so the whole
    // declaration is the sole entry — taken as that rather than by naming
    // an id the resolver is free to choose.
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    // The whole declaration, both views, straight from the fold: the
    // clause order is what a handle's rep indexes into, so taking the
    // folded set's order instead would hand the guest a table the
    // lowered calls were not resolved against.
    let declaration = routing.declaration().context("declaration")?;
    let entry = BatchTx::new(
        TxHash(identity.0),
        declaration,
        env().clock_ms,
        env().randomness,
    )
    .with_calls(routing.calls)
    .with_nullifiers(
        admitted
            .subintents
            .iter()
            .map(|record| record.nullifier)
            .collect(),
    );
    Ok((entry, admitted))
}

/// The blessed engine behind the walk: one instantiation per call, the
/// export invoked from the arguments the kernel assembled.
struct BlessedComposed {
    engine: Engine,
    component: Component,
}

impl GuestBackend for BlessedComposed {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let mut linker = Linker::<SessionHost>::new(&self.engine);
        add_kernel_to_linker(&mut linker).expect("wiring");
        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let instance = linker
            .instantiate(&mut store, &self.component)
            .expect("instantiate");
        let args: Vec<HostArg<'_>> = call.args.iter().map(host_arg).collect();
        let result = call_export(&mut store, &instance, call.export, &args, call.returns)
            .map_err(|trap| format!("{trap:#}"));
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        let exhausted = store.get_fuel().expect("fuel") == 0 && result.is_err();
        InvokeResult {
            session: store.into_data().0,
            fuel,
            result,
            exhausted,
        }
    }
}

/// The reference interpreter behind the same walk.
struct RefComposed {
    component: RefComponent,
}

impl GuestBackend for RefComposed {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let args: Vec<CVal> = call.args.iter().map(ref_arg).collect();
        let mut instance = RefComponentInstance::instantiate(&self.component, SessionHost(session))
            .expect("instantiate");
        instance.set_fuel_limit(call.fuel_budget.min(FUEL));
        let outcome = instance.invoke(call.export, &args).expect("invoke");
        let fuel = instance.fuel_consumed();
        let exhausted = matches!(outcome, Err(ExecError::Trap(RefTrap::OutOfFuel)));
        let result = match outcome {
            Ok(values) => match (call.returns, values.as_slice()) {
                (false, []) => Ok(None),
                (true, [CVal::Bytes(bytes)]) => Ok(Some(bytes.clone())),
                other => Err(format!("unexpected result shape {other:?}")),
            },
            Err(trap) => Err(format!("{trap:?}")),
        };
        InvokeResult {
            session: instance.into_host().0,
            fuel,
            result,
            exhausted,
        }
    }
}

const fn host_kind(kind: CellKind) -> HostCellKind {
    match kind {
        CellKind::Read => HostCellKind::Read,
        CellKind::Locked => HostCellKind::Locked,
        CellKind::Write => HostCellKind::Write,
        CellKind::Delta => HostCellKind::Delta,
        CellKind::Reserve => HostCellKind::Reserve,
        CellKind::RangeRead => HostCellKind::RangeRead,
        CellKind::RangeWrite => HostCellKind::RangeWrite,
    }
}

const fn ref_kind(kind: CellKind) -> ResourceKind {
    match kind {
        CellKind::Read => ResourceKind::ReadCell,
        CellKind::Locked => ResourceKind::LockedCell,
        CellKind::Write => ResourceKind::WriteCell,
        CellKind::Delta => ResourceKind::DeltaCell,
        CellKind::Reserve => ResourceKind::ReserveCell,
        CellKind::RangeRead => ResourceKind::RangeRead,
        CellKind::RangeWrite => ResourceKind::RangeWrite,
    }
}

const fn host_arg<'a>(arg: &GuestArg<'a>) -> HostArg<'a> {
    match arg {
        GuestArg::Handle { rep, kind } => HostArg::Handle {
            rep: *rep,
            kind: host_kind(*kind),
        },
        GuestArg::U64(scalar) => HostArg::U64(*scalar),
        GuestArg::Bytes(bytes) => HostArg::Bytes(bytes),
    }
}

fn ref_arg(arg: &GuestArg<'_>) -> CVal {
    match arg {
        GuestArg::Handle { rep, kind } => CVal::Borrow(*rep, ref_kind(*kind)),
        GuestArg::U64(scalar) => CVal::U64(*scalar),
        GuestArg::Bytes(bytes) => CVal::Bytes(bytes.to_vec()),
    }
}

fn seeded_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(CAROL, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(BOB, RES_Y), encode_amount(30).to_vec())
        .unwrap();
    store.clear_log();
    store
}

fn cells(outcome: &BatchOutcome) -> BTreeMap<SubstateKey, Vec<u8>> {
    let store = outcome.store.clone().collapse();
    store
        .cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

fn amount_of(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    cells(outcome)
        .get(&key)
        .map_or(0, |cell| decode_amount(cell).unwrap())
}

/// Execute the batch on both runtimes and assert byte-identical
/// receipts and end state; returns the blessed outcome.
fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> Result<BatchOutcome> {
    let bytes = build_guest("account")?;
    validate_component(&bytes).context("profile validation")?;
    let engine = blessed_engine()?;
    let blessed = BlessedComposed {
        component: Component::new(&engine, &bytes)?,
        engine,
    };
    let reference = RefComposed {
        component: RefComponent::decode(&bytes)?,
    };
    let blessed_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk { backend: &blessed },
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();
    let ref_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk {
            backend: &reference,
        },
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    assert_eq!(
        blessed_outcome.receipts, ref_outcome.receipts,
        "lanes diverged"
    );
    assert_eq!(
        cells(&blessed_outcome),
        cells(&ref_outcome),
        "state diverged"
    );
    Ok(blessed_outcome)
}

#[test]
fn a_composed_transaction_settles_on_both_runtimes() -> Result<()> {
    let world = world();
    let tree = composed_tree(ALICE, 100);
    let (entry, admitted) = batch_entry(&world, &tree)?;
    let nullifier = admitted.subintents[0].nullifier;

    let outcome = run_both(&seeded_store(), std::slice::from_ref(&entry))?;
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_of(&outcome, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&outcome, vault(ALICE, RES_Y)), 10);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_X)), 100);
    // The spent nullifier records the consuming transaction, receipt and
    // state alike.
    assert_eq!(
        cells(&outcome).get(&nullifier),
        Some(&entry.tx.0.0.to_vec())
    );
    assert_eq!(
        outcome.receipts[&entry.tx].delta.cells.get(&nullifier),
        Some(&Some(entry.tx.0.0.to_vec()))
    );
    Ok(())
}

#[test]
fn racing_compositions_commit_exactly_one() -> Result<()> {
    // Two composers carry the same signed subintent: same nullifier,
    // one conflict group, canonical order picks the winner.
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100))?;
    let (carol_entry, carol_admitted) = batch_entry(&world, &composed_tree(CAROL, 120))?;
    assert_eq!(
        alice_admitted.subintents[0].nullifier,
        carol_admitted.subintents[0].nullifier
    );
    let alice_wins = alice_entry.tx < carol_entry.tx;
    let batch = vec![alice_entry.clone(), carol_entry.clone()];
    let outcome = run_both(&seeded_store(), &batch)?;

    let (winner, loser, pay) = if alice_wins {
        (&alice_entry, &carol_entry, 100)
    } else {
        (&carol_entry, &alice_entry, 120)
    };
    assert!(matches!(
        outcome.receipts[&winner.tx].outcome,
        Outcome::Completed { .. }
    ));
    // A lost race, not a defect: canonical order picked the winner and
    // the loser could not have known which it would be.
    assert_eq!(
        outcome.receipts[&loser.tx].outcome,
        Outcome::NullifierSpent {
            key: alice_admitted.subintents[0].nullifier,
        }
    );

    let (winner_addr, loser_addr) = if alice_wins {
        (ALICE, CAROL)
    } else {
        (CAROL, ALICE)
    };
    assert_eq!(amount_of(&outcome, vault(winner_addr, RES_X)), 150 - pay);
    assert_eq!(amount_of(&outcome, vault(winner_addr, RES_Y)), 10);
    assert_eq!(amount_of(&outcome, vault(loser_addr, RES_X)), 150);
    assert_eq!(amount_of(&outcome, vault(loser_addr, RES_Y)), 0);
    // The subintent leg settled exactly once.
    assert_eq!(amount_of(&outcome, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_X)), pay);
    assert_eq!(
        cells(&outcome).get(&alice_admitted.subintents[0].nullifier),
        Some(&winner.tx.0.0.to_vec())
    );
    Ok(())
}

#[test]
fn a_spent_nullifier_blocks_the_next_batch() -> Result<()> {
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100))?;
    let (carol_entry, _) = batch_entry(&world, &composed_tree(CAROL, 120))?;
    let nullifier = alice_admitted.subintents[0].nullifier;

    let first = run_both(&seeded_store(), std::slice::from_ref(&alice_entry))?;
    let committed = first.store.collapse();

    let second = run_both(&committed, std::slice::from_ref(&carol_entry))?;
    assert_eq!(
        second.receipts[&carol_entry.tx].outcome,
        Outcome::NullifierSpent { key: nullifier }
    );
    assert_eq!(amount_of(&second, vault(CAROL, RES_X)), 150);
    assert_eq!(amount_of(&second, vault(BOB, RES_Y)), 20);
    Ok(())
}

/// A transaction that spends its signed ceiling aborts the same way on
/// both runtimes, and applies nothing.
///
/// The budget is per transaction, not per invocation: a manifest's nodes
/// draw from one allowance, so what the sender declared bounds the whole
/// transaction rather than each of its calls. Exhaustion is the sender's
/// own defect and prices as one — and the reason is fixed here rather
/// than taken from the trap, because each engine words its own and the
/// classification is consensus content.
#[test]
fn a_transaction_that_spends_its_gas_limit_aborts_on_both_runtimes() -> Result<()> {
    let world = world();
    let (entry, _) = batch_entry(&world, &composed_tree(ALICE, 100))?;

    // Enough to enter the guest and nowhere near enough to leave it.
    let starved = entry.with_gas_limit(64);
    let outcome = run_both(&seeded_store(), std::slice::from_ref(&starved))?;

    match &outcome.receipts[&starved.tx].outcome {
        Outcome::UserError { reason } => assert_eq!(reason, OUT_OF_GAS),
        other => panic!("expected the gas ceiling to abort it, got {other:?}"),
    }
    // Nothing moved: the seeded balances stand.
    assert_eq!(amount_of(&outcome, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_X)), 0);
    Ok(())
}

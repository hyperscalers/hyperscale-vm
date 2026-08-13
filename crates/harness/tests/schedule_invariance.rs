//! Schedule invariance end to end: the same transaction batch executed
//! serial, parallel, and under adversarially permuted worker timing, on
//! the blessed engine and the reference interpreter — six runs, one
//! byte-identical outcome: receipts, fuel, and the committed store.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, GuestRunner, KernelSession,
    Locality, MemoryStore, Outcome, OverlayStore, RunResult, TxHash, WorkingStore, decode_amount,
    encode_amount, execute_batch,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, WriteCell, add_kernel_to_linker, blessed_engine,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Engine, Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 9_000,
        randomness: [4; 32],
    }
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn vault(owner: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([owner; 31], AddressClass::Component),
        RoleId(1),
        &[],
    )
}

fn rmw_cell() -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([8; 31], AddressClass::Component),
        RoleId(5),
        &[],
    )
}

/// What each transaction's guest invocation looks like.
#[derive(Clone, Copy)]
enum Shape {
    Transfer {
        sender: SubstateKey,
        recipient: SubstateKey,
    },
    Rmw {
        cell: SubstateKey,
    },
}

fn fixture() -> (MemoryStore, Vec<BatchTx>, BTreeMap<TxHash, Shape>) {
    let recipient = vault(9);
    let mut store = MemoryStore::new();
    for owner in 1u8..=3 {
        store
            .write(vault(owner), encode_amount(100).to_vec())
            .unwrap();
    }
    store.write(rmw_cell(), vec![1, 2, 3]).unwrap();
    store.clear_log();

    let mut batch = Vec::new();
    let mut shapes = BTreeMap::new();
    for (id, owner, amount) in [(0x11u8, 1u8, 30u128), (0x22, 2, 40), (0x33, 3, 50)] {
        let sender = vault(owner);
        let mut declared = EffectSet::new();
        declared
            .insert(Effect {
                target: EffectTarget::Point(sender),
                mode: Mode::Reserve { amount },
            })
            .unwrap();
        declared
            .insert(Effect {
                target: EffectTarget::Point(recipient),
                mode: Mode::Delta,
            })
            .unwrap();
        batch.push(BatchTx::new(
            tx(id),
            declared,
            env().clock_ms,
            env().randomness,
        ));
        shapes.insert(tx(id), Shape::Transfer { sender, recipient });
    }
    for id in [0x44u8, 0x55] {
        let mut declared = EffectSet::new();
        declared
            .insert(Effect {
                target: EffectTarget::Point(rmw_cell()),
                mode: Mode::Write,
            })
            .unwrap();
        batch.push(BatchTx::new(
            tx(id),
            declared,
            env().clock_ms,
            env().randomness,
        ));
        shapes.insert(tx(id), Shape::Rmw { cell: rmw_cell() });
    }
    (store, batch, shapes)
}

fn rep_of(session: &KernelSession, wanted: &Capability) -> u32 {
    u32::try_from(
        session
            .capabilities()
            .iter()
            .position(|c| c == wanted)
            .expect("capability present"),
    )
    .expect("bounded")
}

fn stall(id: TxHash) {
    sleep(Duration::from_millis(u64::from(
        0xFF_u8.wrapping_sub(id.0.0[0]) / 32,
    )));
}

struct BlessedRunner {
    engine: Engine,
    component: Component,
    shapes: BTreeMap<TxHash, Shape>,
    delay: bool,
}

impl BlessedRunner {
    fn new(shapes: BTreeMap<TxHash, Shape>, delay: bool) -> Result<Self> {
        let engine = blessed_engine()?;
        let component = Component::new(&engine, parse_str(KERNEL_GUEST_WAT)?)?;
        Ok(Self {
            engine,
            component,
            shapes,
            delay,
        })
    }
}

impl GuestRunner for BlessedRunner {
    fn run(&self, entry: &BatchTx, session: KernelSession) -> RunResult {
        let id = entry.tx;
        if self.delay {
            stall(id);
        }
        let shape = self.shapes[&id];
        let mut linker = Linker::<SessionHost>::new(&self.engine);
        add_kernel_to_linker(&mut linker).expect("wiring");
        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(FUEL).expect("fuel");
        let instance = linker
            .instantiate(&mut store, &self.component)
            .expect("instantiate");
        let result = match shape {
            Shape::Transfer { sender, recipient } => {
                let a = u32::try_from(
                    store
                        .data()
                        .0
                        .capabilities()
                        .iter()
                        .position(
                            |c| matches!(c, Capability::Reserve { key, .. } if *key == sender),
                        )
                        .expect("capability present"),
                )
                .expect("bounded");
                let b = rep_of(&store.data().0, &Capability::Delta(recipient));
                instance
                    .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>), (u64,)>(
                        &mut store, "transfer",
                    )
                    .and_then(|f| {
                        f.call(
                            &mut store,
                            (Resource::new_borrow(a), Resource::new_borrow(b)),
                        )
                        .map(|(v,)| v)
                    })
            }
            Shape::Rmw { cell } => {
                let rep = rep_of(&store.data().0, &Capability::Write(cell));
                instance
                    .get_typed_func::<(Resource<WriteCell>,), (u64,)>(&mut store, "rmw")
                    .and_then(|f| {
                        f.call(&mut store, (Resource::new_borrow(rep),))
                            .map(|(v,)| v)
                    })
            }
        };
        let outcome = result.map_or_else(
            |_| Outcome::UserError {
                reason: "guest trap".into(),
            },
            |value| Outcome::Completed { value: Some(value) },
        );
        let fuel = FUEL - store.get_fuel().expect("fuel");
        RunResult {
            session: store.into_data().0,
            outcome,
            fuel,
        }
    }
}

struct RefRunner {
    comp: RefComponent,
    shapes: BTreeMap<TxHash, Shape>,
    delay: bool,
}

impl RefRunner {
    fn new(shapes: BTreeMap<TxHash, Shape>, delay: bool) -> Result<Self> {
        let comp = RefComponent::decode(&parse_str(KERNEL_GUEST_WAT)?)?;
        Ok(Self {
            comp,
            shapes,
            delay,
        })
    }
}

impl GuestRunner for RefRunner {
    fn run(&self, entry: &BatchTx, session: KernelSession) -> RunResult {
        let id = entry.tx;
        if self.delay {
            stall(id);
        }
        let shape = self.shapes[&id];
        let (export, args) = match shape {
            Shape::Transfer { sender, recipient } => (
                "transfer",
                vec![
                    CVal::Borrow(
                        u32::try_from(
                    session
                        .capabilities()
                        .iter()
                        .position(
                            |c| matches!(c, Capability::Reserve { key, .. } if *key == sender),
                        )
                        .expect("capability present"),
                )
                .expect("bounded"),
                        ResourceKind::ReserveCell,
                    ),
                    CVal::Borrow(
                        rep_of(&session, &Capability::Delta(recipient)),
                        ResourceKind::DeltaCell,
                    ),
                ],
            ),
            Shape::Rmw { cell } => (
                "rmw",
                vec![CVal::Borrow(
                    rep_of(&session, &Capability::Write(cell)),
                    ResourceKind::WriteCell,
                )],
            ),
        };
        let mut instance =
            RefComponentInstance::instantiate(&self.comp, SessionHost(session)).expect("decode");
        let outcome = instance.invoke(export, &args).expect("invoke").map_or_else(
            |_| Outcome::UserError {
                reason: "guest trap".into(),
            },
            |values| match values.as_slice() {
                [CVal::U64(v)] => Outcome::Completed { value: Some(*v) },
                other => Outcome::UserError {
                    reason: format!("unexpected values {other:?}"),
                },
            },
        );
        let fuel = instance.fuel_consumed();
        RunResult {
            session: instance.into_host().0,
            outcome,
            fuel,
        }
    }
}

/// The end state's full cell map; `base` is the store the batch ran over.
fn cells(outcome: &BatchOutcome, base: &MemoryStore) -> BTreeMap<SubstateKey, Vec<u8>> {
    outcome
        .store
        .collapse_onto(base.clone())
        .cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

#[test]
fn six_schedules_one_outcome() -> Result<()> {
    let (store, batch, shapes) = fixture();

    let mut outcomes = Vec::new();
    for delay in [false, true] {
        let blessed = BlessedRunner::new(shapes.clone(), delay)?;
        let reference = RefRunner::new(shapes.clone(), delay)?;
        for mode in [ExecutionMode::Serial, ExecutionMode::Parallel] {
            // Permuted timing only means anything in parallel mode; skip
            // the redundant serial+delay run.
            if delay && mode == ExecutionMode::Serial {
                continue;
            }
            outcomes.push((
                format!("blessed/{mode:?}/delay={delay}"),
                execute_batch(
                    Arc::new(store.clone()),
                    &batch,
                    &blessed,
                    test_hash,
                    mode,
                    &Locality::All,
                )
                .unwrap(),
            ));
            outcomes.push((
                format!("ref/{mode:?}/delay={delay}"),
                execute_batch(
                    Arc::new(store.clone()),
                    &batch,
                    &reference,
                    test_hash,
                    mode,
                    &Locality::All,
                )
                .unwrap(),
            ));
        }
    }

    let (baseline_name, baseline) = &outcomes[0];
    for (name, outcome) in &outcomes[1..] {
        assert_eq!(
            baseline.receipts, outcome.receipts,
            "{name} receipts diverged from {baseline_name}"
        );
        assert_eq!(
            cells(baseline, &store),
            cells(outcome, &store),
            "{name} state diverged from {baseline_name}"
        );
    }

    // The expected end state, computed independently: three settlements,
    // one shared recipient accumulating every credit, two serialized
    // read-modify-writes.
    let mut final_store = baseline.store.clone();
    let amount = |store: &mut OverlayStore, key: SubstateKey| {
        decode_amount(&store.read(key).unwrap().unwrap()).unwrap()
    };
    assert_eq!(amount(&mut final_store, vault(1)), 70);
    assert_eq!(amount(&mut final_store, vault(2)), 60);
    assert_eq!(amount(&mut final_store, vault(3)), 50);
    assert_eq!(amount(&mut final_store, vault(9)), 120);
    assert_eq!(final_store.read(rmw_cell()).unwrap(), Some(vec![3, 2, 3]));

    // Every transfer completed with its amount; the writers saw canonical
    // order.
    for (id, amount) in [(0x11u8, 30u64), (0x22, 40), (0x33, 50)] {
        assert_eq!(
            baseline.receipts[&tx(id)].outcome,
            Outcome::Completed {
                value: Some(amount)
            }
        );
    }
    assert!(matches!(
        baseline.receipts[&tx(0x44)].outcome,
        Outcome::Completed { .. }
    ));
    Ok(())
}

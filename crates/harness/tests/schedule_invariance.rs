//! Schedule invariance end to end: the same transaction batch executed
//! serial, parallel, and under adversarially permuted worker timing, on
//! the blessed engine and the reference interpreter — six runs, one
//! byte-identical outcome: receipts, fuel, and the committed store.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, SlotId, TestHasher, child_key};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, GuestRunner, KernelSession,
    MemoryStore, OverlayStore, RunResult, Unavailable, WorkingStore, decode_amount, execute_batch,
};
use hyperscale_vm_meter::instantiation_cost;
use hyperscale_vm_ref::{RefModule, RefModuleInstance};
use hyperscale_vm_runtime::{
    Invoking, add_kernel_imports, admit, blessed_engine, instantiate_metered, invoke_export,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Answer, Effect, EffectSet, EffectTarget, Mode, Moves,
    Outcome, ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use wasmtime::{Engine, Linker, Module, Result, Store};
use wat::parse_str;

/// The one answer a fixture guest hands back, so a receipt depends on
/// what the body computed.
fn answered(value: u64) -> Vec<Answer> {
    vec![Answer {
        node: 0,
        value: value.to_le_bytes().to_vec(),
    }]
}

const FUEL: u64 = 1_000_000_000;
/// What the vaults in this batch hold.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(9_000)
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn vault(owner: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([owner; 31], AddressClass::Component),
        SlotId(1),
        &[],
    )
}

fn rmw_cell() -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([8; 31], AddressClass::Component),
        SlotId(5),
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
        store.write(vault(owner), encode_amount(100).to_vec());
    }
    store.write(rmw_cell(), vec![1, 2, 3]);

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
                mode: Mode::Delta { moves: Moves::Both },
            })
            .unwrap();
        batch.push(BatchTx::new(
            tx(id),
            // Both ends of a transfer hold the one resource this batch
            // moves; a cell that said nothing would move nothing.
            Declaration::from_set(declared).denominated(|_| Some(RESOURCE)),
            env(),
        ));
        shapes.insert(tx(id), Shape::Transfer { sender, recipient });
    }
    for id in [0x44u8, 0x55] {
        let mut declared = EffectSet::new();
        declared
            .insert(Effect {
                target: EffectTarget::Point(rmw_cell()),
                mode: Mode::Write { moves: Moves::Both },
            })
            .unwrap();
        batch.push(BatchTx::new(tx(id), Declaration::from_set(declared), env()));
        shapes.insert(tx(id), Shape::Rmw { cell: rmw_cell() });
    }
    (store, batch, shapes)
}

fn rep_where(session: &KernelSession, pred: impl Fn(&Capability) -> bool) -> u32 {
    u32::try_from(
        session
            .capabilities()
            .iter()
            .position(pred)
            .expect("capability present"),
    )
    .expect("bounded")
}

/// The export a shape invokes and the sites it hands it, in parameter
/// order, off the session's own capability table.
fn call_for(session: &KernelSession, shape: Shape) -> (&'static str, Vec<GuestArg<'static>>) {
    match shape {
        Shape::Transfer { sender, recipient } => {
            let a = rep_where(
                session,
                |c| matches!(c, Capability::Reserve { key, .. } if *key == sender),
            );
            let b = rep_where(session, |c| {
                *c == Capability::Delta {
                    key: recipient,
                    moves: Moves::Both,
                }
            });
            (
                "transfer",
                vec![GuestArg::Site { site: a }, GuestArg::Site { site: b }],
            )
        }
        Shape::Rmw { cell } => {
            let rep = rep_where(session, |c| *c == Capability::Write(cell));
            ("rmw", vec![GuestArg::Site { site: rep }])
        }
    }
}

/// How an ending reads as a run: the eight answer bytes complete the
/// transaction with their figure, and anything else aborts in the class
/// it ended in.
fn run_result(session: KernelSession, ended: Invocation, fuel: u64) -> RunResult {
    let reason = match ended.result {
        Invoked::Produced {
            answer: Some(answer),
            ..
        } => match <[u8; 8]>::try_from(answer.as_slice()) {
            Ok(bytes) => {
                return RunResult::Completed {
                    session,
                    answers: answered(u64::from_le_bytes(bytes)),
                    fuel,
                };
            }
            Err(_) => AbortReason::BadReturnShape,
        },
        Invoked::Produced { answer: None, .. } | Invoked::Declined(_) => {
            AbortReason::BadReturnShape
        }
        Invoked::Aborted(reason) | Invoked::Unavailable(reason) => reason,
    };
    RunResult::Aborted {
        session,
        outcome: Outcome::UserError { reason },
        fuel,
    }
}

fn stall(id: TxHash) {
    sleep(Duration::from_millis(u64::from(
        0xFF_u8.wrapping_sub(id.0.0[0]) / 32,
    )));
}

struct BlessedRunner {
    engine: Engine,
    module: Module,
    cost: u64,
    linker: Linker<Invoking<KernelSession>>,
    shapes: BTreeMap<TxHash, Shape>,
    delay: bool,
}

impl BlessedRunner {
    fn new(shapes: BTreeMap<TxHash, Shape>, delay: bool) -> Result<Self> {
        let engine = blessed_engine()?;
        let author = parse_str(KERNEL_GUEST_WAT)?;
        let module = Module::new(&engine, admit(&author)?)?;
        let mut linker = Linker::<Invoking<KernelSession>>::new(&engine);
        add_kernel_imports(&mut linker)?;
        Ok(Self {
            engine,
            module,
            cost: instantiation_cost(&author)?,
            linker,
            shapes,
            delay,
        })
    }
}

impl GuestRunner for BlessedRunner {
    fn run(
        &self,
        entry: &BatchTx,
        session: KernelSession,
    ) -> std::result::Result<RunResult, Unavailable> {
        let id = entry.tx;
        if self.delay {
            stall(id);
        }
        let (export, args) = call_for(&session, self.shapes[&id]);
        let mut store = Store::new(&self.engine, Invoking::new(session));
        let instance = instantiate_metered(&mut store, FUEL, self.cost, |s| {
            self.linker.instantiate(s, &self.module)
        })
        .expect("instantiate");
        let ended = invoke_export(&mut store, &instance, export, &args, FUEL);
        let fuel = ended.fuel;
        Ok(run_result(store.into_data().into_host(), ended, fuel))
    }
}

struct RefRunner {
    module: RefModule,
    shapes: BTreeMap<TxHash, Shape>,
    delay: bool,
}

impl RefRunner {
    fn new(shapes: BTreeMap<TxHash, Shape>, delay: bool) -> Result<Self> {
        let module = RefModule::decode(&admit(&parse_str(KERNEL_GUEST_WAT)?)?)?;
        Ok(Self {
            module,
            shapes,
            delay,
        })
    }
}

impl GuestRunner for RefRunner {
    fn run(
        &self,
        entry: &BatchTx,
        session: KernelSession,
    ) -> std::result::Result<RunResult, Unavailable> {
        let id = entry.tx;
        if self.delay {
            stall(id);
        }
        let (export, args) = call_for(&session, self.shapes[&id]);
        let mut instance = RefModuleInstance::instantiate(&self.module, session, FUEL)
            .unwrap_or_else(|(_, error)| panic!("instantiate: {error}"));
        let ended = instance.invoke(export, &args);
        let fuel = ended.fuel;
        Ok(run_result(instance.into_host(), ended, fuel))
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
                execute_batch(Arc::new(store.clone()), &batch, &blessed, test_hash, mode).unwrap(),
            ));
            outcomes.push((
                format!("ref/{mode:?}/delay={delay}"),
                execute_batch(Arc::new(store.clone()), &batch, &reference, test_hash, mode)
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
                answers: answered(amount)
            }
        );
    }
    assert!(matches!(
        baseline.receipts[&tx(0x44)].outcome,
        Outcome::Completed { .. }
    ));
    Ok(())
}

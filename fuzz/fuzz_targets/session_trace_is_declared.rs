//! The trace-subset oracle, fuzzed.
//!
//! Arbitrary cell contents, reservation amounts, range bounds, book
//! entries, and call sequences drive the kernel-world guest through one
//! session per runtime. The seeded lanes fix these axes and call one
//! export per session; this lane composes them. Both lanes must agree on
//! every outcome, the access log, and the fuel, and `finish` must find
//! every recorded access inside the declared set — the oracle — whatever
//! the sequence did, including the adversarial exports (forged handles,
//! mode escapes, leaked borrows).

#![no_main]

use std::sync::{Arc, LazyLock};

use arbitrary::Unstructured;
use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Outcome, OverlayStore, SubstateStore,
    TxHash, encode_amount,
};
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, RefComponent, RefComponentInstance, ResourceKind,
};
use hyperscale_vm_runtime::{
    DeltaCell, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
    add_kernel_to_linker, blessed_engine,
};
use libfuzzer_sys::fuzz_target;
use wasmtime::component::{Component, Instance, Linker, Resource};
use wasmtime::{Engine, Store};

const FUEL: u64 = 1_000_000_000;
const ASKS: RoleId = RoleId(4);
const BOOK: Address = Address([0x40; 16]);

const EXPORTS: &[&str] = &[
    "transfer",
    "peek",
    "rmw",
    "scan-sum",
    "fill",
    "place",
    "escape",
    "forge",
    "forge-zero",
    "read-value",
    "handle-value",
    "leak",
    "bad-amount",
];

struct Runtime {
    engine: Engine,
    component: Component,
    reference: RefComponent,
}

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let bytes = wat::parse_str(KERNEL_GUEST_WAT).expect("fixture WAT parses");
    let engine = blessed_engine().expect("blessed engine");
    let component = Component::new(&engine, &bytes).expect("fixture compiles");
    let reference = RefComponent::decode(&bytes).expect("the spec decodes the fixture");
    Runtime {
        engine,
        component,
        reference,
    }
});

struct Plan {
    committed: u128,
    reserve: u128,
    locked_bytes: Vec<u8>,
    rmw_bytes: Vec<u8>,
    readable_bytes: Vec<u8>,
    entries: Vec<(u128, Vec<u8>)>,
    lo: u128,
    hi: u128,
    cap: u32,
    spare_read: bool,
    calls: Vec<&'static str>,
}

impl Plan {
    fn new(u: &mut Unstructured) -> arbitrary::Result<Self> {
        let committed = u.int_in_range(0..=1_000u32)?.into();
        let reserve = u.int_in_range(0..=1_200u32)?.into();
        let locked_bytes = small_bytes(u, 1, 4)?;
        let rmw_bytes = small_bytes(u, 0, 4)?;
        let readable_bytes = small_bytes(u, 0, 4)?;
        let mut entries = Vec::new();
        for _ in 0..u.int_in_range(0..=6)? {
            entries.push((u.int_in_range(0..=150u32)?.into(), small_bytes(u, 1, 3)?));
        }
        let a: u128 = u.int_in_range(0..=150u32)?.into();
        let b: u128 = u.int_in_range(0..=150u32)?.into();
        let mut calls = Vec::new();
        for _ in 0..u.int_in_range(1..=5)? {
            calls.push(*u.choose(EXPORTS)?);
        }
        Ok(Self {
            committed,
            reserve,
            locked_bytes,
            rmw_bytes,
            readable_bytes,
            entries,
            lo: a.min(b),
            hi: a.max(b),
            cap: u.int_in_range(0..=8)?,
            spare_read: u.arbitrary()?,
            calls,
        })
    }
}

fn small_bytes(u: &mut Unstructured, min: usize, max: usize) -> arbitrary::Result<Vec<u8>> {
    let len = u.int_in_range(min..=max)?;
    let mut out = vec![0u8; len];
    u.fill_buffer(&mut out)?;
    Ok(out)
}

struct Fx {
    declared: EffectSet,
    store: MemoryStore,
    sender: SubstateKey,
    recipient: SubstateKey,
    config: SubstateKey,
    rmw: SubstateKey,
    readable: SubstateKey,
}

/// Builds the store and the declared set; `None` when the plan produced a
/// shape the effect model refuses (that refusal is not what this lane
/// tests).
fn fixture(plan: &Plan) -> Option<Fx> {
    let sender = child_key(&TestHasher, Address([0x10; 16]), RoleId(1), &[]);
    let recipient = child_key(&TestHasher, Address([0x20; 16]), RoleId(1), &[]);
    let config = child_key(&TestHasher, Address([0x30; 16]), RoleId(3), &[]);
    let rmw = child_key(&TestHasher, Address([0x30; 16]), RoleId(5), &[]);
    let readable = child_key(&TestHasher, Address([0x30; 16]), RoleId(6), &[]);
    let spare = child_key(&TestHasher, Address([0x50; 16]), RoleId(7), &[]);

    let mut store = MemoryStore::new();
    if plan.committed > 0 {
        store.write(sender, encode_amount(plan.committed).to_vec()).ok()?;
    }
    store.write(config, plan.locked_bytes.clone()).ok()?;
    store.lock(config).ok()?;
    store.write(rmw, plan.rmw_bytes.clone()).ok()?;
    store.write(readable, plan.readable_bytes.clone()).ok()?;
    store.write(spare, vec![1]).ok()?;
    for (order, value) in &plan.entries {
        store.entry_write(BOOK, ASKS, *order, value.clone()).ok()?;
    }
    store.clear_log();

    let mut declared = EffectSet::new();
    let mut effects = vec![
        Effect {
            target: EffectTarget::Point(sender),
            mode: Mode::Reserve {
                amount: plan.reserve,
            },
        },
        Effect {
            target: EffectTarget::Point(recipient),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(config),
            mode: Mode::Locked,
        },
        Effect {
            target: EffectTarget::Point(rmw),
            mode: Mode::Write,
        },
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Range {
                owner: BOOK,
                collection: ASKS,
                lo: plan.lo,
                hi: plan.hi,
                cap: plan.cap,
            },
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Range {
                owner: BOOK,
                collection: ASKS,
                lo: plan.lo,
                hi: plan.hi,
                cap: plan.cap,
            },
            mode: Mode::Write,
        },
    ];
    if plan.spare_read {
        // Declared, never handed to the guest: the oracle asserts a
        // subset, and slack in the declaration must stay legal.
        effects.push(Effect {
            target: EffectTarget::Point(spare),
            mode: Mode::Read,
        });
    }
    for effect in effects {
        declared.insert(effect).ok()?;
    }

    Some(Fx {
        declared,
        store,
        sender,
        recipient,
        config,
        rmw,
        readable,
    })
}

fn session(fx: &Fx) -> Option<KernelSession> {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &fx.declared,
        &fx.declared.iter().collect::<Vec<_>>(),
        &[],
        TxHash(Hash32([0x33; 32])),
        EnvInputs {
            clock_ms: 424_242,
            randomness: [11; 32],
        },
        test_hash,
    )
    .ok()
}

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn rep_where(caps: &[Capability], pred: impl Fn(&Capability) -> bool) -> u32 {
    u32::try_from(caps.iter().position(pred).expect("capability present")).expect("bounded")
}

/// The handles each export receives, in parameter order.
fn args_for(fx: &Fx, caps: &[Capability], export: &str) -> Vec<(u32, ResourceKind)> {
    let point = |wanted: SubstateKey, kind: ResourceKind| {
        let rep = rep_where(caps, |c| match (kind, c) {
            (ResourceKind::ReadCell, Capability::Read(key))
            | (ResourceKind::LockedCell, Capability::Locked(key))
            | (ResourceKind::WriteCell, Capability::Write(key))
            | (ResourceKind::DeltaCell, Capability::Delta(key))
            | (ResourceKind::ReserveCell, Capability::Reserve { key, .. }) => *key == wanted,
            _ => false,
        });
        (rep, kind)
    };
    let range = |kind: ResourceKind| {
        let rep = rep_where(caps, |c| {
            matches!(
                (kind, c),
                (ResourceKind::RangeRead, Capability::RangeRead { .. })
                    | (ResourceKind::RangeWrite, Capability::RangeWrite { .. })
            )
        });
        (rep, kind)
    };
    match export {
        "transfer" => vec![
            point(fx.sender, ResourceKind::ReserveCell),
            point(fx.recipient, ResourceKind::DeltaCell),
        ],
        "peek" => vec![point(fx.config, ResourceKind::LockedCell)],
        "rmw" => vec![point(fx.rmw, ResourceKind::WriteCell)],
        "scan-sum" => vec![range(ResourceKind::RangeRead)],
        "fill" | "place" => vec![range(ResourceKind::RangeWrite)],
        "escape" | "bad-amount" => vec![point(fx.recipient, ResourceKind::DeltaCell)],
        "leak" | "handle-value" => vec![point(fx.readable, ResourceKind::ReadCell)],
        "forge" | "forge-zero" => vec![],
        other => unreachable!("unknown export {other}"),
    }
}

/// One comparable outcome across both runtimes.
#[derive(Debug, PartialEq, Eq)]
enum LaneOutcome {
    Value(u64),
    UnknownHandle,
    WrongHandleType,
    BorrowsRemain,
    Refusal(String),
    Other(String),
}

impl LaneOutcome {
    const fn value(&self) -> Option<u64> {
        match self {
            Self::Value(v) => Some(*v),
            _ => None,
        }
    }
}

fn classify_blessed(msg: &str) -> LaneOutcome {
    if msg.contains("unknown handle index") {
        LaneOutcome::UnknownHandle
    } else if msg.contains("borrow handles") {
        LaneOutcome::BorrowsRemain
    } else if let Some(tail) = msg.split("kernel refusal: ").nth(1) {
        LaneOutcome::Refusal(tail.lines().next().unwrap_or(tail).to_string())
    } else if msg.contains("resource") && msg.contains("type") {
        LaneOutcome::WrongHandleType
    } else {
        LaneOutcome::Other(msg.to_string())
    }
}

fn call1<T: 'static>(
    store: &mut Store<SessionHost>,
    instance: &Instance,
    export: &str,
    rep: u32,
) -> Result<u64, wasmtime::Error> {
    let f = instance.get_typed_func::<(Resource<T>,), (u64,)>(&mut *store, export)?;
    f.call(&mut *store, (Resource::new_borrow(rep),))
        .map(|(v,)| v)
}

/// Runs the plan's call sequence on one instance, stopping at the first
/// non-value outcome (a trapped store cannot be re-entered).
fn run_blessed(fx: &Fx, plan: &Plan) -> Option<(Vec<LaneOutcome>, SessionHost, u64)> {
    let rt = &*RUNTIME;
    let host = SessionHost(session(fx)?);
    let caps = host.0.capabilities().to_vec();
    let mut store = Store::new(&rt.engine, host);
    store.set_fuel(FUEL).expect("fuel is configured");
    let mut linker = Linker::<SessionHost>::new(&rt.engine);
    add_kernel_to_linker(&mut linker).expect("kernel world links");
    let instance = linker
        .instantiate(&mut store, &rt.component)
        .expect("fixture instantiates");

    let mut outcomes = Vec::new();
    for export in &plan.calls {
        let args = args_for(fx, &caps, export);
        let result: Result<u64, wasmtime::Error> = match (*export, args.as_slice()) {
            ("transfer", [(a, _), (b, _)]) => instance
                .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>), (u64,)>(
                    &mut store, export,
                )
                .and_then(|f| {
                    f.call(
                        &mut store,
                        (Resource::new_borrow(*a), Resource::new_borrow(*b)),
                    )
                    .map(|(v,)| v)
                }),
            ("forge" | "forge-zero", []) => instance
                .get_typed_func::<(), (u64,)>(&mut store, export)
                .and_then(|f| f.call(&mut store, ()).map(|(v,)| v)),
            (_, [(rep, kind)]) => match kind {
                ResourceKind::ReadCell => call1::<ReadCell>(&mut store, &instance, export, *rep),
                ResourceKind::LockedCell => {
                    call1::<LockedCell>(&mut store, &instance, export, *rep)
                }
                ResourceKind::WriteCell => call1::<WriteCell>(&mut store, &instance, export, *rep),
                ResourceKind::DeltaCell => call1::<DeltaCell>(&mut store, &instance, export, *rep),
                ResourceKind::ReserveCell => {
                    call1::<ReserveCell>(&mut store, &instance, export, *rep)
                }
                ResourceKind::RangeRead => call1::<RangeRead>(&mut store, &instance, export, *rep),
                ResourceKind::RangeWrite => {
                    call1::<RangeWrite>(&mut store, &instance, export, *rep)
                }
            },
            _ => unreachable!("unexpected arg shape for {export}"),
        };
        let outcome = match result {
            Ok(v) => LaneOutcome::Value(v),
            Err(e) => classify_blessed(&format!("{e:#}")),
        };
        let stop = outcome.value().is_none();
        outcomes.push(outcome);
        if stop {
            break;
        }
    }
    let fuel = FUEL - store.get_fuel().expect("fuel is configured");
    Some((outcomes, store.into_data(), fuel))
}

fn run_ref(fx: &Fx, plan: &Plan) -> Option<(Vec<LaneOutcome>, SessionHost, u64)> {
    let rt = &*RUNTIME;
    let host = SessionHost(session(fx)?);
    let caps = host.0.capabilities().to_vec();
    let mut instance =
        RefComponentInstance::instantiate(&rt.reference, host).expect("fixture instantiates");
    instance.set_fuel_limit(FUEL);

    let mut outcomes = Vec::new();
    for export in &plan.calls {
        let args: Vec<CVal> = args_for(fx, &caps, export)
            .into_iter()
            .map(|(rep, kind)| CVal::Borrow(rep, kind))
            .collect();
        let outcome = match instance.invoke(export, &args).expect("fixture invokes") {
            Ok(values) => match values.as_slice() {
                [CVal::U64(v)] => LaneOutcome::Value(*v),
                other => LaneOutcome::Other(format!("unexpected values {other:?}")),
            },
            Err(ExecError::Canon(CanonError::UnknownHandle)) => LaneOutcome::UnknownHandle,
            Err(ExecError::Canon(CanonError::WrongHandleType)) => LaneOutcome::WrongHandleType,
            Err(ExecError::Canon(CanonError::BorrowsRemain)) => LaneOutcome::BorrowsRemain,
            Err(ExecError::Canon(CanonError::Host(m))) => LaneOutcome::Refusal(m),
            Err(e) => LaneOutcome::Other(format!("{e:?}")),
        };
        let stop = outcome.value().is_none();
        outcomes.push(outcome);
        if stop {
            break;
        }
    }
    let fuel = instance.fuel_consumed();
    Some((outcomes, instance.into_host(), fuel))
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(plan) = Plan::new(&mut u) else { return };
    let Some(fx) = fixture(&plan) else { return };

    // An infeasible reservation refuses materialization identically on
    // both lanes; nothing to compare.
    let (Some((blessed, blessed_host, blessed_fuel)), Some((reference, ref_host, ref_fuel))) =
        (run_blessed(&fx, &plan), run_ref(&fx, &plan))
    else {
        return;
    };

    assert_eq!(blessed, reference, "outcomes diverged for {:?}", plan.calls);
    assert_eq!(
        blessed_host.0.store().access_log(),
        ref_host.0.store().access_log(),
        "access logs diverged for {:?}",
        plan.calls
    );
    assert_eq!(blessed_fuel, ref_fuel, "fuel diverged for {:?}", plan.calls);

    // The oracle: every recorded access inside the declared set, whatever
    // the sequence did.
    let value = blessed.last().and_then(LaneOutcome::value);
    let outcome = Outcome::Completed { value };
    let (blessed_receipt, _) = blessed_host
        .0
        .finish(outcome.clone(), blessed_fuel)
        .expect("oracle clean on the blessed side");
    let (ref_receipt, _) = ref_host
        .0
        .finish(outcome, ref_fuel)
        .expect("oracle clean on the reference side");
    assert_eq!(blessed_receipt, ref_receipt, "receipts diverged");
});

//! The trace-subset oracle, fuzzed.
//!
//! Arbitrary cell contents, reservation amounts, range bounds, book
//! entries, and call sequences drive the kernel-world guest through one
//! session per runtime. The seeded lanes fix these axes and call one
//! export per session; this lane composes them. Both lanes must agree on
//! every outcome, the access log, and the fuel, and `finish` must find
//! every recorded access inside the declared set — the oracle — whatever
//! the sequence did, including the adversarial exports (forged sites,
//! mode escapes, a register collected twice).

#![no_main]

use std::sync::{Arc, LazyLock};

use arbitrary::Unstructured;
use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, GuestArg, Invoked, KernelSession, MemoryStore, OverlayStore,
};
use hyperscale_vm_ref::{RefModule, RefModuleInstance};
use hyperscale_vm_runtime::{Invoking, add_kernel_imports, blessed_engine, invoke_export};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Answer, CollectionId, Effect, EffectSet, EffectTarget,
    Mode, Moves, ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use libfuzzer_sys::fuzz_target;
use wasmtime::{Engine, Linker, Module, Store};

const FUEL: u64 = 1_000_000_000;
const ASKS: CollectionId = CollectionId([4; 16]);
/// What the two cells the transfer moves between hold.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

const EXPORTS: &[&str] = &[
    "transfer",
    "peek",
    "rmw",
    "scan-sum",
    "fill",
    "place",
    "no-such-entry",
    "escape",
    "forge",
    "hash-tag",
    "read-value",
    "handle-value",
    "retake",
];

struct Runtime {
    engine: Engine,
    module: Module,
    linker: Linker<Invoking<KernelSession>>,
    reference: RefModule,
}

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    let bytes = wat::parse_str(KERNEL_GUEST_WAT).expect("fixture WAT parses");
    let engine = blessed_engine().expect("blessed engine");
    let module = Module::new(&engine, &bytes).expect("fixture compiles");
    let mut linker = Linker::<Invoking<KernelSession>>::new(&engine);
    add_kernel_imports(&mut linker).expect("kernel imports link");
    let reference = RefModule::decode(&bytes).expect("the spec decodes the fixture");
    Runtime {
        engine,
        module,
        linker,
        reference,
    }
});

struct Plan {
    committed: u128,
    reserve: u128,
    config_bytes: Vec<u8>,
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
        let config_bytes = small_bytes(u, 1, 4)?;
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
            config_bytes,
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

fn owner(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

/// Builds the store and the declared set; `None` when the plan produced a
/// shape the effect model refuses (that refusal is not what this lane
/// tests).
fn fixture(plan: &Plan) -> Option<Fx> {
    let sender = child_key(&TestHasher, owner(0x10), SlotId(1), &[]);
    let recipient = child_key(&TestHasher, owner(0x20), SlotId(1), &[]);
    let config = child_key(&TestHasher, owner(0x30), SlotId(3), &[]);
    let rmw = child_key(&TestHasher, owner(0x30), SlotId(5), &[]);
    let readable = child_key(&TestHasher, owner(0x30), SlotId(6), &[]);
    let spare = child_key(&TestHasher, owner(0x50), SlotId(7), &[]);
    let book = owner(0x40);

    let mut store = MemoryStore::new();
    if plan.committed > 0 {
        store.write(sender, encode_amount(plan.committed).to_vec());
    }
    store.write(config, plan.config_bytes.clone());
    store.write(rmw, plan.rmw_bytes.clone());
    store.write(readable, plan.readable_bytes.clone());
    store.write(spare, vec![1]);
    for (order, value) in &plan.entries {
        store.entry_write(book, ASKS, *order, value.clone());
    }

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
            mode: Mode::Delta { moves: Moves::Both },
        },
        // The configuration leaf is ordinary state, read like any other:
        // its immutability is the one-way door its declaration carries,
        // not a mode of its own.
        Effect {
            target: EffectTarget::Point(config),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(rmw),
            mode: Mode::Write { moves: Moves::Both },
        },
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Range {
                owner: book,
                collection: ASKS,
                lo: plan.lo,
                hi: plan.hi,
                cap: plan.cap,
            },
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Range {
                owner: book,
                collection: ASKS,
                lo: plan.lo,
                hi: plan.hi,
                cap: plan.cap,
            },
            mode: Mode::Write { moves: Moves::Both },
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

/// What each declared cell holds, aligned with the order the capability
/// table is built in.
///
/// The two the transfer moves between, and nothing else: the
/// read-modify-write cell and the ask ladder are written as bytes and as
/// entries, which is what a cell denominating nothing is for.
fn denominations(fx: &Fx) -> Vec<Option<ResourceAddr>> {
    fx.declared
        .iter()
        .map(|effect| match effect.target {
            EffectTarget::Point(key) if key == fx.sender || key == fx.recipient => Some(RESOURCE),
            _ => None,
        })
        .collect()
}

/// A session over the fixture, or `None` where the declaration is
/// infeasible — an over-reservation refuses materialization identically
/// on both lanes, and that refusal is not what this lane tests.
fn session(fx: &Fx) -> Option<KernelSession> {
    let declaration = Declaration {
        set: fx.declared.clone(),
        ordered: fx
            .declared
            .iter()
            .zip(denominations(fx))
            .map(|(effect, holds)| DeclaredAccess {
                effect,
                holds,
                // This lane fuzzes the blessed-vs-reference differential
                // over the declared set. `reach` and `clause` — the
                // conditional-proving axes — are pinned off deliberately:
                // a meaningful value depends on the effect it sits beside
                // (a reach names a denominated value behaviour), so an
                // arbitrary one would refuse at materialization far more
                // often than it would exercise the machinery. The kernel
                // never reads them; their coverage is the admission-tier
                // reach tests in `crates/effects/tests/admission.rs`.
                reach: None,
                clause: None,
            })
            .collect(),
        ..Declaration::default()
    };
    KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &declaration,
        TxHash(Hash32([0x33; 32])),
        EnvInputs::unsealed(424_242),
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

/// The sites each export receives, in parameter order.
///
/// What a fixture picks is a position in the session's capability
/// table: the key it named, or the one interval it declared. A session
/// seats one site per capability in table order, so that position is
/// the site's too.
fn args_for(fx: &Fx, caps: &[Capability], export: &str) -> Vec<u32> {
    let point = |wanted: SubstateKey| {
        rep_where(caps, |c| match c {
            Capability::Read(key)
            | Capability::Write(key)
            | Capability::Delta { key, .. }
            | Capability::Reserve { key, .. } => *key == wanted,
            _ => false,
        })
    };
    // An interval has no key to pick it out by, so which of the two the
    // fixture declared is the selector: the capability's own mode.
    let read_range = || rep_where(caps, |c| matches!(c, Capability::RangeRead(..)));
    let write_range = || rep_where(caps, |c| matches!(c, Capability::RangeWrite(..)));
    match export {
        "transfer" => vec![point(fx.sender), point(fx.recipient)],
        "peek" => vec![point(fx.config)],
        "rmw" => vec![point(fx.rmw)],
        "scan-sum" => vec![read_range()],
        "fill" | "place" | "no-such-entry" => vec![write_range()],
        "escape" => vec![point(fx.recipient)],
        "handle-value" | "read-value" | "retake" => vec![point(fx.readable)],
        "forge" | "hash-tag" => vec![],
        other => unreachable!("unknown export {other}"),
    }
}

/// The sites, as the boundary takes them.
fn guest_args(fx: &Fx, caps: &[Capability], export: &str) -> Vec<GuestArg<'static>> {
    args_for(fx, caps, export)
        .into_iter()
        .map(|site| GuestArg::Site { site })
        .collect()
}

/// One comparable outcome across both runtimes.
///
/// A fixture export answers a `u64` as eight little-endian bytes; every
/// abort carries the class the kernel or the engine assigned it, which
/// is the one comparison here that has to be exact.
#[derive(Debug, PartialEq, Eq)]
enum LaneOutcome {
    Value(u64),
    Aborted(AbortReason),
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

impl From<Invoked> for LaneOutcome {
    fn from(ended: Invoked) -> Self {
        match ended {
            Invoked::Produced {
                answer: Some(answer),
                ..
            } => match <[u8; 8]>::try_from(answer.as_slice()) {
                Ok(bytes) => Self::Value(u64::from_le_bytes(bytes)),
                Err(_) => Self::Other(format!("unexpected answer {answer:?}")),
            },
            Invoked::Aborted(reason) => Self::Aborted(reason),
            other => Self::Other(format!("{other:?}")),
        }
    }
}

/// Runs the plan's call sequence on one instance, stopping at the first
/// non-value outcome (an aborted store cannot be re-entered).
fn run_blessed(fx: &Fx, plan: &Plan) -> Option<(Vec<LaneOutcome>, KernelSession, u64)> {
    let rt = &*RUNTIME;
    let host = session(fx)?;
    let caps = host.capabilities().to_vec();
    let mut store = Store::new(&rt.engine, Invoking::new(host));
    store.set_fuel(FUEL).expect("fuel is configured");
    let instance = rt
        .linker
        .instantiate(&mut store, &rt.module)
        .expect("fixture instantiates");

    let mut outcomes = Vec::new();
    for export in &plan.calls {
        let args = guest_args(fx, &caps, export);
        let outcome =
            LaneOutcome::from(invoke_export(&mut store, &instance, export, &args, FUEL).result);
        let stop = outcome.value().is_none();
        outcomes.push(outcome);
        if stop {
            break;
        }
    }
    let fuel = FUEL - store.get_fuel().expect("fuel is configured");
    Some((outcomes, store.into_data().into_host(), fuel))
}

fn run_ref(fx: &Fx, plan: &Plan) -> Option<(Vec<LaneOutcome>, KernelSession, u64)> {
    let rt = &*RUNTIME;
    let host = session(fx)?;
    let caps = host.capabilities().to_vec();
    let mut instance = RefModuleInstance::instantiate(&rt.reference, host, FUEL)
        .unwrap_or_else(|(_, error)| panic!("fixture instantiates: {error}"));

    let mut outcomes = Vec::new();
    for export in &plan.calls {
        let args = guest_args(fx, &caps, export);
        let outcome = LaneOutcome::from(instance.invoke(export, &args).result);
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
        blessed_host.store().access_log(),
        ref_host.store().access_log(),
        "access logs diverged for {:?}",
        plan.calls
    );
    assert_eq!(blessed_fuel, ref_fuel, "fuel diverged for {:?}", plan.calls);

    // The oracle: every recorded access inside the declared set, whatever
    // the sequence did.
    let answers: Vec<Answer> = blessed
        .last()
        .and_then(LaneOutcome::value)
        .map(|value| {
            vec![Answer {
                node: 0,
                value: value.to_le_bytes().to_vec(),
            }]
        })
        .unwrap_or_default();
    let (blessed_receipt, _) = blessed_host
        .finish(answers.clone(), blessed_fuel)
        .expect("oracle clean on the blessed side");
    let (ref_receipt, _) = ref_host
        .finish(answers, ref_fuel)
        .expect("oracle clean on the reference side");
    assert_eq!(blessed_receipt, ref_receipt, "receipts diverged");
});

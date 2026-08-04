//! Differential lane 2, components: the world-v1 guest runs under the
//! blessed engine and the reference interpreter with the *same kernel
//! session* as host on each side; outcomes, access logs, fuel, and
//! receipts must agree byte-identically, and the trace-subset oracle runs
//! after every successful execution.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Movement, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, encode_amount,
};
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, RefComponent, RefComponentInstance, ResourceKind,
};
use hyperscale_vm_runtime::{
    DeltaCell, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
    add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, Instance, Linker, Resource};
use wasmtime::error::{Context, format_err};
use wasmtime::{Error, Result, Store};
use wat::parse_str;

const CLOCK_MS: u64 = 424_242;
const FUEL: u64 = 1_000_000_000;
const ASKS: RoleId = RoleId(4);

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn tx() -> TxHash {
    TxHash(Hash32([0x33; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: CLOCK_MS,
        randomness: [11; 32],
    }
}

struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    sender: SubstateKey,
    recipient: SubstateKey,
    config: SubstateKey,
    rmw: SubstateKey,
    readable: SubstateKey,
    book: Address,
}

fn fixture() -> Fixture {
    let sender = child_key(&TestHasher, Address([0x10; 16]), RoleId(1), &[]);
    let recipient = child_key(&TestHasher, Address([0x20; 16]), RoleId(1), &[]);
    let config = child_key(&TestHasher, Address([0x30; 16]), RoleId(3), &[]);
    let rmw = child_key(&TestHasher, Address([0x30; 16]), RoleId(5), &[]);
    let readable = child_key(&TestHasher, Address([0x30; 16]), RoleId(6), &[]);
    let book = Address([0x40; 16]);

    let mut store = MemoryStore::new();
    store.write(sender, encode_amount(100).to_vec()).unwrap();
    store.write(config, vec![7, 7]).unwrap();
    store.lock(config).unwrap();
    store.write(rmw, vec![1, 2, 3]).unwrap();
    store.write(readable, vec![5]).unwrap();
    for (order, value) in [(10u128, vec![3u8]), (20, vec![4]), (30, vec![5])] {
        store.entry_write(book, ASKS, order, value).unwrap();
    }
    store.clear_log();

    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Point(sender),
            mode: Mode::Reserve { amount: 75 },
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
                owner: book,
                collection: ASKS,
                lo: 0,
                hi: 100,
                cap: 8,
            },
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Range {
                owner: book,
                collection: ASKS,
                lo: 0,
                hi: 100,
                cap: 8,
            },
            mode: Mode::Write,
        },
    ] {
        declared.insert(effect).unwrap();
    }

    Fixture {
        declared,
        store,
        sender,
        recipient,
        config,
        rmw,
        readable,
        book,
    }
}

fn session(fx: &Fixture) -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &fx.declared,
        &fx.declared.iter().collect::<Vec<_>>(),
        tx(),
        env(),
        test_hash,
    )
    .expect("fixture materializes")
}

fn rep_where(caps: &[Capability], pred: impl Fn(&Capability) -> bool) -> u32 {
    u32::try_from(caps.iter().position(pred).expect("capability present")).expect("bounded")
}

/// The handles each export receives, in parameter order.
fn args_for(fx: &Fixture, caps: &[Capability], export: &str) -> Vec<(u32, ResourceKind)> {
    let point = |wanted: SubstateKey, kind: ResourceKind| {
        let rep = rep_where(caps, |c| match (kind, c) {
            (ResourceKind::ReadCell, Capability::Read(key))
            | (ResourceKind::LockedCell, Capability::Locked(key))
            | (ResourceKind::WriteCell, Capability::Write(key))
            | (ResourceKind::DeltaCell, Capability::Delta(key))
            | (ResourceKind::ReserveCell, Capability::Reserve(key)) => *key == wanted,
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
) -> Result<u64, Error> {
    let f = instance.get_typed_func::<(Resource<T>,), (u64,)>(&mut *store, export)?;
    f.call(&mut *store, (Resource::new_borrow(rep),))
        .map(|(v,)| v)
}

fn run_blessed(fx: &Fixture, export: &str) -> Result<(LaneOutcome, SessionHost, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let host = SessionHost(session(fx));
    let args = args_for(fx, host.0.capabilities(), export);
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let result: Result<u64, Error> = match (export, args.as_slice()) {
        ("transfer", [(a, _), (b, _)]) => {
            let f = instance
                .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>), (u64,)>(
                    &mut store, export,
                )?;
            f.call(
                &mut store,
                (Resource::new_borrow(*a), Resource::new_borrow(*b)),
            )
            .map(|(v,)| v)
        }
        ("forge" | "forge-zero", []) => {
            let f = instance.get_typed_func::<(), (u64,)>(&mut store, export)?;
            f.call(&mut store, ()).map(|(v,)| v)
        }
        (_, [(rep, kind)]) => match kind {
            ResourceKind::ReadCell => call1::<ReadCell>(&mut store, &instance, export, *rep),
            ResourceKind::LockedCell => call1::<LockedCell>(&mut store, &instance, export, *rep),
            ResourceKind::WriteCell => call1::<WriteCell>(&mut store, &instance, export, *rep),
            ResourceKind::DeltaCell => call1::<DeltaCell>(&mut store, &instance, export, *rep),
            ResourceKind::ReserveCell => call1::<ReserveCell>(&mut store, &instance, export, *rep),
            ResourceKind::RangeRead => call1::<RangeRead>(&mut store, &instance, export, *rep),
            ResourceKind::RangeWrite => call1::<RangeWrite>(&mut store, &instance, export, *rep),
        },
        _ => return Err(format_err!("unexpected arg shape for {export}")),
    };

    let outcome = match result {
        Ok(v) => LaneOutcome::Value(v),
        Err(e) => classify_blessed(&format!("{e:#}")),
    };
    let fuel = FUEL - store.get_fuel()?;
    Ok((outcome, store.into_data(), fuel))
}

fn run_ref(fx: &Fixture, export: &str) -> Result<(LaneOutcome, SessionHost, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let host = SessionHost(session(fx));
    let args: Vec<CVal> = args_for(fx, host.0.capabilities(), export)
        .into_iter()
        .map(|(rep, kind)| CVal::Borrow(rep, kind))
        .collect();
    let mut instance = RefComponentInstance::instantiate(&comp, host)?;
    let outcome = match instance.invoke(export, &args)? {
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
    let fuel = instance.fuel_consumed();
    Ok((outcome, instance.into_host(), fuel))
}

/// Runs one export on both lanes, comparing outcome, access log, and fuel;
/// returns the blessed side for further assertions.
fn both(fx: &Fixture, export: &str) -> Result<(LaneOutcome, SessionHost, u64)> {
    let (blessed, blessed_host, blessed_fuel) =
        run_blessed(fx, export).with_context(|| format!("blessed {export}"))?;
    let (reference, ref_host, ref_fuel) =
        run_ref(fx, export).with_context(|| format!("ref {export}"))?;
    assert_eq!(blessed, reference, "{export} outcome diverged");
    assert_eq!(
        blessed_host.0.store().access_log(),
        ref_host.0.store().access_log(),
        "{export} access log diverged"
    );
    assert_eq!(blessed_fuel, ref_fuel, "{export} fuel diverged");
    Ok((blessed, blessed_host, blessed_fuel))
}

/// Finishes both sides' sessions and asserts byte-identical receipts (and
/// a clean oracle); returns the receipt.
fn receipts_agree(fx: &Fixture, export: &str) -> Result<Receipt> {
    let (blessed, blessed_host, blessed_fuel) =
        run_blessed(fx, export).with_context(|| format!("blessed {export}"))?;
    let (reference, ref_host, ref_fuel) =
        run_ref(fx, export).with_context(|| format!("ref {export}"))?;
    assert_eq!(blessed, reference);
    let LaneOutcome::Value(value) = blessed else {
        panic!("{export} did not complete: {blessed:?}");
    };
    let outcome = Outcome::Completed { value: Some(value) };
    let (blessed_receipt, _) = blessed_host
        .0
        .finish(outcome.clone(), blessed_fuel)
        .expect("oracle clean on the blessed side");
    let (ref_receipt, _) = ref_host
        .0
        .finish(outcome, ref_fuel)
        .expect("oracle clean on the reference side");
    assert_eq!(blessed_receipt, ref_receipt, "{export} receipts diverged");
    Ok(blessed_receipt)
}

#[test]
fn transfer_agrees_and_the_receipt_settles_the_reservation() -> Result<()> {
    let fx = fixture();
    let (outcome, ..) = both(&fx, "transfer")?;
    assert_eq!(outcome, LaneOutcome::Value(75));

    let receipt = receipts_agree(&fx, "transfer")?;
    // Commutative changes report as movements: the settlement debits the
    // sender, the delta credits the recipient, and no absolute cell value
    // appears — that is what keeps receipts schedule-invariant.
    assert_eq!(receipt.delta.settles.get(&fx.sender), Some(&75));
    assert_eq!(
        receipt.delta.movements.get(&fx.recipient),
        Some(&Movement {
            credit: 75,
            debit: 0,
        })
    );
    assert!(receipt.delta.cells.is_empty());
    assert!(receipt.delta.entries.is_empty());
    Ok(())
}

#[test]
fn reads_and_writes_agree_across_the_new_surface() -> Result<()> {
    let fx = fixture();

    let (peek, ..) = both(&fx, "peek")?;
    assert_eq!(peek, LaneOutcome::Value(2 + CLOCK_MS));

    let (rmw, ..) = both(&fx, "rmw")?;
    assert_eq!(rmw, LaneOutcome::Value(3));
    let receipt = receipts_agree(&fx, "rmw")?;
    assert_eq!(receipt.delta.cells.get(&fx.rmw), Some(&Some(vec![2, 2, 3])));

    let (scan, ..) = both(&fx, "scan-sum")?;
    // Entry first bytes 3+4+5 plus order first bytes 10+20+30.
    assert_eq!(scan, LaneOutcome::Value(72));

    let (fill, ..) = both(&fx, "fill")?;
    assert_eq!(fill, LaneOutcome::Value(3));
    let receipt = receipts_agree(&fx, "fill")?;
    assert_eq!(
        receipt.delta.entries.get(&(fx.book, ASKS, 10)),
        Some(&Some(vec![9, 9]))
    );
    assert_eq!(receipt.delta.entries.get(&(fx.book, ASKS, 30)), Some(&None));

    let (place, ..) = both(&fx, "place")?;
    assert_eq!(place, LaneOutcome::Value(4));
    let receipt = receipts_agree(&fx, "place")?;
    assert_eq!(
        receipt.delta.entries.get(&(fx.book, ASKS, 42)),
        Some(&Some(vec![7]))
    );
    Ok(())
}

#[test]
fn undeclared_key_and_mode_trap_identically_with_untouched_state() -> Result<()> {
    let fx = fixture();
    // Materialization records the reservation judgment, so a fresh
    // session's log is the pre-execution baseline: a trapped guest must
    // add nothing to it.
    let baseline = session(&fx).store().access_log().to_vec();

    // A handle index the host never lowered.
    let (forge, forge_host, _) = both(&fx, "forge")?;
    assert_eq!(forge, LaneOutcome::UnknownHandle);
    assert_eq!(forge_host.0.store().access_log(), baseline);

    // A delta handle passed where a read-cell borrow is expected: the
    // undeclared *mode* has no handle type to receive, and the canonical
    // ABI rejects it before any host code runs.
    let (escape, escape_host, _) = both(&fx, "escape")?;
    assert_eq!(escape, LaneOutcome::WrongHandleType);
    assert_eq!(escape_host.0.store().access_log(), baseline);
    Ok(())
}

#[test]
fn handle_values_agree_and_index_zero_is_never_allocatable() -> Result<()> {
    let fx = fixture();

    // The borrow's core value reaches the guest, so it can be returned,
    // compared, or arithmetic'd on. The component model reserves index 0,
    // so the first lowered handle is 1 on both runtimes.
    let (value, _, _) = both(&fx, "handle-value")?;
    assert_eq!(value, LaneOutcome::Value(1));

    // And the reserved slot resolves to nothing, rather than aliasing the
    // first live handle.
    let (zero, _, _) = both(&fx, "forge-zero")?;
    assert_eq!(zero, LaneOutcome::UnknownHandle);
    Ok(())
}

#[test]
fn kernel_refusals_carry_identical_messages() -> Result<()> {
    let fx = fixture();
    let (outcome, ..) = both(&fx, "bad-amount")?;
    assert_eq!(
        outcome,
        LaneOutcome::Refusal("amount cell must be 16 bytes, found 3".to_string())
    );
    Ok(())
}

#[test]
fn leaked_borrows_agree() -> Result<()> {
    let fx = fixture();
    let (outcome, ..) = both(&fx, "leak")?;
    assert_eq!(outcome, LaneOutcome::BorrowsRemain);
    Ok(())
}

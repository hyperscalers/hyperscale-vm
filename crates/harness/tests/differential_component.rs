//! Differential lane 2, components: the world-v1 guest runs under the
//! blessed engine and the reference interpreter with the *same kernel
//! session* as host on each side; outcomes, access logs, fuel, and
//! receipts must agree byte-identically, and the trace-subset oracle runs
//! after every successful execution.

use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_harness::driver::test_hash;
use hyperscale_vm_harness::dual::materialize;
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore, Receipt};
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, HandleKind, RefComponent, RefComponentInstance,
};
use hyperscale_vm_runtime::{
    DeltaCell, HostRefusal, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
    add_kernel_to_linker, blessed_engine, validate_component,
};
use hyperscale_vm_types::{
    ABSENT_REP, AbortReason, Address, AddressClass, Answer, CollectionId, Effect, EffectSet,
    EffectTarget, EntryKey, Mode, Movement, ResourceAddr, SubstateKey, TxHash, encode_amount,
};

/// The one answer a fixture guest hands back, so a receipt depends on
/// what the body computed.
fn answered(value: u64) -> Vec<Answer> {
    vec![Answer {
        node: 0,
        value: value.to_le_bytes().to_vec(),
    }]
}
use wasmtime::component::{Component, Instance, Linker, Resource};
use wasmtime::error::{Context, format_err};
use wasmtime::{Error, Result, Store};
use wat::parse_str;

const CLOCK_MS: u64 = 424_242;
const FUEL: u64 = 1_000_000_000;
const ASKS: CollectionId = CollectionId([4; 16]);
/// What the two cells the transfer moves between hold.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

const fn tx() -> TxHash {
    TxHash(Hash32([0x33; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(CLOCK_MS, [11; 32])
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
    let sender = child_key(
        &TestHasher,
        Address::new([0x10; 31], AddressClass::Component),
        SlotId(1),
        &[],
    );
    let recipient = child_key(
        &TestHasher,
        Address::new([0x20; 31], AddressClass::Component),
        SlotId(1),
        &[],
    );
    let config = child_key(
        &TestHasher,
        Address::new([0x30; 31], AddressClass::Component),
        SlotId(3),
        &[],
    );
    let rmw = child_key(
        &TestHasher,
        Address::new([0x30; 31], AddressClass::Component),
        SlotId(5),
        &[],
    );
    let readable = child_key(
        &TestHasher,
        Address::new([0x30; 31], AddressClass::Component),
        SlotId(6),
        &[],
    );
    let book = Address::new([0x40; 31], AddressClass::Component);

    let mut store = MemoryStore::new();
    store.write(sender, encode_amount(100).to_vec());
    store.write(config, vec![7, 7]);
    store.write(rmw, vec![1, 2, 3]);
    store.write(readable, vec![5]);
    for (order, value) in [(10u128, vec![3u8]), (20, vec![4]), (30, vec![5])] {
        store.entry_write(book, ASKS, order, value);
    }

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
            mode: Mode::Read,
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

/// What each declared cell holds, aligned with the order the capability
/// table is built in.
///
/// The two the transfer moves between, and nothing else: the
/// read-modify-write cell and the ask ladder are written as bytes and as
/// entries, which is what a cell denominating nothing is for.
fn denominations(fx: &Fixture) -> Vec<Option<ResourceAddr>> {
    fx.declared
        .iter()
        .map(|effect| match effect.target {
            EffectTarget::Point(key) if key == fx.sender || key == fx.recipient => Some(RESOURCE),
            _ => None,
        })
        .collect()
}

fn session(fx: &Fixture) -> KernelSession {
    materialize(&fx.store, &fx.declared, &denominations(fx), tx(), env())
}

fn rep_at(caps: &[Capability], pred: impl Fn(&Capability) -> bool) -> u32 {
    u32::try_from(caps.iter().position(pred).expect("capability present")).expect("bounded")
}

/// The handles each export receives, in parameter order.
fn args_for(fx: &Fixture, caps: &[Capability], export: &str) -> Vec<(u32, HandleKind)> {
    let point = |wanted: SubstateKey, kind: HandleKind| {
        let rep = rep_at(caps, |c| match (kind, c) {
            (HandleKind::ReadCell, Capability::Read(key))
            | (HandleKind::WriteCell, Capability::Write(key))
            | (HandleKind::DeltaCell, Capability::Delta(key))
            | (HandleKind::ReserveCell, Capability::Reserve { key, .. }) => *key == wanted,
            _ => false,
        });
        (rep, kind)
    };
    let range = |kind: HandleKind| {
        let rep = rep_at(caps, |c| {
            matches!(
                (kind, c),
                (HandleKind::RangeRead, Capability::RangeRead(..))
                    | (HandleKind::RangeWrite, Capability::RangeWrite(..))
            )
        });
        (rep, kind)
    };
    match export {
        "transfer" => vec![
            point(fx.sender, HandleKind::ReserveCell),
            point(fx.recipient, HandleKind::DeltaCell),
        ],
        "peek" => vec![point(fx.config, HandleKind::ReadCell)],
        "rmw" => vec![point(fx.rmw, HandleKind::WriteCell)],
        "scan-sum" => vec![range(HandleKind::RangeRead)],
        "fill" | "place" | "no-such-entry" => vec![range(HandleKind::RangeWrite)],
        "escape" => vec![point(fx.recipient, HandleKind::DeltaCell)],
        "leak" | "handle-value" | "read-value" => vec![point(fx.readable, HandleKind::ReadCell)],
        "forge" | "forge-zero" | "hash-tag" => vec![],
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
    Refusal(AbortReason),
    Other(String),
}

/// The blessed engine's failure as a lane outcome.
///
/// A kernel refusal comes back as the class the host assigned it —
/// downcast, not parsed — which is the one comparison here that has to be
/// exact. The canonical-ABI classes below still read from the engine's
/// prose, because wasmtime words them and resolves them to no trap kind;
/// they are lane bookkeeping and reach no receipt.
fn classify_blessed(error: &Error) -> LaneOutcome {
    if let Some(refusal) = error.downcast_ref::<HostRefusal>() {
        return LaneOutcome::Refusal(refusal.0);
    }
    let msg = format!("{error:#}");
    if msg.contains("unknown handle index") {
        LaneOutcome::UnknownHandle
    } else if msg.contains("borrow handles") {
        LaneOutcome::BorrowsRemain
    } else if msg.contains("resource") && msg.contains("type") {
        LaneOutcome::WrongHandleType
    } else {
        LaneOutcome::Other(msg)
    }
}

fn call1<T: 'static>(
    store: &mut Store<KernelSession>,
    instance: &Instance,
    export: &str,
    rep: u32,
) -> Result<u64, Error> {
    let f = instance.get_typed_func::<(Resource<T>,), (u64,)>(&mut *store, export)?;
    f.call(&mut *store, (Resource::new_borrow(rep),))
        .map(|(v,)| v)
}

fn run_blessed(
    fx: &Fixture,
    export: &str,
    over: Option<&[(u32, HandleKind)]>,
) -> Result<(LaneOutcome, KernelSession, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<KernelSession>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let host = session(fx);
    let args = over.map_or_else(|| args_for(fx, host.capabilities(), export), <[_]>::to_vec);
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
        ("forge" | "forge-zero" | "hash-tag", []) => {
            let f = instance.get_typed_func::<(), (u64,)>(&mut store, export)?;
            f.call(&mut store, ()).map(|(v,)| v)
        }
        (_, [(rep, kind)]) => match kind {
            HandleKind::ReadCell => call1::<ReadCell>(&mut store, &instance, export, *rep),
            HandleKind::WriteCell => call1::<WriteCell>(&mut store, &instance, export, *rep),
            HandleKind::DeltaCell => call1::<DeltaCell>(&mut store, &instance, export, *rep),
            HandleKind::ReserveCell => call1::<ReserveCell>(&mut store, &instance, export, *rep),
            HandleKind::RangeRead => call1::<RangeRead>(&mut store, &instance, export, *rep),
            HandleKind::RangeWrite => call1::<RangeWrite>(&mut store, &instance, export, *rep),
            // Nothing this fixture exports takes value, issues any, or
            // runs a `for-each` site; the bucket lane drives the first
            // two, and the corpus drives the third.
            HandleKind::Bucket
            | HandleKind::Issuer
            | HandleKind::AmountCell
            | HandleKind::AmountRead
            | HandleKind::InstanceRange
            | HandleKind::ReadCellRun
            | HandleKind::WriteCellRun
            | HandleKind::AmountCellRun
            | HandleKind::AmountReadRun
            | HandleKind::DeltaCellRun
            | HandleKind::ReserveCellRun
            | HandleKind::RangeReadRun
            | HandleKind::RangeWriteRun
            | HandleKind::InstanceRangeRun => {
                return Err(format_err!("{export} takes no value handle"));
            }
        },
        _ => return Err(format_err!("unexpected arg shape for {export}")),
    };

    let outcome = match result {
        Ok(v) => LaneOutcome::Value(v),
        Err(e) => classify_blessed(&e),
    };
    let fuel = FUEL - store.get_fuel()?;
    Ok((outcome, store.into_data(), fuel))
}

fn run_ref(
    fx: &Fixture,
    export: &str,
    over: Option<&[(u32, HandleKind)]>,
) -> Result<(LaneOutcome, KernelSession, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let host = session(fx);
    let args: Vec<CVal> = over
        .map_or_else(|| args_for(fx, host.capabilities(), export), <[_]>::to_vec)
        .into_iter()
        .map(|(rep, kind)| CVal::Borrow(rep, kind))
        .collect();
    let mut instance =
        RefComponentInstance::instantiate(&comp, host, u64::MAX).map_err(|(_, error)| error)?;
    let outcome = match instance.invoke(export, &args)? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(v)] => LaneOutcome::Value(*v),
            other => LaneOutcome::Other(format!("unexpected values {other:?}")),
        },
        Err(ExecError::Canon(CanonError::UnknownHandle)) => LaneOutcome::UnknownHandle,
        Err(ExecError::Canon(CanonError::WrongHandleType)) => LaneOutcome::WrongHandleType,
        Err(ExecError::Canon(CanonError::BorrowsRemain)) => LaneOutcome::BorrowsRemain,
        Err(ExecError::Canon(CanonError::Host(reason))) => LaneOutcome::Refusal(reason),
        Err(e) => LaneOutcome::Other(format!("{e:?}")),
    };
    let fuel = instance.fuel_consumed();
    Ok((outcome, instance.into_host(), fuel))
}

/// Runs one export on both lanes, comparing outcome, access log, and fuel;
/// returns the blessed side for further assertions.
fn both(fx: &Fixture, export: &str) -> Result<(LaneOutcome, KernelSession, u64)> {
    both_with(fx, export, None)
}

/// As [`both`], over arguments the caller names rather than the ones the
/// fixture's own capabilities supply — how a test reaches a rep no
/// materialization assigns.
fn both_with(
    fx: &Fixture,
    export: &str,
    over: Option<&[(u32, HandleKind)]>,
) -> Result<(LaneOutcome, KernelSession, u64)> {
    let (blessed, blessed_host, blessed_fuel) =
        run_blessed(fx, export, over).with_context(|| format!("blessed {export}"))?;
    let (reference, ref_host, ref_fuel) =
        run_ref(fx, export, over).with_context(|| format!("ref {export}"))?;
    assert_eq!(blessed, reference, "{export} outcome diverged");
    assert_eq!(
        blessed_host.store().access_log(),
        ref_host.store().access_log(),
        "{export} access log diverged"
    );
    assert_eq!(blessed_fuel, ref_fuel, "{export} fuel diverged");
    Ok((blessed, blessed_host, blessed_fuel))
}

/// Finishes both sides' sessions and asserts byte-identical receipts (and
/// a clean oracle); returns the receipt.
fn receipts_agree(fx: &Fixture, export: &str) -> Result<Receipt> {
    let (blessed, blessed_host, blessed_fuel) =
        run_blessed(fx, export, None).with_context(|| format!("blessed {export}"))?;
    let (reference, ref_host, ref_fuel) =
        run_ref(fx, export, None).with_context(|| format!("ref {export}"))?;
    assert_eq!(blessed, reference);
    let LaneOutcome::Value(value) = blessed else {
        panic!("{export} did not complete: {blessed:?}");
    };
    let (blessed_receipt, _) = blessed_host
        .finish(answered(value), blessed_fuel)
        .expect("oracle clean on the blessed side");
    let (ref_receipt, _) = ref_host
        .finish(answered(value), ref_fuel)
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

/// The host's hash function, reached from inside a guest.
///
/// The one kernel interface a guest cannot check for itself: it has no
/// second implementation to compare against, so what has to agree is that
/// both runtimes call the host's and lift its 32 bytes the same way. The
/// expected digest is computed here, independently of either.
#[test]
fn the_host_hash_agrees_and_lifts_identically() -> Result<()> {
    let fx = fixture();
    let (tag, ..) = both(&fx, "hash-tag")?;
    assert_eq!(
        tag,
        LaneOutcome::Value(u64::from(test_hash(&[0u8; 4])[0])),
        "the digest's first byte, folded by the guest"
    );
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
    let ask = |order: u128| EntryKey {
        owner: fx.book,
        collection: ASKS,
        order,
    };
    assert_eq!(receipt.delta.entries.get(&ask(10)), Some(&Some(vec![9, 9])));
    assert_eq!(receipt.delta.entries.get(&ask(30)), Some(&None));

    let (place, ..) = both(&fx, "place")?;
    assert_eq!(place, LaneOutcome::Value(4));
    let receipt = receipts_agree(&fx, "place")?;
    assert_eq!(receipt.delta.entries.get(&ask(42)), Some(&Some(vec![7])));
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
    assert_eq!(forge_host.store().access_log(), baseline);

    // A delta handle passed where a read-cell borrow is expected: the
    // undeclared *mode* has no handle type to receive, and the canonical
    // ABI rejects it before any host code runs.
    let (escape, escape_host, _) = both(&fx, "escape")?;
    assert_eq!(escape, LaneOutcome::WrongHandleType);
    assert_eq!(escape_host.store().access_log(), baseline);
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

/// A guarded-out clause materializes nothing, and the guest is handed a
/// handle at the reserved rep all the same — an export's parameter list
/// is a function of its signature and cannot lose a parameter to a
/// branch. Reaching it is a body whose control flow disagrees with the
/// verdict it was given, and both lanes say so by name rather than
/// reporting a handle nobody lowered.
#[test]
fn the_reserved_rep_is_an_undeclared_branch_on_both_lanes() -> Result<()> {
    let fx = fixture();
    let (outcome, _, _) = both_with(
        &fx,
        "read-value",
        Some(&[(ABSENT_REP, HandleKind::ReadCell)]),
    )?;
    assert_eq!(outcome, LaneOutcome::Refusal(AbortReason::UndeclaredBranch));
    Ok(())
}

#[test]
fn freed_handle_slots_reuse_most_recent_first_across_invokes() -> Result<()> {
    // Promoted from the session_trace_is_declared fuzz lane. The handle
    // table lives as long as the instance and a guest can observe its
    // indices, so numbering across calls is consensus behaviour: transfer
    // lowers borrows 1 and 2 and the guest drops both, and the next
    // lowered borrow must take the most recently freed slot — 2 — on both
    // runtimes.
    let fx = fixture();
    let bytes = parse_str(KERNEL_GUEST_WAT)?;

    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<KernelSession>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let host = session(&fx);
    let transfer_args = args_for(&fx, host.capabilities(), "transfer");
    let value_args = args_for(&fx, host.capabilities(), "handle-value");
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;
    instance
        .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>), (u64,)>(
            &mut store, "transfer",
        )?
        .call(
            &mut store,
            (
                Resource::new_borrow(transfer_args[0].0),
                Resource::new_borrow(transfer_args[1].0),
            ),
        )?;
    let (blessed_value,) = instance
        .get_typed_func::<(Resource<ReadCell>,), (u64,)>(&mut store, "handle-value")?
        .call(&mut store, (Resource::new_borrow(value_args[0].0),))?;

    let comp = RefComponent::decode(&bytes)?;
    let host = session(&fx);
    let to_cvals = |args: &[(u32, HandleKind)]| -> Vec<CVal> {
        args.iter()
            .map(|(rep, kind)| CVal::Borrow(*rep, *kind))
            .collect()
    };
    let mut instance =
        RefComponentInstance::instantiate(&comp, host, u64::MAX).map_err(|(_, error)| error)?;
    instance
        .invoke("transfer", &to_cvals(&transfer_args))?
        .map_err(|e| format_err!("ref transfer failed: {e:?}"))?;
    let ref_value = match instance
        .invoke("handle-value", &to_cvals(&value_args))?
        .map_err(|e| format_err!("ref handle-value failed: {e:?}"))?
        .as_slice()
    {
        [CVal::U64(v)] => *v,
        other => return Err(format_err!("unexpected values {other:?}")),
    };

    assert_eq!(blessed_value, ref_value, "handle numbering diverged");
    assert_eq!(blessed_value, 2, "the most recently freed slot is reused");
    Ok(())
}

#[test]
fn kernel_refusals_carry_identical_classes() -> Result<()> {
    let fx = fixture();
    let (outcome, ..) = both(&fx, "no-such-entry")?;
    assert_eq!(
        outcome,
        LaneOutcome::Refusal(AbortReason::EntryIndexOutOfBounds)
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

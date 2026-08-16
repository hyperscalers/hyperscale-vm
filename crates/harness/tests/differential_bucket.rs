//! Differential lane 3, owned handles: the bucket guest runs under the
//! blessed engine and the reference interpreter against the *same kernel
//! session*, and the two must agree on what a handle is numbered, on
//! where ownership sits after each call, and on the drop reaching the
//! host.
//!
//! The lane exists because ownership widens what the engines have to
//! agree about. Handle numbering was already differentially tested for
//! borrows; transfer and drop ordering were not, and a divergence in
//! either is a divergence in what value a transaction moved.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::BUCKET_GUEST_WAT;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    AbortReason, Capability, EnvInputs, ISSUER_REP, KernelSession, MemoryStore, Outcome,
    OverlayStore, TxHash, WorkingStore, encode_amount,
};
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, RefComponent, RefComponentInstance, ResourceKind,
};
use hyperscale_vm_runtime::{
    Bucket, DeltaCell, HostRefusal, Issuer, ReadCell, ReserveCell, WriteCell, add_kernel_to_linker,
    blessed_engine, validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::format_err;
use wasmtime::{Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;
/// What the held bucket carries; the guest never learns it, which is the
/// point of the handle.
const HELD: u128 = 40;
/// What the discarded bucket carries.
const SPENT: u128 = 2;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn tx() -> TxHash {
    TxHash(Hash32([0x55; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 909_090,
        randomness: [3; 32],
    }
}

/// What a reserve clause grants, and what the vault behind it holds.
const RESERVED: u128 = 75;
/// What the absolute vault holds before a take.
const BALANCE: u128 = 100;
/// The instance whose invocation the take lane runs inside.
const ISSUER: Address = Address::new([0x80; 31], AddressClass::Component);

struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    readable: SubstateKey,
    vault: SubstateKey,
    ledger: SubstateKey,
    opaque: SubstateKey,
    reserved: SubstateKey,
}

fn fixture() -> Fixture {
    let key = |role: u16| {
        child_key(
            &TestHasher,
            Address::new([0x60; 31], AddressClass::Component),
            RoleId(role),
            &[],
        )
    };
    let (readable, vault, ledger, opaque, reserved) = (key(1), key(2), key(3), key(4), key(5));

    let mut store = MemoryStore::new();
    store.write(readable, vec![5]).unwrap();
    store.write(vault, encode_amount(BALANCE).to_vec()).unwrap();
    store
        .write(ledger, encode_amount(BALANCE).to_vec())
        .unwrap();
    store
        .write(reserved, encode_amount(BALANCE).to_vec())
        .unwrap();
    // A write cell holding something that is not an amount: state a
    // movement can only refuse, which is the narrow reading the class has.
    store.write(opaque, vec![1, 2, 3]).unwrap();
    store.clear_log();

    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write,
        },
        Effect {
            target: EffectTarget::Point(opaque),
            mode: Mode::Write,
        },
        Effect {
            target: EffectTarget::Point(ledger),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(reserved),
            mode: Mode::Reserve { amount: RESERVED },
        },
    ] {
        declared.insert(effect).unwrap();
    }

    Fixture {
        declared,
        store,
        readable,
        vault,
        ledger,
        opaque,
        reserved,
    }
}

fn materialize(fx: &Fixture) -> KernelSession {
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

/// The capability rep for one declared point, by the mode it carries.
fn rep_of(host: &SessionHost, wanted: SubstateKey, mode: Mode) -> u32 {
    let position = host
        .0
        .capabilities()
        .iter()
        .position(|c| match (mode, c) {
            (Mode::Read, Capability::Read(key))
            | (Mode::Write, Capability::Write(key))
            | (Mode::Delta, Capability::Delta(key))
            | (Mode::Reserve { .. }, Capability::Reserve { key, .. }) => *key == wanted,
            _ => false,
        })
        .expect("capability present");
    u32::try_from(position).expect("bounded")
}

/// A session with the fixture's capabilities and two buckets in the
/// kernel's keeping.
///
/// The reps are the table's own order, so both runtimes are handed the
/// same two.
fn session(fx: &Fixture) -> (SessionHost, u32, u32) {
    let mut session = materialize(fx);
    let held = session.open_bucket(HELD);
    let spent = session.open_bucket(SPENT);
    (SessionHost(session), held, spent)
}

/// What one run of the four-call sequence observed.
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    /// The handle `hold` was given for the bucket it keeps.
    held_handle: u64,
    /// The handle `peek` was lent while that own is still seated.
    borrow_handle: u64,
    /// The rep `release` handed back.
    released_rep: u32,
    /// The handle `discard` was given, after two slots have freed.
    discard_handle: u64,
    /// Whether the released bucket was still the kernel's to take.
    released_amount: u128,
    /// Whether the discarded bucket's rep names anything afterwards.
    discarded_survives: bool,
}

/// The sequence under the blessed engine.
fn run_blessed(fx: &Fixture) -> Result<(Trace, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let (host, held, spent) = session(fx);
    let readable = rep_of(&host, fx.readable, Mode::Read);
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let (held_handle,) = instance
        .get_typed_func::<(Resource<Bucket>,), (u64,)>(&mut store, "hold")?
        .call(&mut store, (Resource::new_own(held),))?;
    let (borrow_handle,) = instance
        .get_typed_func::<(Resource<ReadCell>,), (u64,)>(&mut store, "peek")?
        .call(&mut store, (Resource::new_borrow(readable),))?;
    let (released,) = instance
        .get_typed_func::<(), (Resource<Bucket>,)>(&mut store, "release")?
        .call(&mut store, ())?;
    let released_rep = released.rep();
    let (discard_handle,) = instance
        .get_typed_func::<(Resource<Bucket>,), (u64,)>(&mut store, "discard")?
        .call(&mut store, (Resource::new_own(spent),))?;

    let fuel = FUEL - store.get_fuel()?;
    let mut host = store.into_data();
    let trace = Trace {
        held_handle,
        borrow_handle,
        released_rep,
        discard_handle,
        released_amount: host.0.take_bucket(released_rep)?,
        discarded_survives: host.0.bucket(spent).is_ok(),
    };
    Ok((trace, fuel))
}

/// The same sequence under the reference interpreter.
fn run_ref(fx: &Fixture) -> Result<(Trace, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let (host, held, spent) = session(fx);
    let readable = rep_of(&host, fx.readable, Mode::Read);
    let mut instance =
        RefComponentInstance::instantiate(&comp, host).map_err(|(_, error)| error)?;

    let scalar = |export: &str, values: Vec<CVal>| match values.as_slice() {
        [CVal::U64(v)] => Ok(*v),
        other => Err(format_err!("{export} returned {other:?}")),
    };
    let held_handle = scalar("hold", invoke(&mut instance, "hold", &[CVal::Own(held)])?)?;
    let borrow_handle = scalar(
        "peek",
        invoke(
            &mut instance,
            "peek",
            &[CVal::Borrow(readable, ResourceKind::ReadCell)],
        )?,
    )?;
    let released_rep = match invoke(&mut instance, "release", &[])?.as_slice() {
        [CVal::Own(rep)] => *rep,
        other => return Err(format_err!("release returned {other:?}")),
    };
    let discard_handle = scalar(
        "discard",
        invoke(&mut instance, "discard", &[CVal::Own(spent)])?,
    )?;

    let fuel = instance.fuel_consumed();
    let mut host = instance.into_host();
    let trace = Trace {
        held_handle,
        borrow_handle,
        released_rep,
        discard_handle,
        released_amount: host.0.take_bucket(released_rep)?,
        discarded_survives: host.0.bucket(spent).is_ok(),
    };
    Ok((trace, fuel))
}

/// One reference-interpreter call, with a failure carried as an error
/// rather than compared: nothing in this sequence is allowed to fail.
fn invoke(
    instance: &mut RefComponentInstance<'_, SessionHost>,
    export: &str,
    args: &[CVal],
) -> Result<Vec<CVal>> {
    instance
        .invoke(export, args)?
        .map_err(|e| format_err!("ref {export} failed: {e:?}"))
}

/// Which debit to drive, against which of the fixture's cells.
#[derive(Clone, Copy)]
enum Take {
    /// Value created under the invocation's issuance grant.
    Issue(u64),
    /// The same, by an invocation granted none.
    IssueUngranted(u64),
    /// A queued debit of `n` against the delta ledger.
    Delta(u64),
    /// An absolute debit of `n` against the amount vault.
    Vault(u64),
    /// An absolute debit against a cell holding no amount.
    Opaque(u64),
    /// The whole grant.
    Reserve,
    /// The same grant, asked twice.
    ReserveTwice,
}

impl Take {
    const fn export(self) -> &'static str {
        match self {
            Self::Issue(_) | Self::IssueUngranted(_) => "issue",
            Self::Delta(_) => "take-delta",
            Self::Vault(_) | Self::Opaque(_) => "take-write",
            Self::Reserve => "take-reserve",
            Self::ReserveTwice => "take-reserve-twice",
        }
    }

    /// The cell the take debits, and the mode it reaches it through.
    ///
    /// Issuance has none: the grant rides the invocation rather than any
    /// state, which is what makes it the one bucket with nothing behind
    /// it.
    const fn cell(self, fx: &Fixture) -> Option<(SubstateKey, Mode)> {
        match self {
            Self::Issue(_) | Self::IssueUngranted(_) => None,
            Self::Delta(_) => Some((fx.ledger, Mode::Delta)),
            Self::Vault(_) => Some((fx.vault, Mode::Write)),
            Self::Opaque(_) => Some((fx.opaque, Mode::Write)),
            Self::Reserve | Self::ReserveTwice => {
                Some((fx.reserved, Mode::Reserve { amount: RESERVED }))
            }
        }
    }

    /// Whether the invocation driving this take was granted issuance.
    const fn granted(self) -> bool {
        matches!(self, Self::Issue(_))
    }

    /// The amount the export takes, where the mode has the body name one.
    const fn amount(self) -> Option<u64> {
        match self {
            Self::Issue(n)
            | Self::IssueUngranted(n)
            | Self::Delta(n)
            | Self::Vault(n)
            | Self::Opaque(n) => Some(n),
            Self::Reserve | Self::ReserveTwice => None,
        }
    }
}

/// What a take produced.
#[derive(Debug, PartialEq, Eq)]
enum Took {
    /// The value the bucket carried, once the lane took it back out of
    /// the kernel.
    Value(u128),
    /// The host refused, in the class it assigned.
    Refusal(AbortReason),
}

/// One take under the blessed engine.
fn take_blessed(fx: &Fixture, take: Take) -> Result<(Took, SessionHost, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut host = SessionHost(materialize(fx));
    host.0.enter_invocation(ISSUER);
    if take.granted() {
        host.0.grant_issuance();
    }
    let cell = take
        .cell(fx)
        .map(|(key, mode)| (rep_of(&host, key, mode), mode));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let export = take.export();
    let produced = match (cell, take.amount()) {
        (None, amount) => instance
            .get_typed_func::<(Resource<Issuer>, u64), (Resource<Bucket>,)>(&mut store, export)?
            .call(
                &mut store,
                (Resource::new_borrow(ISSUER_REP), amount.unwrap_or(0)),
            ),
        (Some((rep, Mode::Delta)), Some(n)) => instance
            .get_typed_func::<(Resource<DeltaCell>, u64), (Resource<Bucket>,)>(&mut store, export)?
            .call(&mut store, (Resource::new_borrow(rep), n)),
        (Some((rep, Mode::Write)), Some(n)) => instance
            .get_typed_func::<(Resource<WriteCell>, u64), (Resource<Bucket>,)>(&mut store, export)?
            .call(&mut store, (Resource::new_borrow(rep), n)),
        (Some((rep, _)), _) => instance
            .get_typed_func::<(Resource<ReserveCell>,), (Resource<Bucket>,)>(&mut store, export)?
            .call(&mut store, (Resource::new_borrow(rep),)),
    };

    let fuel = FUEL - store.get_fuel()?;
    let mut host = store.into_data();
    let took = match produced {
        Ok((bucket,)) => Took::Value(host.0.take_bucket(bucket.rep())?),
        Err(error) => match error.downcast_ref::<HostRefusal>() {
            Some(refusal) => Took::Refusal(refusal.0),
            None => return Err(error),
        },
    };
    Ok((took, host, fuel))
}

/// The same take under the reference interpreter.
fn take_ref(fx: &Fixture, take: Take) -> Result<(Took, SessionHost, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let mut host = SessionHost(materialize(fx));
    host.0.enter_invocation(ISSUER);
    if take.granted() {
        host.0.grant_issuance();
    }
    let (rep, kind) = match take.cell(fx) {
        None => (ISSUER_REP, ResourceKind::Issuer),
        Some((key, mode)) => (
            rep_of(&host, key, mode),
            match mode {
                Mode::Delta => ResourceKind::DeltaCell,
                Mode::Write => ResourceKind::WriteCell,
                _ => ResourceKind::ReserveCell,
            },
        ),
    };
    let mut args = vec![CVal::Borrow(rep, kind)];
    args.extend(take.amount().map(CVal::U64));
    let mut instance =
        RefComponentInstance::instantiate(&comp, host).map_err(|(_, error)| error)?;

    let produced = instance.invoke(take.export(), &args)?;
    let fuel = instance.fuel_consumed();
    let mut host = instance.into_host();
    let took = match produced {
        Ok(values) => match values.as_slice() {
            [CVal::Own(rep)] => Took::Value(host.0.take_bucket(*rep)?),
            other => return Err(format_err!("{} returned {other:?}", take.export())),
        },
        Err(ExecError::Canon(CanonError::Host(reason))) => Took::Refusal(reason),
        Err(other) => return Err(format_err!("ref {} failed: {other:?}", take.export())),
    };
    Ok((took, host, fuel))
}

/// One take on both engines, comparing what it produced, what it touched
/// and what it cost; returns the blessed side for further assertions.
fn both(fx: &Fixture, take: Take) -> Result<(Took, SessionHost)> {
    let (blessed, blessed_host, blessed_fuel) = take_blessed(fx, take)?;
    let (reference, ref_host, ref_fuel) = take_ref(fx, take)?;
    let export = take.export();
    assert_eq!(blessed, reference, "{export} diverged");
    assert_eq!(
        blessed_host.0.store().access_log(),
        ref_host.0.store().access_log(),
        "{export} access log diverged"
    );
    assert_eq!(blessed_fuel, ref_fuel, "{export} fuel diverged");
    Ok((blessed, blessed_host))
}

#[test]
fn each_take_yields_the_value_it_debits() -> Result<()> {
    let fx = fixture();

    let (delta, host) = both(&fx, Take::Delta(30))?;
    assert_eq!(delta, Took::Value(30));
    let (receipt, _) = host
        .0
        .finish(Outcome::Completed { value: None }, 0)
        .expect("the oracle is clean");
    assert_eq!(
        receipt.delta.movements.get(&fx.ledger).map(|m| m.debit),
        Some(30),
        "the debit the take performed is the movement the receipt carries"
    );

    // An absolute cell resolves at the call, so the balance is already
    // down by what the body is holding.
    let (vault, host) = both(&fx, Take::Vault(30))?;
    assert_eq!(vault, Took::Value(30));
    let (receipt, _) = host
        .0
        .finish(Outcome::Completed { value: None }, 0)
        .expect("the oracle is clean");
    assert_eq!(
        receipt.delta.cells.get(&fx.vault),
        Some(&Some(encode_amount(BALANCE - 30).to_vec()))
    );

    // The grant is the bucket: no amount is named and none can be missed.
    let (reserve, _) = both(&fx, Take::Reserve)?;
    assert_eq!(reserve, Took::Value(RESERVED));
    Ok(())
}

#[test]
fn an_over_take_refuses_in_each_modes_own_terms() -> Result<()> {
    let fx = fixture();

    // Absolute: the read-modify-write resolves at the call, so the
    // refusal is the call's.
    let (vault, _) = both(&fx, Take::Vault(500))?;
    assert_eq!(vault, Took::Refusal(AbortReason::CellUnderflow));

    // Commutative: the debit is queued, so the take succeeds and the
    // movement fold is what refuses — the transaction aborts and no value
    // leaves.
    let (delta, host) = both(&fx, Take::Delta(500))?;
    assert_eq!(delta, Took::Value(500));
    let (receipt, _) = host
        .0
        .finish(Outcome::Completed { value: None }, 0)
        .expect("the oracle is clean");
    assert_eq!(
        receipt.outcome,
        Outcome::Infeasible {
            key: fx.ledger,
            amount: 500,
        }
    );
    Ok(())
}

#[test]
fn a_stored_cell_that_is_not_an_amount_is_the_states_defect() -> Result<()> {
    let fx = fixture();
    let (opaque, _) = both(&fx, Take::Opaque(1))?;
    assert_eq!(opaque, Took::Refusal(AbortReason::MalformedAmountCell));
    Ok(())
}

/// A credit driven on both engines, with the bucket the lane opened for
/// it: what the cell holds afterwards, and whether the handle survived.
#[derive(Debug, PartialEq, Eq)]
struct Credited {
    /// What the credited cell reads as once the receipt settles.
    cell: Option<Vec<u8>>,
    /// The movement the receipt carries, where the mode has one.
    credit: Option<u128>,
    /// Whether the consumed bucket's rep still names anything.
    funds_survive: bool,
    /// The class the host assigned, where the credit was refused.
    refusal: Option<AbortReason>,
}

/// One credit under one engine, both driven from the same closure over
/// the two runtimes' call shapes.
fn put_blessed(fx: &Fixture, export: &str, held: u128, delta: bool) -> Result<(Credited, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut host = SessionHost(materialize(fx));
    let funds = host.0.open_bucket(held);
    let (key, mode) = if delta {
        (fx.ledger, Mode::Delta)
    } else {
        (fx.vault, Mode::Write)
    };
    let rep = rep_of(&host, key, mode);
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let called = if delta {
        instance
            .get_typed_func::<(Resource<DeltaCell>, Resource<Bucket>), (u64,)>(&mut store, export)?
            .call(
                &mut store,
                (Resource::new_borrow(rep), Resource::new_own(funds)),
            )
    } else {
        instance
            .get_typed_func::<(Resource<WriteCell>, Resource<Bucket>), (u64,)>(&mut store, export)?
            .call(
                &mut store,
                (Resource::new_borrow(rep), Resource::new_own(funds)),
            )
    };
    let fuel = FUEL - store.get_fuel()?;
    let host = store.into_data();
    let refusal = match called {
        Ok(_) => None,
        Err(error) => match error.downcast_ref::<HostRefusal>() {
            Some(refusal) => Some(refusal.0),
            None => return Err(error),
        },
    };
    Ok((settled(host, key, funds, refusal), fuel))
}

/// The same credit under the reference interpreter.
fn put_ref(fx: &Fixture, export: &str, held: u128, delta: bool) -> Result<(Credited, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let mut host = SessionHost(materialize(fx));
    let funds = host.0.open_bucket(held);
    let (key, mode, kind) = if delta {
        (fx.ledger, Mode::Delta, ResourceKind::DeltaCell)
    } else {
        (fx.vault, Mode::Write, ResourceKind::WriteCell)
    };
    let args = vec![
        CVal::Borrow(rep_of(&host, key, mode), kind),
        CVal::Own(funds),
    ];
    let mut instance =
        RefComponentInstance::instantiate(&comp, host).map_err(|(_, error)| error)?;
    let called = instance.invoke(export, &args)?;
    let fuel = instance.fuel_consumed();
    let host = instance.into_host();
    let refusal = match called {
        Ok(_) => None,
        Err(ExecError::Canon(CanonError::Host(reason))) => Some(reason),
        Err(other) => return Err(format_err!("ref {export} failed: {other:?}")),
    };
    Ok((settled(host, key, funds, refusal), fuel))
}

/// What the session says about a credit once it settles.
fn settled(
    host: SessionHost,
    key: SubstateKey,
    funds: u32,
    refusal: Option<AbortReason>,
) -> Credited {
    let funds_survive = host.0.bucket(funds).is_ok();
    let (receipt, _) = host
        .0
        .finish(Outcome::Completed { value: None }, 0)
        .expect("the oracle is clean");
    Credited {
        cell: receipt.delta.cells.get(&key).cloned().flatten(),
        credit: receipt.delta.movements.get(&key).map(|m| m.credit),
        funds_survive,
        refusal,
    }
}

/// One credit on both engines, comparing what settled and what it cost.
fn credited(fx: &Fixture, export: &str, held: u128, delta: bool) -> Result<Credited> {
    let (blessed, blessed_fuel) = put_blessed(fx, export, held, delta)?;
    let (reference, ref_fuel) = put_ref(fx, export, held, delta)?;
    assert_eq!(blessed, reference, "{export} diverged");
    assert_eq!(blessed_fuel, ref_fuel, "{export} fuel diverged");
    Ok(blessed)
}

#[test]
fn a_credit_is_what_the_bucket_carried() -> Result<()> {
    let fx = fixture();

    let absolute = credited(&fx, "put-write", 30, false)?;
    assert_eq!(
        absolute.cell,
        Some(encode_amount(BALANCE + 30).to_vec()),
        "the kernel added what crossed to what the cell held"
    );

    let commutative = credited(&fx, "put-delta", 30, true)?;
    assert_eq!(commutative.credit, Some(30));
    Ok(())
}

#[test]
fn a_put_consumes_the_handle_it_was_given() -> Result<()> {
    let fx = fixture();
    // The canonical ABI lifts an owned argument out of the guest's table,
    // so the value is the kernel's again and the rep names nothing.
    let credited = credited(&fx, "put-write", 30, false)?;
    assert!(!credited.funds_survive);

    // And the handle is gone on the guest's side too: dropping it after
    // the put reaches for a slot the table no longer holds, which both
    // engines refuse. The class is the canonical ABI's own and reaches no
    // receipt, so the lane reads each engine's own wording for it.
    let blessed = put_blessed(&fx, "put-write-then-drop", 30, false)
        .expect_err("the blessed engine refuses a consumed handle");
    assert!(format!("{blessed:#}").contains("unknown handle"));
    let reference = put_ref(&fx, "put-write-then-drop", 30, false)
        .expect_err("the interpreter refuses a consumed handle");
    assert!(format!("{reference:#}").contains("UnknownHandle"));
    Ok(())
}

#[test]
fn a_credit_past_the_cells_width_refuses_at_the_call() -> Result<()> {
    let fx = fixture();
    let overflowed = credited(&fx, "put-write", u128::MAX, false)?;
    assert_eq!(overflowed.refusal, Some(AbortReason::CellOverflow));
    // Refused, so nothing moved and the value is still the kernel's to
    // account for.
    assert_eq!(overflowed.cell, None);
    assert!(overflowed.funds_survive);
    Ok(())
}

#[test]
fn issuance_is_the_one_bucket_with_no_cell_behind_it() -> Result<()> {
    let fx = fixture();
    let (issued, _) = both(&fx, Take::Issue(9))?;
    assert_eq!(issued, Took::Value(9));
    Ok(())
}

#[test]
fn an_invocation_granted_nothing_issues_nothing() -> Result<()> {
    let fx = fixture();
    let (refused, _) = both(&fx, Take::IssueUngranted(9))?;
    // The handle is what a declaration grants, so a body that declared no
    // issued output has nothing to name — and reaching for one anyway is
    // the same refusal on both engines.
    assert_eq!(refused, Took::Refusal(AbortReason::IssuanceUngranted));
    Ok(())
}

#[test]
fn a_reservation_answers_once() -> Result<()> {
    let fx = fixture();
    let (twice, _) = both(&fx, Take::ReserveTwice)?;
    // The read this replaces answered every time it was asked, so a body
    // asking twice held two edges against one hold.
    assert_eq!(twice, Took::Refusal(AbortReason::ReservationAlreadyTaken));
    Ok(())
}

#[test]
fn ownership_transfer_and_the_drop_agree_across_the_engines() -> Result<()> {
    let fx = fixture();
    let (blessed, blessed_fuel) = run_blessed(&fx)?;
    let (reference, ref_fuel) = run_ref(&fx)?;
    assert_eq!(blessed, reference, "the bucket sequence diverged");
    assert_eq!(blessed_fuel, ref_fuel, "bucket-sequence fuel diverged");

    // The component model reserves index 0, so the kept bucket takes the
    // first allocatable slot — and keeps it, which is what the borrow
    // lands one past.
    assert_eq!(blessed.held_handle, 1);
    assert_eq!(blessed.borrow_handle, 2);
    // Returning the bucket frees slot 1 after the borrow freed slot 2, so
    // the next lowered handle takes the more recently freed of the two.
    assert_eq!(blessed.discard_handle, 1);
    Ok(())
}

#[test]
fn a_returned_bucket_comes_back_to_the_kernel_whole() -> Result<()> {
    let fx = fixture();
    let (trace, _) = run_blessed(&fx)?;
    // The guest held a handle and gave back the same rep; the amount was
    // never anywhere it could be rewritten.
    assert_eq!(trace.released_amount, HELD);
    Ok(())
}

#[test]
fn a_dropped_bucket_reaches_the_host() -> Result<()> {
    let fx = fixture();
    let (blessed, _) = run_blessed(&fx)?;
    let (reference, _) = run_ref(&fx)?;
    // Nothing but the destructor could have emptied the slot: the lane
    // takes the released bucket by hand and never touches this one.
    assert!(!blessed.discarded_survives);
    assert!(!reference.discarded_survives);
    Ok(())
}

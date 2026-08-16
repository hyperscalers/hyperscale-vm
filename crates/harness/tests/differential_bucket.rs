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
    EnvInputs, KernelSession, MemoryStore, OverlayStore, TxHash, WorkingStore,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    Bucket, ReadCell, add_kernel_to_linker, blessed_engine, validate_component,
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

struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    resource: Address,
}

fn fixture() -> Fixture {
    let readable: SubstateKey = child_key(
        &TestHasher,
        Address::new([0x60; 31], AddressClass::Component),
        RoleId(1),
        &[],
    );
    let mut store = MemoryStore::new();
    store.write(readable, vec![5]).unwrap();
    store.clear_log();

    let mut declared = EffectSet::new();
    declared
        .insert(Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        })
        .unwrap();

    Fixture {
        declared,
        store,
        resource: Address::new([0x70; 31], AddressClass::Resource),
    }
}

/// A session with the read capability materialized and two buckets in the
/// kernel's keeping.
///
/// The reps are the table's own order, so both runtimes are handed the
/// same two.
fn session(fx: &Fixture) -> (SessionHost, u32, u32) {
    let mut session = KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &fx.declared,
        &fx.declared.iter().collect::<Vec<_>>(),
        tx(),
        env(),
        test_hash,
    )
    .expect("fixture materializes");
    let held = session.open_bucket(fx.resource, HELD);
    let spent = session.open_bucket(fx.resource, SPENT);
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
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let (held_handle,) = instance
        .get_typed_func::<(Resource<Bucket>,), (u64,)>(&mut store, "hold")?
        .call(&mut store, (Resource::new_own(held),))?;
    let (borrow_handle,) = instance
        .get_typed_func::<(Resource<ReadCell>,), (u64,)>(&mut store, "peek")?
        .call(&mut store, (Resource::new_borrow(0),))?;
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
        released_amount: host.0.take_bucket(released_rep)?.amount,
        discarded_survives: host.0.bucket(spent).is_ok(),
    };
    Ok((trace, fuel))
}

/// The same sequence under the reference interpreter.
fn run_ref(fx: &Fixture) -> Result<(Trace, u64)> {
    let bytes = parse_str(BUCKET_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let (host, held, spent) = session(fx);
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
            &[CVal::Borrow(0, ResourceKind::ReadCell)],
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
        released_amount: host.0.take_bucket(released_rep)?.amount,
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

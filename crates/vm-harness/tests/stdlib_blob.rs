//! The committed stdlib artifact's conformance lane.
//!
//! `hyperscale-vm-stdlib` ships the account component as committed bytes
//! that CI never rebuilds, so this lane runs those exact bytes: profile
//! validation, then a withdraw+deposit transfer with a pinned balance
//! guard and an entropy stamp on the blessed engine and the reference
//! interpreter, receipts and fuel byte-identical.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, Window, child_key,
};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Movement, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, encode_amount,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, SnapCell, WriteCell, add_kernel_to_linker, blessed_engine,
    validate_component,
};
use hyperscale_vm_stdlib::ACCOUNT_COMPONENT;
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::Context;
use wasmtime::{Result, Store};

const CLOCK_MS: u64 = 77;
const RANDOMNESS: [u8; 32] = [3; 32];
const FUEL: u64 = 10_000_000;
const AMOUNT: u128 = 100;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn keys() -> (SubstateKey, SubstateKey) {
    (
        child_key(&TestHasher, Address([1; 16]), RoleId(1), &[]),
        child_key(&TestHasher, Address([2; 16]), RoleId(1), &[]),
    )
}

/// The sender's entropy leaf — the stamp's exclusive-write target.
fn entropy_key() -> SubstateKey {
    child_key(&TestHasher, Address([1; 16]), RoleId(5), &[])
}

fn session() -> KernelSession {
    let (sender, recipient) = keys();
    let mut declared = EffectSet::new();
    declared
        .insert(Effect {
            target: EffectTarget::Point(sender),
            mode: Mode::Reserve { amount: AMOUNT },
        })
        .unwrap();
    declared
        .insert(Effect {
            target: EffectTarget::Point(recipient),
            mode: Mode::Delta,
        })
        .unwrap();
    declared
        .insert(Effect {
            target: EffectTarget::Point(sender),
            mode: Mode::Snapshot {
                window: Window::Bounded(8),
            },
        })
        .unwrap();
    declared
        .insert(Effect {
            target: EffectTarget::Point(entropy_key()),
            mode: Mode::Write,
        })
        .unwrap();
    let mut store = MemoryStore::new();
    store
        .write(sender, encode_amount(500).to_vec())
        .expect("seed sender balance");
    store.clear_log();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declared,
        TxHash(Hash32([0x77; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: RANDOMNESS,
        },
        test_hash,
    )
    .expect("feasible")
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

fn finish(session: KernelSession, fuel: u64) -> Receipt {
    session
        .finish(Outcome::Completed { value: None }, fuel)
        .expect("oracle clean")
        .0
}

/// Withdraw, deposit, then the pinned balance guard on the blessed
/// engine — one instantiation per call, the session threaded through, as
/// execution invokes guests.
fn blessed_transfer() -> Result<(Receipt, u64)> {
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, ACCOUNT_COMPONENT)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let host = SessionHost(session());
    let (sender, recipient) = keys();
    let sender_rep = rep_of(&host.0, &Capability::Reserve(sender));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let withdraw = instance
        .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(&mut store, "withdraw")?;
    let (bucket,) = withdraw.call(
        &mut store,
        (
            Resource::new_borrow(sender_rep),
            encode_amount(AMOUNT).as_slice(),
        ),
    )?;
    assert_eq!(bucket, encode_amount(AMOUNT).to_vec());
    let withdraw_fuel = FUEL - store.get_fuel()?;
    let host = store.into_data();

    let recipient_rep = rep_of(&host.0, &Capability::Delta(recipient));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let deposit =
        instance.get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")?;
    deposit.call(&mut store, (Resource::new_borrow(recipient_rep), &bucket))?;
    let deposit_fuel = FUEL - store.get_fuel()?;
    let host = store.into_data();

    // The guard reads the batch baseline: the seeded balance, not the
    // reservation-diminished one.
    let snap_rep = rep_of(&host.0, &Capability::Snapshot(sender));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let guard =
        instance.get_typed_func::<(Resource<SnapCell>, &[u8]), ()>(&mut store, "assert-balance")?;
    guard.call(
        &mut store,
        (
            Resource::new_borrow(snap_rep),
            encode_amount(400).as_slice(),
        ),
    )?;
    let guard_fuel = FUEL - store.get_fuel()?;
    let host = store.into_data();

    let entropy_rep = rep_of(&host.0, &Capability::Write(entropy_key()));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let stamp =
        instance.get_typed_func::<(Resource<WriteCell>,), ()>(&mut store, "stamp-entropy")?;
    stamp.call(&mut store, (Resource::new_borrow(entropy_rep),))?;
    let fuel = withdraw_fuel + deposit_fuel + guard_fuel + (FUEL - store.get_fuel()?);

    Ok((finish(store.into_data().0, fuel), fuel))
}

/// The same transfer and guard on the reference interpreter, instantiated
/// per call with the session threaded through.
fn reference_transfer() -> Result<(Receipt, u64)> {
    let component = RefComponent::decode(ACCOUNT_COMPONENT)?;
    let (sender, recipient) = keys();

    let host = SessionHost(session());
    let sender_rep = rep_of(&host.0, &Capability::Reserve(sender));
    let mut instance = RefComponentInstance::instantiate(&component, host)?;
    let outcome = instance.invoke(
        "withdraw",
        &[
            CVal::Borrow(sender_rep, ResourceKind::ReserveCell),
            CVal::Bytes(encode_amount(AMOUNT).to_vec()),
        ],
    )?;
    let values =
        outcome.map_err(|trap| wasmtime::error::format_err!("withdraw trapped: {trap:?}"))?;
    let [CVal::Bytes(bucket)] = values.as_slice() else {
        wasmtime::error::bail!("unexpected withdraw result shape");
    };
    assert_eq!(*bucket, encode_amount(AMOUNT).to_vec());
    let bucket = bucket.clone();
    let withdraw_fuel = instance.fuel_consumed();
    let host = instance.into_host();

    let recipient_rep = rep_of(&host.0, &Capability::Delta(recipient));
    let mut instance = RefComponentInstance::instantiate(&component, host)?;
    let outcome = instance.invoke(
        "deposit",
        &[
            CVal::Borrow(recipient_rep, ResourceKind::DeltaCell),
            CVal::Bytes(bucket),
        ],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("deposit trapped: {trap:?}"))?;
    let deposit_fuel = instance.fuel_consumed();
    let host = instance.into_host();

    let snap_rep = rep_of(&host.0, &Capability::Snapshot(sender));
    let mut instance = RefComponentInstance::instantiate(&component, host)?;
    let outcome = instance.invoke(
        "assert-balance",
        &[
            CVal::Borrow(snap_rep, ResourceKind::SnapCell),
            CVal::Bytes(encode_amount(400).to_vec()),
        ],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("assert-balance trapped: {trap:?}"))?;
    let guard_fuel = instance.fuel_consumed();
    let host = instance.into_host();

    let entropy_rep = rep_of(&host.0, &Capability::Write(entropy_key()));
    let mut instance = RefComponentInstance::instantiate(&component, host)?;
    let outcome = instance.invoke(
        "stamp-entropy",
        &[CVal::Borrow(entropy_rep, ResourceKind::WriteCell)],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("stamp-entropy trapped: {trap:?}"))?;
    let fuel = withdraw_fuel + deposit_fuel + guard_fuel + instance.fuel_consumed();

    Ok((finish(instance.into_host().0, fuel), fuel))
}

#[test]
fn the_committed_blob_validates_and_transfers_on_both_runtimes() -> Result<()> {
    validate_component(ACCOUNT_COMPONENT).context("profile validation of the committed blob")?;

    let (blessed_receipt, blessed_fuel) = blessed_transfer()?;
    let (sender, recipient) = keys();
    assert_eq!(blessed_receipt.delta.settles.get(&sender), Some(&AMOUNT));
    // The stamp wrote the draw the environment handed the transaction —
    // the guest's own output is a function of it.
    assert_eq!(
        blessed_receipt.delta.cells.get(&entropy_key()),
        Some(&Some(RANDOMNESS.to_vec()))
    );
    assert_eq!(
        blessed_receipt.delta.movements.get(&recipient),
        Some(&Movement {
            credit: AMOUNT,
            debit: 0,
        })
    );

    let (reference_receipt, reference_fuel) = reference_transfer()?;
    assert_eq!(
        blessed_receipt, reference_receipt,
        "receipts must be byte-identical across runtimes"
    );
    assert_eq!(
        blessed_fuel, reference_fuel,
        "fuel must be identical across runtimes"
    );
    Ok(())
}

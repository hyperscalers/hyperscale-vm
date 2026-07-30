//! The committed stdlib artifact's conformance lane.
//!
//! `hyperscale-vm-stdlib` ships the account component as committed bytes
//! that CI never rebuilds, so this lane runs those exact bytes: profile
//! validation, then a withdraw+deposit transfer on the blessed engine and
//! the reference interpreter, receipts and fuel byte-identical.

use std::sync::Arc;

use anyhow::{Context, Result};
use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Movement, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, encode_amount,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, add_kernel_to_linker, blessed_engine, validate_component,
};
use hyperscale_vm_stdlib::ACCOUNT_COMPONENT;
use wasmtime::Store;
use wasmtime::component::{Component, Linker, Resource};

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

/// Withdraw then deposit on the blessed engine — one instantiation per
/// call, the session threaded through, as execution invokes guests.
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
    withdraw.post_return(&mut store)?;
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
    deposit.post_return(&mut store)?;
    let fuel = withdraw_fuel + (FUEL - store.get_fuel()?);

    Ok((finish(store.into_data().0, fuel), fuel))
}

/// The same transfer on the reference interpreter, instantiated per call
/// with the session threaded through.
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
    let values = outcome.map_err(|trap| anyhow::anyhow!("withdraw trapped: {trap:?}"))?;
    let [CVal::Bytes(bucket)] = values.as_slice() else {
        anyhow::bail!("unexpected withdraw result shape");
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
    outcome.map_err(|trap| anyhow::anyhow!("deposit trapped: {trap:?}"))?;
    let fuel = withdraw_fuel + instance.fuel_consumed();

    Ok((finish(instance.into_host().0, fuel), fuel))
}

#[test]
fn the_committed_blob_validates_and_transfers_on_both_runtimes() -> Result<()> {
    validate_component(ACCOUNT_COMPONENT).context("profile validation of the committed blob")?;

    let (blessed_receipt, blessed_fuel) = blessed_transfer()?;
    let (sender, recipient) = keys();
    assert_eq!(blessed_receipt.delta.settles.get(&sender), Some(&AMOUNT));
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

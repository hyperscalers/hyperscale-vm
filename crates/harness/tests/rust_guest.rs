//! The realistic guest fixture end to end: build `guests/transfer` with the
//! pinned wit-bindgen toolchain, componentize it, validate it against the
//! profile — the empirical floats-ban test — and run it under the blessed
//! engine with the kernel session as host.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::build_transfer_component;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MaterializeError, MemoryStore, Movement, Outcome,
    OverlayStore, TxHash, WorkingStore, encode_amount,
};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::Context;
use wasmtime::{Result, Store, Trap};

const CLOCK_MS: u64 = 1_234_567;
const RANDOMNESS: [u8; 32] = [9; 32];
const FUEL: u64 = 10_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn keys() -> (SubstateKey, SubstateKey) {
    (
        child_key(
            &TestHasher,
            Address::new([1; 31], AddressClass::Component),
            RoleId(1),
            &[],
        ),
        child_key(
            &TestHasher,
            Address::new([2; 31], AddressClass::Component),
            RoleId(1),
            &[],
        ),
    )
}

fn declared(reserve: u128) -> EffectSet {
    let (sender, recipient) = keys();
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(sender),
        mode: Mode::Reserve { amount: reserve },
    })
    .unwrap();
    set.insert(Effect {
        target: EffectTarget::Point(recipient),
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

fn session(committed: u128, reserve: u128) -> Result<KernelSession, MaterializeError> {
    let (sender, _) = keys();
    let mut store = MemoryStore::new();
    store
        .write(sender, encode_amount(committed).to_vec())
        .unwrap();
    store.clear_log();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declared(reserve),
        &declared(reserve).iter().collect::<Vec<_>>(),
        TxHash(Hash32([0x44; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: RANDOMNESS,
        },
        test_hash,
    )
}

fn handle_reps(session: &KernelSession) -> (u32, u32) {
    let (sender, recipient) = keys();
    let position = |wanted: Capability| {
        u32::try_from(
            session
                .capabilities()
                .iter()
                .position(|c| *c == wanted)
                .expect("capability present"),
        )
        .expect("bounded")
    };
    let reserve = u32::try_from(
        session
            .capabilities()
            .iter()
            .position(|c| matches!(c, Capability::Reserve { key, .. } if *key == sender))
            .expect("capability present"),
    )
    .expect("bounded");
    (reserve, position(Capability::Delta(recipient)))
}

#[test]
fn the_wit_bindgen_guest_conforms_and_transfers() -> Result<()> {
    let component = build_transfer_component()?;

    // The floats verdict: a real Rust guest built with lto + panic=abort
    // must clear the profile, floats ban included.
    validate_component(&component).context("profile validation of the Rust guest")?;

    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, &component)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let host = SessionHost(session(500, 100).expect("feasible"));
    let (sender_rep, recipient_rep) = handle_reps(&host.0);
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance
        .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>, u64), (u64,)>(
            &mut store, "run",
        )?;
    let (tag,) = run.call(
        &mut store,
        (
            Resource::new_borrow(sender_rep),
            Resource::new_borrow(recipient_rep),
            100,
        ),
    )?;

    // The receipt tag folds clock + reserved amount + hash[0] of the
    // randomness draw, computed independently of the guest.
    let digest = test_hash(&RANDOMNESS);
    assert_eq!(tag, CLOCK_MS + 100 + u64::from(digest[0]));

    // Fuel was actually metered.
    let fuel = FUEL - store.get_fuel()?;
    assert!(fuel > 0);

    // The receipt: settlement debits the sender, the delta credits the
    // recipient, and the oracle is clean.
    let (receipt, _) = store
        .into_data()
        .0
        .finish(Outcome::Completed { value: Some(tag) }, fuel)
        .expect("oracle clean");
    let (sender, recipient) = keys();
    assert_eq!(receipt.delta.settles.get(&sender), Some(&100));
    assert_eq!(
        receipt.delta.movements.get(&recipient),
        Some(&Movement {
            credit: 100,
            debit: 0,
        })
    );
    Ok(())
}

#[test]
fn the_guest_floor_panic_is_a_deterministic_trap() -> Result<()> {
    let component = build_transfer_component()?;
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, &component)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let host = SessionHost(session(500, 100).expect("feasible"));
    let (sender_rep, recipient_rep) = handle_reps(&host.0);
    let mut store = Store::new(&engine, host);
    store.set_fuel(10_000_000)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance
        .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>, u64), (u64,)>(
            &mut store, "run",
        )?;
    // The application floor exceeds the reserved amount: the guest's
    // assert must land as a trap, before any delta was queued.
    let err = run
        .call(
            &mut store,
            (
                Resource::new_borrow(sender_rep),
                Resource::new_borrow(recipient_rep),
                200,
            ),
        )
        .expect_err("floor violation must trap");
    assert_eq!(
        err.downcast_ref::<Trap>(),
        Some(&Trap::UnreachableCodeReached),
        "got: {err:#}"
    );
    Ok(())
}

#[test]
fn an_infeasible_reservation_aborts_before_any_execution() {
    let (sender, _) = keys();
    let refused = session(50, 100).expect_err("50 cannot cover 100");
    assert_eq!(
        refused,
        MaterializeError::Infeasible {
            key: sender,
            amount: 100,
        }
    );
}

//! The realistic guest fixture end to end: build `guests/transfer` with the
//! pinned wit-bindgen toolchain, componentize it, validate it against the
//! profile — the empirical floats-ban test — and run it under the blessed
//! engine with the kernel world.

use anyhow::{Context, Result};
use hyperscale_vm_harness::fixtures::{build_transfer_component, repo_root};
use hyperscale_vm_runtime::{
    KernelHost, Substate, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Store, Trap};

const CLOCK_MS: u64 = 1_234_567;

struct TestHost {
    values: Vec<Vec<u8>>,
}

impl KernelHost for TestHost {
    fn read(&mut self, rep: u32) -> Vec<u8> {
        self.values[rep as usize].clone()
    }

    fn write(&mut self, rep: u32, value: Vec<u8>) {
        self.values[rep as usize] = value;
    }

    fn clock_ms(&self) -> u64 {
        CLOCK_MS
    }

    fn randomness(&self) -> [u8; 32] {
        [9; 32]
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let sum = data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        [sum; 32]
    }
}

#[test]
fn the_wit_bindgen_guest_conforms_and_transfers() -> Result<()> {
    // The kernel.wit copy the guest builds against must match the canonical
    // definition in vm-runtime.
    let canonical = std::fs::read(repo_root().join("crates/vm-runtime/wit/kernel.wit"))?;
    let copy = std::fs::read(repo_root().join("guests/transfer/wit/deps/kernel/kernel.wit"))?;
    assert_eq!(canonical, copy, "guest kernel.wit drifted from canonical");

    let component = build_transfer_component()?;

    // The floats verdict: a real Rust guest built with lto + panic=abort
    // must clear the profile, floats ban included.
    validate_component(&component).context("profile validation of the Rust guest")?;

    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, &component)?;
    let mut linker = Linker::<TestHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let mut store = Store::new(
        &engine,
        TestHost {
            values: vec![500u64.to_le_bytes().to_vec(), 20u64.to_le_bytes().to_vec()],
        },
    );
    store.set_fuel(10_000_000)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance.get_typed_func::<(Resource<Substate>, Resource<Substate>, u64), (u64,)>(
        &mut store, "run",
    )?;
    let (tag,) = run.call(
        &mut store,
        (Resource::new_borrow(0), Resource::new_borrow(1), 100),
    )?;
    run.post_return(&mut store)?;

    // Balances moved.
    assert_eq!(store.data_mut().read(0), 400u64.to_le_bytes().to_vec());
    assert_eq!(store.data_mut().read(1), 120u64.to_le_bytes().to_vec());

    // The receipt tag folds clock + new balance + hash[0] of the randomness.
    let hash_first = 9u8.wrapping_mul(32);
    assert_eq!(tag, CLOCK_MS + 120 + u64::from(hash_first));

    // Fuel was actually metered.
    assert!(store.get_fuel()? < 10_000_000);
    Ok(())
}

#[test]
fn the_guest_panic_is_a_deterministic_trap() -> Result<()> {
    let component = build_transfer_component()?;
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, &component)?;
    let mut linker = Linker::<TestHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let mut store = Store::new(
        &engine,
        TestHost {
            values: vec![50u64.to_le_bytes().to_vec(), Vec::new()],
        },
    );
    store.set_fuel(10_000_000)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance.get_typed_func::<(Resource<Substate>, Resource<Substate>, u64), (u64,)>(
        &mut store, "run",
    )?;
    // Insufficient balance: the guest's assert must land as a trap, and no
    // partial write may have reached the host.
    let err = run
        .call(
            &mut store,
            (Resource::new_borrow(0), Resource::new_borrow(1), 100),
        )
        .expect_err("insufficient balance must trap");
    assert_eq!(
        err.downcast_ref::<Trap>(),
        Some(&Trap::UnreachableCodeReached),
        "got: {err:#}"
    );
    assert_eq!(store.data_mut().read(0), 50u64.to_le_bytes().to_vec());
    assert_eq!(store.data_mut().read(1), Vec::<u8>::new());
    Ok(())
}

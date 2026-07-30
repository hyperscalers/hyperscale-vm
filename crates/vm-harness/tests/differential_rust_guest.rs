//! Differential lane 2 over the realistic guest: the wit-bindgen transfer
//! component runs under the blessed engine and the reference interpreter
//! with identical hosts; results, host state, and the trap case must agree.

use anyhow::Result;
use hyperscale_vm_harness::fixtures::build_transfer_component;
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, RefKernelHost, Trap as RefTrap,
};
use hyperscale_vm_runtime::{KernelHost, Substate, add_kernel_to_linker, blessed_engine};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Store, Trap};

const CLOCK_MS: u64 = 777_000;

#[derive(Clone)]
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
        [3; 32]
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let sum = data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        [sum; 32]
    }
}

impl RefKernelHost for TestHost {
    fn read(&mut self, rep: u32) -> Vec<u8> {
        KernelHost::read(self, rep)
    }

    fn write(&mut self, rep: u32, value: Vec<u8>) {
        KernelHost::write(self, rep, value);
    }

    fn clock_ms(&self) -> u64 {
        KernelHost::clock_ms(self)
    }

    fn randomness(&self) -> [u8; 32] {
        KernelHost::randomness(self)
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        KernelHost::hash(self, data)
    }
}

fn starting_host(from: u64) -> TestHost {
    TestHost {
        values: vec![from.to_le_bytes().to_vec(), 20u64.to_le_bytes().to_vec()],
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Value(u64),
    Unreachable,
    Other(String),
}

const FUEL: u64 = 100_000_000;

fn blessed(component: &[u8], from: u64, amount: u64) -> Result<(Outcome, TestHost, u64)> {
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, component)?;
    let mut linker = Linker::<TestHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, starting_host(from));
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance.get_typed_func::<(Resource<Substate>, Resource<Substate>, u64), (u64,)>(
        &mut store, "run",
    )?;
    let result = run
        .call(
            &mut store,
            (Resource::new_borrow(0), Resource::new_borrow(1), amount),
        )
        .and_then(|(v,)| run.post_return(&mut store).map(|()| v));
    let outcome = match result {
        Ok(v) => Outcome::Value(v),
        Err(e) => {
            if e.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached) {
                Outcome::Unreachable
            } else {
                Outcome::Other(format!("{e:#}"))
            }
        }
    };
    let fuel = FUEL - store.get_fuel()?;
    Ok((outcome, store.data().clone(), fuel))
}

fn reference(component: &[u8], from: u64, amount: u64) -> Result<(Outcome, TestHost, u64)> {
    let comp = RefComponent::decode(component)?;
    let mut instance = RefComponentInstance::instantiate(&comp, starting_host(from))?;
    let outcome = match instance.invoke(
        "run",
        &[CVal::Borrow(0), CVal::Borrow(1), CVal::U64(amount)],
    )? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(v)] => Outcome::Value(*v),
            other => Outcome::Other(format!("unexpected values {other:?}")),
        },
        Err(ExecError::Trap(RefTrap::Unreachable)) => Outcome::Unreachable,
        Err(e) => Outcome::Other(format!("{e:?}")),
    };
    let fuel = instance.fuel_consumed();
    Ok((outcome, instance.into_host(), fuel))
}

#[test]
fn the_rust_guest_agrees_between_blessed_engine_and_vm_ref() -> Result<()> {
    let component = build_transfer_component()?;

    // The happy transfer and the insufficient-balance panic.
    for (from, amount) in [(500u64, 100u64), (500, 500), (50, 100)] {
        let (b, b_host, b_fuel) = blessed(&component, from, amount)?;
        let (r, r_host, r_fuel) = reference(&component, from, amount)?;
        assert_eq!(b, r, "outcome diverged for from={from} amount={amount}");
        assert_eq!(
            b_host.values, r_host.values,
            "host state diverged for from={from} amount={amount}"
        );
        if matches!(b, Outcome::Value(_)) {
            assert_eq!(
                b_fuel, r_fuel,
                "fuel diverged for from={from} amount={amount}"
            );
        }
    }

    // Spot-check the expected value independently of both implementations.
    let (outcome, host, _) = reference(&component, 500, 100)?;
    let hash_first = 3u8.wrapping_mul(32);
    assert_eq!(
        outcome,
        Outcome::Value(CLOCK_MS + 120 + u64::from(hash_first))
    );
    assert_eq!(host.values[0], 400u64.to_le_bytes().to_vec());
    assert_eq!(host.values[1], 120u64.to_le_bytes().to_vec());
    Ok(())
}

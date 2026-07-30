//! Differential lane 2, components: the kernel-world guest runs under the
//! blessed engine and the reference interpreter with identical hosts;
//! outcomes, host state, and canonical-ABI violation classes must agree.

use anyhow::Result;
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, RefComponent, RefComponentInstance, RefKernelHost,
};
use hyperscale_vm_runtime::{
    KernelHost, Substate, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::Store;
use wasmtime::component::{Component, Linker, Resource};
use wat::parse_str;

const CLOCK_MS: u64 = 424_242;

#[derive(Clone)]
struct TestHost {
    values: Vec<Vec<u8>>,
    log: Vec<(char, u32)>,
}

impl TestHost {
    fn new(len: usize) -> Self {
        Self {
            values: vec![vec![5; len], Vec::new()],
            log: Vec::new(),
        }
    }
}

impl KernelHost for TestHost {
    fn read(&mut self, rep: u32) -> Vec<u8> {
        self.log.push(('r', rep));
        self.values[rep as usize].clone()
    }

    fn write(&mut self, rep: u32, value: Vec<u8>) {
        self.log.push(('w', rep));
        self.values[rep as usize] = value;
    }

    fn clock_ms(&self) -> u64 {
        CLOCK_MS
    }

    fn randomness(&self) -> [u8; 32] {
        [11; 32]
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

/// One comparable outcome: a value, or a canonical-ABI violation class.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Value(u64),
    UnknownHandle,
    BorrowsRemain,
    Other(String),
}

const FUEL: u64 = 1_000_000_000;

fn blessed_outcome(export: &str, borrows: bool, len: usize) -> Result<(Outcome, TestHost, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<TestHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, TestHost::new(len));
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    // The borrow-liveness check surfaces from post_return, so its error is
    // part of the outcome, never a harness failure.
    let result = if borrows {
        let f = instance.get_typed_func::<(Resource<Substate>, Resource<Substate>), (u64,)>(
            &mut store, export,
        )?;
        f.call(
            &mut store,
            (Resource::new_borrow(0), Resource::new_borrow(1)),
        )
        .and_then(|(v,)| f.post_return(&mut store).map(|()| v))
    } else {
        let f = instance.get_typed_func::<(), (u64,)>(&mut store, export)?;
        f.call(&mut store, ())
            .and_then(|(v,)| f.post_return(&mut store).map(|()| v))
    };

    let outcome = match result {
        Ok(v) => Outcome::Value(v),
        Err(e) => {
            let msg = format!("{e:#}");
            if msg.contains("unknown handle index") {
                Outcome::UnknownHandle
            } else if msg.contains("borrow handles") {
                Outcome::BorrowsRemain
            } else {
                Outcome::Other(msg)
            }
        }
    };
    let host = store.data().clone();
    let fuel = FUEL - store.get_fuel()?;
    Ok((outcome, host, fuel))
}

fn ref_outcome(export: &str, borrows: bool, len: usize) -> Result<(Outcome, TestHost, u64)> {
    let bytes = parse_str(KERNEL_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let mut instance = RefComponentInstance::instantiate(&comp, TestHost::new(len))?;
    let args = if borrows {
        vec![CVal::Borrow(0), CVal::Borrow(1)]
    } else {
        Vec::new()
    };
    let outcome = match instance.invoke(export, &args)? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(v)] => Outcome::Value(*v),
            other => Outcome::Other(format!("unexpected values {other:?}")),
        },
        Err(ExecError::Canon(CanonError::UnknownHandle)) => Outcome::UnknownHandle,
        Err(ExecError::Canon(CanonError::BorrowsRemain)) => Outcome::BorrowsRemain,
        Err(e) => Outcome::Other(format!("{e:?}")),
    };
    let fuel = instance.fuel_consumed();
    Ok((outcome, instance.into_host(), fuel))
}

#[test]
fn component_outcomes_agree_between_blessed_engine_and_vm_ref() -> Result<()> {
    for len in [0usize, 1, 8, 1_000, 65_000] {
        let (blessed, blessed_host, blessed_fuel) = blessed_outcome("run", true, len)?;
        let (reference, ref_host, ref_fuel) = ref_outcome("run", true, len)?;
        assert_eq!(blessed, reference, "run diverged at len {len}");
        assert_eq!(blessed_fuel, ref_fuel, "fuel diverged at len {len}");
        assert_eq!(
            blessed_host.values, ref_host.values,
            "host state diverged at len {len}"
        );
        assert_eq!(
            blessed_host.log, ref_host.log,
            "host access log diverged at len {len}"
        );
        // The expected value, computed independently of both implementations.
        let hash_first = 11u8.wrapping_mul(32);
        assert_eq!(
            blessed,
            Outcome::Value(CLOCK_MS + len as u64 + 32 + u64::from(hash_first))
        );
    }
    Ok(())
}

#[test]
fn forged_handles_and_leaked_borrows_agree() -> Result<()> {
    use anyhow::Context as _;
    let (blessed_forge, blessed_host, _) =
        blessed_outcome("forge", false, 8).context("blessed forge")?;
    let (ref_forge, ref_host, _) = ref_outcome("forge", false, 8).context("ref forge")?;
    assert_eq!(blessed_forge, Outcome::UnknownHandle);
    assert_eq!(ref_forge, Outcome::UnknownHandle);
    assert!(blessed_host.log.is_empty() && ref_host.log.is_empty());

    let (blessed_leak, _, _) = blessed_outcome("leak", true, 8).context("blessed leak")?;
    let (ref_leak, _, _) = ref_outcome("leak", true, 8).context("ref leak")?;
    assert_eq!(blessed_leak, Outcome::BorrowsRemain);
    assert_eq!(ref_leak, Outcome::BorrowsRemain);
    Ok(())
}

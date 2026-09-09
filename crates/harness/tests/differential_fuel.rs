//! Exhaustion as a shared verdict.
//!
//! The engine buffers per-operator fuel into a function-local variable and
//! tests it at three points — function entry, loop header, and before a
//! bulk-op byte charge. The spec charges the same schedule and tests at
//! the same three, so the two run out on the same operator rather than
//! merely somewhere near each other.
//!
//! The sweep is what makes that claim testable: at every budget across the
//! boundary the two runtimes must agree on whether the call completes, and
//! the budget at which each flips is the operator each stopped on.
//!
//! The host-call sweep extends the claim to the boundary supplement: the
//! bytes a host call moves through guest memory are charged into the
//! same counter the instruction schedule draws on, so code that runs
//! *after* the call exhausts at the same budget on both sides.

use hyperscale_vm_embed::abi::{ABI, CRYPTO, MEMORY};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_ref::{
    InstantiateError, RefInstance, RefModule, RefModuleInstance, Trap as RefTrap, Value,
};
use hyperscale_vm_runtime::{
    InstantiationCharges, Invoking, add_kernel_imports, blessed_engine, instantiate_charged,
    instantiation_charges, invoke_export, validate_module,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Engine, Instance, Linker, Module, Result, Store, Trap};
use wat::parse_str;

/// A counted loop: the loop header is the engine's per-iteration fuel
/// check, so the exhaustion point walks with the budget.
const LOOP_FIXTURE: &str = r#"(module
  (func (export "burn") (param i32) (result i32)
    (local $i i32)
    (block
      (loop
        local.get $i
        local.get 0
        i32.ge_u
        br_if 1
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br 0))
    local.get $i))"#;

/// Bulk copies charge per byte at their own check point.
const BULK_FIXTURE: &str = r#"(module
  (memory 1 1)
  (func (export "burn") (param i32) (result i32)
    (i32.const 0)
    (i32.const 0)
    (local.get 0)
    (memory.copy)
    (local.get 0)))"#;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Completed(i32),
    OutOfFuel,
    Other(String),
}

fn blessed_verdict(wasm: &[u8], arg: i32, fuel: u64) -> Result<Verdict> {
    let engine = blessed_engine()?;
    let module = Module::new(&engine, wasm)?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(fuel)?;
    let instance = Instance::new(&mut store, &module, &[])?;
    let func = instance.get_typed_func::<(i32,), (i32,)>(&mut store, "burn")?;
    Ok(match func.call(&mut store, (arg,)) {
        Ok((v,)) => Verdict::Completed(v),
        Err(e) => match e.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => Verdict::OutOfFuel,
            other => Verdict::Other(format!("{other:?}")),
        },
    })
}

fn ref_verdict(wasm: &[u8], arg: i32, fuel: u64) -> Result<Verdict> {
    let module = RefModule::decode(wasm)?;
    let mut instance = match RefInstance::instantiate_with_fuel(&module, fuel) {
        Ok(instance) => instance,
        Err(RefTrap::OutOfFuel) => return Ok(Verdict::OutOfFuel),
        Err(t) => return Ok(Verdict::Other(format!("{t:?}"))),
    };
    Ok(match instance.invoke("burn", &[Value::I32(arg)])? {
        Ok(values) => match values.as_slice() {
            [Value::I32(v)] => Verdict::Completed(*v),
            other => Verdict::Other(format!("{other:?}")),
        },
        Err(RefTrap::OutOfFuel) => Verdict::OutOfFuel,
        Err(t) => Verdict::Other(format!("{t:?}")),
    })
}

/// Sweeps the budget across the exhaustion boundary and returns the lowest
/// budget at which the call completed, asserting agreement at every step.
fn sweep(fixture: &str, arg: i32, range: std::ops::Range<u64>) -> Result<u64> {
    let wasm = parse_str(fixture)?;
    let mut first_completion = None;
    for fuel in range.clone() {
        let blessed = blessed_verdict(&wasm, arg, fuel)?;
        let reference = ref_verdict(&wasm, arg, fuel)?;
        assert_eq!(
            blessed, reference,
            "budget {fuel} split the verdict between the engine and the spec"
        );
        if first_completion.is_none() && matches!(blessed, Verdict::Completed(_)) {
            first_completion = Some(fuel);
        }
    }
    let boundary = first_completion.unwrap_or_else(|| {
        panic!("budget range {range:?} never completed; the sweep proves nothing")
    });
    assert!(
        boundary > range.start,
        "budget range {range:?} never exhausted; the sweep proves nothing"
    );
    Ok(boundary)
}

#[test]
fn a_counted_loop_exhausts_at_the_same_budget() -> Result<()> {
    // Wide enough to bracket the boundary from both sides.
    let boundary = sweep(LOOP_FIXTURE, 20, 1..260)?;
    println!("loop fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

#[test]
fn a_bulk_copy_exhausts_at_the_same_budget() -> Result<()> {
    // The per-byte charge lands at its own check point, ahead of the
    // bounds check, so the boundary sits just past the byte count.
    let boundary = sweep(BULK_FIXTURE, 64, 1..90)?;
    println!("bulk fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

/// A host call, then a counted loop: the call's boundary bytes (8 of data
/// in, 32 of digest out) are debt the loop's own headers must see, so the
/// exhaustion point after the call walks with the budget on both sides.
/// The count is answered as a `u64` at 48.
fn host_call_fixture() -> String {
    format!(
        r#"(module
  (import "{CRYPTO}" "hash" (func $hash (param i32 i32 i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)
  (func (export "burn") (param $n i64)
    (local $i i32)
    (call $hash (i32.const 0) (i32.const 8) (i32.const 16))
    (block
      (loop
        local.get $i
        local.get $n
        i32.wrap_i64
        i32.ge_u
        br_if 1
        local.get $i
        i32.const 1
        i32.add
        local.set $i
        br 0))
    (i64.store (i32.const 48) (i64.extend_i32_u (local.get $i)))
    (call $answer (i32.const 48) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0))))"#
    )
}

/// The verdict an invocation of the host-call fixture is, on either
/// engine: the count it answered, or the exhaustion it ended in.
fn verdict(ended: Invocation) -> Verdict {
    match ended.result {
        Invoked::Produced {
            answer: Some(answer),
            ..
        } => {
            let bytes: [u8; 8] = answer
                .as_slice()
                .try_into()
                .expect("the fixture answers eight bytes");
            Verdict::Completed(
                i32::try_from(u64::from_le_bytes(bytes)).expect("the fixture counts low"),
            )
        }
        Invoked::Aborted(AbortReason::OutOfGas) => {
            assert!(ended.exhausted, "exhaustion carries its flag");
            Verdict::OutOfFuel
        }
        other => Verdict::Other(format!("{other:?}")),
    }
}

fn blessed_host_call_verdict(
    engine: &Engine,
    module: &Module,
    charges: &InstantiationCharges,
    arg: u64,
    fuel: u64,
) -> Result<Verdict> {
    let mut linker = Linker::<Invoking<NoHost>>::new(engine);
    add_kernel_imports(&mut linker)?;
    let mut store = Store::new(engine, Invoking::new(NoHost));
    let instance =
        match instantiate_charged(&mut store, fuel, charges, |s| linker.instantiate(s, module)) {
            Ok(instance) => instance,
            Err(e) => {
                return Ok(match e.downcast_ref::<Trap>() {
                    Some(Trap::OutOfFuel) => Verdict::OutOfFuel,
                    other => Verdict::Other(format!("{other:?}")),
                });
            }
        };
    Ok(verdict(invoke_export(
        &mut store,
        &instance,
        "burn",
        &[GuestArg::U64(arg)],
        fuel,
    )))
}

fn ref_host_call_verdict(module: &RefModule, arg: u64, fuel: u64) -> Result<Verdict> {
    let mut instance = match RefModuleInstance::instantiate(module, NoHost, fuel) {
        Ok(instance) => instance,
        Err((_, InstantiateError::Trap(RefTrap::OutOfFuel))) => return Ok(Verdict::OutOfFuel),
        Err((_, error)) => return Err(error.into()),
    };
    Ok(verdict(instance.invoke("burn", &[GuestArg::U64(arg)])))
}

/// As [`sweep`], for the host-call fixture: same verdict-agreement claim,
/// with the boundary supplement inside the budget.
fn host_call_sweep(arg: u64, range: std::ops::Range<u64>) -> Result<u64> {
    let bytes = parse_str(host_call_fixture())?;
    validate_module(&bytes)?;
    let engine = blessed_engine()?;
    let module = Module::new(&engine, &bytes)?;
    let charges = instantiation_charges(&bytes)?;
    let reference = RefModule::decode(&bytes)?;
    let mut first_completion = None;
    for fuel in range.clone() {
        let blessed = blessed_host_call_verdict(&engine, &module, &charges, arg, fuel)?;
        let interpreted = ref_host_call_verdict(&reference, arg, fuel)?;
        assert_eq!(
            blessed, interpreted,
            "budget {fuel} split the verdict between the engine and the spec"
        );
        if first_completion.is_none() && matches!(blessed, Verdict::Completed(_)) {
            first_completion = Some(fuel);
        }
    }
    let boundary = first_completion.unwrap_or_else(|| {
        panic!("budget range {range:?} never completed; the sweep proves nothing")
    });
    assert!(
        boundary > range.start,
        "budget range {range:?} never exhausted; the sweep proves nothing"
    );
    Ok(boundary)
}

#[test]
fn a_host_call_and_a_loop_exhaust_at_the_same_budget() -> Result<()> {
    // Wide enough to bracket instantiation, the call, its 40 bytes of
    // boundary debt, the loop and the answer from both sides.
    let boundary = host_call_sweep(20, 1..800)?;
    println!("host-call fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

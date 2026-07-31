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

use hyperscale_vm_ref::{RefInstance, RefModule, Trap as RefTrap, Value};
use hyperscale_vm_runtime::blessed_engine;
use wasmtime::{Instance, Module, Result, Store, Trap};
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

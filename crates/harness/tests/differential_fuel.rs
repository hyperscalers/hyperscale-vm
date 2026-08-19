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
//! The component sweep extends the claim to the boundary supplement: bytes
//! a host call moves across the canonical ABI are charged into the same
//! counter the instruction schedule draws on, so code that runs *after*
//! the call exhausts at the same budget on both sides.

use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, RefInstance, RefModule, Trap as RefTrap,
    Value,
};
use hyperscale_vm_runtime::{add_kernel_to_linker, blessed_engine};
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Engine, Instance, Module, Result, Store, Trap};
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
const HOST_CALL_FIXTURE: &str = r#"(component
  (import "hyperscale:kernel/crypto" (instance $crypto
    (export "hash" (func (param "data" (list u8)) (result (list u8))))))
  (alias export $crypto "hash" (func $hash))
  (core module $alloc
    (memory (export "mem") 1 1)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ret i32)
      global.get $next
      local.set $ret
      global.get $next
      local.get 3
      i32.add
      global.set $next
      local.get $ret))
  (core instance $a (instantiate $alloc))
  (core func $hash_l (canon lower (func $hash)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "hash" (func $hash (param i32 i32 i32)))
    (func (export "burn") (param $n i32) (result i64)
      (local $i i32)
      (call $hash (i32.const 0) (i32.const 8) (i32.const 16))
      (block
        (loop
          local.get $i
          local.get $n
          i32.ge_u
          br_if 1
          local.get $i
          i32.const 1
          i32.add
          local.set $i
          br 0))
      local.get $i
      i64.extend_i32_u))
  (core instance $g (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance (export "hash" (func $hash_l))))))
  (func (export "burn") (param "n" u32) (result u64)
    (canon lift (core func $g "burn"))))"#;

fn blessed_component_verdict(
    engine: &Engine,
    component: &Component,
    arg: u32,
    fuel: u64,
) -> Result<Verdict> {
    let mut linker = ComponentLinker::<NoHost>::new(engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(engine, NoHost);
    store.set_fuel(fuel)?;
    let instance = match linker.instantiate(&mut store, component) {
        Ok(instance) => instance,
        Err(e) => {
            return Ok(match e.downcast_ref::<Trap>() {
                Some(Trap::OutOfFuel) => Verdict::OutOfFuel,
                other => Verdict::Other(format!("{other:?}")),
            });
        }
    };
    let func = instance.get_typed_func::<(u32,), (u64,)>(&mut store, "burn")?;
    Ok(match func.call(&mut store, (arg,)) {
        Ok((v,)) => Verdict::Completed(i32::try_from(v).expect("the fixture counts low")),
        Err(e) => match e.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel) => Verdict::OutOfFuel,
            other => Verdict::Other(format!("{other:?}")),
        },
    })
}

fn ref_component_verdict(comp: &RefComponent, arg: u32, fuel: u64) -> Result<Verdict> {
    let mut instance =
        RefComponentInstance::instantiate(comp, NoHost).map_err(|(_, error)| error)?;
    instance.set_fuel_limit(fuel);
    Ok(match instance.invoke("burn", &[CVal::U32(arg)])? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(v)] => {
                Verdict::Completed(i32::try_from(*v).expect("the fixture counts low"))
            }
            other => Verdict::Other(format!("{other:?}")),
        },
        Err(ExecError::Trap(RefTrap::OutOfFuel)) => Verdict::OutOfFuel,
        Err(e) => Verdict::Other(format!("{e:?}")),
    })
}

/// As [`sweep`], for the component fixture: same verdict-agreement claim,
/// with the boundary supplement inside the budget.
fn component_sweep(fixture: &str, arg: u32, range: std::ops::Range<u64>) -> Result<u64> {
    let bytes = parse_str(fixture)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let comp = RefComponent::decode(&bytes)?;
    let mut first_completion = None;
    for fuel in range.clone() {
        let blessed = blessed_component_verdict(&engine, &component, arg, fuel)?;
        let reference = ref_component_verdict(&comp, arg, fuel)?;
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
fn a_host_call_and_a_loop_exhaust_at_the_same_budget() -> Result<()> {
    // Wide enough to bracket instantiation, the call, its 40 bytes of
    // boundary debt, and the loop from both sides.
    let boundary = component_sweep(HOST_CALL_FIXTURE, 20, 1..800)?;
    println!("host-call fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

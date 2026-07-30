//! Regression probe: fuel at a core trap point is engine-defined.
//!
//! Wasmtime does not flush its in-register fuel counter when a core trap
//! unwinds, so a mid-basic-block trap reports zero consumed fuel while
//! vm-ref charges every executed operator. The differential lanes exclude
//! fuel on trap paths because of exactly this; abort pricing cannot ship
//! until the boundary is deterministic and spec-reproducible. This probe
//! pins the current behavior — when it fails, wasmtime's flush semantics
//! changed and the lane exclusion should be revisited.

use hyperscale_vm_ref::{RefInstance, RefModule, Trap as RefTrap};
use hyperscale_vm_runtime::blessed_engine;
use wasmtime::{Instance, Module, Store, Trap};
use wat::parse_str;

const FUEL: u64 = 1_000_000;

/// Burns a few operators, then divides by zero mid-basic-block.
const FIXTURE: &str = r#"(module
  (func (export "boom") (result i32)
    i32.const 7
    i32.const 1
    i32.add
    i32.const 0
    i32.div_s))"#;

#[test]
fn core_trap_fuel_is_unflushed_on_the_engine_and_exact_on_vm_ref() {
    let bytes = parse_str(FIXTURE).expect("fixture parses");

    let engine = blessed_engine().expect("engine");
    let module = Module::new(&engine, &bytes).expect("compiles");
    let mut store = Store::new(&engine, ());
    store.set_fuel(FUEL).expect("fuel on");
    let instance = Instance::new(&mut store, &module, &[]).expect("instantiates");
    let func = instance
        .get_typed_func::<(), i32>(&mut store, "boom")
        .expect("export");
    let error = func.call(&mut store, ()).expect_err("must trap");
    assert_eq!(
        error.downcast_ref::<Trap>(),
        Some(&Trap::IntegerDivisionByZero)
    );
    let engine_consumed = FUEL - store.get_fuel().expect("fuel on");

    let decoded = RefModule::decode(&bytes).expect("decodes");
    let mut ref_instance = RefInstance::instantiate(&decoded).expect("instantiates");
    let trap = ref_instance
        .invoke("boom", &[])
        .expect("no host error")
        .expect_err("must trap");
    assert_eq!(trap, RefTrap::IntegerDivisionByZero);
    let ref_consumed = ref_instance.fuel_consumed();

    // The divergence this probe exists to pin: the engine's fuel register
    // never flushed, vm-ref charged the executed operators.
    assert_eq!(engine_consumed, 0);
    assert!(ref_consumed > 0, "vm-ref charges executed operators");
}

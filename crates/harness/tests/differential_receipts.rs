//! The abort vocabulary, checked against both engines rather than against
//! its own tables.
//!
//! Each runtime classifies its own failures into [`AbortReason`], and the
//! two tables are written independently — one over `wasmtime::Trap`, one
//! over the interpreter's. Nothing in either crate can see both, so the
//! agreement is asserted here: one trapping guest, both engines, equal
//! class. A divergence is two nodes disagreeing about what a transaction
//! is, because the class decides the outcome variant and the outcome
//! variant decides the fee.

use hyperscale_vm_kernel::AbortReason;
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, RefKernelHost};
use hyperscale_vm_runtime::{blessed_engine, classify};
use wasmtime::component::{Component, Linker};
use wasmtime::error::Context;
use wasmtime::{Error, Result, Store};
use wat::parse_str;

/// The interpreter's decode and instantiation failures as engine errors,
/// so both lanes report through one type. Neither is reachable for a
/// component this test builds; the conversion keeps the lane honest
/// rather than papering over one with an `expect`.
fn engine_error(error: &impl ToString) -> Error {
    Error::msg(error.to_string())
}

/// A guest that fails one way per export, and imports nothing.
///
/// Every export the profile can reach a trap through, so the tables are
/// exercised rather than transcribed twice and hoped over.
const TRAPPING_GUEST: &str = r#"
(component
  (core module $m
    (type $ret (func (result i64)))
    (memory 1 1)
    (table 1 1 funcref)
    (func (export "boom") (result i64) unreachable)
    (func (export "divide") (result i64)
      (i64.div_s (i64.const 1) (i64.const 0)))
    (func (export "remainder") (result i64)
      (i64.rem_s (i64.const 1) (i64.const 0)))
    (func (export "overflow") (result i64)
      (i64.div_s (i64.const -9223372036854775808) (i64.const -1)))
    (func (export "reach") (result i64)
      (i64.load (i32.const 100000)))
    (func (export "nullcall") (result i64)
      (call_indirect (type $ret) (i32.const 0)))
    (func (export "fine") (result i64) (i64.const 7)))
  (core instance $i (instantiate $m))
  (func (export "boom") (result u64) (canon lift (core func $i "boom")))
  (func (export "divide") (result u64) (canon lift (core func $i "divide")))
  (func (export "remainder") (result u64) (canon lift (core func $i "remainder")))
  (func (export "overflow") (result u64) (canon lift (core func $i "overflow")))
  (func (export "reach") (result u64) (canon lift (core func $i "reach")))
  (func (export "nullcall") (result u64) (canon lift (core func $i "nullcall")))
  (func (export "fine") (result u64) (canon lift (core func $i "fine"))))
"#;

/// A host with no capabilities: this guest imports none, and the
/// interpreter still wants one to instantiate against.
struct NoHost;

#[allow(clippy::missing_errors_doc)] // unreachable: the guest imports nothing
impl RefKernelHost for NoHost {
    fn read_cell(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn locked_cell(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn write_cell_get(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn write_cell_set(&mut self, _rep: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn delta_add(&mut self, _rep: u32, _amount: &[u8]) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn delta_sub(&mut self, _rep: u32, _amount: &[u8]) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn reserve_amount(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_count(&mut self, _rep: u32) -> Result<u32, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_order(&mut self, _rep: u32, _index: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_entry(&mut self, _rep: u32, _index: u32) -> Result<Vec<u8>, AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_set(&mut self, _rep: u32, _index: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_insert(&mut self, _rep: u32, _order: &[u8], _v: Vec<u8>) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn range_remove(&mut self, _rep: u32, _index: u32) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
    fn clock_ms(&self) -> u64 {
        0
    }
    fn randomness(&self) -> [u8; 32] {
        [0; 32]
    }
    fn hash(&self, _data: &[u8]) -> [u8; 32] {
        [0; 32]
    }
    fn emit(&mut self, _event_type: u32, _payload: Vec<u8>) -> Result<(), AbortReason> {
        Err(AbortReason::HandleUnknown)
    }
}

/// One export's verdict on the blessed engine: its value, or its class.
fn blessed(bytes: &[u8], export: &str) -> Result<std::result::Result<u64, AbortReason>> {
    let engine = blessed_engine()?;
    let component = Component::new(&engine, bytes)?;
    let linker = Linker::<NoHost>::new(&engine);
    let mut store = Store::new(&engine, NoHost);
    store.set_fuel(1_000_000).context("fuel")?;
    let instance = linker.instantiate(&mut store, &component)?;
    let func = instance
        .get_typed_func::<(), (u64,)>(&mut store, export)
        .context("export")?;
    Ok(match func.call(&mut store, ()) {
        Ok((value,)) => Ok(value),
        Err(error) => Err(classify(&error)),
    })
}

/// The same export's verdict on the reference interpreter.
fn reference(bytes: &[u8], export: &str) -> Result<std::result::Result<u64, AbortReason>> {
    let component = RefComponent::decode(bytes).map_err(|e| engine_error(&e))?;
    let mut instance =
        RefComponentInstance::instantiate(&component, NoHost).map_err(|(_, e)| engine_error(&e))?;
    instance.set_fuel_limit(1_000_000);
    let outcome = instance.invoke(export, &[]).map_err(|e| engine_error(&e))?;
    Ok(match outcome {
        Ok(values) => match values.as_slice() {
            [CVal::U64(value)] => Ok(*value),
            _ => Err(AbortReason::BadReturnShape),
        },
        Err(error) => Err(error.abort_reason()),
    })
}

/// Every trap the profile admits classifies identically on both engines,
/// and to the class the vocabulary names for it.
#[test]
fn both_engines_classify_one_trap_as_one_class() -> Result<()> {
    let bytes = parse_str(TRAPPING_GUEST)?;
    let expected = [
        ("boom", AbortReason::Unreachable),
        ("divide", AbortReason::IntegerDivideByZero),
        ("remainder", AbortReason::IntegerDivideByZero),
        ("overflow", AbortReason::IntegerOverflow),
        ("reach", AbortReason::MemoryOutOfBounds),
        ("nullcall", AbortReason::IndirectCallToNull),
    ];
    for (export, class) in expected {
        let blessed = blessed(&bytes, export)?;
        let reference = reference(&bytes, export)?;
        assert_eq!(blessed, reference, "`{export}` classified differently");
        assert_eq!(blessed, Err(class), "`{export}` classified wrongly");
    }
    assert_eq!(blessed(&bytes, "fine")?, Ok(7));
    assert_eq!(reference(&bytes, "fine")?, Ok(7));
    Ok(())
}

/// Exhaustion is the arm that moves a fee, so it is asserted on its own
/// against a ceiling neither engine can finish under.
#[test]
fn both_engines_classify_exhaustion_as_exhaustion() -> Result<()> {
    const SPINNER: &str = r#"
(component
  (core module $m
    (func (export "spin") (result i64)
      (local $i i64)
      (loop $l
        (local.set $i (i64.add (local.get $i) (i64.const 1)))
        (br $l))
      (local.get $i)))
  (core instance $i (instantiate $m))
  (func (export "spin") (result u64) (canon lift (core func $i "spin"))))
"#;
    let bytes = parse_str(SPINNER)?;

    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let linker = Linker::<NoHost>::new(&engine);
    let mut store = Store::new(&engine, NoHost);
    store.set_fuel(50_000).context("fuel")?;
    let instance = linker.instantiate(&mut store, &component)?;
    let func = instance.get_typed_func::<(), (u64,)>(&mut store, "spin")?;
    let blessed = classify(&func.call(&mut store, ()).unwrap_err());

    let decoded = RefComponent::decode(&bytes).map_err(|e| engine_error(&e))?;
    let mut interpreted =
        RefComponentInstance::instantiate(&decoded, NoHost).map_err(|(_, e)| engine_error(&e))?;
    interpreted.set_fuel_limit(50_000);
    let reference = interpreted
        .invoke("spin", &[])
        .map_err(|e| engine_error(&e))?
        .expect_err("the ceiling stops it")
        .abort_reason();

    assert_eq!(blessed, AbortReason::OutOfGas);
    assert_eq!(reference, AbortReason::OutOfGas);
    Ok(())
}

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

use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance};
use hyperscale_vm_runtime::{Returned, blessed_engine, call_export, classify, validate_component};
use hyperscale_vm_types::AbortReason;
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
    let mut instance = RefComponentInstance::instantiate(&component, NoHost, 1_000_000)
        .map_err(|(_, e)| engine_error(&e))?;
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
    let mut interpreted = RefComponentInstance::instantiate(&decoded, NoHost, 50_000)
        .map_err(|(_, e)| engine_error(&e))?;
    let reference = interpreted
        .invoke("spin", &[])
        .map_err(|e| engine_error(&e))?
        .expect_err("the ceiling stops it")
        .abort_reason();

    assert_eq!(blessed, AbortReason::OutOfGas);
    assert_eq!(reference, AbortReason::OutOfGas);
    Ok(())
}

/// A guest that ends every way a method can that carries no edge: the
/// refusal channel's two shapes each answering both ways, and the value
/// a method answers with, alone and behind the channel.
///
/// Hand-written rather than compiled so the memory representation is
/// visible — a one-byte discriminant, the payload at the alignment the
/// wider arm fixes, a byte list as the pointer and length it lowers to
/// — which is exactly what the reference interpreter reads and what
/// nothing but this comparison holds it to.
const ENDING_GUEST: &str = r#"
(component
  (core module $m
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 512)
    (func (export "yes") (result i32)
      (i32.store8 (i32.const 0) (i32.const 0))
      (i32.store (i32.const 4) (i32.const 64))
      (i32.store (i32.const 8) (i32.const 3))
      (i32.store8 (i32.const 64) (i32.const 7))
      (i32.store8 (i32.const 65) (i32.const 8))
      (i32.store8 (i32.const 66) (i32.const 9))
      i32.const 0)
    (func (export "no") (result i32)
      (i32.store8 (i32.const 0) (i32.const 1))
      (i32.store (i32.const 4) (i32.const 5))
      i32.const 0)
    (func (export "unit-yes") (result i32)
      (i32.store8 (i32.const 128) (i32.const 0))
      i32.const 128)
    (func (export "unit-no") (result i32)
      (i32.store8 (i32.const 128) (i32.const 1))
      (i32.store (i32.const 132) (i32.const 9))
      i32.const 128)
    (func (export "answer") (result i32)
      (i32.store (i32.const 256) (i32.const 320))
      (i32.store (i32.const 260) (i32.const 3))
      (i32.store8 (i32.const 320) (i32.const 4))
      (i32.store8 (i32.const 321) (i32.const 5))
      (i32.store8 (i32.const 322) (i32.const 6))
      i32.const 256)
    (func (export "answer-or-decline") (result i32)
      (i32.store8 (i32.const 384) (i32.const 0))
      (i32.store (i32.const 388) (i32.const 448))
      (i32.store (i32.const 392) (i32.const 2))
      (i32.store8 (i32.const 448) (i32.const 1))
      (i32.store8 (i32.const 449) (i32.const 2))
      i32.const 384))
  (core instance $i (instantiate $m))
  (func (export "unit-yes") (result (result (error u32)))
    (canon lift (core func $i "unit-yes") (memory $i "mem") (realloc (func $i "realloc"))))
  (func (export "unit-no") (result (result (error u32)))
    (canon lift (core func $i "unit-no") (memory $i "mem") (realloc (func $i "realloc"))))
  (func (export "answer") (result (list u8))
    (canon lift (core func $i "answer") (memory $i "mem") (realloc (func $i "realloc"))))
  (func (export "answer-or-decline") (result (result (list u8) (error u32)))
    (canon lift (core func $i "answer-or-decline")
      (memory $i "mem") (realloc (func $i "realloc")))))
"#;

#[test]
fn both_engines_read_what_a_method_hands_back_the_same_way() -> Result<()> {
    let bytes = parse_str(ENDING_GUEST)?;
    validate_component(&bytes).expect("the refusal channel is inside the profile");

    for (export, expected) in [
        (
            "unit-yes",
            Returned::Produced {
                edges: Vec::new(),
                answer: None,
            },
        ),
        ("unit-no", Returned::Declined(9)),
        (
            "answer",
            Returned::Produced {
                edges: Vec::new(),
                answer: Some(vec![4, 5, 6]),
            },
        ),
        (
            "answer-or-decline",
            Returned::Produced {
                edges: Vec::new(),
                answer: Some(vec![1, 2]),
            },
        ),
    ] {
        let engine = blessed_engine()?;
        let component = Component::new(&engine, &bytes)?;
        let linker = Linker::<NoHost>::new(&engine);
        let mut store = Store::new(&engine, NoHost);
        store.set_fuel(1_000_000).context("fuel")?;
        let instance = linker.instantiate(&mut store, &component)?;
        let blessed = call_export(&mut store, &instance, export, &[])?;

        let decoded = RefComponent::decode(&bytes).map_err(|e| engine_error(&e))?;
        let mut interpreted = RefComponentInstance::instantiate(&decoded, NoHost, 1_000_000)
            .map_err(|(_, e)| engine_error(&e))?;
        let reference = interpreted
            .invoke(export, &[])
            .map_err(|e| engine_error(&e))?
            .expect("the guest returns");

        assert_eq!(blessed, expected, "`{export}` on the blessed engine");
        assert_eq!(
            lifted(&reference),
            expected,
            "`{export}` on the reference interpreter"
        );
    }
    Ok(())
}

/// The interpreter's lifted values as the blessed engine's verdict, so
/// the two lanes compare in one vocabulary.
fn lifted(values: &[CVal]) -> Returned {
    match values {
        [] => Returned::Produced {
            edges: Vec::new(),
            answer: None,
        },
        [CVal::Declined(code)] => Returned::Declined(*code),
        [CVal::Bytes(answer)] => Returned::Produced {
            edges: Vec::new(),
            answer: Some(answer.clone()),
        },
        other => panic!("off-convention result {other:?}"),
    }
}

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

use hyperscale_vm_embed::abi::{ABI, MEMORY};
use hyperscale_vm_embed::{Invocation, Invoked};
use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_meter::instantiation_cost;
use hyperscale_vm_ref::{RefModule, RefModuleInstance};
use hyperscale_vm_runtime::{
    Invoking, add_kernel_imports, admit, blessed_engine, instantiate_metered, invoke_export,
    validate_module,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::error::{Context, format_err};
use wasmtime::{Linker, Module, Result, Store};
use wat::parse_str;

/// What a call may spend where the guest is expected to finish.
const FUEL: u64 = 1_000_000;

/// A module importing only the two register calls an answer needs, the
/// one memory, and `body`.
///
/// Every export ends by answering eight bytes and replying no edge, so
/// what each one exercises is the way it fails to get there.
fn module(body: &str) -> Result<Vec<u8>> {
    let wat = format!(
        r#"(module
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)
  (func $done (param $ptr i32)
    local.get $ptr
    i32.const 8
    call $answer
    i32.const 0
    i32.const 0
    call $reply)
{body})"#
    );
    let bytes = parse_str(wat)?;
    validate_module(&bytes)?;
    Ok(bytes)
}

/// A guest that fails one way per export.
///
/// Every export the profile can reach a trap through, so the tables are
/// exercised rather than transcribed twice and hoped over; `fine` runs
/// to its answer.
fn trapping_guest() -> Result<Vec<u8>> {
    module(
        r#"
  (type $ret (func (result i64)))
  (table 1 1 funcref)
  (func (export "boom") unreachable (call $done (i32.const 0)))
  (func (export "divide")
    (i64.store (i32.const 0) (i64.div_s (i64.const 1) (i64.const 0)))
    (call $done (i32.const 0)))
  (func (export "remainder")
    (i64.store (i32.const 0) (i64.rem_s (i64.const 1) (i64.const 0)))
    (call $done (i32.const 0)))
  (func (export "overflow")
    (i64.store (i32.const 0)
      (i64.div_s (i64.const -9223372036854775808) (i64.const -1)))
    (call $done (i32.const 0)))
  (func (export "reach")
    (i64.store (i32.const 0) (i64.load (i32.const 100000)))
    (call $done (i32.const 0)))
  (func (export "nullcall")
    (i64.store (i32.const 0) (call_indirect (type $ret) (i32.const 0)))
    (call $done (i32.const 0)))
  (func (export "fine")
    (i64.store (i32.const 0) (i64.const 7))
    (call $done (i32.const 0)))"#,
    )
}

/// One export's ending on the blessed engine, under `budget`.
fn blessed(bytes: &[u8], export: &str, budget: u64) -> Result<Invocation> {
    let engine = blessed_engine()?;
    let module = Module::new(&engine, admit(bytes)?)?;
    let mut linker = Linker::<Invoking<NoHost>>::new(&engine);
    add_kernel_imports(&mut linker)?;
    let mut store = Store::new(&engine, Invoking::new(NoHost));
    let cost = instantiation_cost(bytes).context("prepay")?;
    let instance =
        instantiate_metered(&mut store, budget, cost, |s| linker.instantiate(s, &module))?;
    Ok(invoke_export(&mut store, &instance, export, &[], budget))
}

/// The same export's ending on the reference interpreter.
fn reference(bytes: &[u8], export: &str, budget: u64) -> Result<Invocation> {
    let module =
        RefModule::decode(&admit(bytes)?).map_err(|error| format_err!("decode: {error}"))?;
    let mut instance = RefModuleInstance::instantiate(&module, NoHost, budget)
        .map_err(|(_, error)| format_err!("reference instantiation: {error}"))?;
    Ok(instance.invoke(export, &[]))
}

/// Every trap the profile admits classifies identically on both engines,
/// and to the class the vocabulary names for it.
#[test]
fn both_engines_classify_one_trap_as_one_class() -> Result<()> {
    let bytes = trapping_guest()?;
    let expected = [
        ("boom", AbortReason::Unreachable),
        ("divide", AbortReason::IntegerDivideByZero),
        ("remainder", AbortReason::IntegerDivideByZero),
        ("overflow", AbortReason::IntegerOverflow),
        ("reach", AbortReason::MemoryOutOfBounds),
        ("nullcall", AbortReason::IndirectCallToNull),
    ];
    for (export, class) in expected {
        let blessed = blessed(&bytes, export, FUEL)?.result;
        let reference = reference(&bytes, export, FUEL)?.result;
        assert_eq!(blessed, reference, "`{export}` classified differently");
        assert_eq!(
            blessed,
            Invoked::Aborted(class),
            "`{export}` classified wrongly"
        );
    }
    let seven = Invoked::Produced {
        edges: Vec::new(),
        answer: Some(7u64.to_le_bytes().to_vec()),
    };
    assert_eq!(blessed(&bytes, "fine", FUEL)?.result, seven);
    assert_eq!(reference(&bytes, "fine", FUEL)?.result, seven);
    Ok(())
}

/// Exhaustion is the arm that moves a fee, so it is asserted on its own
/// against a ceiling neither engine can finish under.
#[test]
fn both_engines_classify_exhaustion_as_exhaustion() -> Result<()> {
    const CEILING: u64 = 50_000;
    let bytes = module(
        r#"
  (func (export "spin")
    (local $i i64)
    (loop $l
      (local.set $i (i64.add (local.get $i) (i64.const 1)))
      (br $l))
    (i64.store (i32.const 0) (local.get $i))
    (call $done (i32.const 0)))"#,
    )?;

    let blessed = blessed(&bytes, "spin", CEILING)?;
    let reference = reference(&bytes, "spin", CEILING)?;

    assert_eq!(blessed.result, Invoked::Aborted(AbortReason::OutOfGas));
    assert_eq!(blessed.fuel, CEILING, "exhaustion spends the counter whole");
    assert_eq!(reference.result, Invoked::Aborted(AbortReason::OutOfGas));
    assert_eq!(reference.fuel, CEILING);
    Ok(())
}

/// A guest that ends every way a method can that carries no edge: a
/// completion with nothing answered, a decline, an answer, and an answer
/// through a signature that could have declined and did not.
///
/// Hand-written so what crosses is visible: an answer is bytes at a
/// pointer, a decline is the `i32` the export returns, one more than
/// the error-table index — which is exactly what both engines read and
/// what nothing but this comparison holds them to.
fn ending_guest() -> Result<Vec<u8>> {
    module(
        r#"
  (func (export "unit-yes")
    (call $reply (i32.const 0) (i32.const 0)))
  (func (export "unit-no") (result i32)
    (i32.const 10))
  (func (export "answer")
    (i32.store8 (i32.const 64) (i32.const 4))
    (i32.store8 (i32.const 65) (i32.const 5))
    (i32.store8 (i32.const 66) (i32.const 6))
    (call $answer (i32.const 64) (i32.const 3))
    (call $reply (i32.const 0) (i32.const 0)))
  (func (export "answer-or-decline") (result i32)
    (i32.store8 (i32.const 128) (i32.const 1))
    (i32.store8 (i32.const 129) (i32.const 2))
    (call $answer (i32.const 128) (i32.const 2))
    (call $reply (i32.const 0) (i32.const 0))
    (i32.const 0))"#,
    )
}

#[test]
fn both_engines_read_what_a_method_hands_back_the_same_way() -> Result<()> {
    let bytes = ending_guest()?;

    for (export, expected) in [
        (
            "unit-yes",
            Invoked::Produced {
                edges: Vec::new(),
                answer: None,
            },
        ),
        ("unit-no", Invoked::Declined(9)),
        (
            "answer",
            Invoked::Produced {
                edges: Vec::new(),
                answer: Some(vec![4, 5, 6]),
            },
        ),
        (
            "answer-or-decline",
            Invoked::Produced {
                edges: Vec::new(),
                answer: Some(vec![1, 2]),
            },
        ),
    ] {
        assert_eq!(
            blessed(&bytes, export, FUEL)?.result,
            expected,
            "`{export}` on the blessed engine"
        );
        assert_eq!(
            reference(&bytes, export, FUEL)?.result,
            expected,
            "`{export}` on the reference interpreter"
        );
    }
    Ok(())
}

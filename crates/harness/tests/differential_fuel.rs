//! Exhaustion as a shared verdict.
//!
//! Both engines run the instrumented module, so the counter is decided
//! by the same instructions on both: a block is paid for at its head, a
//! bulk operator pays its bytes where it runs, and `exhaust` refuses in
//! the host. What is left to check is that neither engine adds a charge
//! of its own or drops one — that the budget at which a call first
//! completes is the same budget on both, and that every budget on the
//! way there splits the verdict the same way.
//!
//! The sweep is what makes that claim testable: at every budget across
//! the boundary the two runtimes must agree on whether the call
//! completes, and the budget at which each flips is the block each
//! stopped at.
//!
//! The host-call sweep extends the claim to the boundary supplement: the
//! bytes a host call moves through guest memory are charged into the
//! same counter the module's own checks read, so code that runs *after*
//! the call exhausts at the same budget on both sides.

use hyperscale_vm_embed::abi::{ABI, CRYPTO, MEMORY};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_meter::{FUEL, instantiation_cost};
use hyperscale_vm_ref::{
    ExecError, InstantiateError, RefInstance, RefModule, RefModuleInstance, Value,
};
use hyperscale_vm_runtime::{
    HostRefusal, Invoking, add_kernel_imports, add_meter_import, admit, admit_core_module,
    blessed_engine, instantiate_metered, invoke_export,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Engine, Error, Linker, Module, Result, Store};
use wat::parse_str;

/// A counted loop: the loop header opens a block paid for on every
/// iteration, so the exhaustion point walks with the budget.
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

/// Bulk copies charge per byte at their own check, in front of the
/// operator; the one declared page is prepaid at instantiation.
const BULK_FIXTURE: &str = r#"(module
  (memory 1 1)
  (func (export "burn") (param i32) (result i32)
    (i32.const 0)
    (i32.const 0)
    (local.get 0)
    (memory.copy)
    (local.get 0)))"#;

/// A grow charges per page at its own check, on top of the page
/// prepaid for the declared minimum.
const GROW_FIXTURE: &str = r#"(module
  (memory 1 8)
  (func (export "burn") (param i32) (result i32)
    (local.get 0)
    (memory.grow)))"#;

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Completed(i32),
    OutOfFuel,
    Other(String),
}

/// A bare fixture in both engines' runnable forms.
struct Bare {
    engine: Engine,
    module: Module,
    cost: u64,
    reference: RefModule,
}

impl Bare {
    fn admit(fixture: &str) -> Result<Self> {
        let author = parse_str(fixture)?;
        let admitted = admit_core_module(&author)?;
        let engine = blessed_engine()?;
        Ok(Self {
            module: Module::new(&engine, &admitted)?,
            cost: instantiation_cost(&author)?,
            reference: RefModule::decode(&admitted)?,
            engine,
        })
    }

    fn blessed_verdict(&self, arg: i32, fuel: u64) -> Result<Verdict> {
        let mut linker = Linker::<()>::new(&self.engine);
        add_meter_import(&mut linker)?;
        let mut store = Store::new(&self.engine, ());
        let instance = match instantiate_metered(&mut store, fuel, self.cost, |s| {
            linker.instantiate(s, &self.module)
        }) {
            Ok(instance) => instance,
            Err(e) => return Ok(refused(&e)),
        };
        let func = instance.get_typed_func::<(i32,), (i32,)>(&mut store, "burn")?;
        Ok(match func.call(&mut store, (arg,)) {
            Ok((v,)) => Verdict::Completed(v),
            Err(e) => refused(&e),
        })
    }

    fn ref_verdict(&self, arg: i32, fuel: u64) -> Result<Verdict> {
        let Some(budget) = fuel.checked_sub(self.cost) else {
            return Ok(Verdict::OutOfFuel);
        };
        let mut instance = match RefInstance::instantiate(&self.reference) {
            Ok(instance) => instance,
            Err(t) => return Ok(Verdict::Other(format!("{t:?}"))),
        };
        assert!(
            instance.set_global(FUEL, Value::I64(budget.cast_signed())),
            "an admitted module exports the counter"
        );
        Ok(match instance.invoke("burn", &[Value::I32(arg)])? {
            Ok(values) => match values.as_slice() {
                [Value::I32(v)] => Verdict::Completed(*v),
                other => Verdict::Other(format!("{other:?}")),
            },
            Err(ExecError::Host(AbortReason::OutOfGas)) => Verdict::OutOfFuel,
            Err(e) => Verdict::Other(format!("{e:?}")),
        })
    }
}

/// The blessed engine's refusal as a verdict: the meter's out of gas,
/// or anything else spelled out.
fn refused(error: &Error) -> Verdict {
    match error.downcast_ref::<HostRefusal>() {
        Some(HostRefusal(AbortReason::OutOfGas)) => Verdict::OutOfFuel,
        other => Verdict::Other(format!("{other:?}")),
    }
}

/// Sweeps the budget across the exhaustion boundary and returns the lowest
/// budget at which the call completed, asserting agreement at every step.
fn sweep(fixture: &str, arg: i32, range: std::ops::Range<u64>) -> Result<u64> {
    let bare = Bare::admit(fixture)?;
    let mut first_completion = None;
    for fuel in range.clone() {
        let blessed = bare.blessed_verdict(arg, fuel)?;
        let reference = bare.ref_verdict(arg, fuel)?;
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
    // The per-byte charge lands at its own check, ahead of the operator,
    // so the boundary sits just past the prepaid page and the byte count.
    let boundary = sweep(BULK_FIXTURE, 64, 1..400)?;
    println!("bulk fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

#[test]
fn a_grow_exhausts_at_the_same_budget() -> Result<()> {
    // Three pages grown on top of the one prepaid: four page prices and
    // a handful of operators, bracketed from both sides.
    let boundary = sweep(GROW_FIXTURE, 3, 1..1_200)?;
    println!("grow fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

/// A host call, then a counted loop: the call's boundary bytes (8 of data
/// in, 32 of digest out) are debt the loop's own checks must see, so the
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
        Invoked::Aborted(AbortReason::OutOfGas) => Verdict::OutOfFuel,
        other => Verdict::Other(format!("{other:?}")),
    }
}

fn blessed_host_call_verdict(
    engine: &Engine,
    module: &Module,
    cost: u64,
    arg: u64,
    fuel: u64,
) -> Result<Verdict> {
    let mut linker = Linker::<Invoking<NoHost>>::new(engine);
    add_kernel_imports(&mut linker)?;
    let mut store = Store::new(engine, Invoking::new(NoHost));
    let instance =
        match instantiate_metered(&mut store, fuel, cost, |s| linker.instantiate(s, module)) {
            Ok(instance) => instance,
            Err(e) => return Ok(refused(&e)),
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
        Err((_, InstantiateError::OutOfGas)) => return Ok(Verdict::OutOfFuel),
        Err((_, error)) => return Err(error.into()),
    };
    Ok(verdict(instance.invoke("burn", &[GuestArg::U64(arg)])))
}

/// As [`sweep`], for the host-call fixture: same verdict-agreement claim,
/// with the boundary supplement inside the budget.
fn host_call_sweep(arg: u64, range: std::ops::Range<u64>) -> Result<u64> {
    let author = parse_str(host_call_fixture())?;
    let admitted = admit(&author)?;
    let engine = blessed_engine()?;
    let module = Module::new(&engine, &admitted)?;
    let cost = instantiation_cost(&author)?;
    let reference = RefModule::decode(&admitted)?;
    let mut first_completion = None;
    for fuel in range.clone() {
        let blessed = blessed_host_call_verdict(&engine, &module, cost, arg, fuel)?;
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
    // Wide enough to bracket the prepaid page, the call, its 40 bytes of
    // boundary debt, the loop and the answer from both sides.
    let boundary = host_call_sweep(20, 1..1_200)?;
    println!("host-call fixture: both runtimes first complete at {boundary} fuel");
    Ok(())
}

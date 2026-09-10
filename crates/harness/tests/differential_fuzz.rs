//! Differential lane 1, generated corpus: wasm-smith modules constrained to
//! the profile subset, admitted through the meter, and executed under the
//! blessed engine and the reference interpreter with edge-value arguments.
//! Outcomes and fuel must agree, exhaustion included: both sides run the
//! same instrumented module under the same budget and out-of-fuel is
//! compared like any other verdict.
//!
//! A module the spec cannot decode is not skipped quietly: the profile
//! validator has to have rejected it too, which is the same implication
//! `differential_admission` asserts over a wider corpus.
//!
//! Nor is stack exhaustion masked any longer. The deploy-time frame bound
//! makes it unreachable for an admitted artifact, so either side reaching
//! it is a failure of that bound rather than a case to skip.
//!
//! The corpus is seeded and deterministic: every run generates the identical
//! module set.

use arbitrary::Unstructured;
use hyperscale_vm_harness::on_deep_stack;
use hyperscale_vm_meter::{FUEL as COUNTER, instantiation_cost};
use hyperscale_vm_ref::module::Ty;
use hyperscale_vm_ref::{ExecError, RefInstance, RefModule, Trap as RefTrap, Value};
use hyperscale_vm_runtime::{
    HostRefusal, add_meter_import, admit_core_module, blessed_engine, counter, instantiate_metered,
    remaining, validate_core_module,
};
use hyperscale_vm_types::AbortReason;
use wasm_smith::{Config, Module as SmithModule};
use wasmtime::{Engine, Linker, Module, Result, Store, Trap, Val};

const SEEDS: u64 = 3_072;
const ENTROPY_BYTES: usize = 4096;
const WASMTIME_FUEL: u64 = 5_000_000;
const REF_STEPS: u64 = 5_000_000;

/// Deterministic entropy from a seed: xorshift64* stream.
fn entropy(seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = Vec::with_capacity(ENTROPY_BYTES);
    while out.len() < ENTROPY_BYTES {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        out.extend_from_slice(&state.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes());
    }
    out
}

#[allow(clippy::field_reassign_with_default)] // a knob list reads better than a struct literal
fn profile_config() -> Config {
    let mut config = Config::default();
    config.allow_floats = false;
    config.simd_enabled = false;
    config.relaxed_simd_enabled = false;
    config.threads_enabled = false;
    config.shared_everything_threads_enabled = false;
    config.exceptions_enabled = false;
    config.tail_call_enabled = false;
    config.memory64_enabled = false;
    config.gc_enabled = false;
    config.reference_types_enabled = false;
    config.bulk_memory_enabled = true;
    config.extended_const_enabled = false;
    config.custom_page_sizes_enabled = false;
    config.wide_arithmetic_enabled = false;
    config.allow_start_export = false;
    config.memory_max_size_required = true;
    config.table_max_size_required = true;
    config.max_memories = 1;
    config.max_tables = 1;
    config.max_memory32_bytes = 4 * 65_536;
    config.max_table_elements = 128;
    config.max_imports = 0;
    config.min_funcs = 1;
    config.max_funcs = 8;
    config.min_exports = 1;
    config.export_everything = true;
    config
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Values(Vec<Value>),
    Trap(RefTrap),
    OutOfFuel,
    Exhausted,
    Other(String),
}

const fn map_trap(trap: Trap) -> Option<RefTrap> {
    match trap {
        Trap::UnreachableCodeReached => Some(RefTrap::Unreachable),
        Trap::IntegerDivisionByZero => Some(RefTrap::IntegerDivisionByZero),
        Trap::IntegerOverflow => Some(RefTrap::IntegerOverflow),
        Trap::MemoryOutOfBounds => Some(RefTrap::MemoryOutOfBounds),
        Trap::TableOutOfBounds => Some(RefTrap::TableOutOfBounds),
        Trap::IndirectCallToNull => Some(RefTrap::IndirectCallToNull),
        Trap::BadSignature => Some(RefTrap::BadSignature),
        _ => None,
    }
}

/// A generated module in both engines' runnable forms.
struct Fixture {
    module: Module,
    cost: u64,
    reference: RefModule,
}

fn wasmtime_outcome(
    engine: &Engine,
    fixture: &Fixture,
    export: &str,
    args: &[Value],
) -> (Outcome, Option<u64>) {
    let mut linker = Linker::<()>::new(engine);
    add_meter_import(&mut linker).expect("the meter import registers");
    let mut store = Store::new(engine, ());
    let instance = match instantiate_metered(&mut store, WASMTIME_FUEL, fixture.cost, |s| {
        linker.instantiate(s, &fixture.module)
    }) {
        Ok(i) => i,
        // Instantiation traps (an out-of-bounds active segment) compare like
        // call traps; a budget under the prepaid segments is exhaustion.
        Err(e) => {
            if matches!(
                e.downcast_ref::<HostRefusal>(),
                Some(HostRefusal(AbortReason::OutOfGas))
            ) {
                return (Outcome::OutOfFuel, None);
            }
            return (
                e.downcast_ref::<Trap>()
                    .and_then(|t| map_trap(*t))
                    .map_or_else(
                        || Outcome::Other(format!("instantiate: {e:#}")),
                        Outcome::Trap,
                    ),
                None,
            );
        }
    };
    let Some(func) = instance.get_func(&mut store, export) else {
        return (Outcome::Other("missing export".to_string()), None);
    };
    let vals: Vec<Val> = args
        .iter()
        .map(|v| match v {
            Value::I32(x) => Val::I32(*x),
            Value::I64(x) => Val::I64(*x),
        })
        .collect();
    let result_len = func.ty(&store).results().len();
    let mut results = vec![Val::I32(0); result_len];
    match func.call(&mut store, &vals, &mut results) {
        Ok(()) => {
            let counter = counter(&mut store, &instance);
            let fuel = WASMTIME_FUEL - remaining(&mut store, &counter);
            (
                Outcome::Values(
                    results
                        .iter()
                        .map(|v| match v {
                            Val::I32(x) => Value::I32(*x),
                            Val::I64(x) => Value::I64(*x),
                            other => panic!("non-integer result {other:?}"),
                        })
                        .collect(),
                ),
                Some(fuel),
            )
        }
        Err(e) => (
            match e.downcast_ref::<Trap>() {
                _ if matches!(
                    e.downcast_ref::<HostRefusal>(),
                    Some(HostRefusal(AbortReason::OutOfGas))
                ) =>
                {
                    Outcome::OutOfFuel
                }
                Some(Trap::StackOverflow) => panic!(
                    "an admitted module overflowed the engine's stack; the deploy-time \
                     frame bound is not holding"
                ),
                Some(t) => map_trap(*t).map_or_else(
                    || Outcome::Other(format!("unmapped trap {t:?}")),
                    Outcome::Trap,
                ),
                None => Outcome::Other(format!("{e:#}")),
            },
            None,
        ),
    }
}

fn ref_outcome(fixture: &Fixture, export: &str, args: &[Value]) -> (Outcome, Option<u64>) {
    let Some(budget) = WASMTIME_FUEL.checked_sub(fixture.cost) else {
        return (Outcome::OutOfFuel, None);
    };
    let mut instance = match RefInstance::instantiate(&fixture.reference) {
        Ok(i) => i,
        Err(t) => return (Outcome::Trap(t), None),
    };
    instance.set_step_limit(REF_STEPS);
    assert!(
        instance.set_global(COUNTER, Value::I64(budget.cast_signed())),
        "an admitted module exports the counter"
    );
    match instance.invoke(export, args) {
        Ok(Ok(values)) => {
            let left = instance
                .global(COUNTER)
                .expect("the counter is still exported")
                .as_i64()
                .cast_unsigned();
            (Outcome::Values(values), Some(WASMTIME_FUEL - left))
        }
        Ok(Err(ExecError::Host(AbortReason::OutOfGas))) => (Outcome::OutOfFuel, None),
        Ok(Err(ExecError::Trap(RefTrap::CallDepthExhausted))) => panic!(
            "an admitted module exhausted the spec's call depth; the deploy-time frame \
             bound is not holding"
        ),
        Ok(Err(ExecError::Trap(RefTrap::StepBudgetExhausted))) => (Outcome::Exhausted, None),
        Ok(Err(ExecError::Trap(trap))) => (Outcome::Trap(trap), None),
        Ok(Err(other)) => (Outcome::Other(format!("{other:?}")), None),
        Err(e) => (Outcome::Other(format!("{e:#}")), None),
    }
}

/// Four fixed argument sets per signature, exercising zero, unit, extreme,
/// and mixed values.
fn arg_sets(params: &[bool]) -> Vec<Vec<Value>> {
    let make = |pick: fn(bool, usize) -> Value| {
        params
            .iter()
            .enumerate()
            .map(|(i, is64)| pick(*is64, i))
            .collect::<Vec<_>>()
    };
    vec![
        make(|is64, _| if is64 { Value::I64(0) } else { Value::I32(0) }),
        make(|is64, _| if is64 { Value::I64(1) } else { Value::I32(1) }),
        make(|is64, i| {
            if is64 {
                Value::I64(if i % 2 == 0 { i64::MIN } else { i64::MAX })
            } else {
                Value::I32(if i % 2 == 0 { i32::MIN } else { i32::MAX })
            }
        }),
        make(|is64, i| {
            let i = i64::try_from(i).expect("small arity");
            if is64 {
                Value::I64(7 - 2 * i)
            } else {
                Value::I32(i32::try_from(7 - 2 * i).expect("small arity"))
            }
        }),
    ]
}

#[test]
fn generated_corpus_agrees_between_blessed_engine_and_vm_ref() -> Result<()> {
    on_deep_stack(fuzz_body)
}

fn fuzz_body() -> Result<()> {
    let engine = blessed_engine()?;
    let config = profile_config();

    let mut generated = 0usize;
    let mut skipped_decode = 0usize;
    let mut skipped_profile = 0usize;
    let mut compared = 0usize;
    let mut exhausted = 0usize;

    for seed in 0..SEEDS {
        let bytes = entropy(seed);
        let mut u = Unstructured::new(&bytes);
        let Ok(module) = SmithModule::new(config.clone(), &mut u) else {
            continue;
        };
        let wasm = module.to_bytes();
        generated += 1;

        let ref_module = match RefModule::decode(&wasm) {
            Ok(module) => module,
            Err(e) => {
                // The spec's refusal is only sound if the profile refuses
                // too; otherwise the artifact deploys and cannot execute.
                assert!(
                    validate_core_module(&wasm).is_err(),
                    "seed {seed}: the profile admits a module the spec rejects: {e}"
                );
                skipped_decode += 1;
                continue;
            }
        };
        // Bulk memory generates table and passive-segment operators the
        // profile excludes; those modules leave the lane here.
        let Ok(admitted) = admit_core_module(&wasm) else {
            skipped_profile += 1;
            continue;
        };
        let fixture = Fixture {
            module: Module::new(&engine, &admitted)?,
            cost: instantiation_cost(&wasm)?,
            reference: RefModule::decode(&admitted)?,
        };

        let mut exports: Vec<(String, u32)> = ref_module
            .exports
            .iter()
            .map(|(n, i)| (n.clone(), *i))
            .collect();
        exports.sort();

        for (export, func_idx) in exports {
            let params: Vec<bool> = ref_module
                .func_type(func_idx)
                .params
                .iter()
                .map(|t| matches!(t, Ty::I64))
                .collect();
            for args in arg_sets(&params) {
                let (blessed, blessed_fuel) = wasmtime_outcome(&engine, &fixture, &export, &args);
                let (reference, ref_fuel) = ref_outcome(&fixture, &export, &args);
                if blessed == Outcome::Exhausted || reference == Outcome::Exhausted {
                    exhausted += 1;
                    continue;
                }
                assert_eq!(
                    blessed, reference,
                    "divergence at seed {seed} export {export} args {args:?}"
                );
                if let (Some(b), Some(r)) = (blessed_fuel, ref_fuel) {
                    assert_eq!(
                        b, r,
                        "fuel diverged at seed {seed} export {export} args {args:?}"
                    );
                }
                compared += 1;
            }
        }
    }

    println!(
        "fuzz lane: {generated} modules generated, {skipped_decode} skipped at decode, \
         {skipped_profile} outside the profile, {compared} invocations compared, \
         {exhausted} skipped as exhausted"
    );
    assert!(
        compared > 500,
        "corpus yield too low: {compared} comparisons"
    );
    Ok(())
}

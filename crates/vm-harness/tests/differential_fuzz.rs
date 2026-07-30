//! Differential lane 1, generated corpus: wasm-smith modules constrained to
//! the profile subset, executed under the blessed engine and the reference
//! interpreter with edge-value arguments. Outcomes must agree whenever both
//! sides terminate within budget; either side exhausting its budget skips the
//! comparison (the fuel and step schedules are not comparable until the fuel
//! spec artifact lands).
//!
//! The corpus is seeded and deterministic: every run generates the identical
//! module set.

use anyhow::Result;
use arbitrary::Unstructured;
use hyperscale_vm_ref::module::Ty;
use hyperscale_vm_ref::{RefInstance, RefModule, Trap as RefTrap, Value};
use hyperscale_vm_runtime::blessed_engine;
use wasm_smith::{Config, Module as SmithModule};
use wasmtime::{Engine, Instance, Module, Store, Trap, Val};

const SEEDS: u64 = 256;
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
    config.bulk_memory_enabled = false;
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

fn wasmtime_outcome(engine: &Engine, module: &Module, export: &str, args: &[Value]) -> Outcome {
    let mut store = Store::new(engine, ());
    store.set_fuel(WASMTIME_FUEL).expect("fuel on");
    let instance = match Instance::new(&mut store, module, &[]) {
        Ok(i) => i,
        // Instantiation traps (an out-of-bounds active segment) compare like
        // call traps.
        Err(e) => {
            return e
                .downcast_ref::<Trap>()
                .and_then(|t| map_trap(*t))
                .map_or_else(
                    || Outcome::Other(format!("instantiate: {e:#}")),
                    Outcome::Trap,
                );
        }
    };
    let Some(func) = instance.get_func(&mut store, export) else {
        return Outcome::Other("missing export".to_string());
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
        Ok(()) => Outcome::Values(
            results
                .iter()
                .map(|v| match v {
                    Val::I32(x) => Value::I32(*x),
                    Val::I64(x) => Value::I64(*x),
                    other => panic!("non-integer result {other:?}"),
                })
                .collect(),
        ),
        Err(e) => match e.downcast_ref::<Trap>() {
            Some(Trap::OutOfFuel | Trap::StackOverflow) => Outcome::Exhausted,
            Some(t) => map_trap(*t).map_or_else(
                || Outcome::Other(format!("unmapped trap {t:?}")),
                Outcome::Trap,
            ),
            None => Outcome::Other(format!("{e:#}")),
        },
    }
}

fn ref_outcome(module: &RefModule, export: &str, args: &[Value]) -> Outcome {
    let mut instance = match RefInstance::instantiate(module) {
        Ok(i) => i,
        Err(t) => return Outcome::Trap(t),
    };
    instance.set_step_limit(REF_STEPS);
    match instance.invoke(export, args) {
        Ok(Ok(values)) => Outcome::Values(values),
        Ok(Err(RefTrap::StepBudgetExhausted | RefTrap::CallDepthExhausted)) => Outcome::Exhausted,
        Ok(Err(trap)) => Outcome::Trap(trap),
        Err(e) => Outcome::Other(format!("{e:#}")),
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
    // The interpreter recurses on the Rust stack, and its debug-build frames
    // at 512 call depth exceed the default test-thread stack.
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(fuzz_body)
        .expect("spawn fuzz thread")
        .join()
        .expect("fuzz thread panicked")
}

fn fuzz_body() -> Result<()> {
    let engine = blessed_engine()?;
    let config = profile_config();

    let mut generated = 0usize;
    let mut skipped_decode = 0usize;
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

        let Ok(ref_module) = RefModule::decode(&wasm) else {
            skipped_decode += 1;
            continue;
        };
        let wasmtime_module = Module::new(&engine, &wasm)?;

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
                let blessed = wasmtime_outcome(&engine, &wasmtime_module, &export, &args);
                let reference = ref_outcome(&ref_module, &export, &args);
                if blessed == Outcome::Exhausted || reference == Outcome::Exhausted {
                    exhausted += 1;
                    continue;
                }
                assert_eq!(
                    blessed, reference,
                    "divergence at seed {seed} export {export} args {args:?}"
                );
                compared += 1;
            }
        }
    }

    println!(
        "fuzz lane: {generated} modules generated, {skipped_decode} skipped at decode, \
         {compared} invocations compared, {exhausted} skipped as exhausted"
    );
    assert!(
        compared > 500,
        "corpus yield too low: {compared} comparisons"
    );
    Ok(())
}

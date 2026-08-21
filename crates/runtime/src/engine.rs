//! The blessed engine configuration.
//!
//! One constructor produces the locked [`wasmtime::Config`]; no other
//! configuration path exists, so nothing can accidentally run outside the
//! profile. Fuel is always on and priced by [`crate::fuel`], the profile's
//! disabled proposals are disabled here as defense in depth behind the
//! deploy validator, and NaN canonicalization is enabled even though the
//! profile bans floats.

use wasmtime::{Config, Engine, Result, Strategy};

use crate::fuel::blessed_operator_cost;
use crate::profile::{MAX_MEMORY_PAGES, MAX_WASM_STACK_BYTES};

/// One wasm page: the unit [`MAX_MEMORY_PAGES`] counts.
const WASM_PAGE_BYTES: u64 = 64 * 1024;

/// The locked engine configuration.
#[must_use]
pub fn blessed_config() -> Config {
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    config.consume_fuel(true);
    // Price operators from the canonical schedule rather than the engine's
    // own defaults, so what a receipt reports is a fact about this
    // workspace and not about the version of the engine that ran it.
    config.operator_cost(blessed_operator_cost());
    config.cranelift_nan_canonicalization(true);
    config.wasm_component_model(true);
    config.wasm_component_model_async(false);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config.wasm_threads(false);
    config.wasm_tail_call(false);
    config.wasm_memory64(false);
    config.wasm_gc(false);
    config.wasm_exceptions(false);
    config.wasm_extended_const(false);
    config.wasm_multi_memory(false);
    config.wasm_stack_switching(false);
    config.max_wasm_stack(MAX_WASM_STACK_BYTES);
    // Copy-on-write memory images charge instantiation fuel by the
    // host-page-rounded image span — a host-platform-dependent number.
    // Disabling them makes active-data-segment initialization cost one fuel
    // per byte plus one per segment, identical on every host.
    config.memory_init_cow(false);
    // Map linear memories at the profile's own ceiling instead of
    // wasmtime's 4 GiB span: every invocation maps and unmaps a fresh
    // memory, and the mapped span is that path's cost — page-table work
    // scales with it, and concurrent invocations serialize on the
    // address-space lock. The profile caps every memory at
    // MAX_MEMORY_PAGES, so this reservation admits every grow; the
    // one-page guard trades elided bounds checks for explicit ones, which
    // the smaller mapping repays (measured in the harness allocation
    // spike, which also pins receipt identity across mapping strategies).
    config.memory_reservation(MAX_MEMORY_PAGES * WASM_PAGE_BYTES);
    config.memory_guard_size(WASM_PAGE_BYTES);
    config
}

/// The blessed engine: [`blessed_config`], instantiated.
///
/// # Errors
///
/// Fails only if the host cannot honor the locked configuration (an engine
/// build defect, never an input-dependent condition).
pub fn blessed_engine() -> Result<Engine> {
    Engine::new(&blessed_config())
}

#[cfg(test)]
mod tests {
    use wasmtime::Module;
    use wasmtime::component::Component;
    use wat::parse_str;

    use super::blessed_engine;

    /// Everything [`crate::validator::profile_features`] admits, the
    /// blessed engine compiles: one witness per feature the profile
    /// turns on, so a config edit that quietly disabled one fails here
    /// rather than at the first deployed package that uses it.
    #[test]
    fn the_blessed_engine_accepts_every_profile_feature() {
        let engine = blessed_engine().expect("the blessed engine configures");
        let core = |name: &str, wat: &str| {
            Module::new(&engine, wat)
                .unwrap_or_else(|error| panic!("{name} is in the profile: {error}"));
        };
        core(
            "mutable globals",
            "(module (global (export \"g\") (mut i32) (i32.const 0)))",
        );
        core(
            "sign extension",
            "(module (func (param i32) (result i32) local.get 0 i32.extend8_s))",
        );
        core(
            "multi-value",
            "(module (func (result i32 i32) i32.const 1 i32.const 2))",
        );
        core(
            "bulk memory",
            "(module (memory 1) (func (memory.copy (i32.const 0) (i32.const 0) (i32.const 0))))",
        );
        core(
            "call_indirect over a declared table",
            "(module (table 1 1 funcref) (type $t (func))
                 (func (i32.const 0) (call_indirect (type $t)))
                 (func $f (type $t)))",
        );
        Component::new(&engine, parse_str("(component)").expect("parses"))
            .expect("the component model is in the profile");
    }
}

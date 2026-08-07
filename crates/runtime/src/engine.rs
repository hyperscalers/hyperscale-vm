//! The blessed engine configuration.
//!
//! One constructor produces the locked [`wasmtime::Config`]; no other
//! configuration path exists, so nothing can accidentally run outside the
//! profile. Fuel is always on, the profile's disabled proposals are disabled
//! here as defense in depth behind the deploy validator, and NaN
//! canonicalization is enabled even though the profile bans floats.

use wasmtime::{Config, Engine, Result, Strategy};

use crate::profile::MAX_WASM_STACK_BYTES;

/// The locked engine configuration.
#[must_use]
pub fn blessed_config() -> Config {
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    config.consume_fuel(true);
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

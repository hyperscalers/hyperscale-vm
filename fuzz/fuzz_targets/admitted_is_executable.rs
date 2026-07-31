//! The admission implication, fuzzed.
//!
//! `differential_admission` asserts it over a seeded corpus, which is what
//! CI can afford; this is the workstation lane the promotion policy in
//! `docs/determinism-audit.md` presumes. A finding here is promoted by
//! checking its module into the seeded lane before the fix merges.

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use hyperscale_vm_ref::RefModule;
use hyperscale_vm_runtime::validate_core_module;
use libfuzzer_sys::fuzz_target;
use wasm_smith::{Config, Module};

/// Deliberately wider than the profile: the interesting inputs are the
/// ones the validator has to refuse.
fn config() -> Config {
    let mut config = Config::arbitrary(&mut Unstructured::new(&[])).unwrap_or_default();
    config.allow_floats = false;
    config.simd_enabled = false;
    config.relaxed_simd_enabled = false;
    config.threads_enabled = false;
    config.shared_everything_threads_enabled = false;
    config.exceptions_enabled = false;
    config.tail_call_enabled = false;
    config.memory64_enabled = false;
    config.gc_enabled = false;
    config.custom_page_sizes_enabled = false;
    config.wide_arithmetic_enabled = false;
    config.allow_start_export = false;
    config.max_memories = 1;
    config.max_memory32_bytes = 4 * 65_536;
    config.max_table_elements = 128;
    config.min_funcs = 1;
    config.max_funcs = 8;
    config.min_exports = 1;
    config.export_everything = true;
    config
}

fuzz_target!(|data: &[u8]| {
    let mut unstructured = Unstructured::new(data);
    let Ok(module) = Module::new(config(), &mut unstructured) else {
        return;
    };
    let wasm = module.to_bytes();
    if validate_core_module(&wasm).is_ok() {
        assert!(
            RefModule::decode(&wasm).is_ok(),
            "the profile admits a module the executable spec cannot decode"
        );
    }
});

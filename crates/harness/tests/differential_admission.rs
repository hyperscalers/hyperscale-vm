//! The admission lane: everything the profile validator admits has an
//! executable-spec witness.
//!
//! The other lanes compare two runtimes on artifacts both of them accept.
//! This one asserts the implication that makes those comparisons mean
//! something — a deployable artifact `vm-ref` cannot decode is a socket in
//! the profile whether or not any fixture happens to exercise it, and the
//! surfaces drift apart as the validator and the spec evolve. Asserting
//! the implication structurally is what keeps them from doing so quietly.

use arbitrary::Unstructured;
use hyperscale_vm_harness::fixtures::KERNEL_GUEST_WAT;
use hyperscale_vm_ref::{RefComponent, RefModule};
use hyperscale_vm_runtime::{validate_component, validate_core_module};
use hyperscale_vm_stdlib::ACCOUNT_COMPONENT;
use wasm_smith::{Config, Module as SmithModule};
use wasmtime::Result;
use wat::parse_str;

const SEEDS: u64 = 2_048;
const ENTROPY_BYTES: usize = 16_384;

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

/// Generation shaped like the profile, so most of the corpus is admitted
/// and the implication is asserted over real volume.
fn profile_config() -> Config {
    let mut config = permissive_config();
    config.gc_enabled = false;
    config.reference_types_enabled = false;
    config.bulk_memory_enabled = false;
    config.extended_const_enabled = false;
    config.max_tables = 1;
    config.max_imports = 0;
    config.memory_max_size_required = true;
    config.table_max_size_required = true;
    config
}

/// Generation deliberately wider than the profile: the interesting cases
/// are the ones the validator has to refuse, so bulk memory, references,
/// typed function references, GC, extended const, and multiple tables are
/// all on.
///
/// `gc_enabled` drives both the GC proposal and typed function references,
/// which is why it is on here: those are shapes that reach a signature or a
/// local rather than an operator, and a corpus that never generates one
/// cannot witness the profile refusing it.
#[allow(clippy::field_reassign_with_default)] // a knob list reads better than a struct literal
fn permissive_config() -> Config {
    let mut config = Config::default();
    config.allow_floats = false;
    config.simd_enabled = false;
    config.relaxed_simd_enabled = false;
    config.threads_enabled = false;
    config.shared_everything_threads_enabled = false;
    config.exceptions_enabled = false;
    config.tail_call_enabled = false;
    config.memory64_enabled = false;
    config.gc_enabled = true;
    config.reference_types_enabled = true;
    config.bulk_memory_enabled = true;
    config.extended_const_enabled = true;
    config.custom_page_sizes_enabled = false;
    config.wide_arithmetic_enabled = false;
    config.allow_start_export = false;
    config.max_memories = 1;
    config.max_tables = 2;
    config.max_memory32_bytes = 4 * 65_536;
    config.max_table_elements = 128;
    config.max_imports = 4;
    config.min_funcs = 1;
    config.max_funcs = 8;
    config.min_exports = 1;
    config.export_everything = true;
    config
}

#[test]
fn every_admitted_core_module_decodes_under_the_spec() {
    let mut admitted = 0usize;
    let mut rejected = 0usize;

    // Two corpora: one shaped like the profile, so the implication is
    // asserted over volume, and one deliberately outside it, so the
    // validator's refusals are exercised rather than assumed.
    for (shape, config) in [("profile", profile_config()), ("wide", permissive_config())] {
        for seed in 0..SEEDS {
            let bytes = entropy(seed);
            let mut u = Unstructured::new(&bytes);
            let Ok(module) = SmithModule::new(config.clone(), &mut u) else {
                continue;
            };
            let wasm = module.to_bytes();

            match validate_core_module(&wasm) {
                Ok(()) => {
                    admitted += 1;
                    assert!(
                        RefModule::decode(&wasm).is_ok(),
                        "{shape} seed {seed}: the profile admits a module \
                         the spec cannot decode"
                    );
                }
                Err(_) => rejected += 1,
            }
        }
    }

    println!("admission lane: {admitted} admitted, {rejected} rejected");
    assert!(
        admitted > 50,
        "corpus yield too low to be evidence: {admitted} admitted"
    );
    assert!(
        rejected > 0,
        "the corpus exercises nothing outside the profile"
    );
}

/// The typed-function-reference surfaces, pinned by hand.
///
/// A generated corpus witnesses these only when the generator happens to
/// emit one, and the shapes reach a local or a signature rather than an
/// operator — so the same implication the lane asserts over volume is
/// asserted here over the exact cases a blocklist would miss.
#[test]
fn typed_function_references_have_no_witness_and_no_admission() {
    let fixtures = [
        (
            "typed funcref local",
            r#"(module
                (type $sig (func (result i32)))
                (func (export "run") (result i32)
                  (local $callee (ref null $sig))
                  i32.const 0))"#,
        ),
        (
            "call_ref",
            r#"(module
                (type $sig (func (result i32)))
                (func (export "run") (result i32)
                  (local $callee (ref null $sig))
                  local.get $callee
                  call_ref $sig))"#,
        ),
        (
            "typed funcref parameter",
            r#"(module
                (type $sig (func (result i32)))
                (func (export "run") (param $callee (ref null $sig)) (result i32)
                  i32.const 0))"#,
        ),
    ];

    for (name, wat) in fixtures {
        let wasm = parse_str(wat).expect("fixture parses");
        assert!(
            RefModule::decode(&wasm).is_err(),
            "{name}: the spec decodes it, so the profile could admit it"
        );
        assert!(
            validate_core_module(&wasm).is_err(),
            "{name}: the profile admits a module the spec cannot decode"
        );
    }
}

#[test]
fn every_admitted_component_decodes_under_the_spec() -> Result<()> {
    // The hand-written world guest and the committed stdlib artifact are
    // the two component shapes the profile actually ships.
    let wat = parse_str(KERNEL_GUEST_WAT)?;
    for (name, bytes) in [
        ("kernel-guest", wat.as_slice()),
        ("stdlib", ACCOUNT_COMPONENT),
    ] {
        validate_component(bytes).unwrap_or_else(|e| panic!("{name} must validate: {e}"));
        RefComponent::decode(bytes)
            .unwrap_or_else(|e| panic!("{name} validates but the spec cannot decode it: {e}"));
    }
    Ok(())
}

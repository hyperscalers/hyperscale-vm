//! The profile rejection corpus: one fixture per validator rule, plus the
//! acceptance case proving a conforming kernel guest passes validation
//! and compiles under the blessed engine.
//!
//! The bare rules — the feature set, the structural limits, the stack
//! bound — are judged through `validate_core_module`, which asks nothing
//! of a module's imports and exports; the boundary rules through
//! `validate_module`, which holds both to what the kernel defines.

mod common;

use common::module;
use hyperscale_vm_runtime::profile::MAX_ARTIFACT_BYTES;
use hyperscale_vm_runtime::{ProfileError, blessed_engine, validate_core_module, validate_module};
use wasmtime::Module;
use wat::parse_str;

/// A bare core module carrying `core`.
fn core(core: &str) -> Vec<u8> {
    parse_str(format!("(module {core})")).expect("fixture must parse")
}

fn assert_rejected(bytes: &[u8], expect: &str) {
    let err = validate_core_module(bytes).expect_err("fixture must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains(expect),
        "expected rejection mentioning {expect:?}, got: {msg}"
    );
}

#[test]
fn accepts_a_conforming_kernel_guest() {
    // Kernel imports at the kernel's types, the memory, and an export of
    // every admitted shape. The profile must accept it and the blessed
    // engine must compile it.
    let guest = parse_str(module(
        r#"
  (func (export "run") (param i32 i32) (result i32)
    (local i32)
    local.get 0 i32.const 0 call $site_get local.set 2
    i32.const 64 call $take
    local.get 1 i32.const 0 i32.const 64 local.get 2 call $site_set
    i32.const 0 i32.const 0 call $reply
    i32.const 0)
  (func (export "quiet") (param i64) i32.const 0 i32.const 0 call $reply)"#,
    ))
    .expect("guest must parse");

    validate_module(&guest).expect("conforming guest must validate");
    let engine = blessed_engine().expect("blessed engine");
    Module::new(&engine, &guest).expect("blessed engine must compile the guest");
}

#[test]
fn rejects_floats() {
    let bytes = core("(func (param f64) (result f64) local.get 0 local.get 0 f64.add)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_simd() {
    let bytes = core("(func (result v128) v128.const i64x2 0 0)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_shared_memory() {
    let bytes = core("(memory 1 1 shared)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_tail_calls() {
    let bytes = core("(func $a) (func return_call $a)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_exception_tags() {
    let bytes = core("(tag (param i32))");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_gc_types() {
    let bytes = core("(type (struct (field i32)))");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_imports_outside_the_kernel() {
    let bytes = core(r#"(import "wasi:io/poll" "poll" (func)) (memory (export "memory") 1 1)"#);
    let err = validate_module(&bytes).expect_err("fixture must be rejected");
    assert!(
        matches!(err, ProfileError::ForbiddenImport(ref name) if name == "wasi:io/poll/poll"),
        "{err}"
    );
}

#[test]
fn rejects_start_sections() {
    let bytes = core("(func $init) (start $init)");
    assert!(matches!(
        validate_core_module(&bytes),
        Err(ProfileError::StartSection)
    ));
}

#[test]
fn rejects_memory_without_or_over_maximum() {
    let unbounded = core("(memory 1)");
    assert_rejected(&unbounded, "without a declared maximum");

    let oversized = core("(memory 1 300)");
    assert_rejected(&oversized, "exceeds");
}

#[test]
fn rejects_too_many_functions() {
    let funcs = "(func) ".repeat(10_001);
    let bytes = core(&funcs);
    assert_rejected(&bytes, "functions per module");
}

#[test]
fn rejects_too_many_types() {
    let mut types = String::new();
    for i in 0..1_001 {
        use std::fmt::Write as _;
        let _ = write!(types, "(type (func (param {})))", "i32 ".repeat(i % 8));
    }
    let bytes = core(&types);
    assert_rejected(&bytes, "types per module");
}

#[test]
fn rejects_oversized_function_bodies() {
    let body = "nop\n".repeat(140_000);
    let bytes = core(&format!("(func {body})"));
    assert_rejected(&bytes, "function body bytes");
}

#[test]
fn rejects_too_many_params() {
    let params = "(param i32) ".repeat(40);
    let bytes = core(&format!("(func {params})"));
    assert_rejected(&bytes, "params per function");
}

#[test]
fn rejects_too_many_locals() {
    let locals = "(local i32) ".repeat(600);
    let bytes = core(&format!("(func {locals})"));
    assert_rejected(&bytes, "locals per function");
}

#[test]
fn rejects_excessive_blocks() {
    let blocks = "block end\n".repeat(11_000);
    let bytes = core(&format!("(func {blocks})"));
    assert_rejected(&bytes, "blocks per function");
}

#[test]
fn rejects_oversized_artifacts() {
    let bytes = vec![0u8; MAX_ARTIFACT_BYTES + 1];
    assert!(matches!(
        validate_module(&bytes),
        Err(ProfileError::ArtifactTooLarge { .. })
    ));
}

#[test]
fn rejects_passive_data_and_its_operators() {
    // The spec applies active segments at instantiation and models no
    // other form, so `memory.init`/`data.drop` and the segments they read
    // have no executable witness.
    let bytes = core(
        r#"(memory 1 1) (data "abc") (func (i32.const 0) (i32.const 0) (i32.const 3) (memory.init 0))"#,
    );
    assert_rejected(&bytes, "profile");

    let bytes = core(r#"(memory 1 1) (data "abc")"#);
    assert_rejected(&bytes, "passive data segments");
}

#[test]
fn bounds_data_segments_by_the_memory_minimum() {
    // A segment that ends exactly at the minimum is admitted; one byte
    // further would trap every instantiation, so it never deploys.
    let inside = core(r#"(memory 1 1) (data (i32.const 65533) "abc")"#);
    validate_core_module(&inside).expect("a segment inside the minimum must be admitted");

    let outside = core(r#"(memory 1 1) (data (i32.const 65534) "abc")"#);
    assert_rejected(&outside, "memory minimum");
}

#[test]
fn bounds_data_segments_by_an_imported_memory_minimum() {
    let outside = core(r#"(import "env" "mem" (memory 1 1)) (data (i32.const 65534) "abc")"#);
    assert_rejected(&outside, "memory minimum");
}

#[test]
fn bounds_element_segments_by_the_table_minimum() {
    let inside = core("(table 2 2 funcref) (func $f) (elem (i32.const 1) func $f)");
    validate_core_module(&inside).expect("a segment inside the minimum must be admitted");

    let outside = core("(table 2 2 funcref) (func $f) (elem (i32.const 2) func $f)");
    assert_rejected(&outside, "table minimum");
}

#[test]
fn rejects_reference_typed_globals_and_initializers() {
    // The operator blocklist walks function bodies; a global initializer
    // is not one, and the spec's const-expression vocabulary is integers.
    let bytes = core("(global externref (ref.null extern))");
    assert_rejected(&bytes, "profile");

    let bytes = core("(global i32 (i32.const 1)) (global i32 (global.get 0))");
    assert_rejected(&bytes, "profile");
}

#[test]
fn rejects_core_global_and_tag_imports() {
    let bytes = core(r#"(import "env" "g" (global i32))"#);
    assert_rejected(&bytes, "function, memory, and table imports");
}

#[test]
fn rejects_a_cyclic_call_graph() {
    // Recursion leaves the native stack unbounded, and the engine has no
    // wasm-level depth counter to trap on, so the bound is proven at
    // deploy or not at all.
    let bytes = core("(func (result i32) call 0)");
    assert_rejected(&bytes, "cyclic");

    let bytes = core("(func (result i32) call 1) (func (result i32) call 0)");
    assert_rejected(&bytes, "cyclic");
}

#[test]
fn rejects_a_call_chain_that_will_not_fit() {
    // Each frame carries 512 locals; enough of them in a row and the
    // chain no longer fits the stack the profile reserves for it.
    let locals = "(local i64) ".repeat(512);
    let chain: String = (0..32)
        .map(|i| format!("(func {locals} call {})", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = core(&format!("{chain}\n(func)"));
    assert_rejected(&bytes, "call chain");
}

#[test]
fn accepts_a_deep_but_light_chain() {
    // Depth alone is not the bound — weight is. A long chain of small
    // frames stays well inside it.
    let chain: String = (0..64)
        .map(|i| format!("(func call {})", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = core(&format!("{chain}\n(func)"));
    validate_core_module(&bytes).expect("a light chain must be admitted");
}

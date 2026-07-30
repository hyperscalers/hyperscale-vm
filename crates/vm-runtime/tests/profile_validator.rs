//! The profile rejection corpus: one fixture per validator rule, plus the
//! acceptance case proving a conforming kernel-world guest passes validation
//! and compiles under the blessed engine.

use hyperscale_vm_runtime::profile::MAX_COMPONENT_BYTES;
use hyperscale_vm_runtime::{ProfileError, blessed_engine, validate_component};
use wasmtime::component::Component;
use wat::parse_str;

/// Wraps a core-module body in a minimal component.
fn component_with_core(core: &str) -> Vec<u8> {
    parse_str(format!("(component (core module {core}))")).expect("fixture must parse")
}

fn assert_rejected(bytes: &[u8], expect: &str) {
    let err = validate_component(bytes).expect_err("fixture must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains(expect),
        "expected rejection mentioning {expect:?}, got: {msg}"
    );
}

#[test]
fn accepts_a_conforming_kernel_world_guest() {
    // The milestone 1 capability-shape guest: kernel imports, resource
    // handles, borrow drops. The profile must accept it and the blessed
    // engine must compile it.
    let guest = parse_str(
        r#"
        (component
          (import "hyperscale:kernel/state" (instance $kernel
            (export "substate" (type $substate (sub resource)))
            (export "read" (func (param "s" (borrow $substate)) (result u64)))
            (export "write" (func (param "s" (borrow $substate)) (param "v" u64)))))
          (alias export $kernel "substate" (type $substate))
          (alias export $kernel "read" (func $read))
          (alias export $kernel "write" (func $write))
          (core func $read_l (canon lower (func $read)))
          (core func $write_l (canon lower (func $write)))
          (core func $drop_l (canon resource.drop $substate))
          (core module $m
            (import "k" "read" (func $read (param i32) (result i64)))
            (import "k" "write" (func $write (param i32 i64)))
            (import "k" "drop" (func $drop (param i32)))
            (func (export "run") (param i32 i32) (result i64)
              (local i64)
              local.get 1
              local.get 0
              call $read
              i64.const 1
              i64.add
              call $write
              local.get 0
              call $read
              local.set 2
              local.get 0
              call $drop
              local.get 1
              call $drop
              local.get 2))
          (core instance $i (instantiate $m
            (with "k" (instance
              (export "read" (func $read_l))
              (export "write" (func $write_l))
              (export "drop" (func $drop_l))))))
          (func (export "run")
            (param "a" (borrow $substate)) (param "b" (borrow $substate)) (result u64)
            (canon lift (core func $i "run"))))
        "#,
    )
    .expect("guest must parse");

    validate_component(&guest).expect("conforming guest must validate");
    let engine = blessed_engine().expect("blessed engine");
    Component::new(&engine, &guest).expect("blessed engine must compile the guest");
}

#[test]
fn rejects_bare_core_modules() {
    let module = parse_str("(module)").unwrap();
    assert!(matches!(
        validate_component(&module),
        Err(ProfileError::NotAComponent)
    ));
}

#[test]
fn rejects_floats() {
    let bytes =
        component_with_core("(func (param f64) (result f64) local.get 0 local.get 0 f64.add)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_simd() {
    let bytes = component_with_core("(func (result v128) v128.const i64x2 0 0)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_shared_memory() {
    let bytes = component_with_core("(memory 1 1 shared)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_tail_calls() {
    let bytes = component_with_core("(func $a) (func return_call $a)");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_imports_outside_the_kernel_world() {
    let bytes = parse_str(r#"(component (import "wasi:io/poll" (instance)))"#).unwrap();
    assert_rejected(&bytes, "import outside the kernel world");
}

#[test]
fn rejects_start_sections() {
    let bytes = component_with_core("(func $init) (start $init)");
    assert!(matches!(
        validate_component(&bytes),
        Err(ProfileError::StartSection)
    ));
}

#[test]
fn rejects_memory_without_or_over_maximum() {
    let unbounded = component_with_core("(memory 1)");
    assert_rejected(&unbounded, "without a declared maximum");

    let oversized = component_with_core("(memory 1 300)");
    assert_rejected(&oversized, "exceeds");
}

#[test]
fn rejects_too_many_functions() {
    let funcs = "(func) ".repeat(10_001);
    let bytes = component_with_core(&funcs);
    assert_rejected(&bytes, "functions per module");
}

#[test]
fn rejects_too_many_types() {
    let mut types = String::new();
    for i in 0..1_001 {
        use std::fmt::Write as _;
        let _ = write!(types, "(type (func (param {})))", "i32 ".repeat(i % 8));
    }
    let bytes = component_with_core(&types);
    assert_rejected(&bytes, "types per module");
}

#[test]
fn rejects_oversized_function_bodies() {
    let body = "nop\n".repeat(140_000);
    let bytes = component_with_core(&format!("(func {body})"));
    assert_rejected(&bytes, "function body bytes");
}

#[test]
fn rejects_too_many_params() {
    let params = "(param i32) ".repeat(40);
    let bytes = component_with_core(&format!("(func {params})"));
    assert_rejected(&bytes, "params per function");
}

#[test]
fn rejects_too_many_locals() {
    let locals = "(local i32) ".repeat(600);
    let bytes = component_with_core(&format!("(func {locals})"));
    assert_rejected(&bytes, "locals per function");
}

#[test]
fn rejects_excessive_blocks() {
    let blocks = "block end\n".repeat(11_000);
    let bytes = component_with_core(&format!("(func {blocks})"));
    assert_rejected(&bytes, "blocks per function");
}

#[test]
fn rejects_oversized_artifacts() {
    let bytes = vec![0u8; MAX_COMPONENT_BYTES + 1];
    assert!(matches!(
        validate_component(&bytes),
        Err(ProfileError::ComponentTooLarge { .. })
    ));
}

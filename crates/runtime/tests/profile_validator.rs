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
fn rejects_exception_tags() {
    let bytes = component_with_core("(tag (param i32))");
    assert_rejected(&bytes, "outside the profile feature set");
}

#[test]
fn rejects_gc_types() {
    let bytes = component_with_core("(type (struct (field i32)))");
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
fn rejects_a_tuple_that_is_not_a_run_of_edges() {
    // A tuple is admitted for one reason — it is how a method with more
    // than one edge returns them — so a tuple of anything else is a shape
    // with no meaning in the world rather than a value type to model.
    let bytes = parse_str(
        r#"
(component
  (core module $m
    (memory (export "mem") 1 1)
    (func (export "f") (result i32) (i32.const 0)))
  (core instance $i (instantiate $m))
  (type $pair (tuple u64 u64))
  (func (export "f") (result $pair)
    (canon lift (core func $i "f") (memory $i "mem"))))
"#,
    )
    .expect("fixture must parse");
    assert_rejected(&bytes, "tuple of owned handles");
}

#[test]
fn rejects_oversized_artifacts() {
    let bytes = vec![0u8; MAX_COMPONENT_BYTES + 1];
    assert!(matches!(
        validate_component(&bytes),
        Err(ProfileError::ComponentTooLarge { .. })
    ));
}

#[test]
fn rejects_passive_data_and_its_operators() {
    // The spec applies active segments at instantiation and models no
    // other form, so `memory.init`/`data.drop` and the segments they read
    // have no executable witness.
    let bytes = component_with_core(
        r#"(memory 1 1) (data "abc") (func (i32.const 0) (i32.const 0) (i32.const 3) (memory.init 0))"#,
    );
    assert_rejected(&bytes, "profile");

    let bytes = component_with_core(r#"(memory 1 1) (data "abc")"#);
    assert_rejected(&bytes, "passive data segments");
}

#[test]
fn bounds_data_segments_by_the_memory_minimum() {
    // A segment that ends exactly at the minimum is admitted; one byte
    // further would trap every instantiation, so it never deploys.
    let inside = component_with_core(r#"(memory 1 1) (data (i32.const 65533) "abc")"#);
    validate_component(&inside).expect("a segment inside the minimum must be admitted");

    let outside = component_with_core(r#"(memory 1 1) (data (i32.const 65534) "abc")"#);
    assert_rejected(&outside, "memory minimum");
}

#[test]
fn bounds_data_segments_by_an_imported_memory_minimum() {
    let outside =
        component_with_core(r#"(import "env" "mem" (memory 1 1)) (data (i32.const 65534) "abc")"#);
    assert_rejected(&outside, "memory minimum");
}

#[test]
fn bounds_element_segments_by_the_table_minimum() {
    let inside = component_with_core("(table 2 2 funcref) (func $f) (elem (i32.const 1) func $f)");
    validate_component(&inside).expect("a segment inside the minimum must be admitted");

    let outside = component_with_core("(table 2 2 funcref) (func $f) (elem (i32.const 2) func $f)");
    assert_rejected(&outside, "table minimum");
}

#[test]
fn rejects_reference_typed_globals_and_initializers() {
    // The operator blocklist walks function bodies; a global initializer
    // is not one, and the spec's const-expression vocabulary is integers.
    let bytes = component_with_core("(global externref (ref.null extern))");
    assert_rejected(&bytes, "profile");

    let bytes = component_with_core("(global i32 (i32.const 1)) (global i32 (global.get 0))");
    assert_rejected(&bytes, "profile");
}

#[test]
fn rejects_core_global_and_tag_imports() {
    let bytes = component_with_core(r#"(import "env" "g" (global i32))"#);
    assert_rejected(&bytes, "function, memory, and table imports");
}

#[test]
fn rejects_component_types_outside_the_vocabulary() {
    // A `string` parameter is a well-formed component type the spec has
    // no lifting for; declaring one is enough.
    let bytes =
        parse_str(r#"(component (type (func (param "s" string))))"#).expect("fixture must parse");
    assert_rejected(&bytes, "vocabulary");

    // Lists are admitted only at u8.
    let bytes = parse_str(r"(component (type (list u32)))").expect("fixture must parse");
    assert_rejected(&bytes, "list<u8>");
}

#[test]
fn rejects_a_cyclic_call_graph() {
    // Recursion leaves the native stack unbounded, and the engine has no
    // wasm-level depth counter to trap on, so the bound is proven at
    // deploy or not at all.
    let bytes = component_with_core("(func (result i32) call 0)");
    assert_rejected(&bytes, "cyclic");

    let bytes = component_with_core("(func (result i32) call 1) (func (result i32) call 0)");
    assert_rejected(&bytes, "cyclic");
}

#[test]
fn rejects_a_call_chain_that_will_not_fit() {
    // Each frame carries 512 locals; enough of them in a row and the
    // chain no longer fits the stack the profile reserves for it.
    let locals = "(local i64) ".repeat(512);
    let chain: String = (0..16)
        .map(|i| format!("(func {locals} call {})", i + 1))
        .collect::<Vec<_>>()
        .join("\n");
    let bytes = component_with_core(&format!("{chain}\n(func)"));
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
    let bytes = component_with_core(&format!("{chain}\n(func)"));
    validate_component(&bytes).expect("a light chain must be admitted");
}

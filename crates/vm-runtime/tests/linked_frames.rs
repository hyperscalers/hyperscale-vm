//! The stack bound over a component's linked core instances.
//!
//! Every fixture here is built so that each core module passes the bound on
//! its own and the component does not: judging modules one at a time weighs
//! the edges between them at zero, and the shape that exploits it is the
//! one `wit-bindgen` emits — a trampoline module whose table a third module
//! fills with functions it imported from a second.

use hyperscale_vm_runtime::profile::MAX_CALL_CHAIN_FRAMES;
use hyperscale_vm_runtime::validate_component;
use wat::parse_str;

/// A chain of `len` functions named `{prefix}0..{prefix}len-1`, the last
/// running `tail`.
fn chain(prefix: &str, len: usize, tail: &str) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    for index in 0..len {
        let body = if index + 1 == len {
            tail.to_string()
        } else {
            format!("call ${prefix}{}", index + 1)
        };
        let _ = writeln!(out, "(func ${prefix}{index} (result i64) {body})");
    }
    out
}

/// Two modules, the second's chain continuing into the first's export.
fn across_a_direct_import(first: usize, second: usize) -> Vec<u8> {
    let exported = chain("a", first, "i64.const 7");
    let importing = chain("b", second, "call $imported");
    parse_str(format!(
        r#"(component
             (core module $callee
               {exported}
               (export "run" (func $a0)))
             (core instance $ic (instantiate $callee))
             (core module $caller
               (import "callee" "run" (func $imported (result i64)))
               {importing}
               (export "run" (func $b0)))
             (core instance (instantiate $caller (with "callee" (instance $ic)))))"#
    ))
    .expect("fixture must parse")
}

/// The shim shape: a trampoline module calling through its own table, a
/// main module importing the trampoline, and a fixups module filling that
/// table with a function it imported from main.
///
/// `entry` picks what the table holds — main's own entry point closes a
/// call cycle, and a second chain does not.
fn through_a_shim_table(chain_len: usize, entry: &str) -> Vec<u8> {
    let reaching = chain("a", chain_len, "call $stub");
    let reached = chain("b", chain_len, "i64.const 7");
    parse_str(format!(
        r#"(component
             (core module $shim
               (type $sig (func (result i64)))
               (table (export "t") 1 1 funcref)
               (func (export "stub") (result i64)
                 i32.const 0
                 call_indirect (type $sig)))
             (core instance $is (instantiate $shim))
             (core module $main
               (import "shim" "stub" (func $stub (result i64)))
               {reaching}
               {reached}
               (export "entry" (func $a0))
               (export "reached" (func $b0)))
             (core instance $im (instantiate $main (with "shim" (instance $is))))
             (core module $fixups
               (import "shim" "t" (table $t 1 1 funcref))
               (import "main" "{entry}" (func $target (result i64)))
               (elem (table $t) (i32.const 0) func $target))
             (core instance (instantiate $fixups
               (with "shim" (instance $is))
               (with "main" (instance $im)))))"#
    ))
    .expect("fixture must parse")
}

/// The same shim shape, with a lowered import in the table and a realloc
/// that reaches the trampoline — so the canonical ABI's own callback can
/// call back out of the component, and lowering the import's result calls
/// that realloc again.
///
/// `reaching` picks whether realloc calls the trampoline. Either way the
/// call graph is acyclic and two frames deep: the edge that closes the
/// cycle is a host frame, which the walk terminates on.
fn through_the_canonical_boundary(reaching: bool) -> Vec<u8> {
    let reach = if reaching {
        "i32.const 16 call $stub"
    } else {
        ""
    };
    parse_str(format!(
        r#"(component
             (import "hyperscale:kernel/env" (instance $h
               (export "randomness" (func (result (list u8))))))
             (alias export $h "randomness" (func $draw))
             (core module $shim
               (type $sig (func (param i32)))
               (table (export "t") 1 1 funcref)
               (func (export "stub") (param i32)
                 local.get 0
                 i32.const 0
                 call_indirect (type $sig)))
             (core instance $is (instantiate $shim))
             (core module $alloc
               (import "shim" "stub" (func $stub (param i32)))
               (memory (export "mem") 1 1)
               (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                 {reach}
                 i32.const 1024))
             (core instance $a (instantiate $alloc (with "shim" (instance $is))))
             (core func $draw_l (canon lower (func $draw)
               (memory $a "mem") (realloc (func $a "realloc"))))
             (core module $fixups
               (import "shim" "t" (table $t 1 1 funcref))
               (import "k" "draw" (func $target (param i32)))
               (elem (table $t) (i32.const 0) func $target))
             (core instance (instantiate $fixups
               (with "shim" (instance $is))
               (with "k" (instance (export "draw" (func $draw_l)))))))"#
    ))
    .expect("fixture must parse")
}

fn refusal(bytes: &[u8]) -> String {
    validate_component(bytes)
        .expect_err("the linked chain must be refused")
        .to_string()
}

#[test]
fn an_import_wired_to_another_module_carries_the_chain() {
    // Two thirds of the cap each: fine apart, over it together.
    let two_thirds = MAX_CALL_CHAIN_FRAMES * 2 / 3;
    let refusal = refusal(&across_a_direct_import(two_thirds, two_thirds));
    assert!(refusal.contains("frames"), "{refusal}");

    // A third each, and the same wiring is admitted — the bound weighs the
    // boundary, it does not refuse crossing one.
    let third = MAX_CALL_CHAIN_FRAMES / 3;
    validate_component(&across_a_direct_import(third, third))
        .expect("a chain that fits must cross a module boundary freely");
}

#[test]
fn a_table_another_module_fills_carries_the_chain() {
    // main's first chain reaches the shim's trampoline, whose table holds
    // main's second chain: one chain, three modules, and no module holding
    // more than half of it.
    let half = MAX_CALL_CHAIN_FRAMES / 2;
    let refusal = refusal(&through_a_shim_table(half, "reached"));
    assert!(refusal.contains("frames"), "{refusal}");

    let quarter = MAX_CALL_CHAIN_FRAMES / 4;
    validate_component(&through_a_shim_table(quarter, "reached"))
        .expect("the shim shape itself is admissible; it is the depth that is not");
}

#[test]
fn a_cycle_closed_through_the_canonical_boundary_is_refused() {
    // The chain bound sees an acyclic graph two frames deep, and it is
    // right: the cycle runs through a host frame. What makes that frame
    // continue back into wasm is the canonical ABI calling the guest's
    // realloc to lower the import's result — so the refusal is about which
    // guest code the ABI runs as its callback, not about depth.
    let refusal = refusal(&through_the_canonical_boundary(true));
    assert!(refusal.contains("realloc"), "{refusal}");

    // The same three modules, the same lowered import in the same table:
    // only the edge out of realloc is gone, and the artifact is admitted.
    validate_component(&through_the_canonical_boundary(false))
        .expect("a realloc that reaches no lowered import is ordinary guest code");
}

#[test]
fn a_cycle_closed_through_another_modules_table_is_refused() {
    // Core instantiation is acyclic — fixups needs main, main needs the
    // shim — yet the calls are not: the shim's trampoline reaches main's
    // entry point, which reaches the trampoline. No single module contains
    // the cycle, and no static stack bound exists for it.
    let refusal = refusal(&through_a_shim_table(4, "entry"));
    assert!(refusal.contains("cyclic"), "{refusal}");
}

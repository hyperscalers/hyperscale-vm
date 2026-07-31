//! Regression probe: how many native bytes a wasm frame actually costs.
//!
//! The deploy-time stack bound converts a function's slot count into a
//! native frame size, and that conversion is a codegen detail — it has to
//! over-approximate every backend the matrix admits or an artifact passes
//! deploy and overflows anyway. Guessing the multiplier would make the
//! bound decorative, so it is measured: recurse until the engine's stack
//! limit trips, and divide the limit by the depth reached.
//!
//! This probe pins the measurement. When it fails, codegen's frame layout
//! moved and `profile::STACK_BYTES_PER_SLOT` should be re-derived from the
//! new numbers rather than nudged.

use hyperscale_vm_runtime::blessed_config;
use hyperscale_vm_runtime::profile::{
    MAX_WASM_STACK_BYTES, STACK_BYTES_PER_SLOT, STACK_FRAME_OVERHEAD_BYTES,
};
use wasmtime::{Engine, Instance, Module, Store, Strategy, Trap};
use wat::parse_str;

/// A self-recursive function holding `locals` i64 locals live across its
/// own call, so the register allocator has to spill them to the frame.
fn recursive_module(locals: usize) -> String {
    let decls = "(local i64) ".repeat(locals);
    // Each local is loaded from a distinct memory address. Arithmetic on
    // the parameter would only be rematerialised after the call — cheaper
    // than a spill, and the frame would not grow — but a load cannot be,
    // because the call may have written the memory.
    let mut init = String::new();
    for i in 0..locals {
        use std::fmt::Write;
        let _ = writeln!(init, "i32.const {}\ni64.load\nlocal.set {}", i * 8, i + 1);
    }
    // ...and every one is summed after the recursive call, so all of them
    // are live across it and have to survive in the frame.
    let mut live = String::new();
    for i in 0..locals {
        use std::fmt::Write;
        let _ = writeln!(live, "local.get {}\ni64.add", i + 1);
    }
    format!(
        r#"(module
  (memory 4 4)
  (global $depth (mut i32) (i32.const 0))
  (func $rec (param i64) (result i64)
    {decls}
    {init}
    global.get $depth
    i32.const 1
    i32.add
    global.set $depth
    local.get 0
    call $rec
    {live})
  (func (export "run") (result i64)
    i64.const 0
    call $rec)
  (func (export "depth") (result i32)
    global.get $depth))"#
    )
}

/// Recurses to exhaustion and reports the depth reached, or `None` if the
/// backend cannot compile the fixture at all.
fn depth_at_overflow(strategy: Strategy, locals: usize) -> Option<u32> {
    let mut config = blessed_config();
    config.strategy(strategy);
    let engine = Engine::new(&config).expect("engine");
    let wasm = parse_str(recursive_module(locals)).expect("fixture parses");
    let module = Module::new(&engine, &wasm).ok()?;
    let mut store = Store::new(&engine, ());
    // Fuel must not be what stops it.
    store.set_fuel(u64::MAX).expect("fuel on");
    let instance = Instance::new(&mut store, &module, &[]).expect("instantiates");
    let run = instance
        .get_typed_func::<(), i64>(&mut store, "run")
        .expect("export");
    let error = run
        .call(&mut store, ())
        .expect_err("must exhaust the stack");
    assert_eq!(
        error.downcast_ref::<Trap>(),
        Some(&Trap::StackOverflow),
        "the probe must stop on the stack, not on anything else"
    );
    let depth = instance
        .get_typed_func::<(), i32>(&mut store, "depth")
        .expect("export");
    Some(u32::try_from(depth.call(&mut store, ()).expect("depth")).expect("non-negative"))
}

#[test]
fn the_profile_frame_model_over_approximates_every_backend() {
    let mut measured = false;
    for strategy in [Strategy::Cranelift, Strategy::Winch] {
        for locals in [0usize, 8, 64, 256] {
            let Some(depth) = depth_at_overflow(strategy, locals) else {
                println!("{strategy:?} locals {locals:>4}: backend declined the fixture");
                continue;
            };
            assert!(depth > 0, "no frames were entered at {locals} locals");
            measured = true;
            let observed =
                f64::from(u32::try_from(MAX_WASM_STACK_BYTES).expect("fits")) / f64::from(depth);
            // One param plus the declared locals: the slot count the
            // deploy bound derives its budget from.
            let slots = 1 + locals;
            let modelled = f64::from(
                u32::try_from(STACK_FRAME_OVERHEAD_BYTES + STACK_BYTES_PER_SLOT * slots)
                    .expect("fits"),
            );
            println!(
                "{strategy:?} locals {locals:>4}: depth {depth:>6}, {observed:>8.1} bytes \
                 observed, {modelled:>8.1} modelled, margin {:.1}x",
                modelled / observed
            );
            assert!(
                modelled >= observed,
                "{strategy:?} at {locals} locals costs {observed:.1} bytes, over the \
                 modelled {modelled:.1} — the deploy bound would admit an artifact that \
                 overflows"
            );
        }
    }
    assert!(measured, "no backend produced a measurement");
}

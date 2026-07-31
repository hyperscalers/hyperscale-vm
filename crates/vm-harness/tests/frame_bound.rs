//! The deploy-time frame bound against the executable spec's counter.
//!
//! `frames.rs` proves an admitted artifact cannot exhaust the native stack,
//! and `error.rs` states that `vm-ref`'s `CallDepthExhausted` is therefore
//! unreachable. Neither claim is checkable inside the crate that makes it:
//! the profile cannot see the spec's counter and the spec cannot see the
//! profile, by design — the two are written independently, and this is the
//! only crate that depends on both.
//!
//! So the ordering is asserted here at compile time, and the boundary is
//! walked at run time: the deepest chain the profile admits must validate
//! and execute identically on both runtimes, and one frame more must be
//! refused.

use hyperscale_vm_harness::on_deep_stack;
use hyperscale_vm_ref::{MAX_CALL_DEPTH, RefInstance, RefModule, Trap, Value};
use hyperscale_vm_runtime::profile::{
    MAX_CALL_CHAIN_BYTES, MAX_CALL_CHAIN_FRAMES, STACK_FRAME_OVERHEAD_BYTES,
};
use hyperscale_vm_runtime::{blessed_engine, validate_core_module};
use wasmtime::{Instance, Module, Result, Store};
use wat::parse_str;

/// The claim `error.rs` makes: a chain the profile admits cannot reach the
/// spec's counter.
const _: () = assert!(
    MAX_CALL_CHAIN_FRAMES < MAX_CALL_DEPTH,
    "the profile admits a call chain deeper than the executable spec tolerates"
);

/// And the reason the frame cap has to exist at all: the byte budget alone
/// does not bound depth anywhere near tightly enough to do this job.
const _: () = assert!(
    MAX_CALL_CHAIN_BYTES / STACK_FRAME_OVERHEAD_BYTES > MAX_CALL_CHAIN_FRAMES,
    "the byte budget already caps depth, so the frame cap is doing nothing"
);

/// A chain of `depth` functions, each calling the next and the last
/// returning a constant. Every frame is as cheap as a frame can be, so the
/// byte budget is nowhere near binding and the frame cap is what decides.
fn chain(depth: usize) -> String {
    use std::fmt::Write;

    let mut module = String::from("(module\n");
    for index in 0..depth {
        let body = if index + 1 == depth {
            "i64.const 7".to_string()
        } else {
            format!("call $f{}", index + 1)
        };
        let _ = writeln!(module, "  (func $f{index} (result i64) {body})");
    }
    module.push_str("  (export \"run\" (func $f0)))");
    module
}

#[test]
fn the_deepest_admissible_chain_is_admitted_and_one_more_is_not() {
    let admissible = parse_str(chain(MAX_CALL_CHAIN_FRAMES)).expect("fixture parses");
    validate_core_module(&admissible)
        .unwrap_or_else(|e| panic!("the profile must admit its own maximum chain: {e}"));

    let over = parse_str(chain(MAX_CALL_CHAIN_FRAMES + 1)).expect("fixture parses");
    let refusal = validate_core_module(&over)
        .expect_err("one frame past the cap must be refused")
        .to_string();
    assert!(
        refusal.contains("frames"),
        "the refusal must name the frame budget, not another limit: {refusal}"
    );
}

#[test]
fn a_chain_past_the_specs_counter_never_deploys() {
    // The witness the frame cap exists to remove: this chain costs a third
    // of the byte budget, so nothing but the frame cap refuses it — and if
    // it deployed, the blessed engine would return where the spec traps.
    let wasm = parse_str(chain(MAX_CALL_DEPTH + 64)).expect("fixture parses");
    let refusal = validate_core_module(&wasm)
        .expect_err("a chain past the spec's counter must not deploy")
        .to_string();
    assert!(refusal.contains("frames"), "{refusal}");

    on_deep_stack(move || {
        let reference = RefModule::decode(&wasm).expect("the spec decodes it regardless");
        let mut interpreter = RefInstance::instantiate(&reference).expect("instantiates");
        assert_eq!(
            interpreter.invoke("run", &[]).expect("invocable"),
            Err(Trap::CallDepthExhausted),
            "the trap the deploy-time bound keeps out of reach"
        );
    });
}

#[test]
fn both_runtimes_execute_the_deepest_admissible_chain() -> Result<()> {
    on_deep_stack(|| {
        let wasm = parse_str(chain(MAX_CALL_CHAIN_FRAMES)).expect("fixture parses");
        validate_core_module(&wasm).expect("admitted");

        let engine = blessed_engine()?;
        let module = Module::new(&engine, &wasm)?;
        let mut store = Store::new(&engine, ());
        store.set_fuel(u64::MAX)?;
        let instance = Instance::new(&mut store, &module, &[])?;
        let blessed = instance
            .get_typed_func::<(), i64>(&mut store, "run")?
            .call(&mut store, ())?;

        let reference = RefModule::decode(&wasm).expect("the spec decodes what the profile admits");
        let mut interpreter = RefInstance::instantiate(&reference).expect("instantiates");
        let spec = interpreter
            .invoke("run", &[])
            .expect("invocable")
            .expect("the spec's counter must be out of reach for an admitted chain");

        assert_eq!(spec, vec![Value::I64(blessed)]);
        Ok(())
    })
}

//! Differential lane 3: the canonical ABI's control rules.
//!
//! The data rules — how a value crosses the boundary — are covered by the
//! component lane. This one covers the rule about *when* the boundary may
//! be crossed at all: guest code the ABI runs as its own callback may not
//! call back out of the component. It is the one rule an artifact can break
//! while every individual edge stays sound, so it is the one a call-graph
//! bound cannot see on its own.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, EffectSet, Hash32, Hasher, TestHasher};
use hyperscale_vm_harness::fixtures::{REENTRANT_DROP_WAT, REENTRANT_REALLOC_WAT};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore, TxHash};
use hyperscale_vm_ref::{CanonError, ExecError, RefComponent, RefComponentInstance};
use hyperscale_vm_runtime::{add_kernel_to_linker, blessed_engine, validate_component};
use wasmtime::component::{Component, Linker};
use wasmtime::{Error, Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn session() -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration::from_set(EffectSet::new()),
        TxHash(Hash32([0x44; 32])),
        EnvInputs {
            clock_ms: 7,
            randomness: [11; 32],
        },
        test_hash,
    )
    .expect("an empty declaration materializes")
}

fn run_blessed(bytes: &[u8]) -> Result<Error> {
    let engine = blessed_engine()?;
    let component = Component::new(&engine, bytes)?;
    let mut linker = Linker::<KernelSession>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, session());
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;
    let draw = instance.get_typed_func::<(), (u64,)>(&mut store, "draw")?;
    Ok(draw
        .call(&mut store, ())
        .expect_err("the re-entrant realloc must not return a value"))
}

fn run_ref(bytes: &[u8]) -> Result<ExecError> {
    let comp = RefComponent::decode(bytes)?;
    let mut instance =
        RefComponentInstance::instantiate(&comp, session()).map_err(|(_, error)| error)?;
    instance.set_fuel_limit(FUEL);
    Ok(instance
        .invoke("draw", &[])?
        .expect_err("the re-entrant realloc must not return a value"))
}

#[test]
fn a_lowered_import_called_from_realloc_is_refused_by_both_runtimes() -> Result<()> {
    let bytes = parse_str(REENTRANT_REALLOC_WAT)?;

    let blessed = format!("{:#}", run_blessed(&bytes)?);
    assert!(
        blessed.contains("cannot leave component instance"),
        "the blessed engine's re-entrance verdict changed shape: {blessed}"
    );
    assert_eq!(
        run_ref(&bytes)?,
        ExecError::Canon(CanonError::CannotLeave),
        "the spec must reach the same verdict, not run the cycle to a depth bound"
    );
    Ok(())
}

#[test]
fn the_profile_refuses_the_shape_before_either_runtime_sees_it() {
    let bytes = parse_str(REENTRANT_REALLOC_WAT).expect("fixture must parse");
    let refusal = validate_component(&bytes)
        .expect_err("a realloc that reaches a lowered import must not deploy")
        .to_string();
    assert!(refusal.contains("realloc"), "{refusal}");
}

#[test]
fn a_resource_drop_called_from_realloc_is_refused_by_both_runtimes() -> Result<()> {
    let bytes = parse_str(REENTRANT_DROP_WAT)?;

    let blessed = format!("{:#}", run_blessed(&bytes)?);
    assert!(
        blessed.contains("cannot leave component instance"),
        "the blessed engine's may-leave verdict changed shape: {blessed}"
    );
    assert_eq!(
        run_ref(&bytes)?,
        ExecError::Canon(CanonError::CannotLeave),
        "the spec must refuse to leave, not judge the drop on its own terms"
    );
    Ok(())
}

#[test]
fn the_profile_refuses_the_drop_shape_before_either_runtime_sees_it() {
    let bytes = parse_str(REENTRANT_DROP_WAT).expect("fixture must parse");
    let refusal = validate_component(&bytes)
        .expect_err("a realloc that reaches a canon builtin must not deploy")
        .to_string();
    assert!(refusal.contains("realloc"), "{refusal}");
}

//! Pins the engine's instantiation-time fuel model under the blessed config.
//!
//! The engine compiles one init function per module that needs one: any
//! active data segment forces it, as do element segments applying to an
//! imported table (a local table's elements are precomputed host-side). The
//! init function's entry costs one fuel, each data segment adds one plus one
//! per byte, and element writes are free. vm-ref mirrors exactly this model
//! at `instantiate_module`, and the differential lanes verify it end to end;
//! this test pins the engine side directly so an upstream change in the
//! model is caught here first.
//!
//! The blessed config disables copy-on-write memory images because such an
//! image charges instantiation fuel by the host-page-rounded image span — a
//! host-platform-dependent number (16 KiB pages on darwin/aarch64, 4 KiB on
//! most Linux hosts). If the images were re-enabled these assertions would trip on
//! every platform.

use hyperscale_vm_runtime::blessed_engine;
use wasmtime::{Instance, Module, Ref, RefType, Result, Store, Table, TableType};

fn instantiation_fuel(wat: &str) -> Result<u64> {
    let engine = blessed_engine()?;
    let module = Module::new(&engine, wat)?;
    let mut store = Store::new(&engine, ());
    store.set_fuel(1_000_000)?;
    Instance::new(&mut store, &module, &[])?;
    Ok(1_000_000 - store.get_fuel()?)
}

#[test]
fn modules_without_init_work_charge_nothing() -> Result<()> {
    assert_eq!(instantiation_fuel("(module)")?, 0);
    assert_eq!(instantiation_fuel("(module (memory 1))")?, 0);
    // A local table's element segments are precomputed host-side.
    assert_eq!(
        instantiation_fuel(
            "(module (table 10 10 funcref) (func $f) (elem (i32.const 0) $f $f $f $f))"
        )?,
        0
    );
    Ok(())
}

#[test]
fn data_segments_charge_entry_plus_one_plus_bytes() -> Result<()> {
    assert_eq!(
        instantiation_fuel(r#"(module (memory 1) (data (i32.const 0) "x"))"#)?,
        3
    );
    let seg = "x".repeat(1000);
    assert_eq!(
        instantiation_fuel(&format!(
            r#"(module (memory 1) (data (i32.const 0) "{seg}"))"#
        ))?,
        1002
    );
    let seg = "x".repeat(10);
    assert_eq!(
        instantiation_fuel(&format!(
            r#"(module (memory 1) (data (i32.const 0) "{seg}") (data (i32.const 100) "{seg}"))"#
        ))?,
        23
    );
    Ok(())
}

#[test]
fn imported_table_elements_charge_the_init_entry_only() -> Result<()> {
    let engine = blessed_engine()?;
    for elems in [1usize, 32] {
        let items = "$f ".repeat(elems);
        let module = Module::new(
            &engine,
            format!(
                r#"(module
                  (import "e" "t" (table 64 64 funcref))
                  (func $f)
                  (elem (i32.const 0) {items}))"#
            )
            .as_str(),
        )?;
        let mut store = Store::new(&engine, ());
        store.set_fuel(1_000_000)?;
        let ty = TableType::new(RefType::FUNCREF, 64, Some(64));
        let table = Table::new(&mut store, ty, Ref::Func(None))?;
        Instance::new(&mut store, &module, &[table.into()])?;
        assert_eq!(1_000_000 - store.get_fuel()?, 1, "element count {elems}");
    }
    Ok(())
}

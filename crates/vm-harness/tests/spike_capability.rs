//! Milestone 1 spike, question 3: the capability shape.
//!
//! Validates that the D2 enforcement mechanism is expressible as a fixed
//! import surface plus a per-transaction handle table: the kernel exports one
//! `substate` resource type with read/write functions, and capability
//! granularity comes from which handles the host materializes for the call.
//! Three properties are probed: declared handles work and resolve per-store
//! (per-transaction) state; a guest cannot mint a handle it was not given
//! (the import surface has no constructor); and a guest forging a raw handle
//! index at the core level traps deterministically instead of reaching state.

use wasmtime::component::{Component, Linker, Resource, ResourceType};
use wasmtime::{Config, Engine, Result, Store, StoreContextMut};

/// Host-side marker for the substate resource; the handle's rep indexes the
/// store's substate table.
struct SubstateMarker;

/// Per-transaction host state: the declared substates' values and an access
/// log proving which reps the guest actually reached.
#[derive(Default)]
struct Tx {
    values: Vec<u64>,
    log: Vec<(char, u32)>,
}

const GUEST_WAT: &str = r#"
(component
  (import "kernel" (instance $kernel
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
    ;; Read a, write a+1 into b, read a again; the canonical ABI requires
    ;; every borrow handle dropped before the export returns.
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
      local.get 2)
    ;; Forge a handle index the host never lowered.
    (func (export "forge") (result i64)
      i32.const 9999
      call $read))

  (core instance $i (instantiate $m
    (with "k" (instance
      (export "read" (func $read_l))
      (export "write" (func $write_l))
      (export "drop" (func $drop_l))))))

  (func (export "run")
    (param "a" (borrow $substate)) (param "b" (borrow $substate)) (result u64)
    (canon lift (core func $i "run")))
  (func (export "forge") (result u64)
    (canon lift (core func $i "forge"))))
"#;

fn build() -> Result<(Engine, Component, Linker<Tx>)> {
    let engine = Engine::new(&Config::new())?;
    let component = Component::new(&engine, GUEST_WAT)?;
    let mut linker = Linker::<Tx>::new(&engine);
    let mut kernel = linker.instance("kernel")?;
    kernel.resource(
        "substate",
        ResourceType::host::<SubstateMarker>(),
        |_, _| Ok(()),
    )?;
    kernel.func_wrap(
        "read",
        |mut store: StoreContextMut<'_, Tx>, (r,): (Resource<SubstateMarker>,)| {
            let rep = r.rep();
            let tx = store.data_mut();
            tx.log.push(('r', rep));
            let value = tx.values[rep as usize];
            Ok((value,))
        },
    )?;
    kernel.func_wrap(
        "write",
        |mut store: StoreContextMut<'_, Tx>, (r, v): (Resource<SubstateMarker>, u64)| {
            let rep = r.rep();
            let tx = store.data_mut();
            tx.log.push(('w', rep));
            tx.values[rep as usize] = v;
            Ok(())
        },
    )?;
    Ok((engine, component, linker))
}

#[test]
fn declared_handles_reach_per_transaction_state() -> Result<()> {
    let (engine, component, linker) = build()?;

    // Two "transactions" with different declared values; same component, same
    // linker, distinct stores. Each must see only its own state.
    for (initial, expected_b) in [(10_u64, 11_u64), (500, 501)] {
        let mut store = Store::new(
            &engine,
            Tx {
                values: vec![initial, 0],
                log: Vec::new(),
            },
        );
        let instance = linker.instantiate(&mut store, &component)?;
        let run = instance
            .get_typed_func::<(Resource<SubstateMarker>, Resource<SubstateMarker>), (u64,)>(
                &mut store, "run",
            )?;
        let (out,) = run.call(
            &mut store,
            (Resource::new_borrow(0), Resource::new_borrow(1)),
        )?;
        assert_eq!(out, initial);
        assert_eq!(store.data().values, vec![initial, expected_b]);
        assert_eq!(store.data().log, vec![('r', 0), ('w', 1), ('r', 0)]);
    }
    Ok(())
}

#[test]
fn forged_handle_index_traps_before_reaching_state() -> Result<()> {
    let (engine, component, linker) = build()?;
    let mut store = Store::new(
        &engine,
        Tx {
            values: vec![10, 0],
            log: Vec::new(),
        },
    );
    let instance = linker.instantiate(&mut store, &component)?;
    let forge = instance.get_typed_func::<(), (u64,)>(&mut store, "forge")?;
    let err = forge
        .call(&mut store, ())
        .expect_err("forged index must fail");

    // The failure must be deterministic and must have happened before any
    // host function observed an access: the log stays empty.
    assert!(
        store.data().log.is_empty(),
        "forged access reached the host"
    );
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown handle index"),
        "unexpected failure shape: {msg}"
    );
    Ok(())
}

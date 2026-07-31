//! Milestone 1 spike, question 5: per-transaction instantiation cost.
//!
//! The capability shape instantiates once per (transaction, component) so the
//! handle table is per-transaction. This probe measures the full per-call
//! sequence — fresh store, instantiate, typed call — under three strategies:
//! plain linker instantiation, `InstancePre`, and `InstancePre` on the pooling
//! allocator. Numbers are printed for the findings record; the only assertion
//! is a generous sanity ceiling. Measure with `--release` — debug numbers are
//! not the answer.

use std::time::Instant;

use anyhow::Result;
use wasmtime::component::{Component, InstancePre, Linker, Resource, ResourceType};
use wasmtime::{
    Config, Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Store, StoreContextMut,
    Strategy,
};

struct SubstateMarker;

#[derive(Default)]
struct Tx {
    values: Vec<u64>,
}

// The Q3 guest: a realistic per-transaction shape (resource handles in, host
// calls, borrow drops) rather than a bare add.
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
"#;

fn kernel_linker(engine: &Engine) -> Result<Linker<Tx>> {
    let mut linker = Linker::<Tx>::new(engine);
    let mut kernel = linker.instance("kernel")?;
    kernel.resource(
        "substate",
        ResourceType::host::<SubstateMarker>(),
        |_, _| Ok(()),
    )?;
    kernel.func_wrap(
        "read",
        |store: StoreContextMut<'_, Tx>, (r,): (Resource<SubstateMarker>,)| {
            Ok((store.data().values[r.rep() as usize],))
        },
    )?;
    kernel.func_wrap(
        "write",
        |mut store: StoreContextMut<'_, Tx>, (r, v): (Resource<SubstateMarker>, u64)| {
            store.data_mut().values[r.rep() as usize] = v;
            Ok(())
        },
    )?;
    Ok(linker)
}

fn one_transaction_pre(engine: &Engine, pre: &InstancePre<Tx>) -> Result<u64> {
    let mut store = Store::new(engine, Tx { values: vec![7, 0] });
    let instance = pre.instantiate(&mut store)?;
    let run = instance
        .get_typed_func::<(Resource<SubstateMarker>, Resource<SubstateMarker>), (u64,)>(
            &mut store, "run",
        )?;
    let (out,) = run.call(
        &mut store,
        (Resource::new_borrow(0), Resource::new_borrow(1)),
    )?;
    Ok(out)
}

fn one_transaction_linker(
    engine: &Engine,
    linker: &Linker<Tx>,
    component: &Component,
) -> Result<u64> {
    let mut store = Store::new(engine, Tx { values: vec![7, 0] });
    let instance = linker.instantiate(&mut store, component)?;
    let run = instance
        .get_typed_func::<(Resource<SubstateMarker>, Resource<SubstateMarker>), (u64,)>(
            &mut store, "run",
        )?;
    let (out,) = run.call(
        &mut store,
        (Resource::new_borrow(0), Resource::new_borrow(1)),
    )?;
    Ok(out)
}

fn measure(label: &str, mut f: impl FnMut() -> Result<u64>) -> Result<f64> {
    const WARMUP: u32 = 200;
    const ITERS: u32 = 5_000;
    for _ in 0..WARMUP {
        assert_eq!(f()?, 7);
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        f()?;
    }
    let nanos_per = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);
    println!("{label:32} {nanos_per:>10.0} ns/tx");
    Ok(nanos_per)
}

#[test]
fn per_transaction_instantiation_cost() -> Result<()> {
    let mut config = Config::new();
    config.strategy(Strategy::Cranelift);
    let engine = Engine::new(&config)?;
    let component = Component::new(&engine, GUEST_WAT)?;
    let linker = kernel_linker(&engine)?;
    let pre = linker.instantiate_pre(&component)?;

    let mut pooled_config = Config::new();
    pooled_config.strategy(Strategy::Cranelift);
    pooled_config.allocation_strategy(InstanceAllocationStrategy::Pooling(
        PoolingAllocationConfig::default(),
    ));
    let pooled_engine = Engine::new(&pooled_config)?;
    let pooled_component = Component::new(&pooled_engine, GUEST_WAT)?;
    let pooled_pre = kernel_linker(&pooled_engine)?.instantiate_pre(&pooled_component)?;

    let plain = measure("linker instantiate", || {
        one_transaction_linker(&engine, &linker, &component)
    })?;
    let pre_ns = measure("InstancePre", || one_transaction_pre(&engine, &pre))?;
    let pooled = measure("InstancePre + pooling", || {
        one_transaction_pre(&pooled_engine, &pooled_pre)
    })?;

    // Generous sanity ceiling: per-transaction instantiation must be
    // microseconds, not milliseconds, or the capability shape needs the
    // handle-table-swap fallback.
    for (label, ns) in [("linker", plain), ("pre", pre_ns), ("pooled", pooled)] {
        assert!(ns < 1_000_000.0, "{label} instantiation is {ns} ns/tx");
    }
    Ok(())
}

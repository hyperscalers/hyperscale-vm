//! Milestone 1 spike, question 6: canonical-ABI copy visibility.
//!
//! D22 charges canonical-ABI lift/lower proportional to bytes moved, as a
//! host-side supplement, because no engine provides it. This probe checks
//! both halves of that plan at the pin: that engine fuel is indeed blind to
//! boundary copy size (the gap is real), and that the host boundary sees the
//! byte counts it needs to charge the supplement itself (the fix is possible
//! with no engine support).

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Result, Store};

// A guest with real canonical-ABI copies: a string crosses host→guest (lower,
// via guest realloc into linear memory) and the guest returns its length.
const GUEST_WAT: &str = r#"
(component
  (core module $m
    (memory (export "mem") 32)
    (global $next (mut i32) (i32.const 64))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ret i32)
      global.get $next
      local.set $ret
      global.get $next
      local.get 3
      i32.add
      global.set $next
      local.get $ret)
    (func (export "take") (param i32 i32) (result i32)
      local.get 1))
  (core instance $i (instantiate $m))
  (func (export "take") (param "s" string) (result u32)
    (canon lift (core func $i "take")
      (memory $i "mem")
      (realloc (func $i "realloc"))
      string-encoding=utf8)))
"#;

fn fuel_for_call(engine: &Engine, component: &Component, payload: &str) -> Result<(u32, u64)> {
    let linker = Linker::<()>::new(engine);
    let mut store = Store::new(engine, ());
    store.set_fuel(10_000_000)?;
    let instance = linker.instantiate(&mut store, component)?;
    let take = instance.get_typed_func::<(&str,), (u32,)>(&mut store, "take")?;
    let before = store.get_fuel()?;
    let (len,) = take.call(&mut store, (payload,))?;
    let consumed = before - store.get_fuel()?;
    Ok((len, consumed))
}

#[test]
fn engine_fuel_is_blind_to_boundary_copy_size() -> Result<()> {
    let mut config = Config::new();
    config.consume_fuel(true);
    let engine = Engine::new(&config)?;
    let component = Component::new(&engine, GUEST_WAT)?;

    let small = "x".repeat(1024);
    let large = "x".repeat(1024 * 1024);

    let (small_len, small_fuel) = fuel_for_call(&engine, &component, &small)?;
    let (large_len, large_fuel) = fuel_for_call(&engine, &component, &large)?;
    println!("1KiB copy: fuel={small_fuel}   1MiB copy: fuel={large_fuel}");

    // The host boundary sees exact byte counts: the lifted length is the
    // supplement's charging basis, with no engine support required.
    assert_eq!(small_len, 1024);
    assert_eq!(large_len, 1024 * 1024);

    // A 1024x larger copy must not cost 1024x fuel for the gap to be real;
    // equality (the realloc call is size-independent) is the expected shape.
    assert_eq!(
        small_fuel, large_fuel,
        "engine fuel now varies with copy size; revisit the D22 supplement"
    );
    Ok(())
}

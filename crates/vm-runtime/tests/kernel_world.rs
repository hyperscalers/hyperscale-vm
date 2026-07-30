//! The kernel world end to end: a guest exercising `state`, `env`, and
//! `crypto` with real canonical-ABI copies, under the blessed engine, with
//! the boundary supplement charged against fuel.

use hyperscale_vm_runtime::gas::FUEL_PER_BOUNDARY_BYTE;
use hyperscale_vm_runtime::{
    KernelHost, Substate, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Engine, Result, Store, Trap};
use wat::parse_str;

/// A guest that reads substate `a`, writes those bytes to substate `b`,
/// then folds clock, randomness, and a hash into its return value:
/// `clock + len(a) + len(hash) + hash[0]`.
///
/// List-returning imports lower through a separate allocator module
/// instantiated first, so the canon lower options can name its memory and
/// realloc while the main module imports the same memory.
const GUEST_WAT: &str = r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "substate" (type $substate (sub resource)))
    (export "read" (func (param "s" (borrow $substate)) (result (list u8))))
    (export "write" (func (param "s" (borrow $substate)) (param "value" (list u8))))))
  (import "hyperscale:kernel/env" (instance $env
    (export "clock" (func (result u64)))
    (export "randomness" (func (result (list u8))))))
  (import "hyperscale:kernel/crypto" (instance $crypto
    (export "hash" (func (param "data" (list u8)) (result (list u8))))))

  (alias export $state "substate" (type $sub))
  (alias export $state "read" (func $read))
  (alias export $state "write" (func $write))
  (alias export $env "clock" (func $clock))
  (alias export $env "randomness" (func $randomness))
  (alias export $crypto "hash" (func $hash))

  (core module $alloc
    (memory (export "mem") 4 4)
    (global $next (mut i32) (i32.const 1024))
    (func (export "realloc") (param i32 i32 i32 i32) (result i32)
      (local $ret i32)
      global.get $next
      local.set $ret
      global.get $next
      local.get 3
      i32.add
      global.set $next
      local.get $ret))
  (core instance $a (instantiate $alloc))

  (core func $read_l (canon lower (func $read)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $write_l (canon lower (func $write)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $clock_l (canon lower (func $clock)))
  (core func $randomness_l (canon lower (func $randomness)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $hash_l (canon lower (func $hash)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $drop_l (canon resource.drop $sub))

  (core module $m
    (import "env" "mem" (memory 4 4))
    (import "k" "read" (func $read (param i32 i32)))
    (import "k" "write" (func $write (param i32 i32 i32)))
    (import "k" "clock" (func $clock (result i64)))
    (import "k" "randomness" (func $randomness (param i32)))
    (import "k" "hash" (func $hash (param i32 i32 i32)))
    (import "k" "drop" (func $drop (param i32)))
    (func (export "run") (param i32 i32) (result i64)
      (local $ptr i32) (local $len i32) (local $now i64)
      ;; read(a) -> return area at 8: {ptr, len}
      local.get 0
      i32.const 8
      call $read
      i32.const 8
      i32.load
      local.set $ptr
      i32.const 12
      i32.load
      local.set $len
      ;; write(b, the same buffer) - no guest-side copy
      local.get 1
      local.get $ptr
      local.get $len
      call $write
      ;; clock
      call $clock
      local.set $now
      ;; randomness -> return area at 16
      i32.const 16
      call $randomness
      ;; hash(randomness bytes) -> return area at 24
      i32.const 16
      i32.load
      i32.const 20
      i32.load
      i32.const 24
      call $hash
      ;; result = clock + len(a) + len(hash) + hash[0]
      local.get $now
      local.get $len
      i64.extend_i32_u
      i64.add
      i32.const 28
      i32.load
      i64.extend_i32_u
      i64.add
      i32.const 24
      i32.load
      i32.load8_u
      i64.extend_i32_u
      i64.add
      ;; borrows must drop before return
      local.get 0
      call $drop
      local.get 1
      call $drop))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance
      (export "read" (func $read_l))
      (export "write" (func $write_l))
      (export "clock" (func $clock_l))
      (export "randomness" (func $randomness_l))
      (export "hash" (func $hash_l))
      (export "drop" (func $drop_l))))))

  (func (export "run")
    (param "a" (borrow $sub)) (param "b" (borrow $sub)) (result u64)
    (canon lift (core func $i "run"))))
"#;

const CLOCK_MS: u64 = 111_222;

struct TestHost {
    values: Vec<Vec<u8>>,
}

impl KernelHost for TestHost {
    fn read(&mut self, rep: u32) -> Vec<u8> {
        self.values[rep as usize].clone()
    }

    fn write(&mut self, rep: u32, value: Vec<u8>) {
        self.values[rep as usize] = value;
    }

    fn clock_ms(&self) -> u64 {
        CLOCK_MS
    }

    fn randomness(&self) -> [u8; 32] {
        [7; 32]
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let sum = data.iter().fold(0u8, |acc, b| acc.wrapping_add(*b));
        [sum; 32]
    }
}

fn run_guest(engine: &Engine, substate_len: usize, fuel: u64) -> Result<(u64, u64, Vec<Vec<u8>>)> {
    let bytes = parse_str(GUEST_WAT)?;
    validate_component(&bytes)?;
    let component = Component::new(engine, &bytes)?;
    let mut linker = Linker::<TestHost>::new(engine);
    add_kernel_to_linker(&mut linker)?;

    let mut store = Store::new(
        engine,
        TestHost {
            values: vec![vec![3; substate_len], Vec::new()],
        },
    );
    store.set_fuel(fuel)?;
    let instance = linker.instantiate(&mut store, &component)?;
    let run = instance
        .get_typed_func::<(Resource<Substate>, Resource<Substate>), (u64,)>(&mut store, "run")?;
    let (out,) = run.call(
        &mut store,
        (Resource::new_borrow(0), Resource::new_borrow(1)),
    )?;
    run.post_return(&mut store)?;
    let consumed = fuel - store.get_fuel()?;
    let values = std::mem::take(&mut store.data_mut().values);
    Ok((out, consumed, values))
}

#[test]
fn kernel_world_round_trips_state_env_and_crypto() -> Result<()> {
    let engine = blessed_engine()?;
    let len = 1_000usize;
    let (out, _consumed, values) = run_guest(&engine, len, 10_000_000)?;

    // hash input is the 32-byte randomness draw of 7s.
    let hash_first = 7u8.wrapping_mul(32);
    let expected = CLOCK_MS + len as u64 + 32 + u64::from(hash_first);
    assert_eq!(out, expected);

    // The write leg copied substate 0's bytes into substate 1.
    assert_eq!(values[1], vec![3; len]);
    Ok(())
}

#[test]
fn boundary_charge_scales_exactly_with_bytes_moved() -> Result<()> {
    let engine = blessed_engine()?;
    let (_, small, _) = run_guest(&engine, 1_000, 10_000_000)?;
    let (_, large, _) = run_guest(&engine, 65_000, 10_000_000)?;

    // The guest never loops over the bytes (it passes the read buffer
    // straight to write), so the fuel difference is purely the boundary
    // supplement: the read return and the write argument, once each.
    let expected_delta = 2 * (65_000 - 1_000) * FUEL_PER_BOUNDARY_BYTE;
    assert_eq!(large - small, expected_delta);
    Ok(())
}

#[test]
fn boundary_charge_exhaustion_is_a_deterministic_out_of_fuel_trap() -> Result<()> {
    let engine = blessed_engine()?;
    let err = run_guest(&engine, 65_000, 20_000).expect_err("charge must exceed the budget");
    assert_eq!(err.downcast_ref::<Trap>(), Some(&Trap::OutOfFuel));
    Ok(())
}

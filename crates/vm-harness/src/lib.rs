//! Differential harness: runs seeded corpora under the blessed engine (every
//! backend the feature matrix admits) and the reference interpreter, comparing
//! outcomes byte-identically — return values, host access logs, trap kind.
//!
//! Also home of the profile rejection corpus and guest fixtures (hand-written
//! WAT compiled at test time, plus one realistic Rust guest). Dev-only: never
//! a dependency of `vm-runtime` or `vm-ref`.

/// Shared guest fixtures for the differential lanes.
pub mod fixtures {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result, ensure};
    use wit_component::ComponentEncoder;

    /// The repository root, derived from this crate's manifest directory.
    ///
    /// # Panics
    ///
    /// If the crate is somehow not two levels below a root.
    #[must_use]
    pub fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/vm-harness has a repo root")
            .to_path_buf()
    }

    /// Builds the `guests/transfer` crate with the pinned toolchain and
    /// returns the componentized artifact.
    ///
    /// # Errors
    ///
    /// Fails if the guest build or componentization fails.
    pub fn build_transfer_component() -> Result<Vec<u8>> {
        let guest_dir = repo_root().join("guests/transfer");
        let status = Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&guest_dir)
            .status()
            .context("spawn cargo for the guest build")?;
        ensure!(status.success(), "guest build failed");

        let core = std::fs::read(
            guest_dir.join("target/wasm32-unknown-unknown/release/transfer_guest.wasm"),
        )
        .context("read guest core module")?;
        let component = ComponentEncoder::default()
            .validate(true)
            .module(&core)
            .context("encode component")?
            .encode()
            .context("componentize")?;
        Ok(component)
    }
    /// The kernel-world component guest.
    ///
    /// `run` reads substate `a`, writes its bytes to substate `b`, and folds
    /// clock, randomness, and a hash into the return value; `forge` passes a
    /// handle index the host never lowered; `leak` reads through a valid
    /// borrow but never drops it.
    pub const KERNEL_GUEST_WAT: &str = r#"
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
      local.get 0
      i32.const 8
      call $read
      i32.const 8
      i32.load
      local.set $ptr
      i32.const 12
      i32.load
      local.set $len
      local.get 1
      local.get $ptr
      local.get $len
      call $write
      call $clock
      local.set $now
      i32.const 16
      call $randomness
      i32.const 16
      i32.load
      i32.const 20
      i32.load
      i32.const 24
      call $hash
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
      local.get 0
      call $drop
      local.get 1
      call $drop)
    (func (export "forge") (result i64)
      i32.const 9999
      i32.const 8
      call $read
      i32.const 12
      i32.load
      i64.extend_i32_u)
    (func (export "leak") (param i32 i32) (result i64)
      local.get 0
      i32.const 8
      call $read
      i32.const 12
      i32.load
      i64.extend_i32_u))

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
    (canon lift (core func $i "run")))
  (func (export "forge") (result u64)
    (canon lift (core func $i "forge")))
  (func (export "leak")
    (param "a" (borrow $sub)) (param "b" (borrow $sub)) (result u64)
    (canon lift (core func $i "leak"))))
"#;
}

//! Differential harness: runs seeded corpora under the blessed engine (every
//! backend the feature matrix admits) and the reference interpreter, comparing
//! outcomes byte-identically — return values, host access logs, trap kind.
//!
//! Also home of the profile rejection corpus and guest fixtures (hand-written
//! WAT compiled at test time, plus one realistic Rust guest). Dev-only: never
//! a dependency of `vm-runtime` or `vm-ref`.

/// Native stack for a lane that drives the executable spec near its
/// call-depth bound.
///
/// `vm-ref` recurses on the native stack once per wasm frame, and its own
/// frames are large in an unoptimised build — deep enough that the default
/// test thread runs out well before the counter does. An overflow there
/// aborts the process instead of producing the verdict the lane exists to
/// compare, so the lanes size their stack rather than inherit one.
pub const DEEP_STACK_BYTES: usize = 256 * 1024 * 1024;

/// Runs `body` on a thread with [`DEEP_STACK_BYTES`] of stack, carrying its
/// panic rather than replacing it.
///
/// # Panics
///
/// If the thread cannot be spawned, or with `body`'s own payload.
pub fn on_deep_stack<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(DEEP_STACK_BYTES)
        .spawn(body)
        .expect("spawn a deep-stack thread")
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// Shared guest fixtures for the differential lanes.
pub mod fixtures {
    use std::path::PathBuf;
    use std::process::Command;

    use wasmtime::Result;
    use wasmtime::error::{Context, ensure, format_err};
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

    /// Builds a `guests/<name>` crate with the pinned toolchain and
    /// returns the componentized artifact.
    ///
    /// The environment is scrubbed of the caller's toolchain selection:
    /// a `cargo` spawned from inside a cargo run inherits
    /// `RUSTUP_TOOLCHAIN`, which overrides `guests/rust-toolchain.toml`
    /// and would build a consensus artifact with whatever the host
    /// happens to have. The pin is only a pin if it wins.
    ///
    /// # Errors
    ///
    /// Fails if the guest build or componentization fails.
    pub fn build_guest(name: &str) -> Result<Vec<u8>> {
        let guest_dir = repo_root().join("guests").join(name);
        let status = Command::new("cargo")
            .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
            .current_dir(&guest_dir)
            .env_remove("RUSTUP_TOOLCHAIN")
            .env_remove("CARGO")
            .env_remove("CARGO_HOME")
            .env_remove("RUSTC")
            .env_remove("RUSTUP_HOME")
            .status()
            .context("spawn cargo for the guest build")?;
        ensure!(status.success(), "guest build failed");

        let core = std::fs::read(
            guest_dir
                .join("target/wasm32-unknown-unknown/release")
                .join(format!("{}_guest.wasm", name.replace('-', "_"))),
        )
        .context("read guest core module")?;
        // wit-component's API errors with `anyhow::Error`, which has no
        // `StdError` impl to convert through; flatten its chain instead.
        let component = ComponentEncoder::default()
            .validate(true)
            .module(&core)
            .map_err(|e| format_err!("encode component: {e:#}"))?
            .encode()
            .map_err(|e| format_err!("componentize: {e:#}"))?;
        Ok(component)
    }

    /// The transfer fixture's artifact.
    ///
    /// # Errors
    ///
    /// Fails if the guest build or componentization fails.
    pub fn build_transfer_component() -> Result<Vec<u8>> {
        build_guest("transfer")
    }
    /// The kernel-world component guest, exercising the per-mode surface.
    ///
    /// `transfer` moves a reserved amount into a delta cell; `peek` reads a
    /// locked cell; `rmw` bumps a write cell's first byte; `scan-sum`
    /// folds a read interval's entry and order bytes; `fill` rewrites entry
    /// zero and removes the last entry of a write interval; `place` inserts
    /// order 42; `escape` passes a delta handle to a read-cell function
    /// (the mode-escape trap); `forge` passes a handle index the host never
    /// lowered; `leak` never drops its borrow; `bad-amount` sends a 3-byte
    /// amount cell (a deterministic kernel refusal).
    pub const KERNEL_GUEST_WAT: &str = r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "read-cell" (type $rc (sub resource)))
    (export "locked-cell" (type $sc (sub resource)))
    (export "write-cell" (type $wc (sub resource)))
    (export "delta-cell" (type $dc (sub resource)))
    (export "reserve-cell" (type $vc (sub resource)))
    (export "range-read" (type $rr (sub resource)))
    (export "range-write" (type $rw (sub resource)))
    (export "read-cell-get" (func (param "c" (borrow $rc)) (result (list u8))))
    (export "locked-cell-get" (func (param "c" (borrow $sc)) (result (list u8))))
    (export "write-cell-get" (func (param "c" (borrow $wc)) (result (list u8))))
    (export "write-cell-set" (func (param "c" (borrow $wc)) (param "value" (list u8))))
    (export "delta-cell-add" (func (param "c" (borrow $dc)) (param "amount" (list u8))))
    (export "reserve-cell-amount" (func (param "c" (borrow $vc)) (result (list u8))))
    (export "range-read-count" (func (param "r" (borrow $rr)) (result u32)))
    (export "range-read-order" (func (param "r" (borrow $rr)) (param "index" u32) (result (list u8))))
    (export "range-read-entry" (func (param "r" (borrow $rr)) (param "index" u32) (result (list u8))))
    (export "range-write-count" (func (param "r" (borrow $rw)) (result u32)))
    (export "range-write-set" (func (param "r" (borrow $rw)) (param "index" u32) (param "value" (list u8))))
    (export "range-write-insert" (func (param "r" (borrow $rw)) (param "order" (list u8)) (param "value" (list u8))))
    (export "range-write-remove" (func (param "r" (borrow $rw)) (param "index" u32)))))
  (import "hyperscale:kernel/env" (instance $env
    (export "clock" (func (result u64)))))

  (alias export $state "read-cell" (type $rcell))
  (alias export $state "locked-cell" (type $scell))
  (alias export $state "write-cell" (type $wcell))
  (alias export $state "delta-cell" (type $dcell))
  (alias export $state "reserve-cell" (type $vcell))
  (alias export $state "range-read" (type $rrange))
  (alias export $state "range-write" (type $wrange))
  (alias export $state "read-cell-get" (func $read_get))
  (alias export $state "locked-cell-get" (func $locked_get))
  (alias export $state "write-cell-get" (func $write_get))
  (alias export $state "write-cell-set" (func $write_set))
  (alias export $state "delta-cell-add" (func $delta_add))
  (alias export $state "reserve-cell-amount" (func $reserve_amount))
  (alias export $state "range-read-count" (func $rr_count))
  (alias export $state "range-read-order" (func $rr_order))
  (alias export $state "range-read-entry" (func $rr_entry))
  (alias export $state "range-write-count" (func $rw_count))
  (alias export $state "range-write-set" (func $rw_set))
  (alias export $state "range-write-insert" (func $rw_insert))
  (alias export $state "range-write-remove" (func $rw_remove))
  (alias export $env "clock" (func $clock))

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

  (core func $read_get_l (canon lower (func $read_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $locked_get_l (canon lower (func $locked_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $write_get_l (canon lower (func $write_get)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $write_set_l (canon lower (func $write_set)
    (memory $a "mem")))
  (core func $delta_add_l (canon lower (func $delta_add)
    (memory $a "mem")))
  (core func $reserve_amount_l (canon lower (func $reserve_amount)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $rr_count_l (canon lower (func $rr_count)))
  (core func $rr_order_l (canon lower (func $rr_order)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $rr_entry_l (canon lower (func $rr_entry)
    (memory $a "mem") (realloc (func $a "realloc"))))
  (core func $rw_count_l (canon lower (func $rw_count)))
  (core func $rw_set_l (canon lower (func $rw_set)
    (memory $a "mem")))
  (core func $rw_insert_l (canon lower (func $rw_insert)
    (memory $a "mem")))
  (core func $rw_remove_l (canon lower (func $rw_remove)))
  (core func $clock_l (canon lower (func $clock)))
  (core func $drop_r (canon resource.drop $rcell))
  (core func $drop_s (canon resource.drop $scell))
  (core func $drop_w (canon resource.drop $wcell))
  (core func $drop_d (canon resource.drop $dcell))
  (core func $drop_v (canon resource.drop $vcell))
  (core func $drop_rr (canon resource.drop $rrange))
  (core func $drop_rw (canon resource.drop $wrange))

  (core module $m
    (import "env" "mem" (memory 4 4))
    (import "k" "read-get" (func $read_get (param i32 i32)))
    (import "k" "locked-get" (func $locked_get (param i32 i32)))
    (import "k" "write-get" (func $write_get (param i32 i32)))
    (import "k" "write-set" (func $write_set (param i32 i32 i32)))
    (import "k" "delta-add" (func $delta_add (param i32 i32 i32)))
    (import "k" "reserve-amount" (func $reserve_amount (param i32 i32)))
    (import "k" "rr-count" (func $rr_count (param i32) (result i32)))
    (import "k" "rr-order" (func $rr_order (param i32 i32 i32)))
    (import "k" "rr-entry" (func $rr_entry (param i32 i32 i32)))
    (import "k" "rw-count" (func $rw_count (param i32) (result i32)))
    (import "k" "rw-set" (func $rw_set (param i32 i32 i32 i32)))
    (import "k" "rw-insert" (func $rw_insert (param i32 i32 i32 i32 i32)))
    (import "k" "rw-remove" (func $rw_remove (param i32 i32)))
    (import "k" "clock" (func $clock (result i64)))
    (import "k" "drop-r" (func $drop_r (param i32)))
    (import "k" "drop-s" (func $drop_s (param i32)))
    (import "k" "drop-w" (func $drop_w (param i32)))
    (import "k" "drop-d" (func $drop_d (param i32)))
    (import "k" "drop-v" (func $drop_v (param i32)))
    (import "k" "drop-rr" (func $drop_rr (param i32)))
    (import "k" "drop-rw" (func $drop_rw (param i32)))

    (func (export "transfer") (param i32 i32) (result i64)
      local.get 0
      i32.const 8
      call $reserve_amount
      local.get 1
      i32.const 8
      i32.load
      i32.const 12
      i32.load
      call $delta_add
      i32.const 8
      i32.load
      i64.load
      local.get 0
      call $drop_v
      local.get 1
      call $drop_d)

    (func (export "peek") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $locked_get
      i32.const 12
      i32.load
      i64.extend_i32_u
      call $clock
      i64.add
      local.get 0
      call $drop_s)

    (func (export "rmw") (param i32) (result i64)
      (local $ptr i32) (local $len i32)
      local.get 0
      i32.const 8
      call $write_get
      i32.const 8
      i32.load
      local.set $ptr
      i32.const 12
      i32.load
      local.set $len
      local.get $len
      if
        local.get $ptr
        local.get $ptr
        i32.load8_u
        i32.const 1
        i32.add
        i32.store8
      end
      local.get 0
      local.get $ptr
      local.get $len
      call $write_set
      local.get $len
      i64.extend_i32_u
      local.get 0
      call $drop_w)

    (func (export "scan-sum") (param i32) (result i64)
      (local $n i32) (local $i i32) (local $sum i64)
      local.get 0
      call $rr_count
      local.set $n
      block
        loop
          local.get $i
          local.get $n
          i32.ge_u
          br_if 1
          local.get 0
          local.get $i
          i32.const 8
          call $rr_entry
          local.get $sum
          i32.const 8
          i32.load
          i32.load8_u
          i64.extend_i32_u
          i64.add
          local.set $sum
          local.get 0
          local.get $i
          i32.const 16
          call $rr_order
          local.get $sum
          i32.const 16
          i32.load
          i32.load8_u
          i64.extend_i32_u
          i64.add
          local.set $sum
          local.get $i
          i32.const 1
          i32.add
          local.set $i
          br 0
        end
      end
      local.get $sum
      local.get 0
      call $drop_rr)

    (func (export "fill") (param i32) (result i64)
      (local $n i32)
      local.get 0
      call $rw_count
      local.set $n
      local.get $n
      if
        i32.const 512
        i32.const 9
        i32.store8
        i32.const 513
        i32.const 9
        i32.store8
        local.get 0
        i32.const 0
        i32.const 512
        i32.const 2
        call $rw_set
        local.get 0
        local.get $n
        i32.const 1
        i32.sub
        call $rw_remove
      end
      local.get $n
      i64.extend_i32_u
      local.get 0
      call $drop_rw)

    (func (export "place") (param i32) (result i64)
      i32.const 640
      i32.const 42
      i32.store8
      i32.const 660
      i32.const 7
      i32.store8
      local.get 0
      i32.const 640
      i32.const 16
      i32.const 660
      i32.const 1
      call $rw_insert
      local.get 0
      call $rw_count
      i64.extend_i32_u
      local.get 0
      call $drop_rw)

    (func (export "escape") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "forge") (result i64)
      i32.const 9999
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "handle-value") (param i32) (result i64)
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_r)

    (func (export "forge-zero") (result i64)
      i32.const 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "leak") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      i32.const 12
      i32.load
      i64.extend_i32_u)

    (func (export "bad-amount") (param i32) (result i64)
      local.get 0
      i32.const 0
      i32.const 3
      call $delta_add
      i64.const 0))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance
      (export "read-get" (func $read_get_l))
      (export "locked-get" (func $locked_get_l))
      (export "write-get" (func $write_get_l))
      (export "write-set" (func $write_set_l))
      (export "delta-add" (func $delta_add_l))
      (export "reserve-amount" (func $reserve_amount_l))
      (export "rr-count" (func $rr_count_l))
      (export "rr-order" (func $rr_order_l))
      (export "rr-entry" (func $rr_entry_l))
      (export "rw-count" (func $rw_count_l))
      (export "rw-set" (func $rw_set_l))
      (export "rw-insert" (func $rw_insert_l))
      (export "rw-remove" (func $rw_remove_l))
      (export "clock" (func $clock_l))
      (export "drop-r" (func $drop_r))
      (export "drop-s" (func $drop_s))
      (export "drop-w" (func $drop_w))
      (export "drop-d" (func $drop_d))
      (export "drop-v" (func $drop_v))
      (export "drop-rr" (func $drop_rr))
      (export "drop-rw" (func $drop_rw))))))

  (func (export "transfer")
    (param "a" (borrow $vcell)) (param "b" (borrow $dcell)) (result u64)
    (canon lift (core func $i "transfer")))
  (func (export "peek")
    (param "c" (borrow $scell)) (result u64)
    (canon lift (core func $i "peek")))
  (func (export "rmw")
    (param "c" (borrow $wcell)) (result u64)
    (canon lift (core func $i "rmw")))
  (func (export "scan-sum")
    (param "r" (borrow $rrange)) (result u64)
    (canon lift (core func $i "scan-sum")))
  (func (export "fill")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "fill")))
  (func (export "place")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "place")))
  (func (export "escape")
    (param "c" (borrow $dcell)) (result u64)
    (canon lift (core func $i "escape")))
  (func (export "forge") (result u64)
    (canon lift (core func $i "forge")))
  (func (export "handle-value")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "handle-value")))
  (func (export "forge-zero") (result u64)
    (canon lift (core func $i "forge-zero")))
  (func (export "leak")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "leak")))
  (func (export "bad-amount")
    (param "c" (borrow $dcell)) (result u64)
    (canon lift (core func $i "bad-amount"))))
"#;

    /// A component whose `realloc` calls a lowered import, closing a call
    /// cycle through the canonical-ABI boundary.
    ///
    /// `draw` calls `randomness`, whose lowering calls the guest's realloc
    /// to allocate the result — and that realloc calls `randomness` again,
    /// through a trampoline a third module's element segment filled. Every
    /// edge is ordinary: core instantiation is acyclic, and the only cycle
    /// runs through a host frame, so the deploy-time call graph is acyclic
    /// and the heaviest chain it sees is two frames deep.
    ///
    /// The canonical ABI's re-entrance rule is what actually stops it: a
    /// lowered import called from inside a lowering leaves an instance that
    /// is not free to be left.
    pub const REENTRANT_REALLOC_WAT: &str = r#"
(component
  (import "hyperscale:kernel/env" (instance $env
    (export "randomness" (func (result (list u8))))))
  (alias export $env "randomness" (func $randomness))

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
      i32.const 16
      call $stub
      local.get $ret))
  (core instance $a (instantiate $alloc (with "shim" (instance $is))))

  (core func $randomness_l (canon lower (func $randomness)
    (memory $a "mem") (realloc (func $a "realloc"))))

  (core module $fixups
    (import "shim" "t" (table $t 1 1 funcref))
    (import "k" "randomness" (func $target (param i32)))
    (elem (table $t) (i32.const 0) func $target))
  (core instance (instantiate $fixups
    (with "shim" (instance $is))
    (with "k" (instance (export "randomness" (func $randomness_l))))))

  (core module $main
    (import "env" "mem" (memory 4 4))
    (import "k" "randomness" (func $randomness (param i32)))
    (func (export "draw") (result i64)
      i32.const 8
      call $randomness
      i32.const 8
      i32.load
      i64.extend_i32_u))
  (core instance $m (instantiate $main
    (with "env" (instance $a))
    (with "k" (instance (export "randomness" (func $randomness_l))))))

  (func (export "draw") (result u64) (canon lift (core func $m "draw"))))
"#;

    /// A component whose `realloc` calls `canon resource.drop`.
    ///
    /// No call cycle closes — a drop leaves the instance without
    /// re-entering it — so only the may-leave rule stands between the
    /// callback and the host. The rule covers every canon builtin, not
    /// just the lowered import the realloc-cycle fixture uses; a runtime
    /// that checks it on one dispatch arm and not another diverges from
    /// the blessed engine exactly here.
    pub const REENTRANT_DROP_WAT: &str = r#"
(component
  (import "hyperscale:kernel/env" (instance $env
    (export "randomness" (func (result (list u8))))))
  (alias export $env "randomness" (func $randomness))
  (import "hyperscale:kernel/state" (instance $state
    (export "read-cell" (type $rc (sub resource)))))
  (alias export $state "read-cell" (type $rcell))

  (core func $drop (canon resource.drop $rcell))

  (core module $alloc
    (import "k" "drop" (func $drop (param i32)))
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
      i32.const 0
      call $drop
      local.get $ret))
  (core instance $a (instantiate $alloc
    (with "k" (instance (export "drop" (func $drop))))))

  (core func $randomness_l (canon lower (func $randomness)
    (memory $a "mem") (realloc (func $a "realloc"))))

  (core module $main
    (import "env" "mem" (memory 4 4))
    (import "k" "randomness" (func $randomness (param i32)))
    (func (export "draw") (result i64)
      i32.const 8
      call $randomness
      i32.const 8
      i32.load
      i64.extend_i32_u))
  (core instance $m (instantiate $main
    (with "env" (instance $a))
    (with "k" (instance (export "randomness" (func $randomness_l))))))

  (func (export "draw") (result u64) (canon lift (core func $m "draw"))))
"#;
}

/// The kernel session as both runtimes' host.
///
/// Thin delegation so one [`hyperscale_vm_kernel::KernelSession`] drives
/// the blessed engine and the reference interpreter with identical
/// semantics and identical refusal messages.
pub mod session_host {
    use hyperscale_vm_kernel::KernelSession;
    use hyperscale_vm_ref::RefKernelHost;
    use hyperscale_vm_runtime::KernelHost;

    /// Wraps a session for use as a wasmtime store data or a `vm-ref` host.
    #[derive(Debug)]
    pub struct SessionHost(pub KernelSession);

    macro_rules! delegate {
        ($trait_path:path) => {
            impl $trait_path for SessionHost {
                fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                    self.0.read_cell(rep).map_err(|t| t.to_string())
                }
                fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                    self.0.locked_cell(rep).map_err(|t| t.to_string())
                }
                fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                    self.0.write_cell_get(rep).map_err(|t| t.to_string())
                }
                fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), String> {
                    self.0.write_cell_set(rep, value).map_err(|t| t.to_string())
                }
                fn delta_add(&mut self, rep: u32, amount: &[u8]) -> Result<(), String> {
                    self.0.delta_add(rep, amount).map_err(|t| t.to_string())
                }
                fn delta_sub(&mut self, rep: u32, amount: &[u8]) -> Result<(), String> {
                    self.0.delta_sub(rep, amount).map_err(|t| t.to_string())
                }
                fn reserve_amount(&mut self, rep: u32) -> Result<Vec<u8>, String> {
                    self.0.reserve_amount(rep).map_err(|t| t.to_string())
                }
                fn range_count(&mut self, rep: u32) -> Result<u32, String> {
                    self.0.range_count(rep).map_err(|t| t.to_string())
                }
                fn range_order(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String> {
                    self.0.range_order(rep, index).map_err(|t| t.to_string())
                }
                fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, String> {
                    self.0.range_entry(rep, index).map_err(|t| t.to_string())
                }
                fn range_set(
                    &mut self,
                    rep: u32,
                    index: u32,
                    value: Vec<u8>,
                ) -> Result<(), String> {
                    self.0
                        .range_set(rep, index, value)
                        .map_err(|t| t.to_string())
                }
                fn range_insert(
                    &mut self,
                    rep: u32,
                    order: &[u8],
                    value: Vec<u8>,
                ) -> Result<(), String> {
                    self.0
                        .range_insert(rep, order, value)
                        .map_err(|t| t.to_string())
                }
                fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), String> {
                    self.0.range_remove(rep, index).map_err(|t| t.to_string())
                }
                fn clock_ms(&self) -> u64 {
                    self.0.clock_ms()
                }
                fn randomness(&self) -> [u8; 32] {
                    self.0.randomness()
                }
                fn hash(&self, data: &[u8]) -> [u8; 32] {
                    self.0.hash(data)
                }
                fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), String> {
                    self.0.emit(event_type, payload).map_err(|t| t.to_string())
                }
            }
        };
    }

    delegate!(KernelHost);
    delegate!(RefKernelHost);
}

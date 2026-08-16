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

    use hyperscale_vm_cli::compile;
    use wasmtime::Result;
    use wasmtime::error::format_err;

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
            .expect("crates/harness has a repo root")
            .to_path_buf()
    }

    /// Builds a `guests/<name>` crate and returns the componentized
    /// artifact.
    ///
    /// One implementation of the guest build, and it is the command's:
    /// what a test compiles and what `cargo hyperscale` compiles are the
    /// same bytes because they are the same call.
    ///
    /// # Errors
    ///
    /// Fails if the guest build, the componentization, or the
    /// deterministic profile refuses.
    pub fn build_guest(name: &str) -> Result<Vec<u8>> {
        compile(&repo_root().join("guests").join(name))
            .map_err(|error| format_err!("{name}: {error}"))
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
    /// lowered; `leak` never drops its borrow; `no-such-entry` removes past
    /// the interval's last entry (a deterministic kernel refusal).
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
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "read-cell-get" (func (param "c" (borrow $rc)) (result (list u8))))
    (export "locked-cell-get" (func (param "c" (borrow $sc)) (result (list u8))))
    (export "write-cell-get" (func (param "c" (borrow $wc)) (result (list u8))))
    (export "write-cell-set" (func (param "c" (borrow $wc)) (param "value" (list u8))))
    (export "delta-cell-add" (func (param "c" (borrow $dc)) (param "value" $amt)))
    (export "reserve-cell-amount" (func (param "c" (borrow $vc)) (result $amt)))
    (export "range-read-count" (func (param "r" (borrow $rr)) (result u32)))
    (export "range-read-order" (func (param "r" (borrow $rr)) (param "index" u32) (result $amt)))
    (export "range-read-entry" (func (param "r" (borrow $rr)) (param "index" u32) (result (list u8))))
    (export "range-write-count" (func (param "r" (borrow $rw)) (result u32)))
    (export "range-write-set" (func (param "r" (borrow $rw)) (param "index" u32) (param "value" (list u8))))
    (export "range-write-insert" (func (param "r" (borrow $rw)) (param "order" $amt) (param "value" (list u8))))
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
    (import "k" "delta-add" (func $delta_add (param i32 i64 i64)))
    (import "k" "reserve-amount" (func $reserve_amount (param i32 i32)))
    (import "k" "rr-count" (func $rr_count (param i32) (result i32)))
    (import "k" "rr-order" (func $rr_order (param i32 i32 i32)))
    (import "k" "rr-entry" (func $rr_entry (param i32 i32 i32)))
    (import "k" "rw-count" (func $rw_count (param i32) (result i32)))
    (import "k" "rw-set" (func $rw_set (param i32 i32 i32 i32)))
    (import "k" "rw-insert" (func $rw_insert (param i32 i64 i64 i32 i32)))
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
      i64.load
      i32.const 16
      i64.load
      call $delta_add
      i32.const 8
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
      i32.const 660
      i32.const 7
      i32.store8
      local.get 0
      i64.const 42
      i64.const 0
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

    (func (export "no-such-entry") (param i32) (result i64)
      local.get 0
      i32.const 99
      call $rw_remove
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
  (func (export "no-such-entry")
    (param "r" (borrow $wrange)) (result u64)
    (canon lift (core func $i "no-such-entry"))))
"#;

    /// The bucket guest: a component that takes value out of the cells it
    /// was lent, keeps it, gives it back, and throws some away.
    ///
    /// `hold` takes an `own<bucket>` and stashes the handle in a global,
    /// so the handle outlives the call that delivered it; `release`
    /// returns the stashed handle, which is where ownership crosses back
    /// out; `discard` takes one and drops it, which is where the host's
    /// own destructor runs. `peek` reads a cell through a borrow and
    /// exists to interleave the two: owned and borrowed handles share one
    /// table, so what a borrow is numbered depends on what an own is
    /// still holding.
    ///
    /// `take-delta`, `take-write` and `take-reserve` are the debits, each
    /// handing back the bucket it produced rather than a number; and
    /// `take-reserve-twice` asks one grant the same question twice, which
    /// is the one thing a take can refuse that the read beside it could
    /// not. `issue` is the one bucket with no cell behind it, and the
    /// only export here whose handle is an authority rather than a
    /// target. `put-write` and `put-delta` are the credits, each
    /// consuming the bucket it was handed; `put-write-then-drop` reaches
    /// for the handle afterwards, which is the one thing a put makes
    /// impossible. `take-two` debits two cells and hands both back at
    /// once, which is what a method with more than one edge does.
    ///
    /// The three handle-returning exports return the handle index they
    /// were given, because that index is a core `i32` a body can read and
    /// therefore something the two engines must agree on to the number.
    pub const BUCKET_GUEST_WAT: &str = r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "bucket" (type $bk (sub resource)))
    (export "issuer" (type $is (sub resource)))
    (export "read-cell" (type $rc (sub resource)))
    (export "write-cell" (type $wc (sub resource)))
    (export "delta-cell" (type $dc (sub resource)))
    (export "reserve-cell" (type $vc (sub resource)))
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "read-cell-get" (func (param "c" (borrow $rc)) (result (list u8))))
    (export "issuer-take" (func (param "i" (borrow $is)) (param "amount" $amt) (result (own $bk))))
    (export "write-cell-take" (func (param "c" (borrow $wc)) (param "amount" $amt) (result (own $bk))))
    (export "write-cell-put" (func (param "c" (borrow $wc)) (param "funds" (own $bk))))
    (export "delta-cell-put" (func (param "c" (borrow $dc)) (param "funds" (own $bk))))
    (export "delta-cell-take" (func (param "c" (borrow $dc)) (param "amount" $amt) (result (own $bk))))
    (export "reserve-cell-take" (func (param "c" (borrow $vc)) (result (own $bk))))))

  (alias export $state "bucket" (type $bucket))
  (alias export $state "issuer" (type $issuer))
  (alias export $state "read-cell" (type $rcell))
  (alias export $state "write-cell" (type $wcell))
  (alias export $state "delta-cell" (type $dcell))
  (alias export $state "reserve-cell" (type $vcell))
  (alias export $state "read-cell-get" (func $read_get))
  (alias export $state "issuer-take" (func $issue))
  (alias export $state "write-cell-take" (func $write_take))
  (alias export $state "write-cell-put" (func $write_put))
  (alias export $state "delta-cell-put" (func $delta_put))
  (alias export $state "delta-cell-take" (func $delta_take))
  (alias export $state "reserve-cell-take" (func $reserve_take))

  (core module $alloc
    (memory (export "mem") 1 1)
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
  (core func $issue_l (canon lower (func $issue)))
  (core func $write_take_l (canon lower (func $write_take)))
  (core func $write_put_l (canon lower (func $write_put)))
  (core func $delta_put_l (canon lower (func $delta_put)))
  (core func $delta_take_l (canon lower (func $delta_take)))
  (core func $reserve_take_l (canon lower (func $reserve_take)))
  (core func $drop_bucket (canon resource.drop $bucket))
  (core func $drop_read (canon resource.drop $rcell))
  (core func $drop_issuer (canon resource.drop $issuer))
  (core func $drop_write (canon resource.drop $wcell))
  (core func $drop_delta (canon resource.drop $dcell))
  (core func $drop_reserve (canon resource.drop $vcell))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "read-get" (func $read_get (param i32 i32)))
    (import "k" "issue" (func $issue (param i32 i64 i64) (result i32)))
    (import "k" "write-take" (func $write_take (param i32 i64 i64) (result i32)))
    (import "k" "write-put" (func $write_put (param i32 i32)))
    (import "k" "delta-put" (func $delta_put (param i32 i32)))
    (import "k" "delta-take" (func $delta_take (param i32 i64 i64) (result i32)))
    (import "k" "reserve-take" (func $reserve_take (param i32) (result i32)))
    (import "k" "drop-bucket" (func $drop_bucket (param i32)))
    (import "k" "drop-read" (func $drop_read (param i32)))
    (import "k" "drop-issuer" (func $drop_issuer (param i32)))
    (import "k" "drop-write" (func $drop_write (param i32)))
    (import "k" "drop-delta" (func $drop_delta (param i32)))
    (import "k" "drop-reserve" (func $drop_reserve (param i32)))
    (global $held (mut i32) (i32.const 0))

    (func (export "hold") (param i32) (result i64)
      local.get 0
      global.set $held
      local.get 0
      i64.extend_i32_u)

    (func (export "release") (result i32)
      global.get $held)

    (func (export "peek") (param i32) (result i64)
      local.get 0
      i32.const 8
      call $read_get
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_read)

    (func (export "discard") (param i32) (result i64)
      local.get 0
      i64.extend_i32_u
      local.get 0
      call $drop_bucket)

    (func (export "issue") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $issue
      local.get 0
      call $drop_issuer)

    ;; Credit the cell with the bucket, then say whether the handle it
    ;; consumed still names anything: a live one would answer, and a
    ;; consumed one traps, which is what the negative index reports.
    (func (export "put-write") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $write_put
      local.get 0
      call $drop_write
      i64.const 0)

    (func (export "put-delta") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $delta_put
      local.get 0
      call $drop_delta
      i64.const 0)

    ;; The same credit, then a second drop of the handle it consumed.
    (func (export "put-write-then-drop") (param i32 i32) (result i64)
      local.get 0
      local.get 1
      call $write_put
      local.get 1
      call $drop_bucket
      local.get 0
      call $drop_write
      i64.const 0)

    ;; Two debits, from two cells, handed back together: the handles go
    ;; into the return area in declared order and the area's pointer is
    ;; what a spilled result returns.
    (func (export "take-two") (param i32 i32 i64 i64) (result i32)
      (local $one i32) (local $two i32)
      local.get 0
      local.get 2
      i64.const 0
      call $delta_take
      local.set $one
      local.get 1
      local.get 3
      i64.const 0
      call $write_take
      local.set $two
      i32.const 64
      local.get $one
      i32.store
      i32.const 68
      local.get $two
      i32.store
      local.get 0
      call $drop_delta
      local.get 1
      call $drop_write
      i32.const 64)

    (func (export "take-write") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $write_take
      local.get 0
      call $drop_write)

    (func (export "take-delta") (param i32 i64) (result i32)
      local.get 0
      local.get 1
      i64.const 0
      call $delta_take
      local.get 0
      call $drop_delta)

    (func (export "take-reserve") (param i32) (result i32)
      local.get 0
      call $reserve_take
      local.get 0
      call $drop_reserve)

    (func (export "take-reserve-twice") (param i32) (result i32)
      local.get 0
      call $reserve_take
      call $drop_bucket
      local.get 0
      call $reserve_take
      local.get 0
      call $drop_reserve))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance
      (export "read-get" (func $read_get_l))
      (export "issue" (func $issue_l))
      (export "write-take" (func $write_take_l))
      (export "write-put" (func $write_put_l))
      (export "delta-put" (func $delta_put_l))
      (export "delta-take" (func $delta_take_l))
      (export "reserve-take" (func $reserve_take_l))
      (export "drop-bucket" (func $drop_bucket))
      (export "drop-read" (func $drop_read))
      (export "drop-issuer" (func $drop_issuer))
      (export "drop-write" (func $drop_write))
      (export "drop-delta" (func $drop_delta))
      (export "drop-reserve" (func $drop_reserve))))))

  (func (export "hold")
    (param "b" (own $bucket)) (result u64)
    (canon lift (core func $i "hold")))
  (func (export "release") (result (own $bucket))
    (canon lift (core func $i "release")))
  (func (export "peek")
    (param "c" (borrow $rcell)) (result u64)
    (canon lift (core func $i "peek")))
  (func (export "discard")
    (param "b" (own $bucket)) (result u64)
    (canon lift (core func $i "discard")))
  (func (export "issue")
    (param "i" (borrow $issuer)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "issue")))
  (func (export "take-two")
    (param "d" (borrow $dcell)) (param "w" (borrow $wcell))
    (param "a" u64) (param "b" u64)
    (result (tuple (own $bucket) (own $bucket)))
    (canon lift (core func $i "take-two") (memory $a "mem")))
  (func (export "put-write")
    (param "c" (borrow $wcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-write")))
  (func (export "put-delta")
    (param "c" (borrow $dcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-delta")))
  (func (export "put-write-then-drop")
    (param "c" (borrow $wcell)) (param "funds" (own $bucket)) (result u64)
    (canon lift (core func $i "put-write-then-drop")))
  (func (export "take-write")
    (param "c" (borrow $wcell)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "take-write")))
  (func (export "take-delta")
    (param "c" (borrow $dcell)) (param "amount" u64) (result (own $bucket))
    (canon lift (core func $i "take-delta")))
  (func (export "take-reserve")
    (param "v" (borrow $vcell)) (result (own $bucket))
    (canon lift (core func $i "take-reserve")))
  (func (export "take-reserve-twice")
    (param "v" (borrow $vcell)) (result (own $bucket))
    (canon lift (core func $i "take-reserve-twice"))))
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
/// semantics and identical refusal classes.
pub mod session_host {
    use hyperscale_vm_kernel::{AbortReason, KernelSession};
    use hyperscale_vm_ref::RefKernelHost;
    use hyperscale_vm_runtime::KernelHost;

    /// Wraps a session for use as a wasmtime store data or a `vm-ref` host.
    #[derive(Debug)]
    pub struct SessionHost(pub KernelSession);

    macro_rules! delegate {
        ($trait_path:path) => {
            impl $trait_path for SessionHost {
                fn read_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
                    self.0.read_cell(rep).map_err(AbortReason::from)
                }
                fn locked_cell(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
                    self.0.locked_cell(rep).map_err(AbortReason::from)
                }
                fn write_cell_get(&mut self, rep: u32) -> Result<Vec<u8>, AbortReason> {
                    self.0.write_cell_get(rep).map_err(AbortReason::from)
                }
                fn write_cell_set(&mut self, rep: u32, value: Vec<u8>) -> Result<(), AbortReason> {
                    self.0.write_cell_set(rep, value).map_err(AbortReason::from)
                }
                fn delta_add(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason> {
                    self.0.delta_add(rep, amount).map_err(AbortReason::from)
                }
                fn delta_sub(&mut self, rep: u32, amount: u128) -> Result<(), AbortReason> {
                    self.0.delta_sub(rep, amount).map_err(AbortReason::from)
                }
                fn delta_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
                    self.0.delta_put(rep, funds).map_err(AbortReason::from)
                }
                fn write_put(&mut self, rep: u32, funds: u32) -> Result<(), AbortReason> {
                    self.0.write_put(rep, funds).map_err(AbortReason::from)
                }
                fn issuer_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
                    self.0.issuer_take(rep, amount).map_err(AbortReason::from)
                }
                fn delta_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
                    self.0.delta_take(rep, amount).map_err(AbortReason::from)
                }
                fn write_take(&mut self, rep: u32, amount: u128) -> Result<u32, AbortReason> {
                    self.0.write_take(rep, amount).map_err(AbortReason::from)
                }
                fn reserve_amount(&mut self, rep: u32) -> Result<u128, AbortReason> {
                    self.0.reserve_amount(rep).map_err(AbortReason::from)
                }
                fn reserve_take(&mut self, rep: u32) -> Result<u32, AbortReason> {
                    self.0.reserve_take(rep).map_err(AbortReason::from)
                }
                fn range_count(&mut self, rep: u32) -> Result<u32, AbortReason> {
                    self.0.range_count(rep).map_err(AbortReason::from)
                }
                fn range_order(&mut self, rep: u32, index: u32) -> Result<u128, AbortReason> {
                    self.0.range_order(rep, index).map_err(AbortReason::from)
                }
                fn range_entry(&mut self, rep: u32, index: u32) -> Result<Vec<u8>, AbortReason> {
                    self.0.range_entry(rep, index).map_err(AbortReason::from)
                }
                fn range_set(
                    &mut self,
                    rep: u32,
                    index: u32,
                    value: Vec<u8>,
                ) -> Result<(), AbortReason> {
                    self.0
                        .range_set(rep, index, value)
                        .map_err(AbortReason::from)
                }
                fn range_insert(
                    &mut self,
                    rep: u32,
                    order: u128,
                    value: Vec<u8>,
                ) -> Result<(), AbortReason> {
                    self.0
                        .range_insert(rep, order, value)
                        .map_err(AbortReason::from)
                }
                fn range_remove(&mut self, rep: u32, index: u32) -> Result<(), AbortReason> {
                    self.0.range_remove(rep, index).map_err(AbortReason::from)
                }
                fn bucket_drop(&mut self, rep: u32) -> Result<(), AbortReason> {
                    self.0.drop_bucket(rep).map_err(AbortReason::from)
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
                fn emit(&mut self, event_type: u32, payload: Vec<u8>) -> Result<(), AbortReason> {
                    self.0.emit(event_type, payload).map_err(AbortReason::from)
                }
            }
        };
    }

    delegate!(KernelHost);
    delegate!(RefKernelHost);
}

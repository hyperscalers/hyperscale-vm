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

pub mod driver;
pub mod dual;

/// Shared guest fixtures for the differential lanes.
pub mod fixtures {
    use std::path::PathBuf;

    use hyperscale_vm_cli::compile;
    use hyperscale_vm_kernel::KernelHost;
    use hyperscale_vm_types::math::U256;
    use hyperscale_vm_types::{AbortReason, Drawn};
    use wasmtime::Result;
    use wasmtime::error::format_err;

    /// A host with no capabilities, for guests that import none.
    ///
    /// Both engines want something implementing the trait to instantiate
    /// against, and a guest exercising only `math` reaches no state — so
    /// every arm here answers with the class an unreachable call would
    /// earn rather than a panic.
    pub struct NoHost;

    #[allow(clippy::missing_errors_doc)] // unreachable: the guest imports nothing
    impl KernelHost for NoHost {
        fn run_len(&mut self, _rep: u32) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn run_declared(&mut self, _rep: u32, _index: u32) -> Result<bool, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn run_at(&mut self, _rep: u32, _index: u32) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn read_cell(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn write_cell_get(&mut self, _rep: u32) -> Result<Vec<u8>, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn write_cell_set(&mut self, _rep: u32, _value: Vec<u8>) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn write_cell_clear(&mut self, _rep: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn amount_cell_balance(&mut self, _rep: u32) -> Result<u128, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn burn(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn mint_instances(&mut self, _rep: u32, _ids: &[u64]) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_take(&mut self, _rep: u32, _ids: &[u64]) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_put(&mut self, _rep: u32, _funds: u32, _v: Vec<u8>) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn bucket_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn bucket_split(&mut self, _rep: u32, _num: U256, _den: U256) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn bucket_put(&mut self, _rep: u32, _other: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn bucket_amount(&mut self, _rep: u32) -> Result<u128, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn delta_put(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn write_put(&mut self, _rep: u32, _funds: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn mint(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn delta_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn write_take(&mut self, _rep: u32, _amount: u128) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn reserve_take(&mut self, _rep: u32) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn take_scan_debt(&mut self) -> usize {
            0
        }
        fn range_count(&mut self, _rep: u32) -> Result<u32, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_covered(&mut self, _rep: u32) -> Result<bool, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_order(&mut self, _rep: u32, _index: u32) -> Result<u128, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_entry(&mut self, _rep: u32, _index: u32) -> Result<Vec<u8>, AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_set(
            &mut self,
            _rep: u32,
            _index: u32,
            _value: Vec<u8>,
        ) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_insert(
            &mut self,
            _rep: u32,
            _order: u128,
            _v: Vec<u8>,
        ) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn range_remove(&mut self, _rep: u32, _index: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn bucket_drop(&mut self, _rep: u32) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
        fn epoch(&self) -> u64 {
            0
        }
        fn open_seal(&self, _rep: u32, _epoch: u64) -> Result<Drawn, AbortReason> {
            Ok(Drawn::Pending)
        }
        fn clock_ms(&self) -> u64 {
            0
        }
        fn hash(&self, _data: &[u8]) -> [u8; 32] {
            [0; 32]
        }
        fn emit(&mut self, _event_type: u32, _payload: Vec<u8>) -> Result<(), AbortReason> {
            Err(AbortReason::HandleUnknown)
        }
    }

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

    /// The kernel-world component guest, exercising the per-mode surface.
    ///
    /// Written as WAT so its memory representation is readable in this
    /// source, and so it can reach shapes no compiled guest expresses: a
    /// forged handle, a mode escape, a borrow it never drops.
    ///
    /// `transfer` takes a reservation and moves the value it grants into
    /// a delta cell; `hash-tag` folds
    /// the host hash of four scratch bytes, which is the one kernel
    /// interface a guest cannot check for itself; `peek` reads a cell
    /// and folds the clock in; `rmw` bumps a write cell's first byte;
    /// `scan-sum`
    /// folds a read interval's entry and order bytes; `fill` rewrites entry
    /// zero and removes the last entry of a write interval; `place` inserts
    /// order 42; `escape` passes a delta handle to a read-cell function
    /// (the mode-escape trap); `forge` passes a handle index the host never
    /// lowered; `read-value` reads whatever read cell it is handed, which
    /// is how a test reaches the rep a clause nobody declared would have
    /// occupied; `leak` never drops its borrow; `no-such-entry` removes
    /// past the interval's last entry (a deterministic kernel refusal).
    pub const KERNEL_GUEST_WAT: &str = include_str!("fixtures/kernel_guest.wat");

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
    /// `weigh` reads what a bucket carries and hands it back, which is
    /// the one question about value that moves none. `halve` splits a
    /// bucket and merges the halves straight back, and `split` keeps only
    /// what came off. `self-merge` names one bucket as both sides of a
    /// merge, which the canonical ABI refuses: an owned argument cannot
    /// come out of a slot the same call is borrowing.
    ///
    /// The three handle-returning exports return the handle index they
    /// were given, because that index is a core `i32` a body can read and
    /// therefore something the two engines must agree on to the number.
    pub const BUCKET_GUEST_WAT: &str = include_str!("fixtures/bucket_guest.wat");

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
    pub const REENTRANT_REALLOC_WAT: &str = include_str!("fixtures/reentrant_realloc.wat");

    /// A component whose `realloc` calls `canon resource.drop`.
    ///
    /// No call cycle closes — a drop leaves the instance without
    /// re-entering it — so only the may-leave rule stands between the
    /// callback and the host. The rule covers every canon builtin, not
    /// just the lowered import the realloc-cycle fixture uses; a runtime
    /// that checks it on one dispatch arm and not another diverges from
    /// the blessed engine exactly here.
    pub const REENTRANT_DROP_WAT: &str = include_str!("fixtures/reentrant_drop.wat");
}

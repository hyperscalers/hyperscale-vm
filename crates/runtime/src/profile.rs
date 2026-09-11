//! The deterministic profile's structural limits.
//!
//! Every constant here is a consensus value: a module that exceeds one is
//! rejected at deploy, identically on every node. Runtime limits (fuel, call
//! depth) live on the engine configuration; these are the shapes checked once,
//! before code enters state.

use hyperscale_vm_types::MAX_TX_BYTES_LEN;

/// Maximum size of an artifact, custom sections included.
///
/// An artifact reaches the chain as a publish transaction's body, so it can
/// be no larger than one: the deploy ceiling is the wire ceiling, and the two
/// are one constant so they cannot drift into a module that admits at
/// deploy but no envelope can carry.
pub const MAX_ARTIFACT_BYTES: usize = MAX_TX_BYTES_LEN;

/// Maximum functions defined in one core module.
pub const MAX_FUNCTIONS_PER_MODULE: usize = 10_000;

/// Maximum types declared in one core module.
pub const MAX_TYPES_PER_MODULE: usize = 1_000;

/// Maximum encoded size of one function body, locals included.
pub const MAX_FUNCTION_BODY_BYTES: usize = 128 * 1024;

/// Maximum parameters on one core function type.
pub const MAX_PARAMS_PER_FUNCTION: usize = 32;

/// Maximum declared locals in one function body.
pub const MAX_LOCALS_PER_FUNCTION: usize = 512;

/// Maximum structured control-flow entries (`block`/`loop`/`if`) in one
/// function body — the basic-block proxy the compile-bomb bounds use.
pub const MAX_BLOCKS_PER_FUNCTION: usize = 10_000;

/// Maximum structured control-flow entries summed over a core module.
pub const MAX_BLOCKS_PER_MODULE: usize = 100_000;

/// Maximum linear memories per core module.
pub const MAX_MEMORIES_PER_MODULE: usize = 1;

/// Maximum linear memory size in 64 KiB pages; a memory must declare a
/// maximum, and it must not exceed this.
pub const MAX_MEMORY_PAGES: u64 = 256;

/// Maximum tables per core module — one, matching the executable spec's
/// hard single-table decode limit.
pub const MAX_TABLES_PER_MODULE: usize = 1;

/// Maximum elements in one table; a table must declare a maximum, and it must
/// not exceed this.
pub const MAX_TABLE_ELEMENTS: u64 = 10_000;

/// Maximum globals per core module.
pub const MAX_GLOBALS_PER_MODULE: usize = 1_000;

/// Host stack budget for guest execution, in bytes.
pub const MAX_WASM_STACK_BYTES: usize = 512 * 1024;

/// Native frame bytes charged per value slot — parameters, declared
/// locals, and operands live across a call.
///
/// Measured, not assumed: `spike_frame_size` recurses to exhaustion and
/// divides the stack budget by the depth reached. Cranelift costs exactly
/// eight bytes per slot over a forty-eight byte fixed frame; the model
/// carries margin over that so a codegen change moves the spike before it
/// moves consensus.
pub const STACK_BYTES_PER_SLOT: usize = 32;

/// Native frame bytes charged before any slot: saved registers, the
/// return address, and alignment.
pub const STACK_FRAME_OVERHEAD_BYTES: usize = 256;

/// Maximum value slots one frame may need: parameters, declared locals,
/// and the deepest operand stack together.
pub const MAX_SLOTS_PER_FRAME: usize = MAX_PARAMS_PER_FUNCTION + MAX_LOCALS_PER_FUNCTION + 256;

/// Native stack reserved for the host frames at either end of a guest
/// call chain: the kernel's call into the export, and the import a leaf
/// calls out to.
pub const HOST_FRAME_RESERVE_BYTES: usize = 64 * 1024;

/// What one guest call chain may consume.
///
/// The whole reserve, because one chain stands at a time: an import is a
/// host function that returns without calling back into the guest.
pub const MAX_CALL_CHAIN_BYTES: usize = MAX_WASM_STACK_BYTES - HOST_FRAME_RESERVE_BYTES;

/// How many frames one guest call chain may stand at once.
///
/// The byte budget bounds a chain's stack consumption, which is not the
/// same limit as its depth: at [`STACK_FRAME_OVERHEAD_BYTES`], the
/// cheapest frame anything can cost, [`MAX_CALL_CHAIN_BYTES`] alone admits
/// eight hundred and ninety-six of them — deeper than the executable
/// spec's own call counter tolerates, so an artifact could validate here
/// and trap there.
///
/// Both runtimes have to execute what the profile admits, so depth is
/// bounded too. The cap sits at half the spec's counter: reaching that
/// counter then means this bound failed, not that a guest was merely deep,
/// which is what lets the differential lanes treat it as a defect rather
/// than as a divergence to excuse. `vm-harness` asserts the ordering at
/// compile time — it is the only crate that can see both constants.
pub const MAX_CALL_CHAIN_FRAMES: usize = 256;

/// The prefix every kernel import module carries: `kernel/state`,
/// `kernel/env`, and so on.
pub const KERNEL_IMPORT_PREFIX: &str = "kernel/";

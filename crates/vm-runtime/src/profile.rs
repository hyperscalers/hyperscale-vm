//! The deterministic profile's structural limits.
//!
//! Every constant here is a consensus value: a component that exceeds one is
//! rejected at deploy, identically on every node. Runtime limits (fuel, call
//! depth) live on the engine configuration; these are the shapes checked once,
//! before code enters state.

/// Maximum size of a component artifact, custom sections included.
pub const MAX_COMPONENT_BYTES: usize = 4 * 1024 * 1024;

/// Maximum core modules inside one component.
pub const MAX_CORE_MODULES: usize = 8;

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

/// The single import package a contract world may name.
///
/// Component import names follow the `package:namespace/interface` grammar,
/// so every permitted import starts with this prefix —
/// `hyperscale:kernel/state`, `hyperscale:kernel/env`, and so on.
pub const KERNEL_IMPORT_PREFIX: &str = "hyperscale:kernel/";

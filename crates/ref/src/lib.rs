//! Reference interpreter of the deterministic profile.
//!
//! A slow, obviously-correct implementation of exactly the subset the profile
//! validator admits — the executable spec, differentially tested against the
//! blessed engine. Execution semantics are implemented independently of
//! wasmtime; sharing is permitted at the decode layer (wasmparser), at the
//! boundary dispatch, which is stated once in `hyperscale-vm-embed` for
//! both engines, and at the meter, whose instrumented module both engines
//! run. The schedule that module charges by is restated here in
//! [`fuel_cost`], sharing no constant with the pass.

pub mod boundary;
pub mod error;
pub mod interp;
pub mod module;
pub mod ops;

pub use boundary::RefModuleInstance;
pub use error::{DecodeError, InstantiateError, Trap};
pub use interp::{ExecError, MAX_CALL_DEPTH, RefInstance};
pub use module::{RefModule, translate};
pub use ops::{Op, Value, fuel_cost};

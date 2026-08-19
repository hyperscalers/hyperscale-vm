//! Reference interpreter of the deterministic profile.
//!
//! A slow, obviously-correct implementation of exactly the subset the profile
//! validator admits — the executable spec, differentially tested against the
//! blessed engine. Execution semantics, canonical-ABI lift/lower, and the fuel
//! schedule are implemented independently of wasmtime; sharing is permitted
//! only at the decode layer (wasmparser).

pub mod component;
pub mod error;
pub mod interp;
pub mod module;
pub mod ops;

pub use component::{CVal, RefComponent, RefComponentInstance, ResourceKind};
pub use error::{DecodeError, InstantiateError, Trap};
pub use interp::{CanonError, ExecError, MAX_CALL_DEPTH, RefInstance};
pub use module::RefModule;
pub use ops::Value;

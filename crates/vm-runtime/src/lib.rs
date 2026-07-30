//! Component Model host under the frozen deterministic profile.
//!
//! Home of the blessed-engine embedding (wasmtime, version-pinned), the
//! deploy-time profile validator, the `hyperscale:kernel` world, and the
//! metering layer (engine fuel plus the canonical-ABI copy supplement).

pub mod engine;
pub mod profile;
pub mod validator;

pub use engine::{blessed_config, blessed_engine};
pub use validator::{ProfileError, validate_component};

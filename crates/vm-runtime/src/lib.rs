//! Component Model host under the frozen deterministic profile.
//!
//! Home of the blessed-engine embedding (wasmtime, version-pinned), the
//! deploy-time profile validator, the `hyperscale:kernel` world, and the
//! metering layer (engine fuel plus the canonical-ABI copy supplement).
//!
//! Validation is the half that needs no engine: the profile's limits, the
//! stack bounds, and the validator itself read the artifact's bytes and
//! nothing else. Keeping them outside the `engine` feature is what lets a
//! build carrying no blessed engine still judge an artifact — an embedder
//! whose runtime interprets components rather than compiling them needs
//! the verdict just as much, and needs nothing else from here to get it.

pub mod frames;
pub mod profile;
pub mod validator;

#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod gas;
#[cfg(feature = "engine")]
pub mod world;

pub use validator::{ProfileError, validate_component, validate_core_module};
#[cfg(feature = "engine")]
pub use {
    engine::{blessed_config, blessed_engine},
    world::{
        DeltaCell, KernelHost, RangeRead, RangeWrite, ReadCell, ReserveCell, SnapCell, WriteCell,
        add_kernel_to_linker,
    },
};

//! The blessed engine's host under the frozen deterministic profile.
//!
//! Home of the blessed-engine embedding (wasmtime, version-pinned), the
//! deploy-time profile validator, the kernel imports, and the metering
//! layer (engine fuel plus the boundary copy supplement).
//!
//! Validation is the half that needs no engine: the profile's limits, the
//! stack bounds, and the validator itself read the artifact's bytes and
//! nothing else. Keeping them outside the `engine` feature is what lets a
//! build carrying no blessed engine still judge an artifact — an embedder
//! whose runtime interprets modules rather than compiling them needs the
//! verdict just as much, and needs nothing else from here to get it.

pub mod charges;
pub mod exports;
pub mod frames;
pub mod profile;
pub mod totality;
pub mod validator;

#[cfg(feature = "engine")]
pub mod abort;
#[cfg(feature = "engine")]
pub mod call;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod fuel;
#[cfg(feature = "engine")]
pub mod imports;

pub use charges::{InstantiationCharges, instantiation_charges};
pub use exports::{ModuleExport, module_exports};
pub use hyperscale_vm_embed::abi::CoreType;
pub use totality::{TotalityError, check_body, check_method, check_reachable};
pub use validator::{ProfileError, validate_core_module, validate_module};
#[cfg(feature = "engine")]
pub use {
    abort::{CallError, HostRefusal, classify, exhausted, trap_reason},
    call::{Returned, call_export, invoke_export},
    charges::instantiate_charged,
    engine::{blessed_config, blessed_engine},
    fuel::blessed_operator_cost,
    imports::{Invoking, add_kernel_imports},
};

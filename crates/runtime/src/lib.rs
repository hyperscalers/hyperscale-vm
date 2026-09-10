//! The blessed engine's host under the frozen deterministic profile.
//!
//! Home of the blessed-engine embedding (wasmtime, version-pinned), the
//! deploy-time profile validator, the admission sequence that runs the
//! meter's pass over what the validator admits, the kernel imports, and
//! the engine's side of the counter.
//!
//! Validation and admission are the half that needs no engine: the
//! profile's limits, the stack bounds, the validator and the pass read
//! the artifact's bytes and nothing else. Keeping them outside the
//! `engine` feature is what lets a build carrying no blessed engine
//! still judge an artifact and produce the module to run — an embedder
//! whose runtime interprets modules rather than compiling them needs
//! both just as much, and needs nothing else from here to get them.

pub mod admit;
pub mod exports;
pub mod frames;
pub mod profile;
pub mod totality;
pub mod validator;

#[cfg(feature = "engine")]
pub mod abort;
#[cfg(feature = "engine")]
pub mod budget;
#[cfg(feature = "engine")]
pub mod call;
#[cfg(feature = "engine")]
pub mod engine;
#[cfg(feature = "engine")]
pub mod imports;

pub use admit::{admit, admit_core_module};
pub use exports::{ModuleExport, module_exports};
pub use hyperscale_vm_embed::abi::CoreType;
pub use totality::{TotalityError, check_body, check_method, check_reachable};
pub use validator::{ProfileError, validate_core_module, validate_module};
#[cfg(feature = "engine")]
pub use {
    abort::{CallError, HostRefusal, classify, trap_reason},
    budget::{add_meter_import, counter, instantiate_metered, remaining},
    call::{Returned, call_export, invoke_export},
    engine::{blessed_config, blessed_engine},
    imports::{Invoking, add_kernel_imports},
};

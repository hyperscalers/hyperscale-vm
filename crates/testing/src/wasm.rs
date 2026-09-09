//! The blessed engine behind a chain: the package crate built to an
//! artifact, and the artifact executed.
//!
//! What a network would run, which is the point of the lane — the
//! boundary, the profile validator, and fuel all stand where a native
//! execution of the same bodies would have nothing to say.

use std::collections::BTreeMap;
use std::sync::{LazyLock, Mutex};

use hyperscale_vm_cli::compile;
use hyperscale_vm_effects::PackageHash;
use hyperscale_vm_kernel::{GuestBackend, GuestCall, InvokeResult, Invoked, KernelSession};
use hyperscale_vm_runtime::{
    InstantiationCharges, Invoking, add_kernel_imports, blessed_engine, instantiate_charged,
    invoke_module, module_instantiation_charges, validate_module,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Engine, Linker, Module, Store};

use crate::{Code, Package};

/// The ceiling one invocation may consume.
///
/// A figure no honest package reaches, because a test that ran out of
/// fuel would be reporting the ceiling rather than the bug. Public so a
/// second lane can meter against the same number: two ceilings would be
/// a divergence with nothing to catch it.
pub const FUEL_CEILING: u64 = 1_000_000_000;

/// The one blessed engine of the process.
///
/// Every compiled [`Module`] is bound to the engine that compiled it,
/// so one engine is what lets the compilation cache below hand a module
/// to any chain in the process.
static ENGINE: LazyLock<Engine> =
    LazyLock::new(|| blessed_engine().expect("the blessed engine configures"));

/// Modules compiled once per process, by the content address a call
/// names them at.
///
/// The key already means "these exact bytes", so the cache cannot go
/// stale within a run — and the cargo build behind [`Blessed::build`]
/// happens once per distinct package rather than once per test.
static COMPILED: LazyLock<Mutex<BTreeMap<PackageHash, (Module, InstantiationCharges)>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// Compiled packages, by the content address a call names them at.
#[derive(Clone)]
pub struct Blessed {
    engine: Engine,
    modules: BTreeMap<PackageHash, (Module, InstantiationCharges)>,
}

impl Blessed {
    /// An empty registry over the process's blessed engine.
    ///
    /// # Panics
    ///
    /// Panics if the blessed engine cannot configure — a build defect,
    /// never an input-dependent condition.
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: ENGINE.clone(),
            modules: BTreeMap::new(),
        }
    }

    /// Take a package whose module bytes are already to hand.
    ///
    /// # Panics
    ///
    /// Panics if the bytes fail the profile, do not compile, or do not
    /// derive a charge sequence — a fixture defect, never a runtime
    /// condition.
    pub fn seed(&mut self, package: PackageHash, module: &[u8]) {
        let entry = {
            let mut compiled = COMPILED.lock().expect("no cache user panics mid-insert");
            compiled
                .entry(package)
                .or_insert_with(|| {
                    validate_module(module).expect("a seeded package clears the profile");
                    let charges =
                        module_instantiation_charges(module).expect("a validated package derives");
                    (
                        Module::new(&ENGINE, module).expect("a seeded package compiles"),
                        charges,
                    )
                })
                .clone()
        };
        self.modules.insert(package, entry);
    }

    /// Build the package crate and take what it produced, under the
    /// address the chain publishes it at.
    ///
    /// # Panics
    ///
    /// Panics if the crate does not build, or on anything [`Self::seed`]
    /// panics on.
    pub fn build(&mut self, package: PackageHash, at: &Package) {
        if let Some(entry) = COMPILED
            .lock()
            .expect("no cache user panics mid-insert")
            .get(&package)
        {
            self.modules.insert(package, entry.clone());
            return;
        }
        let Code::Crate(dir) = &at.code else {
            let Code::Unreachable(why) = &at.code else {
                unreachable!("a package's code is one of two things")
            };
            panic!(
                "this package has no code the wasm lane can build: {why}. The wasm lane \
                 runs from the package's own crate; a test of bodies written elsewhere \
                 says so with `#[hyperscale_vm_testing::test(native)]`"
            );
        };
        let module =
            compile(dir).unwrap_or_else(|error| panic!("the package crate did not build: {error}"));
        self.seed(package, &module);
    }
}

impl Default for Blessed {
    fn default() -> Self {
        Self::new()
    }
}

impl GuestBackend for Blessed {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let mut store = Store::new(&self.engine, Invoking::new(session));
        let Some((module, charges)) = self.modules.get(&call.package) else {
            return InvokeResult {
                session: store.into_data().into_host(),
                fuel: 0,
                result: Invoked::Aborted(AbortReason::CodeUnavailable),
                exhausted: false,
            };
        };
        let mut linker = Linker::<Invoking<KernelSession>>::new(&self.engine);
        add_kernel_imports(&mut linker).expect("the kernel imports wire");
        let instance = instantiate_charged(
            &mut store,
            call.fuel_budget.min(FUEL_CEILING),
            charges,
            |store| linker.instantiate(store, module),
        )
        .expect("a published package instantiates");
        let end = invoke_module(
            &mut store,
            &instance,
            call.export,
            call.args,
            call.fuel_budget.min(FUEL_CEILING),
        );
        InvokeResult {
            session: store.into_data().into_host(),
            fuel: end.fuel,
            result: end.result,
            exhausted: end.exhausted,
        }
    }
}

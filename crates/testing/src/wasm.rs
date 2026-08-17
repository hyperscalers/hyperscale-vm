//! The blessed engine behind a chain: the package crate built to an
//! artifact, and the artifact executed.
//!
//! What a network would run, which is the point of the lane — the
//! canonical ABI, the profile validator, and fuel all stand where a
//! native execution of the same bodies would have nothing to say.

use std::collections::BTreeMap;

use hyperscale_vm_cli::compile;
use hyperscale_vm_effects::{AbortReason, PackageHash, TestHasher, package_hash};
use hyperscale_vm_kernel::{GuestBackend, GuestCall, InvokeResult, Invoked, KernelSession};
use hyperscale_vm_runtime::{
    Returned, add_kernel_to_linker, blessed_engine, call_export, classify, exhausted,
    validate_component,
};
use wasmtime::component::{Component, Linker};
use wasmtime::{Engine, Store};

use crate::Package;

/// The ceiling one invocation may consume.
///
/// A figure no honest package reaches, because a test that ran out of
/// fuel would be reporting the ceiling rather than the bug.
const FUEL: u64 = 1_000_000_000;

/// Compiled packages, by the content address a call names them at.
pub struct Blessed {
    engine: Engine,
    components: BTreeMap<PackageHash, Component>,
}

impl Blessed {
    pub fn new() -> Self {
        Self {
            engine: blessed_engine().expect("the blessed engine configures"),
            components: BTreeMap::new(),
        }
    }

    /// Take a package whose component bytes are already to hand.
    pub fn seed(&mut self, package: PackageHash, component: &[u8]) {
        validate_component(component).expect("a seeded package clears the profile");
        self.components.insert(
            package,
            Component::new(&self.engine, component).expect("a seeded package compiles"),
        );
    }

    /// Build the package crate and take what it produced.
    pub fn build(&mut self, package: &Package) -> PackageHash {
        let component = compile(&package.crate_dir)
            .unwrap_or_else(|error| panic!("the package crate did not build: {error}"));
        let hash = package_hash(&TestHasher, &component);
        self.seed(hash, &component);
        hash
    }
}

impl GuestBackend for Blessed {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let mut store = Store::new(&self.engine, session);
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let Some(component) = self.components.get(&call.package) else {
            return InvokeResult {
                session: store.into_data(),
                fuel: 0,
                result: Invoked::Aborted(AbortReason::CodeUnavailable),
                exhausted: false,
            };
        };
        let mut linker = Linker::<KernelSession>::new(&self.engine);
        add_kernel_to_linker(&mut linker).expect("the kernel world wires");
        let instance = linker
            .instantiate(&mut store, component)
            .expect("a published package instantiates");
        let outcome = call_export(&mut store, &instance, call.export, call.args);
        let exhausted = outcome.as_ref().err().is_some_and(exhausted);
        let result = match outcome {
            Ok(Returned::Edges(reps)) => Invoked::Produced(reps),
            Ok(Returned::Declined(code)) => Invoked::Declined(code),
            Err(error) => Invoked::Aborted(classify(&error)),
        };
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        InvokeResult {
            session: store.into_data(),
            fuel,
            result,
            exhausted,
        }
    }
}

//! One session-level invocation on both engines.
//!
//! The batch driver compares whole transactions; these lanes compare
//! single exports over a hand-built session — handle numbering, host
//! refusals, fuel — where the fixture is the session itself rather than
//! a manifest. What must not be restated per lane is the embedding
//! choreography and the comparison: a stale copy of either in a
//! differential test misclassifies identically on both sides, masking
//! exactly what the lane exists to catch.
//!
//! Arguments are the binding's own [`GuestArg`]s, and an ending is the
//! whole [`Invocation`] — the verdict and the fuel — because the core
//! boundary leaves an engine nothing to word: what differs between the
//! lanes is execution.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, DeclaredAccess};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_meter::instantiation_cost;
use hyperscale_vm_ref::{RefModule, RefModuleInstance};
use hyperscale_vm_runtime::{
    Invoking, add_kernel_imports, admit, blessed_engine, counter, instantiate_metered,
    invoke_export, remaining,
};
use hyperscale_vm_types::{AbortReason, EffectSet, ResourceAddr, TxHash};
use wasmtime::error::{ensure, format_err};
use wasmtime::{Engine, Instance, Linker, Module, Result, Store};

use crate::driver::test_hash;

/// A guest in both engines' runnable forms, admitted and compiled once.
pub struct DualGuest {
    engine: Engine,
    module: Module,
    /// What instantiation prepays off the counter.
    cost: u64,
    reference: RefModule,
}

impl DualGuest {
    /// Admit `bytes` and compile what the meter made of them for both
    /// engines.
    ///
    /// # Errors
    ///
    /// Fails where admission or either engine refuses the bytes.
    pub fn compile(bytes: &[u8]) -> Result<Self> {
        let admitted = admit(bytes)?;
        let engine = blessed_engine()?;
        Ok(Self {
            module: Module::new(&engine, &admitted)?,
            cost: instantiation_cost(bytes)?,
            reference: RefModule::decode(&admitted)?,
            engine,
        })
    }

    /// Instantiate on both engines, one fresh session per lane.
    ///
    /// The sessions must be built identically — the closure runs once
    /// per lane — which is what makes every comparison downstream a
    /// comparison of the engines rather than of the fixtures.
    ///
    /// # Errors
    ///
    /// Fails where either engine refuses to instantiate.
    pub fn instantiate(
        &self,
        budget: u64,
        session: impl Fn() -> KernelSession,
    ) -> Result<DualInstance<'_>> {
        self.instantiate_pair(budget, session(), session())
    }

    /// As [`Self::instantiate`], over the sessions an earlier step handed
    /// back — how a lane threads one transaction across several
    /// invocations.
    ///
    /// # Errors
    ///
    /// Fails where either engine refuses to instantiate.
    pub fn instantiate_pair(
        &self,
        budget: u64,
        blessed: KernelSession,
        reference: KernelSession,
    ) -> Result<DualInstance<'_>> {
        let mut linker = Linker::<Invoking<KernelSession>>::new(&self.engine);
        add_kernel_imports(&mut linker)?;
        let mut store = Store::new(&self.engine, Invoking::new(blessed));
        let instance = instantiate_metered(&mut store, budget, self.cost, |s| {
            linker.instantiate(s, &self.module)
        })?;
        let reference = RefModuleInstance::instantiate(&self.reference, reference, budget)
            .map_err(|(_, error)| format_err!("reference instantiation: {error}"))?;
        Ok(DualInstance {
            budget,
            store,
            instance,
            reference,
        })
    }
}

/// One instantiation per engine, holding a session each; every call runs
/// on both and must end identically, fuel included.
pub struct DualInstance<'a> {
    budget: u64,
    store: Store<Invoking<KernelSession>>,
    instance: Instance,
    reference: RefModuleInstance<'a, KernelSession>,
}

/// One lane's end: the session back from its engine, and the fuel the
/// whole instantiation-and-call sequence charged.
pub struct LaneEnd {
    /// The session, for post-state observation.
    pub session: KernelSession,
    /// Fuel consumed of the budget.
    pub fuel: u64,
}

impl DualInstance<'_> {
    /// Invoke `export` on both engines and require the same ending.
    ///
    /// # Errors
    ///
    /// Fails where the lanes diverge.
    pub fn invoke_both(&mut self, export: &str, args: &[GuestArg<'_>]) -> Result<Invocation> {
        let blessed = invoke_export(&mut self.store, &self.instance, export, args, self.budget);
        let reference = self.reference.invoke(export, args);
        ensure!(
            blessed == reference,
            "{export} diverged: blessed {blessed:?}, reference {reference:?}"
        );
        Ok(blessed)
    }

    /// Both sessions and what each lane charged, fuel compared here so
    /// no lane forgets to.
    ///
    /// # Errors
    ///
    /// Fails where the fuel figures diverge.
    pub fn finish(mut self) -> Result<(LaneEnd, LaneEnd)> {
        let counter = counter(&mut self.store, &self.instance);
        let blessed_fuel = self.budget - remaining(&mut self.store, &counter);
        let reference_fuel = self.reference.consumed();
        ensure!(
            blessed_fuel == reference_fuel,
            "fuel diverged: blessed {blessed_fuel}, reference {reference_fuel}"
        );
        Ok((
            LaneEnd {
                session: self.store.into_data().into_host(),
                fuel: blessed_fuel,
            },
            LaneEnd {
                session: self.reference.into_host(),
                fuel: reference_fuel,
            },
        ))
    }
}

/// What a lane reads off an ending, in the shapes the fixtures answer in.
///
/// A fixture export answers a `u64` as eight little-endian bytes and
/// hands a bucket back as its one edge; these read exactly that, and
/// fail on any other ending so a lane cannot mistake a refusal for a
/// figure.
pub trait Ended {
    /// The single `u64` the export answered with.
    ///
    /// # Errors
    ///
    /// Fails on any other ending.
    fn scalar(&self) -> Result<u64>;

    /// The one bucket the export handed back.
    ///
    /// # Errors
    ///
    /// Fails on any other ending.
    fn bucket(&self) -> Result<u32>;

    /// The class the invocation aborted with, if it did.
    fn refusal(&self) -> Option<AbortReason>;
}

impl Ended for Invocation {
    fn scalar(&self) -> Result<u64> {
        match &self.result {
            Invoked::Produced {
                answer: Some(answer),
                ..
            } => {
                let bytes: [u8; 8] = answer
                    .as_slice()
                    .try_into()
                    .map_err(|_| format_err!("expected eight answer bytes, got {answer:?}"))?;
                Ok(u64::from_le_bytes(bytes))
            }
            other => Err(format_err!("expected an answer, got {other:?}")),
        }
    }

    fn bucket(&self) -> Result<u32> {
        match &self.result {
            Invoked::Produced { edges, .. } => match edges.as_slice() {
                [rep] => Ok(*rep),
                other => Err(format_err!("expected one bucket, got {other:?}")),
            },
            other => Err(format_err!("expected a bucket, got {other:?}")),
        }
    }

    fn refusal(&self) -> Option<AbortReason> {
        match self.result {
            Invoked::Aborted(reason) => Some(reason),
            _ => None,
        }
    }
}

/// A session over `store` under `declared`, each effect holding its
/// denomination — the shape every session-level fixture materializes.
///
/// # Panics
///
/// Panics if the declaration is infeasible over the store — a fixture
/// defect, never a lane outcome.
#[must_use]
pub fn materialize(
    store: &MemoryStore,
    declared: &EffectSet,
    denominations: &[Option<ResourceAddr>],
    tx: TxHash,
    env: EnvInputs,
) -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store.clone())),
        &Declaration {
            set: declared.clone(),
            ordered: declared
                .iter()
                .zip(denominations.iter().copied())
                .map(|(effect, holds)| DeclaredAccess {
                    reach: None,
                    effect,
                    holds,
                    clause: None,
                })
                .collect(),
            ..Declaration::default()
        },
        tx,
        env,
        test_hash,
    )
    .expect("fixture materializes")
}

/// The rep of the capability matching `pred`.
///
/// # Panics
///
/// Panics if no capability matches — a fixture defect.
#[must_use]
pub fn rep_where(session: &KernelSession, pred: impl Fn(&Capability) -> bool) -> u32 {
    let position = session
        .capabilities()
        .iter()
        .position(pred)
        .expect("capability present");
    u32::try_from(position).expect("bounded")
}

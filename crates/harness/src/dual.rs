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
//! Arguments and results speak [`CVal`], the executable spec's boundary
//! vocabulary; the blessed lane lowers and lifts it here, the same way
//! the production embedding does, so handle numbering is compared like
//! for like.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, DeclaredAccess};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_ref::{
    CVal, CanonError, ExecError, RefComponent, RefComponentInstance, ResourceKind,
};
use hyperscale_vm_runtime::{
    AmountCell, AmountRead, Bucket, DeltaCell, HostRefusal, InstanceRange, InstantiationCharges,
    Issuer, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
    add_kernel_to_linker, blessed_engine, classify, instantiate_charged, instantiation_charges,
    validate_component,
};
use hyperscale_vm_types::{AbortReason, Address, EffectSet, TxHash};
use wasmtime::component::{Component, Instance, Linker, Resource, ResourceAny, Val};
use wasmtime::error::{bail, ensure, format_err};
use wasmtime::{Engine, Result, Store};

use crate::driver::test_hash;

/// A guest in both engines' runnable forms, compiled once.
pub struct DualGuest {
    engine: Engine,
    component: Component,
    charges: InstantiationCharges,
    reference: RefComponent,
}

impl DualGuest {
    /// Validate and compile `bytes` for both engines.
    ///
    /// # Errors
    ///
    /// Fails where the profile, either engine, or the charge derivation
    /// refuses the bytes.
    pub fn compile(bytes: &[u8]) -> Result<Self> {
        validate_component(bytes)?;
        let engine = blessed_engine()?;
        Ok(Self {
            component: Component::new(&engine, bytes)?,
            charges: instantiation_charges(bytes)?,
            reference: RefComponent::decode(bytes)?,
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
        let mut linker = Linker::<KernelSession>::new(&self.engine);
        add_kernel_to_linker(&mut linker)?;
        let mut store = Store::new(&self.engine, blessed);
        let instance = instantiate_charged(&mut store, budget, &self.charges, |s| {
            linker.instantiate(s, &self.component)
        })?;
        let reference = RefComponentInstance::instantiate(&self.reference, reference, budget)
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
/// on both and must end identically.
pub struct DualInstance<'a> {
    budget: u64,
    store: Store<KernelSession>,
    instance: Instance,
    reference: RefComponentInstance<'a, KernelSession>,
}

/// How one dual invocation ended — identically, or the harness fails.
#[derive(Debug, PartialEq, Eq)]
pub enum DualOutcome {
    /// The values the export returned, in the spec's boundary vocabulary.
    Values(Vec<CVal>),
    /// The host refused, in the class it assigned.
    Refused(AbortReason),
    /// The guest trapped, in the class both engines classified it as.
    Trapped(AbortReason),
}

impl DualOutcome {
    /// The single scalar a `u64`-returning export produced.
    ///
    /// # Errors
    ///
    /// Fails on any other ending.
    pub fn scalar(&self) -> Result<u64> {
        match self {
            Self::Values(values) => match values.as_slice() {
                [CVal::U64(v)] => Ok(*v),
                other => Err(format_err!("expected one u64, got {other:?}")),
            },
            other => Err(format_err!("expected a value, got {other:?}")),
        }
    }

    /// The single owned bucket rep the export handed back.
    ///
    /// # Errors
    ///
    /// Fails on any other ending.
    pub fn bucket(&self) -> Result<u32> {
        match self {
            Self::Values(values) => match values.as_slice() {
                [CVal::Own(rep)] => Ok(*rep),
                other => Err(format_err!("expected one owned bucket, got {other:?}")),
            },
            other => Err(format_err!("expected a value, got {other:?}")),
        }
    }

    /// The refusal class, if the host refused.
    #[must_use]
    pub const fn refusal(&self) -> Option<AbortReason> {
        match self {
            Self::Refused(reason) => Some(*reason),
            _ => None,
        }
    }
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
    /// Fails where the lanes diverge, or where an ending falls outside
    /// the vocabulary the comparison speaks.
    pub fn invoke_both(&mut self, export: &str, args: &[CVal]) -> Result<DualOutcome> {
        let blessed = self.invoke_blessed(export, args)?;
        let reference = self.invoke_reference(export, args)?;
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
    pub fn finish(self) -> Result<(LaneEnd, LaneEnd)> {
        let blessed_fuel = self.budget - self.store.get_fuel()?;
        let reference_fuel = self.reference.fuel_consumed();
        ensure!(
            blessed_fuel == reference_fuel,
            "fuel diverged: blessed {blessed_fuel}, reference {reference_fuel}"
        );
        Ok((
            LaneEnd {
                session: self.store.into_data(),
                fuel: blessed_fuel,
            },
            LaneEnd {
                session: self.reference.into_host(),
                fuel: reference_fuel,
            },
        ))
    }

    fn invoke_blessed(&mut self, export: &str, args: &[CVal]) -> Result<DualOutcome> {
        let Some(func) = self.instance.get_func(&mut self.store, export) else {
            bail!("no export {export}");
        };
        let mut lowered = Vec::with_capacity(args.len());
        for arg in args {
            lowered.push(lower(&mut self.store, arg)?);
        }
        let arity = func.ty(&self.store).results().len();
        let mut results = vec![Val::Bool(false); arity];
        match func.call(&mut self.store, &lowered, &mut results) {
            Ok(()) => {
                let mut values = Vec::new();
                for result in results {
                    lift(&mut self.store, result, &mut values)?;
                }
                Ok(DualOutcome::Values(values))
            }
            Err(error) => {
                if let Some(refusal) = error.downcast_ref::<HostRefusal>() {
                    return Ok(DualOutcome::Refused(refusal.0));
                }
                Ok(DualOutcome::Trapped(classify(&error)))
            }
        }
    }

    fn invoke_reference(&mut self, export: &str, args: &[CVal]) -> Result<DualOutcome> {
        match self.reference.invoke(export, args)? {
            Ok(values) => Ok(DualOutcome::Values(values)),
            Err(ExecError::Canon(CanonError::Host(reason))) => Ok(DualOutcome::Refused(reason)),
            Err(error) => Ok(DualOutcome::Trapped(error.abort_reason())),
        }
    }
}

/// A [`CVal`] argument as the blessed engine's boundary value. Borrows
/// lower as borrows, mirroring the spec's own lowering, so handle
/// numbering compares like for like.
fn lower(store: &mut Store<KernelSession>, arg: &CVal) -> Result<Val> {
    Ok(match arg {
        CVal::Bool(b) => Val::Bool(*b),
        CVal::U32(v) => Val::U32(*v),
        CVal::U64(v) => Val::U64(*v),
        CVal::Own(rep) => Val::Resource(ResourceAny::try_from_resource(
            Resource::<Bucket>::new_own(*rep),
            &mut *store,
        )?),
        CVal::Borrow(rep, kind) => Val::Resource(borrow(store, *rep, *kind)?),
        CVal::Address(bytes) => {
            let word = |at: usize| {
                Val::U64(u64::from_le_bytes(
                    bytes[at..at + 8].try_into().expect("eight bytes"),
                ))
            };
            Val::Record(vec![
                ("a".to_owned(), word(0)),
                ("b".to_owned(), word(8)),
                ("c".to_owned(), word(16)),
                ("d".to_owned(), word(24)),
            ])
        }
        CVal::Bytes(bytes) => Val::List(bytes.iter().copied().map(Val::U8).collect()),
        CVal::Ids(ids) => Val::List(ids.iter().copied().map(Val::U64).collect()),
        CVal::Declined(_) => bail!("a declined result is not an argument"),
    })
}

/// A borrowed handle at the resource type its kind names.
///
/// Registered as an owned host handle rather than a borrowed one — the
/// production lowering's own choice: a borrow is only representable
/// inside an active call scope, and there is none while arguments are
/// still being assembled. The guest parameter is a borrow either way;
/// the canonical ABI lends the handle for the call and takes it back.
fn borrow(store: &mut Store<KernelSession>, rep: u32, kind: ResourceKind) -> Result<ResourceAny> {
    let store = &mut *store;
    match kind {
        ResourceKind::Bucket => {
            ResourceAny::try_from_resource(Resource::<Bucket>::new_own(rep), store)
        }
        ResourceKind::Issuer => {
            ResourceAny::try_from_resource(Resource::<Issuer>::new_own(rep), store)
        }
        ResourceKind::ReadCell => {
            ResourceAny::try_from_resource(Resource::<ReadCell>::new_own(rep), store)
        }
        ResourceKind::LockedCell => {
            ResourceAny::try_from_resource(Resource::<LockedCell>::new_own(rep), store)
        }
        ResourceKind::WriteCell => {
            ResourceAny::try_from_resource(Resource::<WriteCell>::new_own(rep), store)
        }
        ResourceKind::AmountCell => {
            ResourceAny::try_from_resource(Resource::<AmountCell>::new_own(rep), store)
        }
        ResourceKind::AmountRead => {
            ResourceAny::try_from_resource(Resource::<AmountRead>::new_own(rep), store)
        }
        ResourceKind::DeltaCell => {
            ResourceAny::try_from_resource(Resource::<DeltaCell>::new_own(rep), store)
        }
        ResourceKind::ReserveCell => {
            ResourceAny::try_from_resource(Resource::<ReserveCell>::new_own(rep), store)
        }
        ResourceKind::RangeRead => {
            ResourceAny::try_from_resource(Resource::<RangeRead>::new_own(rep), store)
        }
        ResourceKind::RangeWrite => {
            ResourceAny::try_from_resource(Resource::<RangeWrite>::new_own(rep), store)
        }
        ResourceKind::InstanceRange => {
            ResourceAny::try_from_resource(Resource::<InstanceRange>::new_own(rep), store)
        }
    }
}

/// One blessed result into the comparison vocabulary. Tuples flatten,
/// because the spec's lift reports a tuple result as its elements.
fn lift(store: &mut Store<KernelSession>, value: Val, out: &mut Vec<CVal>) -> Result<()> {
    match value {
        Val::Bool(b) => out.push(CVal::Bool(b)),
        Val::U32(v) => out.push(CVal::U32(v)),
        Val::U64(v) => out.push(CVal::U64(v)),
        Val::Resource(handle) => out.push(CVal::Own(
            handle.try_into_resource::<Bucket>(&mut *store)?.rep(),
        )),
        Val::Tuple(items) => {
            for item in items {
                lift(store, item, out)?;
            }
        }
        Val::Result(Ok(None)) => {}
        Val::Result(Ok(Some(inner))) => lift(store, *inner, out)?,
        Val::Result(Err(Some(code))) => match *code {
            Val::U32(code) => out.push(CVal::Declined(code)),
            other => bail!("declined with {other:?}"),
        },
        Val::List(items) => {
            let mut bytes = Vec::with_capacity(items.len());
            let mut ids = Vec::with_capacity(items.len());
            for item in &items {
                match item {
                    Val::U8(b) => bytes.push(*b),
                    Val::U64(id) => ids.push(*id),
                    other => bail!("a list of {other:?} is outside the vocabulary"),
                }
            }
            if ids.is_empty() {
                out.push(CVal::Bytes(bytes));
            } else {
                out.push(CVal::Ids(ids));
            }
        }
        other => bail!("a result of {other:?} is outside the vocabulary"),
    }
    Ok(())
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
    denominations: &[Option<Address>],
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
                .map(|(effect, holds)| DeclaredAccess { effect, holds })
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

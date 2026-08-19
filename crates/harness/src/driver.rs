//! The dual-engine driver: one component registry, one execution per
//! lane, one agreement assertion.
//!
//! Every batch fixture wants the same arrangement — the blessed engine
//! and the executable spec over the same package set, held to
//! byte-identical receipts, with the packages' own native bodies as a
//! third lane where they exist — and an arrangement each test binary
//! restates is one that drifts. The dangerous copy is the comparison: a
//! stale convention in a *differential* test misclassifies identically
//! on both lanes, masking exactly the divergence class the lane exists
//! to catch.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{Hasher, PackageHash, TestHasher, Value, child_key};
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, ExecutionMode, GuestBackend, GuestCall, InvokeResult, KernelSession,
    Locality, ManifestWalk, MemoryStore, Receipt, decode_amount, execute_batch,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance};
use hyperscale_vm_testing::{Blessed, Dispatch, FUEL_CEILING, Native};
use hyperscale_vm_types::{AbortReason, Address, Outcome, SubstateKey, encode_amount};

/// The reference interpreter over a package set: each call's code is
/// resolved by the package its lowered call names, decoded from the
/// same committed bytes the blessed lane compiled.
#[derive(Default)]
pub struct Reference {
    components: BTreeMap<PackageHash, RefComponent>,
}

impl Reference {
    /// Decode a package's component bytes under the address a call
    /// names them at.
    ///
    /// # Panics
    ///
    /// Panics if the bytes do not decode — a fixture defect, not a
    /// runtime condition.
    pub fn seed(&mut self, package: PackageHash, component: &[u8]) {
        self.components.insert(
            package,
            RefComponent::decode(component).expect("a seeded package decodes"),
        );
    }
}

impl GuestBackend for Reference {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let component = self
            .components
            .get(&call.package)
            .expect("the call names a seeded package");
        let args: Vec<CVal> = call.args.iter().map(CVal::from).collect();
        let mut instance = RefComponentInstance::instantiate(
            component,
            session,
            call.fuel_budget.min(FUEL_CEILING),
        )
        .map_err(|(_, error)| error)
        .expect("a seeded package instantiates");
        let end = instance.invoke_kernel(call.export, &args);
        InvokeResult {
            session: instance.into_host(),
            fuel: end.fuel,
            result: end.result,
            exhausted: end.exhausted,
        }
    }
}

/// The lanes a fixture batch executes on: both engines always, the
/// packages' own native bodies where seeded.
pub struct Lanes {
    blessed: Blessed,
    reference: Reference,
    native: Native,
    native_seeded: bool,
}

impl Lanes {
    /// Empty lanes over a fresh blessed engine; seed packages before
    /// running anything.
    #[must_use]
    pub fn new() -> Self {
        Self {
            blessed: Blessed::new(),
            reference: Reference::default(),
            native: Native::default(),
            native_seeded: false,
        }
    }

    /// Seed one package's component bytes on both engine lanes: the
    /// blessed lane validates and compiles them, the reference lane
    /// decodes them.
    pub fn seed(&mut self, package: PackageHash, component: &[u8]) {
        self.blessed.seed(package, component);
        self.reference.seed(package, component);
    }

    /// Seed the package's own native body as the third lane.
    pub fn seed_native(&mut self, package: PackageHash, dispatch: Dispatch) {
        self.native.seed(package, dispatch);
        self.native_seeded = true;
    }
}

impl Default for Lanes {
    fn default() -> Self {
        Self::new()
    }
}

/// Execute the batch on every lane and assert they agree; returns the
/// blessed outcome and its collapsed end state.
///
/// The two engines are held to byte-identical receipts, fuel included —
/// that figure is consensus content and agreeing on it is the point of
/// having two — and to identical end state, whole receipts with their
/// abort classes: the vocabulary is closed, so a failure path the two
/// runtimes classify differently is a divergence rather than a wording
/// difference to look past. The native lane runs the packages' own
/// bodies with nothing metering them, so it is held to everything but
/// the fuel figure — it is what says the committed blobs still do what
/// their source says.
///
/// # Panics
///
/// Panics where the lanes disagree, or where a batch fails to execute
/// at all.
pub fn run_lanes(
    lanes: &Lanes,
    store: &MemoryStore,
    batch: &[BatchTx],
) -> (BatchOutcome, MemoryStore) {
    let blessed_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk {
            backend: &lanes.blessed,
        },
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();
    let ref_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk {
            backend: &lanes.reference,
        },
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    assert_eq!(
        blessed_outcome.receipts, ref_outcome.receipts,
        "lanes diverged"
    );
    if lanes.native_seeded && !metered_out(&blessed_outcome) {
        let native_outcome = execute_batch(
            Arc::new(store.clone()),
            batch,
            &ManifestWalk {
                backend: &lanes.native,
            },
            test_hash,
            ExecutionMode::Serial,
            &Locality::All,
        )
        .unwrap();
        assert_eq!(
            comparable(&blessed_outcome),
            comparable(&native_outcome),
            "the packages' own modules diverged from their committed artifacts"
        );
    }
    let end = blessed_outcome.store.collapse_onto(store.clone());
    assert_eq!(
        cells(&end),
        cells(&ref_outcome.store.collapse_onto(store.clone())),
        "state diverged"
    );
    (blessed_outcome, end)
}

/// The fixture hash: [`TestHasher`] in the shape `execute_batch` takes.
#[must_use]
pub fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// The vault an owner holds a resource's balance in, under the
/// [`TestHasher`] derivation.
pub fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// Every cell a store holds, comparable across lanes.
#[must_use]
pub fn cells(end: &MemoryStore) -> BTreeMap<SubstateKey, Vec<u8>> {
    end.cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

/// The balance a cell holds, or zero where no cell exists.
///
/// # Panics
///
/// Panics if the cell exists and is not an amount.
#[must_use]
pub fn amount_of(end: &MemoryStore, key: SubstateKey) -> u128 {
    cells(end)
        .get(&key)
        .map_or(0, |cell| decode_amount(cell).unwrap())
}

/// Seed `amount` of `resource` into an owner's vault.
///
/// # Panics
///
/// Panics if the store refuses the write.
pub fn seed_vault(
    store: &mut MemoryStore,
    owner: impl Into<Address>,
    resource: impl Into<Address>,
    amount: u128,
) {
    store
        .write(vault(owner, resource), encode_amount(amount).to_vec())
        .unwrap();
}

/// Whether the engines ended on the one verdict the native lane cannot
/// reach: a transaction that spent its signed ceiling.
///
/// Nothing meters that lane, so a body the engines cut off runs to
/// completion there. It is the lane's stated boundary rather than a
/// divergence — a test about the ceiling is a test about the engines —
/// and reading it off the outcome is what keeps the exception from
/// being a flag a caller could forget to pass.
fn metered_out(outcome: &BatchOutcome) -> bool {
    outcome.receipts.values().any(|receipt| {
        matches!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::OutOfGas
            }
        )
    })
}

/// What a lane is held to when it cannot report the one figure an
/// engine produces: everything a contract is about.
fn comparable(outcome: &BatchOutcome) -> Vec<Receipt> {
    outcome
        .receipts
        .values()
        .map(|receipt| Receipt {
            fuel: 0,
            ..receipt.clone()
        })
        .collect()
}

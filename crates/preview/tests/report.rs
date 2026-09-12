//! What a preview reports about a run.
//!
//! The library runs the entry the chain would run, against state a
//! source hands it, and says what a receipt would say — with the
//! ceilings a composer should sign over what it measured.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, Hash32, Hasher, NodeCall, PackageHash, ShardId, TestHasher,
};
use hyperscale_vm_kernel::{
    BatchTx, EnvInputs, GuestBackend, GuestCall, InvokeResult, Invoked, KernelSession, MemoryStore,
};
use hyperscale_vm_preview::{CellSource, Local, Slack, preview};
use hyperscale_vm_types::{AbortReason, Address, AddressClass, EffectSet, Outcome, TxHash};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest spending a fixed figure per call, and aborting where a test
/// asks it to.
struct Spending {
    fuel: u64,
    aborts: bool,
}

impl GuestBackend for Spending {
    fn invoke(&self, session: KernelSession, _call: &GuestCall<'_>) -> InvokeResult {
        InvokeResult {
            session,
            fuel: self.fuel,
            result: if self.aborts {
                Invoked::Aborted(AbortReason::Unreachable)
            } else {
                Invoked::Produced {
                    edges: Vec::new(),
                    answer: None,
                }
            },
        }
    }
}

fn call() -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target: Address::new([0xA1; 31], AddressClass::Component),
        export: "spend".into(),
        args: Vec::new(),
        edges: Vec::new(),
        outputs: Vec::new(),
        answers: false,
        issues: Vec::new(),
        evidence: Vec::new(),
        signed_in: None,
        requires: Vec::new(),
    }
}

fn entry(calls: usize) -> BatchTx {
    BatchTx::new(
        TxHash(Hash32([0x11; 32])),
        Declaration::from_set(EffectSet::new()),
        EnvInputs::unsealed(1_000),
    )
    .with_calls(vec![call(); calls])
}

fn source() -> Arc<dyn CellSource> {
    Arc::new(Local::at(MemoryStore::new(), ShardId(0), 1_000))
}

/// The report says what each node spent, what ceiling would cover it,
/// and the anchor it read at.
#[test]
fn a_report_names_the_fuel_and_the_ceiling_per_node() {
    let report = preview(
        &entry(2),
        None,
        source(),
        &Spending {
            fuel: 1_000,
            aborts: false,
        },
        test_hash,
        Slack::of(2_500),
    );
    assert!(report.completed(), "{:?}", report.outcome);
    assert_eq!(report.spent, vec![1_000, 1_000]);
    assert_eq!(
        report.ceilings,
        vec![1_250, 1_250],
        "a quarter of room over what each node measured"
    );
    assert_eq!(report.compute(), 2_500, "and the envelope's compute term");
    assert_eq!(report.anchors.len(), 1);
    assert_eq!(report.anchors[0].clock_ms, 1_000);
}

/// No slack is the measurement itself, which is what a lane pinning a
/// run's cost wants and what no composer should sign.
#[test]
fn no_slack_reports_the_measurement() {
    let report = preview(
        &entry(1),
        None,
        source(),
        &Spending {
            fuel: 4_096,
            aborts: false,
        },
        test_hash,
        Slack::NONE,
    );
    assert_eq!(report.ceilings, report.spent);
}

/// A run that aborts reports the ending and what it spent getting
/// there, so a composer sees where the fuel went before the failure.
#[test]
fn an_aborted_run_reports_what_it_spent() {
    let report = preview(
        &entry(2),
        None,
        source(),
        &Spending {
            fuel: 700,
            aborts: true,
        },
        test_hash,
        Slack::GENEROUS,
    );
    assert_eq!(
        report.outcome,
        Outcome::UserError {
            reason: AbortReason::Unreachable
        }
    );
    assert!(!report.completed());
    assert_eq!(report.spent, vec![700], "the node that failed and no more");
    assert_eq!(report.refusal, None, "a trap is the guest's, not a refusal");
}

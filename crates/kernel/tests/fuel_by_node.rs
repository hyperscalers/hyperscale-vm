//! What a walk spent, node by node.
//!
//! A composer signs a ceiling per node, so what a receipt hands back has
//! to be where the fuel went rather than one total — the total is the
//! fold, carried beside it so no reader recomputes it. A node this
//! member does not run spends nothing and keeps its place, and an abort
//! ends the vector at the node that failed.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, NodeCall, PackageHash, TestHasher};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{AbortReason, Address, AddressClass, EffectSet, Outcome, TxHash};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest that spends `step` more fuel on each successive call, so the
/// figures are distinguishable per node, and aborts the call at
/// `aborts_at` once it has spent its own.
struct Stepping {
    step: u64,
    aborts_at: Option<u64>,
    /// The walk invokes one node at a time in node order, so counting
    /// the calls is how the fixture tells them apart.
    invoked: AtomicU64,
}

impl GuestBackend for Stepping {
    fn invoke(&self, session: KernelSession, _call: &GuestCall<'_>) -> InvokeResult {
        let node = self.invoked.fetch_add(1, Ordering::Relaxed);
        let fuel = self.step * (node + 1);
        InvokeResult {
            session,
            fuel,
            result: if self.aborts_at == Some(node) {
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

/// Run `calls` nodes, each spending `step` times its own index plus one.
fn run(calls: usize, step: u64, aborts_at: Option<u64>) -> Receipt {
    let tx = TxHash(Hash32([0x11; 32]));
    let entry = BatchTx::new(
        tx,
        Declaration::from_set(EffectSet::new()),
        EnvInputs::unsealed(1_000),
    )
    .with_calls(vec![call(); calls]);
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
        &[entry],
        &ManifestWalk {
            backend: &Stepping {
                step,
                aborts_at,
                invoked: AtomicU64::new(0),
            },
        },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&tx].clone()
}

#[test]
fn the_receipt_reports_the_fuel_each_node_spent() {
    let receipt = run(3, 100, None);
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
    assert_eq!(receipt.fuel_by_node, vec![100, 200, 300]);
}

/// The total is the fold and nothing else, so a reader that wants one
/// figure and a reader that wants the breakdown cannot disagree.
#[test]
fn the_total_is_the_vector_folded() {
    for calls in 1..4 {
        let receipt = run(calls, 7, None);
        assert_eq!(
            receipt.fuel,
            receipt.fuel_by_node.iter().sum::<u64>(),
            "the total is what the nodes spent between them"
        );
    }
}

/// An abort ends the vector at the node that failed: what ran is
/// reported, and nothing claims to have run after it.
#[test]
fn an_abort_reports_up_to_the_node_that_failed() {
    let receipt = run(3, 100, Some(1));
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::Unreachable
        }
    );
    assert_eq!(receipt.fuel_by_node, vec![100, 200]);
    assert_eq!(receipt.fuel, 300);
}

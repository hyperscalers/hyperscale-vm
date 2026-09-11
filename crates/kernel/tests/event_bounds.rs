//! A transaction's events are bounded by what its calls declared.
//!
//! The bound rides the batch entry, which the embedder fills from the
//! packages the manifest names; the session meters every emit against
//! it and traps at the one that crosses it. Per transaction, not per
//! call: two calls under the bound individually can still cross it
//! between them, which is what makes the figure a declaration rather
//! than a per-invocation allowance.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, NodeCall, PackageHash, TestHasher};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, EffectSet, MAX_EVENT_BYTES_PER_TX, Outcome, TxHash,
};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest whose every export emits one event of the given width.
struct Emitting {
    bytes: usize,
}

impl GuestBackend for Emitting {
    fn invoke(&self, mut session: KernelSession, _call: &GuestCall<'_>) -> InvokeResult {
        let result = match session.emit(0, vec![0u8; self.bytes]) {
            Ok(()) => Invoked::Produced {
                edges: Vec::new(),
                answer: None,
            },
            Err(trap) => Invoked::Aborted(trap.into()),
        };
        InvokeResult {
            session,
            fuel: 0,
            result,
        }
    }
}

fn call() -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target: Address::new([0xA1; 31], AddressClass::Component),
        export: "emit".into(),
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

/// Run `calls` invocations each emitting `bytes`, under `bound` where
/// one is bound at all.
fn run(calls: usize, bytes: usize, bound: Option<usize>) -> Receipt {
    let tx = TxHash(Hash32([0x11; 32]));
    let mut entry = BatchTx::new(
        tx,
        Declaration::from_set(EffectSet::new()),
        EnvInputs::unsealed(1_000),
    )
    .with_calls(vec![call(); calls]);
    if let Some(bound) = bound {
        entry = entry.with_event_bytes(bound);
    }
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
        &[entry],
        &ManifestWalk {
            backend: &Emitting { bytes },
        },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&tx].clone()
}

#[test]
fn events_up_to_the_declared_bound_are_carried() {
    let receipt = run(1, 100, Some(100));
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
    assert_eq!(receipt.events.len(), 1);
    assert_eq!(receipt.events[0].payload.len(), 100);
}

#[test]
fn an_emit_past_the_declared_bound_aborts_the_transaction() {
    let receipt = run(1, 101, Some(100));
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// The bound is the transaction's, not each call's: two calls under it
/// alone cross it between them.
#[test]
fn the_bound_is_spent_across_the_calls_between_them() {
    assert!(matches!(
        run(2, 50, Some(100)).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        run(2, 60, Some(100)).outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// An entry binding nothing meters against the wire cap, which is what
/// an in-crate fixture wants and what no embedder leaves it at.
#[test]
fn an_unbound_entry_meters_against_the_wire_cap() {
    assert!(matches!(
        run(1, 4096, None).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        run(MAX_EVENT_BYTES_PER_TX / 4096 + 1, 4096, None).outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

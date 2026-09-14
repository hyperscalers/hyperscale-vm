//! A node's events are bounded by what the method it calls declared.
//!
//! The bounds ride the batch entry, one per node, which the embedder
//! fills from the methods the manifest names; the session meters every
//! emit of a frame against its own figure and traps at the one that
//! crosses it. Per node, like the compute ceilings beside them: a
//! method that emits states what one call into it may, so a node's
//! slack is never another's to spend and a method that states nothing
//! may emit nothing. The transaction's own total is metered beside
//! them, since what a receipt may carry is one figure however many
//! frames declared their own.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, NodeCall, PackageHash, TestHasher};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, EVENT_FRAME_BYTES, EffectSet, MAX_EVENT_BYTES_PER_TX,
    MAX_EVENT_PAYLOAD_BYTES, Outcome, TxHash,
};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest whose every export emits `events` events of `bytes` each.
struct Emitting {
    bytes: usize,
    events: usize,
}

impl GuestBackend for Emitting {
    fn invoke(&self, mut session: KernelSession, _call: &GuestCall<'_>) -> InvokeResult {
        let mut result = Invoked::Produced {
            edges: Vec::new(),
            answer: None,
        };
        for _ in 0..self.events {
            if let Err(trap) = session.emit(0, vec![0u8; self.bytes]) {
                result = Invoked::Aborted(trap.into());
                break;
            }
        }
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

/// Run `calls` invocations each emitting `bytes`, under `bounds` where
/// any are bound at all.
fn run(calls: usize, bytes: usize, bounds: &[u32]) -> Receipt {
    emitting(calls, bytes, 1, bounds)
}

/// [`run`], with each call emitting `events` events rather than one.
fn emitting(calls: usize, bytes: usize, events: usize, bounds: &[u32]) -> Receipt {
    let tx = TxHash(Hash32([0x11; 32]));
    let entry = BatchTx::new(
        tx,
        Declaration::from_set(EffectSet::new()),
        EnvInputs::unsealed(1_000),
    )
    .with_calls(vec![call(); calls])
    .with_event_bytes(bounds.to_vec());
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
        &[entry],
        &ManifestWalk {
            backend: &Emitting { bytes, events },
        },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&tx].clone()
}

/// A bound is a bound on what the receipt keeps, so it covers the
/// framing an event carries beside its payload.
fn bound_for(payload: usize) -> u32 {
    u32::try_from(payload + EVENT_FRAME_BYTES).expect("a bound fits u32")
}

#[test]
fn events_up_to_the_declared_bound_are_carried() {
    let receipt = run(1, 100, &[bound_for(100)]);
    assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
    assert_eq!(receipt.events.len(), 1);
    assert_eq!(receipt.events[0].payload.len(), 100);
}

#[test]
fn an_emit_past_the_declared_bound_aborts_the_transaction() {
    let receipt = run(1, 101, &[bound_for(100)]);
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// Each node spends its own figure and none of its neighbour's: two
/// calls that would cross a shared bound between them both complete,
/// and one past its own aborts however much the other left.
#[test]
fn a_nodes_bound_is_its_own_and_never_its_neighbours() {
    assert!(matches!(
        run(2, 60, &[100, 100]).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        run(2, 60, &[100, 50]).outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// The frames' bounds do not add up past what a receipt may carry: a
/// manifest whose nodes are each within their own figure still stops at
/// the transaction's cap.
///
/// A derivation refuses such a manifest before it is signed, so what
/// this pins is the kernel's own backstop — the bound that holds for a
/// batch entry nothing derived.
#[test]
fn the_transactions_own_total_bounds_what_its_frames_declare() {
    let page = MAX_EVENT_PAYLOAD_BYTES;
    // A page and the framing kept around it, which is what the receipt
    // carries and so what the transaction's own total counts.
    let kept = page + EVENT_FRAME_BYTES;
    let whole = MAX_EVENT_BYTES_PER_TX / kept;
    let bounds = vec![u32::try_from(kept).expect("a page fits u32"); whole + 1];
    assert!(matches!(
        run(whole, page, &bounds).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        run(whole + 1, page, &bounds).outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// A method that states nothing may emit nothing, which is what makes
/// the declaration a bound rather than a contribution to a pool.
#[test]
fn a_node_bounded_at_nothing_may_emit_nothing() {
    assert_eq!(
        run(1, 1, &[0]).outcome,
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
        run(1, 4096, &[]).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        emitting(1, 4096, MAX_EVENT_BYTES_PER_TX / 4096 + 1, &[]).outcome,
        Outcome::UserError {
            reason: AbortReason::EventBytesExceeded
        }
    );
}

/// A vector short of the manifest is the composer's defect, like a
/// ceiling short of it: the walk refuses rather than metering the node
/// at nothing and pricing the sender for it.
#[test]
fn a_bound_short_of_the_manifest_is_a_composition_defect() {
    assert_eq!(
        run(2, 1, &[100]).outcome,
        Outcome::ProtocolError {
            reason: AbortReason::MissingCeiling
        }
    );
}

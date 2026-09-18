//! A node is metered against its own signed ceiling and nothing else.
//!
//! One ceiling per manifest node, in node order: a node that runs past
//! its own aborts the transaction with its predecessors' slack unspent,
//! and a node that aborts leaves every later node unrun. A batch that
//! binds ceilings and has none for a node is its composer's defect,
//! priced to nobody.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use hyperscale_hbor::Capped;
use hyperscale_vm_effects::{Declaration, Hash32, Hasher, NodeCall, PackageHash, TestHasher};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{AbortReason, Address, AddressClass, EffectSet, Outcome, TxHash};

/// What every export here costs to run.
const COST: u64 = 1_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest whose every export spends [`COST`] fuel, trapping where the
/// budget it is handed is short of that, and counting the invocations
/// it was asked for.
struct Spending {
    invoked: AtomicUsize,
}

impl GuestBackend for Spending {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        self.invoked.fetch_add(1, Ordering::SeqCst);
        if call.fuel_budget < COST {
            return InvokeResult {
                session,
                fuel: call.fuel_budget,
                result: Invoked::Aborted(AbortReason::OutOfGas),
            };
        }
        InvokeResult {
            session,
            fuel: COST,
            result: Invoked::Produced {
                edges: Vec::new(),
                answer: None,
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
        requires: Vec::new(),
    }
}

/// Run `nodes` spending nodes under `gas_limits`: the receipt and how
/// many nodes the guest was asked to run.
fn run(nodes: usize, gas_limits: Vec<u64>) -> (Receipt, usize) {
    let tx = TxHash(Hash32([0x11; 32]));
    let batch = vec![
        BatchTx::new(
            tx,
            Declaration::from_set(EffectSet::new()),
            EnvInputs::unsealed(1_000),
        )
        .with_calls(vec![call(); nodes])
        .with_gas_limits(gas_limits),
    ];
    let backend = Spending {
        invoked: AtomicUsize::new(0),
    };
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
        &batch,
        &ManifestWalk { backend: &backend },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    (
        outcome.receipts[&tx].clone(),
        backend.invoked.load(Ordering::SeqCst),
    )
}

#[test]
fn every_node_under_its_ceiling_completes() {
    let (receipt, invoked) = run(3, vec![COST, COST, COST]);
    assert_eq!(
        receipt.outcome,
        Outcome::Completed {
            answers: Capped::empty()
        }
    );
    assert_eq!(invoked, 3);
    assert_eq!(receipt.fuel, 3 * COST, "the receipt reports the sum");
}

/// The first node's slack is not the second's to spend: a second node
/// short of its own ceiling traps however much the first left.
#[test]
fn a_node_traps_at_its_own_ceiling_with_a_predecessor_slack_unspent() {
    let (receipt, invoked) = run(2, vec![10 * COST, COST - 1]);
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::OutOfGas
        }
    );
    assert_eq!(invoked, 2, "the first node ran and the second was asked");
    assert_eq!(
        receipt.fuel,
        COST + (COST - 1),
        "what the first spent plus what the second had"
    );
}

/// A node that traps ends the walk: nothing after it runs.
#[test]
fn a_trapping_node_leaves_its_successors_unrun() {
    let (receipt, invoked) = run(3, vec![COST - 1, COST, COST]);
    assert_eq!(
        receipt.outcome,
        Outcome::UserError {
            reason: AbortReason::OutOfGas
        }
    );
    assert_eq!(invoked, 1, "the first node trapped and no other was asked");
}

/// No ceilings bound leaves every node unbounded, which is the fixture
/// default and never an envelope's.
#[test]
fn unbound_ceilings_meter_nothing() {
    let (receipt, invoked) = run(2, Vec::new());
    assert_eq!(
        receipt.outcome,
        Outcome::Completed {
            answers: Capped::empty()
        }
    );
    assert_eq!(invoked, 2);
}

/// Ceilings bound for fewer nodes than the batch walks is a batch
/// composed against another call list: the composer's defect, refused
/// where the walk reaches the node without one and priced to nobody.
#[test]
fn a_node_without_a_ceiling_is_a_composition_defect() {
    let (receipt, invoked) = run(3, vec![COST, COST]);
    assert_eq!(
        receipt.outcome,
        Outcome::ProtocolError {
            reason: AbortReason::MissingCeiling
        }
    );
    assert_eq!(invoked, 2, "the two nodes with ceilings ran");
}

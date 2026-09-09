//! An answer is the declaration's promise, held at the reply.
//!
//! A core signature cannot say whether an export answers, so the
//! signature says it and the walk holds the guest to it: an export that
//! answers where its signature says it does not, or stays silent where
//! it says it does, is a package whose code and metadata part company,
//! and the receipt says so on the terms a wrong arity has.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, NodeCall, PackageHash, TestHasher};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{AbortReason, Address, AddressClass, EffectSet, Outcome, TxHash};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A guest whose exports answer or stay silent by name.
struct Speaking;

impl GuestBackend for Speaking {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let answer = match call.export {
            "speak" => Some(vec![7]),
            "silent" => None,
            other => panic!("no fixture for {other}"),
        };
        InvokeResult {
            session,
            fuel: 0,
            result: Invoked::Produced {
                edges: Vec::new(),
                answer,
            },
            exhausted: false,
        }
    }
}

fn call(export: &str, answers: bool) -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target: Address::new([0xA1; 31], AddressClass::Component),
        export: export.into(),
        args: Vec::new(),
        edges: Vec::new(),
        outputs: Vec::new(),
        answers,
        issues: Vec::new(),
        evidence: Vec::new(),
        requires: Vec::new(),
    }
}

fn run(export: &str, answers: bool) -> Receipt {
    let tx = TxHash(Hash32([0x11; 32]));
    let batch = vec![
        BatchTx::new(
            tx,
            Declaration::from_set(EffectSet::new()),
            EnvInputs::unsealed(1_000),
        )
        .with_calls(vec![call(export, answers)]),
    ];
    let outcome = execute_batch(
        Arc::new(MemoryStore::new()) as Arc<dyn Baseline>,
        &batch,
        &ManifestWalk { backend: &Speaking },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&tx].clone()
}

#[test]
fn an_answer_the_signature_promised_is_recorded() {
    let receipt = run("speak", true);
    let Outcome::Completed { answers } = receipt.outcome else {
        panic!("{:?}", receipt.outcome);
    };
    assert_eq!(answers.len(), 1);
    assert_eq!(answers[0].value, vec![7]);
}

#[test]
fn silence_the_signature_promised_is_recorded() {
    let receipt = run("silent", false);
    assert_eq!(receipt.outcome, Outcome::Completed { answers: vec![] });
}

#[test]
fn an_answer_the_signature_did_not_promise_is_a_bad_shape() {
    for (export, answers) in [("speak", false), ("silent", true)] {
        let receipt = run(export, answers);
        assert_eq!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::BadReturnShape
            },
            "{export} answering {answers}"
        );
    }
}

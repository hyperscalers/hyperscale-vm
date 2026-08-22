//! What a method answers with is the vocabulary's width, not the guest's.
//!
//! A receipt carries the value a method handed back, and a receipt is a
//! wire object: the bytes one answer may carry stand in
//! [`MAX_ANSWER_BYTES`], and a guest handing back more is refused where
//! the value comes back rather than at the encoding that could not hold
//! it. The macro couples an answer to a type; a hand-written guest is
//! not so held, and this is the walk holding it.

use hyperscale_vm_effects::{MethodSignature, PackageMetadata, Totality};
use hyperscale_vm_kernel::{GuestArg, Invoked, KernelSession};
use hyperscale_vm_testing::{Chain, Package, PrincipalAddr, principal};
use hyperscale_vm_types::{AbortReason, ComponentAddr, MAX_ANSWER_BYTES, Outcome};

const CALLER: PrincipalAddr = principal(0x41);

/// One method that answers and produces no edge.
fn answering() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "say".into(),
        MethodSignature {
            totality: Totality::Infallible,
            answers: true,
            ..MethodSignature::default()
        },
    );
    metadata
}

/// A body answering with `WIDTH` bytes, whatever the vocabulary carries.
fn body<const WIDTH: usize>(
    export: &str,
    session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "say");
    assert!(args.is_empty(), "the method takes nothing: {args:?}");
    (
        session,
        Invoked::Produced {
            edges: Vec::new(),
            answer: Some(vec![0xA5; WIDTH]),
        },
    )
}

fn answering_at<const WIDTH: usize>() -> (Chain, ComponentAddr) {
    let mut chain = Chain::native();
    let hash = chain.publish(Package::new(
        answering(),
        env!("CARGO_MANIFEST_DIR"),
        body::<WIDTH>,
    ));
    let instance = chain.instantiate_raw(CALLER, hash, ());
    (chain, instance)
}

/// The widest answer the vocabulary carries completes, and the receipt
/// holds every byte of it.
#[test]
fn an_answer_at_the_cap_lands_in_the_receipt() {
    let (mut chain, instance) = answering_at::<MAX_ANSWER_BYTES>();
    let outcome = chain.transact(CALLER, |b| {
        let [] = b.call(instance, "say", ())?.into_array()?;
        Ok(())
    });
    outcome.expect_completed();
    let Outcome::Completed { answers } = &outcome.receipt().outcome else {
        panic!("the method completes");
    };
    assert_eq!(
        answers.iter().map(|a| a.value.len()).collect::<Vec<_>>(),
        [MAX_ANSWER_BYTES],
        "the receipt carries the whole answer",
    );
}

/// One byte past it is the guest's own defect, refused before anything
/// downstream has to encode what it could not hold.
#[test]
fn an_answer_past_the_cap_is_refused() {
    let (mut chain, instance) = answering_at::<{ MAX_ANSWER_BYTES + 1 }>();
    let outcome = chain.transact(CALLER, |b| {
        let [] = b.call(instance, "say", ())?.into_array()?;
        Ok(())
    });
    assert_eq!(outcome.aborted(), Some(AbortReason::AnswerTooLarge));
}

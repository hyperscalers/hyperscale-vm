//! The fungible account: the package every principal answers.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on,
//! the code that executes them and the wrappers a client calls them
//! through are all read off one text.
//!
//! Free functions rather than a handle, because the instance registry
//! serves this package to every principal address by class rather than
//! by record. A principal's address derives from a key and folds in
//! no package hash, so [`PrincipalAddr`] is already the whole of what a
//! handle could say.
//!
//! [`PrincipalAddr`]: hyperscale_vm_types::PrincipalAddr

use hyperscale_hbor::to_vec;
use hyperscale_vm_effects::{PackageMetadata, RuleBytes, StoredRule};
use hyperscale_vm_manifest_builder::{BuildError, Proof, TypedBuilder, TypedError};
use hyperscale_vm_types::PrincipalAddr;

// The package, read from the crate the artifact is built from rather
// than copied into this one: a second copy is the drift the derivation
// exists to remove.
#[path = "../../../guests/account/src/lib.rs"]
mod package;

/// The replacement an account keeps while one is waiting, so a consumer
/// can read the state a flow passes through rather than only its ends.
pub use package::account::Pending;
pub use package::account::client::*;

/// Sign in as the principal the builder declares: [`authorize`], with
/// the signer the builder already names rather than a second naming of
/// the same party.
///
/// The explicit form stays for a composition signing into another
/// party's account through that account's own stored rule; this one is
/// for the intent's own principal, where naming anyone else would only
/// be the disagreement admission refuses.
///
/// # Errors
///
/// As [`authorize`].
pub fn sign_in(builder: &mut TypedBuilder<'_>) -> Result<Proof, TypedError> {
    let who = builder.signer();
    authorize(builder, who)
}

/// One replacement as the cell holds it.
///
/// The account's own encoder rather than a second one beside it: a
/// consumer seeding the state a flow passes through writes exactly what
/// the guest would have written.
///
/// # Panics
///
/// Only on an encoder failure no well-formed record can reach.
#[must_use]
pub fn encode_pending(pending: &Pending) -> Vec<u8> {
    to_vec(pending).expect("a record encodes")
}
/// The package's own bodies, dispatched natively.
///
/// The same module the declaration is traced from, so a test running
/// this is running the code the artifact was built from rather than a
/// stand-in for it.
pub use package::account::invoke;

/// The fungible account.
///
/// Spending and writing require the account's own authority; being paid
/// does not. Anyone may credit you, and a transfer therefore still
/// composes under the sender's single signature — the recipient is not
/// asked for one, because nothing about a deposit is theirs to refuse.
/// A method writing a leaf under the target's prefix is gated for the
/// same reason a withdrawal is, though it moves nothing.
///
/// No method reads another account's balance. A precondition on mutable
/// state is a fresh read, which makes the read's owner a participant —
/// the account surface has no shape that wants one yet.
#[must_use]
pub fn metadata() -> PackageMetadata {
    package::account::blueprint().metadata()
}

/// Store one rule as all three: the rule that governs, the one that may
/// replace it, and the one that may enact a replacement early.
///
/// # Errors
///
/// Any refusal the call does not type against `securify`, and
/// [`BuildError::RuleArgTooDeep`] where the rule nests past what its wire
/// encoding admits — handed back rather than panicked, the compose site
/// being where its author can fix it.
pub fn securify_uniform(
    b: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    rule: &StoredRule,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    let sealed = RuleBytes::try_from(rule).map_err(|_| BuildError::RuleArgTooDeep)?;
    securify(
        b,
        who,
        sealed.clone(),
        sealed.clone(),
        sealed,
        recovery_delay_ms,
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Claim, Records, StoredRule, TestHasher};
    use hyperscale_vm_manifest_builder::{BuildError, TypedBuilder, TypedError};
    use hyperscale_vm_types::PrincipalAddr;

    use super::securify_uniform;

    const WHO: PrincipalAddr = PrincipalAddr::new([0x11; 31]);

    /// A rule nested past its wire depth comes back from `securify_uniform`
    /// as a refusal, not a panic — the encode fails before the call to
    /// `securify` is ever composed.
    #[test]
    fn securify_uniform_refuses_a_rule_too_deep_to_encode() {
        let chain = Records::new();
        let mut builder = TypedBuilder::new(&chain, &TestHasher, WHO);
        let mut rule = StoredRule::claim(Claim::of_subject(WHO));
        for _ in 0..32 {
            rule = StoredRule::CountOf {
                count: 1,
                rules: vec![rule],
            };
        }
        assert!(matches!(
            securify_uniform(&mut builder, WHO, &rule, 0),
            Err(TypedError::Build(BuildError::RuleArgTooDeep)),
        ));
    }
}

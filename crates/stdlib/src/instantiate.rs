//! Instantiation, as one call.
//!
//! Every composition that creates a component writes the same three
//! nodes, and all three of the facts deciding what they are belong to
//! the package rather than the caller: which method seals, whether it
//! reads a proof, and whether it yields the supply the component comes
//! up holding. A composition that guessed either is refused at admission —
//! `UnexpectedEvidence` for a proof nobody asked for, an output arity
//! nobody consumed — which is a long way from where it was written.
//!
//! What is *not* here is resolving the record. A composer's tier decides
//! how the chain comes to answer for an address it has never seen: an
//! envelope presents the record beside the call, and a test chain
//! registers it. Either way the target resolves before the call is
//! typed, which is why this takes an address and not a record.
//!
//! Here rather than in the generated client because filing the edge is
//! an account's business, and a package's own client cannot reach the
//! account — the stdlib depends on the SDK, so the dependency runs one
//! way.

use hyperscale_vm_effects::ResourceKind;
use hyperscale_vm_manifest_builder::{Args, TypedBuilder, TypedError};
use hyperscale_vm_types::ComponentAddr;

use crate::account;

/// Append the instantiation of the component at `address`, over `args`.
///
/// The seal is called, and the supply it yields — where the package
/// declares one — is filed in the account the intent acts as: the
/// seal's gate is answered by that intent's signature, so who brings a
/// package up is the builder's own account and not a second thing to
/// state. What the package asks for is read off its own declaration,
/// so a caller states only what is theirs to state: where, and the
/// arguments its bring-up takes — bound at the call the way every other
/// method's are, and `()` for a package whose bring-up takes none.
///
/// # Errors
///
/// [`TypedError`] where the composition does not build — a chain that
/// answers for no such address, a package that declares no seal, or a
/// seal the builder cannot shape.
pub fn instantiate(
    b: &mut TypedBuilder<'_>,
    address: ComponentAddr,
    args: impl Args,
) -> Result<(), TypedError> {
    let founder = b.leading();
    // Which method seals is the declaration's answer, not a name this
    // crate knows.
    let (seal, signature) = b.seal_of(address)?;
    // A gated seal reads the intent's own signature, which the call
    // carries whether or not the seal asks for one — so there is nothing
    // to compose ahead of it and no branch on what its gate says.
    let outputs = b.call(address, &seal, args)?;
    // One edge per supply the package states, and the kind decides which
    // door each is filed through: a balance lands in a vault and an
    // instance in the holdings interval, and the two share no accessor.
    //
    // Paired by position, which is what the seal's own declaration
    // fixes: the founding order is the order its issuances are declared
    // in, and the edges come back in that order.
    let edges = outputs.into_vec();
    if edges.len() != signature.issues.len() {
        return Err(TypedError::OutputArity {
            method: seal,
            declared: edges.len(),
            claimed: signature.issues.len(),
        });
    }
    for (issuance, edge) in signature.issues.iter().zip(edges) {
        match issuance.kind {
            ResourceKind::NonFungible => account::deposit_nf(b, founder, edge)?,
            ResourceKind::Fungible => account::deposit(b, founder, edge)?,
        }
    }
    Ok(())
}

//! Instantiation, as one call.
//!
//! Every composition that creates a component writes the same three
//! nodes, and the two facts deciding which of them exist are the
//! package's rather than the caller's: whether `instantiate` reads a
//! proof, and whether it yields the supply the component comes up
//! holding. A composition that guessed either is refused at admission —
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

use hyperscale_vm_effects::{MethodSignature, ResourceKind};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_types::{ComponentAddr, PrincipalAddr};

use crate::account;

/// The published name of the seal every instance-serving package
/// declares.
pub const INSTANTIATE: &str = "instantiate";

/// Append the instantiation of the component at `address`, as
/// `founder`.
///
/// The seal is called, and the supply it yields — where the package
/// declares one — is filed in the founder's own account. What the
/// package asks for is read off `signature`, so a caller states only
/// what is theirs to state: who is bringing it up, and where.
///
/// # Errors
///
/// [`TypedError`] where the composition does not build — a chain that
/// answers for no such address, or a seal the builder cannot shape.
pub fn instantiate(
    root: &mut TypedBuilder<'_>,
    founder: PrincipalAddr,
    address: ComponentAddr,
    signature: &MethodSignature,
) -> Result<(), TypedError> {
    // Read off the declaration rather than asked of the caller: a method
    // that admits anyone reads no proof, and one that issues nothing
    // yields no edge.
    let outputs = if signature.requires_evidence() {
        let signed_in = account::authorize(root, founder)?;
        root.call_as(signed_in, address, INSTANTIATE, ())?
    } else {
        root.call(address, INSTANTIATE, ())?
    };
    // The kind decides which door the edge is filed through: a balance
    // lands in a vault and an instance in the holdings interval, and the
    // two share no accessor.
    match signature.issues.as_ref().map(|issued| issued.kind) {
        Some(ResourceKind::NonFungible) => account::deposit_nf(root, founder, outputs.one()?),
        Some(ResourceKind::Fungible) => account::deposit(root, founder, outputs.one()?),
        None => outputs.none(),
    }
}

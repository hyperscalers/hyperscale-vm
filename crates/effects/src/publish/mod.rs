//! Publish-time judging, as the composed verdict of three gates.
//!
//! [`bounds`] asks what a signature and a package's tables may hold at
//! all, [`declaration`] asks whether the accesses one method declares are
//! its to declare, and [`abi`] asks whether a guest's export can be
//! bound to them. Three because they are three questions with three
//! answers and nothing between them: each has its own verdict type, and
//! [`check_signature`] is the only thing that knows the order.
//!
//! Every verdict is a pure function of the metadata, identical on every
//! node: refused at publish, and refused again at routing for a package
//! that reached the cache without one.

mod abi;
mod bounds;
mod declaration;
#[cfg(test)]
mod fixtures;

pub use abi::{AbiError, check_abi};
use bounds::check_signature_bounds;
pub use bounds::{MetadataBoundsError, SignatureBoundsError, check_metadata};
pub use declaration::{
    DeclarationError, check_declarations, founds_its_resource, seal_clauses, seals,
};

use crate::signature::MethodSignature;

/// Why a signature is refused at publish: the composed verdict of every
/// judgment the vocabulary makes of one.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    /// Past a structural bound.
    #[error(transparent)]
    Bounds(#[from] SignatureBoundsError),
    /// A declaration rule refused it.
    #[error(transparent)]
    Declaration(#[from] DeclarationError),
    /// The ABI binding refused it — the gate shape included.
    #[error(transparent)]
    Abi(#[from] AbiError),
}

/// A signature every publish-time judgment has passed.
///
/// The witness [`check_signature`] mints, and the only thing the checked
/// judgments hand out: a consumer holding one no longer has to know the
/// list of checks, and a fold that forgot one is unrepresentable rather
/// than an ordering nothing states.
#[derive(Clone, Copy, Debug)]
pub struct CheckedSignature<'a> {
    signature: &'a MethodSignature,
}

impl<'a> CheckedSignature<'a> {
    /// Mint the witness without judging — for the cache, whose invariant
    /// is that everything behind its door already passed.
    pub(crate) const fn trusted(signature: &'a MethodSignature) -> Self {
        Self { signature }
    }

    /// The signature itself.
    #[must_use]
    pub const fn signature(&self) -> &'a MethodSignature {
        self.signature
    }
}

impl std::ops::Deref for CheckedSignature<'_> {
    type Target = MethodSignature;

    fn deref(&self) -> &Self::Target {
        self.signature
    }
}

/// Judge one signature as the publish gate does: the structural bounds,
/// the declaration rules, and the ABI binding, whose shape check covers
/// the gate.
///
/// # Errors
///
/// [`SignatureError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_signature(
    signature: &MethodSignature,
) -> Result<CheckedSignature<'_>, SignatureError> {
    check_signature_bounds(signature)?;
    check_declarations(signature)?;
    check_abi(signature)?;
    Ok(CheckedSignature::trusted(signature))
}

//! A name the protocol spells, as against a string a package chooses.
//!
//! Every name a consumer resolves by — a method, an event, an error, a
//! slot, a configuration field, a struct field, an enum variant — is the
//! identifier that declared it. [`Name`] is where that stops being a
//! convention: bounded in bytes, and held to what an identifier is made
//! of, so a decoded name is one a reader can render, compare, and carry
//! back to the item it came from.
//!
//! What it closes is a package publishing a name a reader cannot trust.
//! Rust admits non-ASCII identifiers and configures no lint against
//! them, so without this a package could publish a method whose name
//! carries bidi overrides, and every rendering of that package would
//! show a human whatever the overrides arranged.
//!
//! The macro is the first tier rather than this one. A declaration is
//! held to an ASCII identifier where it is written, on the identifier's
//! own span; this holds a name that arrives from the wire, which has
//! passed no macro.

use std::fmt;
use std::ops::Deref;

use crate::decode::Decoder;
use crate::encode::{Encoder, Sink};
use crate::error::{DecodeError, EncodeError};
use crate::node::ShapeNode;
use crate::shape::HborShape;
use crate::{HborDecode, HborEncode, HborWidth, bounded};

/// The most bytes a name may occupy.
///
/// Generous against what a declaration spells and finite against what a
/// hand-written artifact could claim: the longest name in the protocol's
/// own packages is under a third of this.
pub const MAX_NAME_BYTES: usize = 64;

/// A string that is not a name the protocol spells.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MalformedName {
    /// No characters at all, which resolves to nothing and renders as
    /// nothing.
    #[error("a name is at least one character")]
    Empty,
    /// More bytes than a name may occupy.
    #[error("{actual} bytes past the {MAX_NAME_BYTES} a name may occupy")]
    TooLong {
        /// The length the string had.
        actual: usize,
    },
    /// A character no identifier is made of.
    #[error("{0:?} is not a character an identifier is made of")]
    Outside(char),
    /// A leading digit, which no identifier opens with.
    #[error("a name opens with a letter or an underscore, never a digit")]
    LeadingDigit,
}

/// A name a consumer resolves by: the identifier that declared it.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Rendered as the name it is, so a message carrying one reads as the
/// word rather than as a wrapper around it.
impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `text` is an ASCII identifier, and what is wrong with it
/// where it is not.
///
/// The same characters Rust admits in an identifier, less the ones no
/// ASCII keyboard has: a name is carried, rendered and compared by
/// consumers that are not Rust, and none of them should have to
/// normalize to do it.
///
/// # Errors
///
/// [`MalformedName`], saying which of the four it is.
pub fn admissible(text: &str) -> Result<(), MalformedName> {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return Err(MalformedName::Empty);
    };
    if text.len() > MAX_NAME_BYTES {
        return Err(MalformedName::TooLong { actual: text.len() });
    }
    if first.is_ascii_digit() {
        return Err(MalformedName::LeadingDigit);
    }
    // Reported as the character an author wrote rather than as the byte
    // it starts with: what they have to change is the character.
    if let Some(outside) = text
        .chars()
        .find(|held| !held.is_ascii_alphanumeric() && *held != '_')
    {
        return Err(MalformedName::Outside(outside));
    }
    Ok(())
}

impl Name {
    /// `text`, where it is a name.
    ///
    /// # Errors
    ///
    /// [`MalformedName`] for an empty name, one past the cap, or one
    /// carrying a character no identifier is made of.
    pub fn new(text: String) -> Result<Self, MalformedName> {
        admissible(&text)?;
        Ok(Self(text))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The name, out from under its type.
    #[must_use]
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Deref for Name {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// So a table keyed by name is looked up by the `&str` a caller holds.
impl std::borrow::Borrow<str> for Name {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for Name {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Name {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl TryFrom<String> for Name {
    type Error = MalformedName;

    fn try_from(text: String) -> Result<Self, MalformedName> {
        Self::new(text)
    }
}

impl TryFrom<&str> for Name {
    type Error = MalformedName;

    fn try_from(text: &str) -> Result<Self, MalformedName> {
        Self::new(text.to_owned())
    }
}

impl HborWidth for Name {
    const MIN_ENCODED_LEN: usize = 1;
}

impl HborEncode for Name {
    fn encode<S: Sink>(&self, encoder: &mut Encoder<S>) -> Result<(), EncodeError> {
        encoder.write_sized(self.0.as_bytes())
    }
}

/// Read as the text it is, then held to being a name: bytes that are not
/// one are not a value of this type, on the same terms bytes that are
/// not UTF-8 are not a value of a string.
impl HborDecode for Name {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let text = bounded::decode_bounded_string(decoder, MAX_NAME_BYTES)?;
        admissible(&text)
            .map_err(|_| DecodeError::FailedValidation("not a name the protocol spells"))?;
        Ok(Self(text))
    }
}

impl HborShape for Name {
    const NODE: &'static ShapeNode = &ShapeNode::Text {
        cap: MAX_NAME_BYTES,
    };
}

#[cfg(test)]
mod tests {
    use super::{MAX_NAME_BYTES, MalformedName, Name};
    use crate::{assert_canonical, from_slice, to_vec};

    #[test]
    fn a_name_is_the_identifier_that_declared_it() {
        assert!(Name::try_from("deposit_nf").is_ok());
        assert!(Name::try_from("ValidatorRegistered").is_ok());
        assert!(Name::try_from("_held").is_ok());
        assert!(Name::try_from("t0").is_ok());
        assert_eq!(Name::try_from(""), Err(MalformedName::Empty));
        assert_eq!(Name::try_from("café"), Err(MalformedName::Outside('é')));
        assert_eq!(Name::try_from("a b"), Err(MalformedName::Outside(' ')));
        assert_eq!(
            Name::try_from("deposit-nf"),
            Err(MalformedName::Outside('-')),
            "the rendering that folded two identifiers into one is gone"
        );
        assert_eq!(Name::try_from("0th"), Err(MalformedName::LeadingDigit));
        let long = "a".repeat(MAX_NAME_BYTES + 1);
        assert_eq!(
            Name::try_from(long.as_str()),
            Err(MalformedName::TooLong {
                actual: MAX_NAME_BYTES + 1
            })
        );
        assert!(Name::try_from("a".repeat(MAX_NAME_BYTES).as_str()).is_ok());
    }

    /// A name reaching a consumer from the wire has passed no macro, so
    /// what it is made of is what the decoder holds it to.
    #[test]
    fn a_name_the_protocol_would_not_spell_does_not_decode() {
        let name = Name::try_from("deposit_nf").expect("a name");
        assert_eq!(from_slice::<Name>(&to_vec(&name).unwrap()), Ok(name));
        assert_canonical(&Name::try_from("Staked").expect("a name"));

        // The rendering a package would be read by, arranged by bytes a
        // reader never sees.
        let bidi = to_vec(&"a\u{202E}b".to_owned()).unwrap();
        assert!(from_slice::<Name>(&bidi).is_err());
        let empty = to_vec(&String::new()).unwrap();
        assert!(from_slice::<Name>(&empty).is_err());
        let long = to_vec(&"a".repeat(MAX_NAME_BYTES + 1)).unwrap();
        assert!(from_slice::<Name>(&long).is_err());
    }
}

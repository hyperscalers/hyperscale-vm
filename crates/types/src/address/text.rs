//! The human-readable address encoding: bech32m over a class-worded,
//! network-suffixed prefix.
//!
//! An address reads as `<class>_<network>1<data><checksum>` — `account_sim1…`,
//! `component_main1…`. Three things a reader can get wrong are checked
//! against each other rather than trusted: the class word in the prefix,
//! the class tag in the address bytes, and the network the caller is
//! transacting on. The class is deliberately stated twice — worded for a
//! human, canonical in the trailing byte — so a string whose two halves
//! disagree is refused rather than resolved in favour of one of them.
//!
//! The network is the caller's to check. It has a register — which names
//! exist, and which id each carries — and that register lives with the
//! network definitions rather than here, so [`Address::from_text`] answers
//! with the word it read and the caller compares it against the network it
//! means. Duplicating the register here would be a second copy to drift.
//!
//! The checksum is bech32m ([BIP-350]), which is what the format buys: any
//! single character substitution and most short transpositions are caught
//! before an address reaches a signature. The implementation is here rather
//! than pulled in because it is one polymod and one charset, and both are
//! pinned against BIP-350's own vectors below.
//!
//! [BIP-350]: https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki

use core::fmt;

use thiserror::Error;

use super::{Address, AddressClass, InvalidAddress};

/// The bech32 data alphabet, in value order.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// The BCH generator polynomial's coefficients.
const GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

/// The constant bech32m checks against, where bech32 used 1. This is the
/// whole difference between the two, and it is what makes an address
/// undecodable by a bech32 reader rather than silently mutable in its last
/// character.
const BECH32M_CONST: u32 = 0x2bc8_30a3;

/// The encoding's own length cap.
const MAX_ENCODED_LEN: usize = 90;

/// The separator between the human-readable prefix and the data.
const SEPARATOR: char = '1';

/// Why a string names no address, or an address no string.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum TextError {
    /// No separator, so there is no prefix to read.
    #[error("no `{SEPARATOR}` separator")]
    MissingSeparator,
    /// An empty prefix or an empty network word.
    #[error("the prefix is incomplete")]
    IncompletePrefix,
    /// A character outside the alphabet the encoding admits.
    #[error("character {0:?} is not in the encoding")]
    InvalidCharacter(char),
    /// Upper and lower case in one string; each alone is fine.
    #[error("mixed case")]
    MixedCase,
    /// The checksum does not cover the characters that precede it.
    #[error("the checksum does not match")]
    BadChecksum,
    /// Longer than the encoding admits.
    #[error("{0} characters exceeds the {MAX_ENCODED_LEN} the encoding admits")]
    TooLong(usize),
    /// The data was not the 32 bytes an address is.
    #[error("{0} data bytes is not an address")]
    WrongLength(usize),
    /// Padding bits a decoder must not accept, because two strings would
    /// then name one address.
    #[error("non-canonical padding")]
    BadPadding,
    /// A leading word that names no class.
    #[error("`{0}` names no class")]
    UnknownClass(String),
    /// The prefix's class word and the address's own tag disagree.
    #[error("the prefix says {worded} but the address is {tagged}")]
    ClassMismatch {
        /// The class the prefix worded.
        worded: AddressClass,
        /// The class the trailing byte names.
        tagged: AddressClass,
    },
    /// The bytes carry no class at all.
    #[error(transparent)]
    NotAnAddress(#[from] InvalidAddress),
}

/// The network word a string named, alongside the address it carried.
///
/// Held as read rather than resolved: this crate has no register of
/// networks, and inventing one here would be the second copy that drifts
/// from the first.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NetworkWord(pub String);

impl fmt::Display for NetworkWord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Address {
    /// The address as text, for `network`.
    ///
    /// # Errors
    ///
    /// [`TextError`] if `network` is empty, is not lowercase alphanumeric,
    /// or makes the string longer than the encoding admits.
    pub fn to_text(self, network: &str) -> Result<String, TextError> {
        if network.is_empty() {
            return Err(TextError::IncompletePrefix);
        }
        if let Some(bad) = network
            .chars()
            .find(|c| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        {
            return Err(TextError::InvalidCharacter(bad));
        }
        let prefix = format!("{}_{network}", self.class().word());
        let words = to_words(&self.to_bytes());
        encode(&prefix, &words)
    }

    /// The address a string names, and the network word it named it under.
    ///
    /// The caller compares the word against the network it is transacting
    /// on; every other cross-check — checksum, alphabet, case, class word
    /// against class tag, data length — is made here.
    ///
    /// # Errors
    ///
    /// [`TextError`] naming which of those the string failed.
    pub fn from_text(text: &str) -> Result<(Self, NetworkWord), TextError> {
        let (prefix, words) = decode(text)?;
        let bytes: [u8; 32] = from_words(&words)?
            .try_into()
            .map_err(|bytes: Vec<u8>| TextError::WrongLength(bytes.len()))?;
        let address = Self::from_bytes(bytes)?;

        let (class, network) = prefix
            .split_once('_')
            .ok_or(TextError::IncompletePrefix)
            .and_then(|(class, network)| {
                if network.is_empty() {
                    Err(TextError::IncompletePrefix)
                } else {
                    Ok((class, network))
                }
            })?;
        let worded = AddressClass::from_word(class)
            .ok_or_else(|| TextError::UnknownClass(class.to_owned()))?;
        let tagged = address.class();
        if worded != tagged {
            return Err(TextError::ClassMismatch { worded, tagged });
        }
        Ok((address, NetworkWord(network.to_owned())))
    }
}

/// The checksum's view of the prefix: every byte's high bits, a zero, then
/// every byte's low bits.
fn prefix_words(prefix: &str) -> impl Iterator<Item = u8> + '_ {
    prefix
        .bytes()
        .map(|byte| byte >> 5)
        .chain(core::iter::once(0))
        .chain(prefix.bytes().map(|byte| byte & 31))
}

/// The BCH residue of `words` under the generator.
fn polymod(words: impl Iterator<Item = u8>) -> u32 {
    let mut residue = 1u32;
    for word in words {
        let top = residue >> 25;
        residue = ((residue & 0x01ff_ffff) << 5) ^ u32::from(word);
        for (bit, generator) in GENERATORS.iter().enumerate() {
            if (top >> bit) & 1 == 1 {
                residue ^= generator;
            }
        }
    }
    residue
}

/// The six checksum words closing `prefix` and `words`.
fn checksum(prefix: &str, words: &[u8]) -> [u8; 6] {
    let residue = polymod(
        prefix_words(prefix)
            .chain(words.iter().copied())
            .chain([0; 6]),
    ) ^ BECH32M_CONST;
    let mut out = [0u8; 6];
    for (index, word) in out.iter_mut().enumerate() {
        *word = ((residue >> (5 * (5 - index))) & 31) as u8;
    }
    out
}

/// `prefix`, the separator, `words`, and the checksum over both.
fn encode(prefix: &str, words: &[u8]) -> Result<String, TextError> {
    let len = prefix.len() + 1 + words.len() + 6;
    if len > MAX_ENCODED_LEN {
        return Err(TextError::TooLong(len));
    }
    let mut text = String::with_capacity(len);
    text.push_str(prefix);
    text.push(SEPARATOR);
    for word in words.iter().copied().chain(checksum(prefix, words)) {
        text.push(char::from(CHARSET[word as usize]));
    }
    Ok(text)
}

/// The prefix and data words a string carries, checksum verified and
/// stripped.
fn decode(text: &str) -> Result<(String, Vec<u8>), TextError> {
    if text.len() > MAX_ENCODED_LEN {
        return Err(TextError::TooLong(text.len()));
    }
    if let Some(bad) = text.chars().find(|c| !c.is_ascii_graphic()) {
        return Err(TextError::InvalidCharacter(bad));
    }
    // Either case decodes; both at once does not, because the checksum
    // covers one canonical form and a mixed string has two readings.
    let upper = text.chars().any(char::is_uppercase);
    let lower = text.chars().any(char::is_lowercase);
    if upper && lower {
        return Err(TextError::MixedCase);
    }
    let text = text.to_ascii_lowercase();

    let separator = text.rfind(SEPARATOR).ok_or(TextError::MissingSeparator)?;
    let (prefix, data) = (&text[..separator], &text[separator + 1..]);
    if prefix.is_empty() {
        return Err(TextError::IncompletePrefix);
    }
    if data.len() < 6 {
        return Err(TextError::BadChecksum);
    }
    let mut words = Vec::with_capacity(data.len());
    for character in data.chars() {
        let value = CHARSET
            .iter()
            .zip(0u8..)
            .find_map(|(candidate, value)| (char::from(*candidate) == character).then_some(value))
            .ok_or(TextError::InvalidCharacter(character))?;
        words.push(value);
    }
    if polymod(prefix_words(prefix).chain(words.iter().copied())) != BECH32M_CONST {
        return Err(TextError::BadChecksum);
    }
    words.truncate(words.len() - 6);
    Ok((prefix.to_owned(), words))
}

/// Bytes to five-bit words, zero-padded to a whole word.
fn to_words(bytes: &[u8]) -> Vec<u8> {
    let mut words = Vec::with_capacity(bytes.len() * 8 / 5 + 1);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in bytes {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        words.push(((acc << (5 - bits)) & 31) as u8);
    }
    words
}

/// Five-bit words back to bytes, refusing any padding a re-encoding would
/// not produce — two strings naming one address is exactly what a
/// canonical encoding must not allow.
fn from_words(words: &[u8]) -> Result<Vec<u8>, TextError> {
    let mut bytes = Vec::with_capacity(words.len() * 5 / 8);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for word in words {
        acc = (acc << 5) | u32::from(*word);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            bytes.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits >= 5 || (acc << (8 - bits)) & 0xff != 0 {
        return Err(TextError::BadPadding);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::{ComponentAddr, NativeAddr, PackageAddr, PrincipalAddr, ResourceAddr};
    use super::{
        Address, AddressClass, MAX_ENCODED_LEN, NetworkWord, TextError, decode, encode, to_words,
    };

    /// BIP-350's own valid bech32m strings. Pinning them is what makes the
    /// checksum here the published one rather than one that merely
    /// round-trips against itself.
    const BIP350_VALID: [&str; 7] = [
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    #[test]
    fn the_published_vectors_verify_and_re_encode() {
        for vector in BIP350_VALID {
            let (prefix, words) = decode(vector).expect(vector);
            // Re-encoding a verified string reproduces it in lower case:
            // the checksum this computes is the one BIP-350 published.
            assert_eq!(
                encode(&prefix, &words).as_deref(),
                Ok(vector.to_lowercase().as_str())
            );
        }
    }

    #[test]
    fn a_mutated_vector_fails_its_checksum() {
        // One character of the data half, moved to its neighbour in the
        // alphabet: the property the encoding exists for.
        let mutated = "split1checkupstagehandshakeupstreamerranterredcaperredlc445q";
        assert_eq!(decode(mutated), Err(TextError::BadChecksum));
        // BIP-350's own invalid case: a checksum computed over the prefix
        // in the other case than the one it is presented in.
        assert_eq!(decode("M1VUXWEZ"), Err(TextError::BadChecksum));
    }

    #[test]
    fn the_shapes_a_string_must_have() {
        assert_eq!(decode("qyrz8wqd2c9m"), Err(TextError::MissingSeparator));
        assert_eq!(decode("1qyrz8wqd2c9m"), Err(TextError::IncompletePrefix));
        assert_eq!(decode("A1lqfn3a"), Err(TextError::MixedCase));
        assert_eq!(decode("abc1"), Err(TextError::BadChecksum));
        assert_eq!(
            decode("abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzm6b"),
            Err(TextError::InvalidCharacter('b'))
        );
        let long = "a".repeat(MAX_ENCODED_LEN + 1);
        assert_eq!(decode(&long), Err(TextError::TooLong(long.len())));
    }

    #[test]
    fn every_class_round_trips_under_its_own_word() {
        let addresses = [
            PrincipalAddr::new([0x11; 31]).address(),
            ComponentAddr::new([0x22; 31]).address(),
            PackageAddr::new([0x33; 31]).address(),
            ResourceAddr::new([0x44; 31]).address(),
            NativeAddr::new([0x55; 31]).address(),
        ];
        for address in addresses {
            let text = address.to_text("sim").expect("a short network word fits");
            assert!(text.starts_with(&format!("{}_sim1", address.class().word())));
            assert!(
                text.len() <= MAX_ENCODED_LEN,
                "{text} is {} chars",
                text.len()
            );
            assert_eq!(
                Address::from_text(&text),
                Ok((address, NetworkWord("sim".to_owned())))
            );
            // The encoding admits either case and no mixture of them.
            assert_eq!(
                Address::from_text(&text.to_uppercase()).map(|(address, _)| address),
                Ok(address)
            );
        }
    }

    #[test]
    fn the_network_travels_with_the_address_but_is_the_callers_to_judge() {
        let address = PrincipalAddr::new([0x11; 31]).address();
        let simulator = address.to_text("simulator").unwrap();
        let mainnet = address.to_text("main").unwrap();
        assert_ne!(simulator, mainnet, "the network is covered by the checksum");
        // Both decode: which network a reader means is not this crate's
        // register to hold, so it answers with the word and no verdict.
        assert_eq!(
            Address::from_text(&simulator).unwrap().1,
            NetworkWord("simulator".to_owned())
        );
        assert_eq!(
            Address::from_text(&mainnet).unwrap().1,
            NetworkWord("main".to_owned())
        );
    }

    #[test]
    fn a_prefix_that_contradicts_the_tag_is_refused() {
        // The doubling earns its keep here: the same 32 bytes, worded as
        // the class they are not.
        let component = ComponentAddr::new([0x22; 31]).address();
        let words = to_words(&component.to_bytes());
        let forged = encode("account_sim", &words).unwrap();
        assert_eq!(
            Address::from_text(&forged),
            Err(TextError::ClassMismatch {
                worded: AddressClass::Principal,
                tagged: AddressClass::Component,
            })
        );
    }

    #[test]
    fn a_prefix_that_names_no_class_is_refused() {
        let words = to_words(&ComponentAddr::new([0x22; 31]).to_bytes());
        assert_eq!(
            Address::from_text(&encode("wallet_sim", &words).unwrap()),
            Err(TextError::UnknownClass("wallet".to_owned()))
        );
        // And a prefix with no network half at all.
        assert_eq!(
            Address::from_text(&encode("component", &words).unwrap()),
            Err(TextError::IncompletePrefix)
        );
    }

    #[test]
    fn data_that_is_not_an_address_is_refused() {
        assert_eq!(
            Address::from_text(&encode("component_sim", &to_words(&[0x22; 31])).unwrap()),
            Err(TextError::WrongLength(31))
        );
        let mut unassigned = [0x22; 32];
        unassigned[31] = 0x00;
        let refused = Address::from_text(&encode("component_sim", &to_words(&unassigned)).unwrap());
        assert!(matches!(refused, Err(TextError::NotAnAddress(_))));
    }

    #[test]
    fn a_network_word_the_prefix_cannot_carry_is_refused() {
        let address = PrincipalAddr::new([0x11; 31]).address();
        assert_eq!(address.to_text(""), Err(TextError::IncompletePrefix));
        assert_eq!(
            address.to_text("Main"),
            Err(TextError::InvalidCharacter('M'))
        );
        assert_eq!(
            address.to_text("a_b"),
            Err(TextError::InvalidCharacter('_'))
        );
        // 52 data words plus six of checksum leave a bounded prefix.
        let long = "n".repeat(40);
        assert!(matches!(address.to_text(&long), Err(TextError::TooLong(_))));
    }
}

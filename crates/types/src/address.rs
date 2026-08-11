//! The address space state lives in.

use core::fmt;

use hyperscale_hbor::{
    DecodeError, Decoder, EncodeError, Encoder, Hbor, HborDecode, HborEncode, HborWidth,
};
use thiserror::Error;

/// A global object's address: its 16-byte owner prefix in the JMT key space.
///
/// Every substate an object owns lives under this prefix, and a shard
/// boundary never cuts through a prefix, so an address resolves to exactly
/// one shard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct Address(pub [u8; 16]);

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// The local half of a substate key, assigned within an owner's prefix.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct LocalKey(pub [u8; 16]);

impl fmt::Debug for LocalKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LocalKey(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// A full JMT leaf key: owner prefix followed by the local half.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct SubstateKey {
    /// The owning object's address; fixes the key's shard.
    pub owner: Address,
    /// The slot within the owner's prefix.
    pub local: LocalKey,
}

impl SubstateKey {
    /// The key as its 32 leaf bytes: owner prefix, then local half. The
    /// same bytes the wire encoding carries and the state tree keys its
    /// leaf by — the key *is* its placement.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        bytes[..16].copy_from_slice(&self.owner.0);
        bytes[16..].copy_from_slice(&self.local.0);
        bytes
    }

    /// Rebuild a key from its 32 leaf bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut owner = [0u8; 16];
        let mut local = [0u8; 16];
        owner.copy_from_slice(&bytes[..16]);
        local.copy_from_slice(&bytes[16..]);
        Self {
            owner: Address(owner),
            local: LocalKey(local),
        }
    }
}

/// The signature scheme a principal's auth material belongs to.
///
/// A principal address commits to the scheme alongside the key, so one
/// public key presented under two schemes is two principals — a scheme
/// added later cannot land on an address already in use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct SchemeId(pub u16);

impl SchemeId {
    /// Ed25519, the only scheme the protocol verifies. A second scheme
    /// arrives with its verifier and takes the next value; nothing may
    /// claim one before then, because the address space would be spent.
    pub const ED25519: Self = Self(1);
}

/// The class of object an address names.
///
/// The class is a fact about the address rather than a lookup: what
/// derived it, what it commits to, and what a client may do with it are
/// all readable from the address alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressClass {
    /// An account or persona, addressed by the auth material that opens
    /// it.
    Principal,
    /// An instance of a user package, addressed by the code and the
    /// creation-fixed configuration it runs under. Both are welded in:
    /// an instance cannot change either without becoming a different
    /// address.
    Component,
    /// Published code, addressed by its content and immutable for as
    /// long as it exists.
    Package,
    /// A resource, addressed by the provenance of its supply — who may
    /// mint it.
    Resource,
    /// A protocol-defined role. The role is what the address names; the
    /// code behind it moves with the protocol version, which is the one
    /// upgrade channel a package address deliberately lacks.
    Native,
}

impl AddressClass {
    /// The trailing byte naming this class.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Principal => 0x01,
            Self::Component => 0x02,
            Self::Package => 0x03,
            Self::Resource => 0x04,
            Self::Native => 0x05,
        }
    }

    /// The class a tag byte names, or `None` for a byte naming none.
    ///
    /// Zero and every unassigned value are invalid rather than reserved:
    /// zeroed memory fails closed, and a class added later is a protocol
    /// version change that older parsers refuse outright instead of
    /// misreading.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0x01 => Some(Self::Principal),
            0x02 => Some(Self::Component),
            0x03 => Some(Self::Package),
            0x04 => Some(Self::Resource),
            0x05 => Some(Self::Native),
            _ => None,
        }
    }

    /// The word a human-readable encoding leads with.
    ///
    /// `Principal` reads as `account` because that is the word its
    /// holders use for it; the class is deliberately doubled — worded
    /// here, canonical in the tag byte — and a decoder that finds the two
    /// disagreeing rejects.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Principal => "account",
            Self::Component => "component",
            Self::Package => "package",
            Self::Resource => "resource",
            Self::Native => "native",
        }
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// A byte string that names no address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("address tag {tag:#04x} names no class")]
pub struct InvalidAddress {
    /// The trailing byte that named no class.
    pub tag: u8,
}

/// An address of the wrong class for what it was asked to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("expected {expected} address, found {found}")]
pub struct WrongClass {
    /// The class the conversion required.
    pub expected: AddressClass,
    /// The class the address actually carries.
    pub found: AddressClass,
}

/// A global object's address: 31 bytes of domain-separated hash followed
/// by the byte naming its class.
///
/// The address certifies itself. Its body commits to the derivation that
/// produced it — auth material, package and configuration, content,
/// minter — so a claimed binding is checked by recomputing the derivation
/// and never by consulting state. That is what lets any shard verify any
/// target with no foreign reads, and what makes a false claim
/// cryptographically impossible rather than a lookup that disagrees.
///
/// The tag trails rather than leads because the leading bytes are what
/// the shard trie routes on. Leaving them uniformly distributed hash
/// output spreads every class across the prefix space; a leading tag
/// would herd each class onto one slice of it.
///
/// Thirty-one body bytes put the birthday bound at roughly 2^124, which
/// is what buys self-certification with no registration step to fall back
/// on.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GlobalAddress([u8; 32]);

impl GlobalAddress {
    /// The address with `body` under `class`.
    #[must_use]
    pub const fn new(body: [u8; 31], class: AddressClass) -> Self {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 31 {
            bytes[i] = body[i];
            i += 1;
        }
        bytes[31] = class.tag();
        Self(bytes)
    }

    /// The class this address names.
    ///
    /// # Panics
    ///
    /// Never, for an address that exists: every constructor validates the
    /// tag, so an unassigned one is refused before a value is built
    /// rather than carried into a reader.
    #[must_use]
    pub const fn class(self) -> AddressClass {
        AddressClass::from_tag(self.0[31]).expect("a constructed address carries an assigned tag")
    }

    /// The derivation commitment: everything but the tag.
    #[must_use]
    pub fn body(self) -> [u8; 31] {
        let mut body = [0u8; 31];
        body.copy_from_slice(&self.0[..31]);
        body
    }

    /// The address as its 32 bytes — the form it takes on the wire and in
    /// a key.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// The address 32 bytes name, or an error if the tag names no class.
    ///
    /// This is the parse every wire path runs through, and it is where
    /// an unassigned class fails closed.
    ///
    /// # Errors
    ///
    /// [`InvalidAddress`] when the trailing byte names no class.
    pub const fn from_bytes(bytes: [u8; 32]) -> Result<Self, InvalidAddress> {
        match AddressClass::from_tag(bytes[31]) {
            Some(_) => Ok(Self(bytes)),
            None => Err(InvalidAddress { tag: bytes[31] }),
        }
    }
}

impl fmt::Debug for GlobalAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GlobalAddress(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl HborWidth for GlobalAddress {
    const MIN_ENCODED_LEN: usize = 32;
}

impl HborEncode for GlobalAddress {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_fixed(&self.0);
        Ok(())
    }
}

impl HborDecode for GlobalAddress {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
        let bytes: [u8; 32] = decoder.read_array()?;
        Self::from_bytes(bytes).map_err(|err| DecodeError::InvalidDiscriminant(err.tag))
    }
}

macro_rules! class_addr {
    ($(#[$doc:meta])* $name:ident => $class:ident) => {
        $(#[$doc])*
        ///
        /// Constructed only through a checked conversion, so holding one
        /// is evidence of its class.
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(GlobalAddress);

        impl $name {
            /// The class every value of this type carries.
            pub const CLASS: AddressClass = AddressClass::$class;

            /// The address, with its class forgotten.
            #[must_use]
            pub const fn address(self) -> GlobalAddress {
                self.0
            }
        }

        impl TryFrom<GlobalAddress> for $name {
            type Error = WrongClass;

            fn try_from(address: GlobalAddress) -> Result<Self, Self::Error> {
                let found = address.class();
                if found == AddressClass::$class {
                    Ok(Self(address))
                } else {
                    Err(WrongClass { expected: AddressClass::$class, found })
                }
            }
        }

        impl From<$name> for GlobalAddress {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "("))?;
                for byte in &self.0.0 {
                    write!(f, "{byte:02x}")?;
                }
                write!(f, ")")
            }
        }
    };
}

class_addr! {
    /// An address checked to name a principal.
    PrincipalAddr => Principal
}
class_addr! {
    /// An address checked to name a component instance.
    ComponentAddr => Component
}
class_addr! {
    /// An address checked to name a package.
    PackageAddr => Package
}
class_addr! {
    /// An address checked to name a resource.
    ResourceAddr => Resource
}
class_addr! {
    /// An address checked to name a protocol role.
    NativeAddr => Native
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{assert_canonical, from_slice, to_vec};

    use super::{
        Address, AddressClass, ComponentAddr, GlobalAddress, LocalKey, PrincipalAddr, SubstateKey,
    };

    #[test]
    fn addresses_are_their_bytes_on_the_wire() {
        assert_eq!(to_vec(&Address([7; 16])).unwrap(), vec![7u8; 16]);
        let key = SubstateKey {
            owner: Address([1; 16]),
            local: LocalKey([2; 16]),
        };
        assert_eq!(to_vec(&key).unwrap().len(), 32);
        assert_canonical(&key);
    }

    #[test]
    fn a_key_and_its_leaf_bytes_round_trip() {
        let key = SubstateKey {
            owner: Address([1; 16]),
            local: LocalKey([2; 16]),
        };
        let bytes = key.to_bytes();
        assert_eq!(&bytes[..16], &[1; 16]);
        assert_eq!(&bytes[16..], &[2; 16]);
        assert_eq!(SubstateKey::from_bytes(bytes), key);
        // The leaf bytes are the wire encoding: one layout, not two.
        assert_eq!(to_vec(&key).unwrap(), bytes);
    }

    const CLASSES: [AddressClass; 5] = [
        AddressClass::Principal,
        AddressClass::Component,
        AddressClass::Package,
        AddressClass::Resource,
        AddressClass::Native,
    ];

    #[test]
    fn a_class_is_recoverable_from_the_address_it_tagged() {
        for class in CLASSES {
            let address = GlobalAddress::new([9; 31], class);
            assert_eq!(address.class(), class);
            assert_eq!(address.body(), [9; 31]);
            assert_eq!(address.to_bytes()[31], class.tag());
            assert_eq!(AddressClass::from_tag(class.tag()), Some(class));
        }
    }

    #[test]
    fn the_assigned_tags_are_one_through_five() {
        let tags: Vec<u8> = CLASSES.iter().map(|class| class.tag()).collect();
        assert_eq!(tags, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn a_class_word_names_exactly_one_class() {
        let words: Vec<&str> = CLASSES.iter().map(|class| class.word()).collect();
        assert_eq!(
            words,
            vec!["account", "component", "package", "resource", "native"]
        );
        let unique: std::collections::BTreeSet<&str> = words.iter().copied().collect();
        assert_eq!(unique.len(), words.len());
    }

    #[test]
    fn an_unassigned_tag_names_no_address() {
        for tag in [0x00u8, 0x06, 0x7f, 0xff] {
            assert_eq!(AddressClass::from_tag(tag), None);
            let mut bytes = [3u8; 32];
            bytes[31] = tag;
            let err = GlobalAddress::from_bytes(bytes).unwrap_err();
            assert_eq!(err.tag, tag);
            // The same refusal on the wire: an address a decoder cannot
            // classify is not an address it accepts and classifies later.
            assert!(from_slice::<GlobalAddress>(&bytes).is_err());
        }
    }

    #[test]
    fn a_zeroed_address_fails_closed() {
        assert!(GlobalAddress::from_bytes([0; 32]).is_err());
    }

    #[test]
    fn a_global_address_is_its_bytes_on_the_wire() {
        let address = GlobalAddress::new([5; 31], AddressClass::Resource);
        let encoded = to_vec(&address).unwrap();
        assert_eq!(encoded, address.to_bytes());
        assert_eq!(encoded.len(), 32);
        assert_eq!(from_slice::<GlobalAddress>(&encoded).unwrap(), address);
        assert_canonical(&address);
    }

    #[test]
    fn a_typed_address_refuses_every_other_class() {
        let principal = GlobalAddress::new([1; 31], AddressClass::Principal);
        assert_eq!(
            PrincipalAddr::try_from(principal).unwrap().address(),
            principal
        );
        let err = ComponentAddr::try_from(principal).unwrap_err();
        assert_eq!(err.expected, AddressClass::Component);
        assert_eq!(err.found, AddressClass::Principal);

        for class in CLASSES {
            let address = GlobalAddress::new([2; 31], class);
            assert_eq!(
                PrincipalAddr::try_from(address).is_ok(),
                class == AddressClass::Principal
            );
        }
    }
}

//! The address space state lives in.

use core::fmt;

use hyperscale_hbor::{
    DecodeError, Decoder, EncodeError, Encoder, Hbor, HborDecode, HborEncode, HborWidth,
};
use thiserror::Error;

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

/// The byte width of a JMT leaf key: the owner address, then the local
/// half.
pub const LEAF_KEY_BYTES: usize = 48;

impl SubstateKey {
    /// The key as its 48 leaf bytes: owner prefix, then local half. The
    /// same bytes the wire encoding carries and the state tree keys its
    /// leaf by — the key *is* its placement.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; LEAF_KEY_BYTES] {
        let mut bytes = [0u8; LEAF_KEY_BYTES];
        bytes[..32].copy_from_slice(&self.owner.to_bytes());
        bytes[32..].copy_from_slice(&self.local.0);
        bytes
    }

    /// Rebuild a key from its 48 leaf bytes.
    ///
    /// # Errors
    ///
    /// [`InvalidAddress`] when the owner half's tag names no class —
    /// a leaf key is only a key if its owner is an address.
    pub fn from_bytes(bytes: [u8; LEAF_KEY_BYTES]) -> Result<Self, InvalidAddress> {
        let mut owner = [0u8; 32];
        let mut local = [0u8; 16];
        owner.copy_from_slice(&bytes[..32]);
        local.copy_from_slice(&bytes[32..]);
        Ok(Self {
            owner: Address::from_bytes(owner)?,
            local: LocalKey(local),
        })
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

/// An address of a class nothing invokes methods on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("a {found} address is not callable")]
pub struct NotCallable {
    /// The class the address carries.
    pub found: AddressClass,
}

/// An address of a class that denominates no supply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("a {found} address names no resource")]
pub struct NotAResource {
    /// The class the address carries.
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
///
/// The address is also the owner prefix in the JMT key space: every
/// substate an object owns lives under it, and a shard boundary never
/// cuts through a prefix, so an address resolves to exactly one shard.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 32]);

impl Address {
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

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address(")?;
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

impl HborWidth for Address {
    const MIN_ENCODED_LEN: usize = 32;
}

impl HborEncode for Address {
    fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
        encoder.write_fixed(&self.0);
        Ok(())
    }
}

impl HborDecode for Address {
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
        pub struct $name(Address);

        impl $name {
            /// The class every value of this type carries.
            pub const CLASS: AddressClass = AddressClass::$class;

            /// The address of this class with `body`.
            ///
            /// The class comes from the constructor rather than from an
            /// argument, so a value of this type cannot be built carrying
            /// another class's tag and a fixture needs no checked
            /// conversion to write one down.
            #[must_use]
            pub const fn new(body: [u8; 31]) -> Self {
                Self(Address::new(body, AddressClass::$class))
            }

            /// The address, with its class forgotten.
            #[must_use]
            pub const fn address(self) -> Address {
                self.0
            }

            /// The derivation commitment: everything but the tag.
            #[must_use]
            pub fn body(self) -> [u8; 31] {
                self.0.body()
            }

            /// The address as its 32 bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0.to_bytes()
            }
        }

        // A typed address and an untyped one are equal when their bytes
        // are: knowing the class of one side is not a difference the
        // comparison should have to be told about.
        impl PartialEq<Address> for $name {
            fn eq(&self, other: &Address) -> bool {
                self.0 == *other
            }
        }

        impl PartialEq<$name> for Address {
            fn eq(&self, other: &$name) -> bool {
                *self == other.0
            }
        }

        impl HborWidth for $name {
            const MIN_ENCODED_LEN: usize = 32;
        }

        impl HborEncode for $name {
            fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
                self.0.encode(encoder)
            }
        }

        impl HborDecode for $name {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                let address = Address::decode(decoder)?;
                Self::try_from(address)
                    .map_err(|err| DecodeError::InvalidDiscriminant(err.found.tag()))
            }
        }

        impl TryFrom<Address> for $name {
            type Error = WrongClass;

            fn try_from(address: Address) -> Result<Self, Self::Error> {
                let found = address.class();
                if found == AddressClass::$class {
                    Ok(Self(address))
                } else {
                    Err(WrongClass { expected: AddressClass::$class, found })
                }
            }
        }

        impl From<$name> for Address {
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

/// The classes a position admits, for a position no single class fills.
///
/// Each of these is a small closed set over the class newtypes: the
/// variants are the classes the position accepts, the conversion from a
/// plain [`Address`] is where an address of any other class is refused,
/// and a reader dispatching over the set is exhaustive rather than
/// carrying an arm for classes that cannot arrive.
macro_rules! position_addr {
    (
        $(#[$doc:meta])*
        $name:ident, $error:ident {
            $($(#[$variant_doc:meta])* $variant:ident($class:ident)),+ $(,)?
        }
    ) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $($(#[$variant_doc])* $variant($class),)+
        }

        impl $name {
            /// The address, with the position's narrowing forgotten.
            #[must_use]
            pub const fn address(self) -> Address {
                match self {
                    $(Self::$variant(address) => address.address(),)+
                }
            }

            /// The class the address carries.
            #[must_use]
            pub const fn class(self) -> AddressClass {
                match self {
                    $(Self::$variant(_) => $class::CLASS,)+
                }
            }

            /// The address as its 32 bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 32] {
                self.address().to_bytes()
            }
        }

        $(
            impl From<$class> for $name {
                fn from(address: $class) -> Self {
                    Self::$variant(address)
                }
            }
        )+

        impl From<$name> for Address {
            fn from(value: $name) -> Self {
                value.address()
            }
        }

        impl TryFrom<Address> for $name {
            type Error = $error;

            fn try_from(address: Address) -> Result<Self, Self::Error> {
                $(
                    if let Ok(narrowed) = $class::try_from(address) {
                        return Ok(Self::$variant(narrowed));
                    }
                )+
                Err($error { found: address.class() })
            }
        }

        impl PartialEq<Address> for $name {
            fn eq(&self, other: &Address) -> bool {
                self.address() == *other
            }
        }

        impl PartialEq<$name> for Address {
            fn eq(&self, other: &$name) -> bool {
                *self == other.address()
            }
        }

        impl HborWidth for $name {
            const MIN_ENCODED_LEN: usize = 32;
        }

        impl HborEncode for $name {
            fn encode(&self, encoder: &mut Encoder<'_>) -> Result<(), EncodeError> {
                self.address().encode(encoder)
            }
        }

        impl HborDecode for $name {
            fn decode(decoder: &mut Decoder<'_>) -> Result<Self, DecodeError> {
                let address = Address::decode(decoder)?;
                Self::try_from(address)
                    .map_err(|err| DecodeError::InvalidDiscriminant(err.found.tag()))
            }
        }
    };
}

position_addr! {
    /// An address a method may be invoked on.
    ///
    /// Callability is not one class. An account and an instance of a user
    /// package both answer calls; a package *is* code and a resource *is*
    /// a supply, so neither has methods to name, and naming one as a
    /// target is a byte string a reader refuses rather than a claim it
    /// resolves and rejects later.
    ///
    /// No protocol role is callable, so the native class is absent — the
    /// register's two roles are a resource and a publisher. A callable
    /// role arrives with its conversion, which is the fail-closed
    /// direction: a class not listed here cannot be called at all.
    CallTarget, NotCallable {
        /// An account, answering through the protocol's account blueprint.
        Principal(PrincipalAddr),
        /// An instance, answering through the blueprint its address
        /// commits to.
        Component(ComponentAddr),
    }
}

position_addr! {
    /// An address naming the resource an amount is denominated in.
    ///
    /// Two classes name resources, because the protocol's own resource
    /// has no minter to commit to. An ordinary resource address commits
    /// its provenance — who may mint it — while the native fee resource
    /// is derived from the role it plays, its supply moving only with the
    /// protocol. Keeping them separate classes is what keeps one tag
    /// naming one derivation rule.
    ResourceRef, NotAResource {
        /// A resource addressed by who may mint it.
        Resource(ResourceAddr),
        /// A protocol resource, addressed by the role it plays.
        Native(NativeAddr),
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::AddressClass::{Component, Native, Package, Principal, Resource};
    use super::{
        Address, AddressClass, CallTarget, ComponentAddr, LocalKey, NativeAddr, PackageAddr,
        PrincipalAddr, ResourceAddr, ResourceRef, SubstateKey,
    };

    fn owner(seed: u8) -> Address {
        Address::new([seed; 31], Component)
    }

    #[test]
    fn addresses_are_their_bytes_on_the_wire() {
        let address = owner(7);
        assert_eq!(to_vec(&address).unwrap(), address.to_bytes());
        let key = SubstateKey {
            owner: owner(1),
            local: LocalKey([2; 16]),
        };
        assert_eq!(to_vec(&key).unwrap().len(), 48);
        assert_canonical(&key);
    }

    #[test]
    fn a_key_and_its_leaf_bytes_round_trip() {
        let key = SubstateKey {
            owner: owner(1),
            local: LocalKey([2; 16]),
        };
        let bytes = key.to_bytes();
        assert_eq!(&bytes[..32], &key.owner.to_bytes());
        assert_eq!(&bytes[32..], &[2; 16]);
        assert_eq!(SubstateKey::from_bytes(bytes).unwrap(), key);
        // The leaf bytes are the wire encoding: one layout, not two.
        assert_eq!(to_vec(&key).unwrap(), bytes);
    }

    #[test]
    fn a_leaf_key_whose_owner_names_no_class_is_not_a_key() {
        let mut bytes = [4u8; 48];
        bytes[31] = 0x00;
        assert!(SubstateKey::from_bytes(bytes).is_err());
    }

    const CLASSES: [AddressClass; 5] = [Principal, Component, Package, Resource, Native];

    #[test]
    fn a_class_is_recoverable_from_the_address_it_tagged() {
        for class in CLASSES {
            let address = Address::new([9; 31], class);
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
            let err = Address::from_bytes(bytes).unwrap_err();
            assert_eq!(err.tag, tag);
            // The same refusal on the wire: an address a decoder cannot
            // classify is not an address it accepts and classifies later.
            assert!(from_slice::<Address>(&bytes).is_err());
        }
    }

    #[test]
    fn a_zeroed_address_fails_closed() {
        assert!(Address::from_bytes([0; 32]).is_err());
    }

    #[test]
    fn a_global_address_is_its_bytes_on_the_wire() {
        let address = Address::new([5; 31], Resource);
        let encoded = to_vec(&address).unwrap();
        assert_eq!(encoded, address.to_bytes());
        assert_eq!(encoded.len(), 32);
        assert_eq!(from_slice::<Address>(&encoded).unwrap(), address);
        assert_canonical(&address);
    }

    #[test]
    fn a_typed_address_refuses_every_other_class() {
        let principal = Address::new([1; 31], Principal);
        assert_eq!(
            PrincipalAddr::try_from(principal).unwrap().address(),
            principal
        );
        let err = ComponentAddr::try_from(principal).unwrap_err();
        assert_eq!(err.expected, Component);
        assert_eq!(err.found, Principal);

        for class in CLASSES {
            let address = Address::new([2; 31], class);
            assert_eq!(PrincipalAddr::try_from(address).is_ok(), class == Principal);
        }
    }

    #[test]
    fn a_typed_constructor_carries_its_own_class() {
        assert_eq!(PrincipalAddr::new([8; 31]).address().class(), Principal);
        assert_eq!(ComponentAddr::new([8; 31]).address().class(), Component);
        assert_eq!(PackageAddr::new([8; 31]).address().class(), Package);
        assert_eq!(ResourceAddr::new([8; 31]).address().class(), Resource);
        assert_eq!(NativeAddr::new([8; 31]).address().class(), Native);
        // The body is the constructor's argument and the tag is the
        // constructor's choice, so the two cannot disagree.
        assert_eq!(ResourceAddr::new([8; 31]).body(), [8; 31]);
        assert_eq!(
            ResourceAddr::new([8; 31]).to_bytes(),
            Address::new([8; 31], Resource).to_bytes()
        );
    }

    #[test]
    fn a_typed_address_equals_the_untyped_one_it_narrows() {
        let native = NativeAddr::new([0x5A; 31]);
        assert_eq!(native, native.address());
        assert_eq!(native.address(), native);
        assert_ne!(native, Address::new([0x5A; 31], Resource));
        let position = ResourceRef::from(native);
        assert_eq!(position, native.address());
        assert_eq!(native.address(), position);
    }

    #[test]
    fn a_call_target_admits_the_classes_that_answer_calls() {
        let principal = Address::new([1; 31], Principal);
        let component = Address::new([2; 31], Component);
        assert_eq!(
            CallTarget::try_from(principal),
            Ok(CallTarget::Principal(PrincipalAddr::new([1; 31])))
        );
        assert_eq!(
            CallTarget::try_from(component),
            Ok(CallTarget::Component(ComponentAddr::new([2; 31])))
        );
        for class in [Package, Resource, Native] {
            let err = CallTarget::try_from(Address::new([3; 31], class)).unwrap_err();
            assert_eq!(err.found, class);
        }
        // The position forgets its narrowing on the way back out.
        assert_eq!(
            CallTarget::try_from(component).unwrap().address(),
            component
        );
        assert_eq!(CallTarget::try_from(component).unwrap().class(), Component);
    }

    #[test]
    fn a_resource_reference_admits_the_classes_that_name_supply() {
        for class in [Resource, Native] {
            let address = Address::new([4; 31], class);
            let resource = ResourceRef::try_from(address).unwrap();
            assert_eq!(resource.address(), address);
            assert_eq!(resource.class(), class);
        }
        for class in [Principal, Component, Package] {
            let err = ResourceRef::try_from(Address::new([4; 31], class)).unwrap_err();
            assert_eq!(err.found, class);
        }
    }

    #[test]
    fn a_position_is_its_address_bytes_on_the_wire() {
        let target = CallTarget::Component(ComponentAddr::new([6; 31]));
        let encoded = to_vec(&target).unwrap();
        assert_eq!(encoded, target.address().to_bytes());
        assert_eq!(from_slice::<CallTarget>(&encoded).unwrap(), target);
        assert_canonical(&target);

        let resource = ResourceRef::Native(NativeAddr::new([7; 31]));
        assert_eq!(to_vec(&resource).unwrap(), resource.address().to_bytes());
        assert_canonical(&resource);
    }

    #[test]
    fn a_class_a_position_refuses_is_refused_at_decode() {
        // A package answers no calls, so a target naming one is not a
        // target a reader accepts and rejects afterwards.
        let package = to_vec(&Address::new([9; 31], Package)).unwrap();
        assert!(matches!(
            from_slice::<CallTarget>(&package),
            Err(DecodeError::InvalidDiscriminant(tag)) if tag == Package.tag()
        ));
        assert!(matches!(
            from_slice::<ResourceRef>(&package),
            Err(DecodeError::InvalidDiscriminant(tag)) if tag == Package.tag()
        ));
        // And so is a class the position does admit, read as another.
        assert!(from_slice::<ResourceAddr>(&package).is_err());
        assert_eq!(
            from_slice::<PackageAddr>(&package).unwrap(),
            PackageAddr::new([9; 31])
        );
    }
}

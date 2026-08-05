//! The address space state lives in.

use core::fmt;

use hyperscale_hbor::Hbor;

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

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{assert_canonical, to_vec};

    use super::{Address, LocalKey, SubstateKey};

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
}

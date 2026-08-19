//! What a proof carries.
//!
//! An authority verdict is a comparison, and this is the thing compared:
//! the claim a gate mints and a rule names. Three cases, because the
//! system has three — a target acting as itself, a fungible badge held
//! in some amount, and one named instance of a non-fungible one — and a
//! claim that flattened them to an address could not tell two holders of
//! one badge resource apart.
//!
//! A claim is never caller-supplied. Every one is minted by a gate that
//! read state to verify it, resolved at admission from what the target's
//! own declaration names, so widening what a proof says widens nothing
//! about who may say it.

use hyperscale_hbor::Hbor;
use hyperscale_vm_types::{Address, CallTarget, ResourceAddr};

use crate::types::Value;

/// A claim a proof carries and a rule names.
///
/// Each case carries the narrowed address its meaning requires — an
/// identity is something callable, a badge is a resource — so a claim
/// pairing a case with the wrong class is unrepresentable, and a decoder
/// meeting one fails closed rather than admitting a comparison no gate
/// could ever mint one side of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum Presented {
    /// An account or component acting as itself.
    Identity(CallTarget),
    /// A fungible badge the holder holds some of.
    Resource(ResourceAddr),
    /// One named instance of a non-fungible badge.
    Instance(ResourceAddr, u64),
}

impl Presented {
    /// The claim a declared expression's value makes, or `None` for a
    /// value that names no claim at all.
    ///
    /// Unambiguous on the address cases because a resource is never an
    /// acting identity: [`CallTarget`] refuses a resource, so the only
    /// thing minting a target's own address mints a component or a
    /// principal. Which case an expression yields is therefore a
    /// property of the address it evaluates to, not of the site that
    /// evaluated it — a gate naming a configured resource address wants
    /// the badge, and says so by naming it. An address that is neither
    /// callable nor a resource — a package, a protocol role — names no
    /// claim: no gate mints one, so a rule naming one could never be
    /// satisfied anyway, and refusing it at the naming is the honest
    /// spelling of that.
    ///
    /// [`CallTarget`]: hyperscale_vm_types::CallTarget
    #[must_use]
    pub fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Address(address) => Self::of_address(*address),
            Value::Tuple(fields) => match fields.as_slice() {
                [Value::Address(resource), Value::U64(id)] => ResourceAddr::try_from(*resource)
                    .ok()
                    .map(|resource| Self::Instance(resource, *id)),
                _ => None,
            },
            _ => None,
        }
    }

    /// The claim one address makes: a resource is a badge, a callable
    /// address is something acting as itself, and any other class names
    /// no claim.
    #[must_use]
    pub fn of_address(address: Address) -> Option<Self> {
        if let Ok(resource) = ResourceAddr::try_from(address) {
            return Some(Self::Resource(resource));
        }
        CallTarget::try_from(address).ok().map(Self::Identity)
    }

    /// The resource or identity the claim is about, whichever it is.
    #[must_use]
    pub const fn address(&self) -> Address {
        match self {
            Self::Identity(target) => target.address(),
            Self::Resource(resource) | Self::Instance(resource, _) => resource.address(),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass, CallTarget, ResourceAddr};

    use super::Presented;
    use crate::types::{EdgeContent, Value};

    fn address(byte: u8, class: AddressClass) -> Address {
        Address::new([byte; 31], class)
    }

    /// Which claim an expression names is a property of the address it
    /// evaluates to, not of the gate that evaluated it: a resource is a
    /// badge wherever it appears, and nothing else can be one. So a
    /// guarded gate over a configured resource slot requires the badge
    /// — which is what a custodial method mints, and how the two meet.
    #[test]
    fn the_claim_an_address_names_is_read_off_its_class() {
        let badge = address(0xB0, AddressClass::Resource);
        assert_eq!(
            Presented::of(&Value::Address(badge)),
            Some(Presented::Resource(
                ResourceAddr::try_from(badge).expect("a resource address"),
            ))
        );

        for class in [AddressClass::Principal, AddressClass::Component] {
            let who = address(0x11, class);
            assert_eq!(
                Presented::of(&Value::Address(who)),
                Some(Presented::Identity(
                    CallTarget::try_from(who).expect("a callable address"),
                ))
            );
        }

        // An address that is neither callable nor a resource names no
        // claim: no gate can mint one, so a rule naming one could never
        // be satisfied — refused at the naming instead.
        for class in [AddressClass::Package, AddressClass::Native] {
            let who = address(0x11, class);
            assert_eq!(Presented::of(&Value::Address(who)), None);
        }
    }

    /// A resource and an id name one instance of that resource. The
    /// pair is the only shape that does: an id beside anything else is
    /// two values, not a claim.
    #[test]
    fn a_resource_and_an_id_name_one_instance() {
        let badge = address(0xB0, AddressClass::Resource);
        assert_eq!(
            Presented::of(&Value::Tuple(vec![Value::Address(badge), Value::U64(7)])),
            Some(Presented::Instance(
                ResourceAddr::try_from(badge).expect("a resource address"),
                7,
            ))
        );

        // A non-resource with an id names nothing: only a resource has
        // instances.
        assert_eq!(
            Presented::of(&Value::Tuple(vec![
                Value::Address(address(0x11, AddressClass::Component)),
                Value::U64(7),
            ])),
            None
        );

        // Neither does a value that is not an address at all.
        for value in [
            Value::U64(7),
            Value::Bytes(vec![1]),
            Value::Tuple(vec![Value::Address(badge)]),
            Value::List(vec![Value::Address(badge)]),
            Value::Bucket {
                resource: badge,
                content: EdgeContent::Fungible,
            },
        ] {
            assert_eq!(Presented::of(&value), None, "{value:?}");
        }
    }
}

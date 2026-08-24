//! What a proof carries.
//!
//! An authority verdict is a comparison, and this is the thing compared:
//! the claim a gate mints and a rule names. One subject, and — where the
//! subject is a non-fungible badge — which instance of it, because a
//! claim that could not tell two holders of one badge apart would admit
//! either wherever it named one.
//!
//! What a subject *is* — an account acting as itself, a badge somebody
//! holds — is its address class's answer, read where a site needs it
//! rather than folded into an arm here. A claim that decided the kind at
//! construction made the same address mean different things depending on
//! which site built it, and the three spellings of `issued(Badge)` that
//! once meant three different things were what that cost.
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
/// Equality is the whole of judgment, so the shape is the whole of the
/// meaning: two claims are the same claim exactly when they name the same
/// subject and the same instance of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub struct Presented {
    /// Who or what the claim is about.
    pub subject: Address,
    /// Which instance of it, where the subject is a non-fungible badge
    /// and the claim is about one instance rather than any.
    pub instance: Option<u64>,
}

impl Presented {
    /// A claim about `subject` as a whole: an address acting as itself,
    /// or a badge held in any amount.
    #[must_use]
    pub fn of_subject(subject: impl Into<Address>) -> Self {
        Self {
            subject: subject.into(),
            instance: None,
        }
    }

    /// A claim about one named instance of a non-fungible badge.
    #[must_use]
    pub const fn of_instance(badge: ResourceAddr, id: u64) -> Self {
        Self {
            subject: badge.address(),
            instance: Some(id),
        }
    }

    /// The badge this claim names, where its subject is one.
    #[must_use]
    pub fn badge(&self) -> Option<ResourceAddr> {
        ResourceAddr::try_from(self.subject).ok()
    }

    /// The callable address this claim names, where its subject is one.
    #[must_use]
    pub fn callable(&self) -> Option<CallTarget> {
        CallTarget::try_from(self.subject).ok()
    }

    /// The claim a declared expression's value makes, or `None` for a
    /// value that names no claim at all.
    ///
    /// An address that is neither callable nor a resource — a package, a
    /// protocol role — names no claim: no gate mints one, so a rule
    /// naming one could never be satisfied anyway, and refusing it at the
    /// naming is the honest spelling of that.
    #[must_use]
    pub fn of(value: &Value) -> Option<Self> {
        match value {
            Value::Address(address) => Self::of_address(*address),
            Value::Tuple(fields) => match fields.as_slice() {
                [Value::Address(resource), Value::U64(id)] => ResourceAddr::try_from(*resource)
                    .ok()
                    .map(|badge| Self::of_instance(badge, *id)),
                _ => None,
            },
            _ => None,
        }
    }

    /// The claim one address makes, where it makes one.
    #[must_use]
    pub fn of_address(address: Address) -> Option<Self> {
        let names_something =
            ResourceAddr::try_from(address).is_ok() || CallTarget::try_from(address).is_ok();
        names_something.then(|| Self::of_subject(address))
    }

    /// The address the claim is about.
    #[must_use]
    pub const fn address(&self) -> Address {
        self.subject
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

    /// A claim names a subject, and what that subject *is* is its class's
    /// answer given where the question matters: a resource is a badge
    /// wherever it appears, and a callable address is something acting as
    /// itself. What the claim carries is the same either way, which is
    /// what keeps one spelling from meaning two things.
    #[test]
    fn the_claim_an_address_names_is_the_address_itself() {
        let badge = address(0xB0, AddressClass::Resource);
        let named = Presented::of(&Value::Address(badge)).expect("a resource names a badge");
        assert_eq!(named, Presented::of_subject(badge));
        assert_eq!(
            named.badge(),
            Some(ResourceAddr::try_from(badge).expect("a resource address"))
        );
        assert_eq!(named.callable(), None);

        for class in [AddressClass::Principal, AddressClass::Component] {
            let who = address(0x11, class);
            let named = Presented::of(&Value::Address(who)).expect("a callable names itself");
            assert_eq!(named, Presented::of_subject(who));
            assert_eq!(named.badge(), None);
            assert_eq!(
                named.callable(),
                Some(CallTarget::try_from(who).expect("a callable address"))
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
            Some(Presented::of_instance(
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
                resource: ResourceAddr::try_from(badge).expect("resource class"),
                content: EdgeContent::Fungible,
            },
        ] {
            assert_eq!(Presented::of(&value), None, "{value:?}");
        }
    }
}

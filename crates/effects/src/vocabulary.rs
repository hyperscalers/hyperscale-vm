//! The protocol's own names: the slots an engine derives keys for, and
//! the account method its own flows call.
//!
//! Nothing here belongs to a package. A package's slots, its caps and
//! the signatures its guest executes travel with the package; what is
//! left is the vocabulary every package is written in.
//!
//! A slot is vocabulary exactly when somebody who is **not its owner**
//! has to find it without being told. A fee burn finds a payer's vault, a
//! gate finds the rule governing an address, a sealed movement rule finds
//! whether the mover holds a badge, and the injected halt read finds a
//! holder's flag — in every case against an address whose code the reader
//! knows nothing about, so deriving the key is the only way to reach it.
//! That is what makes their values protocol facts, and what makes them
//! the band a package's own slots clear
//! ([`PACKAGE_SLOT_BASE`](crate::PACKAGE_SLOT_BASE)) rather than a table
//! every package adds a line to.
//!
//! The criterion cuts the other way just as sharply. A cell only its own
//! owner reaches is that package's, however protocol-shaped it looks —
//! which is why an account's quarantine is one of its own slots. And a
//! cell an *issuer* reaches under somebody else's prefix is not
//! vocabulary either: the issuer names the slot as a manifest argument,
//! so it is found because it was told rather than because it was
//! derived.

use crate::types::SlotId;

/// A fungible balance cell under its holder.
pub const VAULT: SlotId = SlotId(1);
/// A creation-fixed configuration leaf.
pub const CONFIG: SlotId = SlotId(2);
/// An account's stored authority: the cell `authorize` reads and
/// `securify` creates. Absent for a virtual account.
pub const AUTH: SlotId = SlotId(3);
/// A resource's record cell under its issuer: kind and display
/// quantization, keyed by the resource's own address.
pub const RESOURCE: SlotId = SlotId(4);
/// A holder's non-fungible instances: per resource, the entries of the
/// holder's `(NF_VAULT, resource)` sub-collection at the instance's id —
/// created at deposit, removed at withdrawal.
pub const NF_VAULT: SlotId = SlotId(5);
/// A non-fungible instance's data cell under its issuer, keyed by the
/// resource and the instance's id: written at mint, immutable after.
pub const INSTANCE: SlotId = SlotId(6);
/// A holder's halt flag for one resource, keyed by that resource:
/// present where the issuer has stopped them moving it, absent
/// otherwise.
///
/// The one piece of mutable state the behaviours need, and the reason it
/// is needed is that a sealed rule cannot change: freezing is a fact
/// about a holder at a moment, and the address commits facts about the
/// resource forever. Non-directional, because a halt stops both ways at
/// once.
///
/// One leaf per `(holder, resource)` rather than one collection per
/// holder. Asking whether a collection holds an entry is one seek either
/// way, so the read is not what decides it: a declaration over an
/// interval is priced by the span it excludes and conflicts with every
/// write to it, so one holder's unrelated resources would contend over a
/// fact about one of them.
pub const HALT: SlotId = SlotId(7);

/// The method a rest policy deposits through.
///
/// Every principal is answered by an account, so the four names below
/// are the ones a flow may assume without reading any package's
/// metadata. This is where value a composition did not route comes to
/// rest.
pub const DEPOSIT_METHOD: &str = "deposit";

/// The method that mints a principal's own identity as a claim.
///
/// What a composer reaches for when an injected entry names the party
/// signing the intent: the entry is the resource's, so nothing about the
/// method being called says a proof is wanted, and the claim has to come
/// from somewhere.
pub const AUTHORIZE_METHOD: &str = "authorize";

/// The method that mints a claim on a badge its caller holds.
pub const PRESENT_BADGE_METHOD: &str = "present-badge";

/// The same over one instance of a non-fungible badge.
pub const PRESENT_INSTANCE_METHOD: &str = "present-instance";

#[cfg(test)]
mod tests {
    use super::{AUTH, CONFIG, HALT, INSTANCE, NF_VAULT, RESOURCE, VAULT};
    use crate::types::PACKAGE_SLOT_BASE;

    /// The band, held from the one side that can drift.
    ///
    /// The other two bands hold themselves: a package's slots are built
    /// by [`package_slot`](crate::types::package_slot) and cannot land
    /// below the base by construction, and the kernel's are held by a
    /// `const` assertion at each definition. The vocabulary is written
    /// out by hand, so it is the one a careless value could widen into
    /// the band every package numbers from.
    #[test]
    fn the_protocol_vocabulary_stays_under_the_package_band() {
        for slot in [VAULT, CONFIG, AUTH, RESOURCE, NF_VAULT, INSTANCE, HALT] {
            assert!(
                slot.0 < PACKAGE_SLOT_BASE,
                "{slot:?} reaches into the band packages number from"
            );
        }
    }
}

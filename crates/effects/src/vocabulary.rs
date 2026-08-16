//! The protocol's own names: the roles an engine derives keys for, and
//! the native roles an address can carry.
//!
//! Nothing here belongs to a package. A package's roles, its caps and
//! the signatures its guest executes travel with the package; what is
//! left is the vocabulary every package is written in.
//!
//! These are the cells an engine finds without consulting any metadata —
//! a fee burn finds a payer's vault, an auth gate finds a stored rule,
//! the resource surface finds a record and a holder's instances. That is
//! what makes their values protocol facts, and what makes them the band
//! a package's own roles clear
//! ([`PACKAGE_ROLE_BASE`](crate::PACKAGE_ROLE_BASE)) rather than a table
//! every package adds a line to.

use crate::types::{NativeRole, RoleId};

/// The native fee and transfer resource.
pub const XRD: NativeRole = NativeRole(1);
/// The publisher the protocol's own packages sit under.
pub const GENESIS_PUBLISHER: NativeRole = NativeRole(2);

/// A fungible balance cell under its holder.
pub const VAULT: RoleId = RoleId(1);
/// The guaranteed-delivery fallback cell beside a vault.
pub const CLAIMS: RoleId = RoleId(2);
/// A creation-fixed configuration leaf.
pub const CONFIG: RoleId = RoleId(3);
/// An account's stored authority: the cell `authorize` reads and
/// `securify` creates. Absent for a virtual account.
pub const AUTH: RoleId = RoleId(4);
/// A resource's record cell under its issuer: kind and display
/// quantization, keyed by the resource's own address.
pub const RESOURCE: RoleId = RoleId(5);
/// A holder's non-fungible instances: per resource, the entries of the
/// holder's `(NF_VAULT, resource)` sub-collection at the instance's id —
/// created at deposit, removed at withdrawal.
pub const NF_VAULT: RoleId = RoleId(6);
/// A non-fungible instance's data cell under its issuer, keyed by the
/// resource and the instance's id: written at mint, immutable after.
pub const INSTANCE: RoleId = RoleId(7);

/// The entry cap a holdings interval declares: enough for every id one
/// edge can carry, since [`MAX_IDS_PER_EDGE`](crate::types::MAX_IDS_PER_EDGE)
/// fits it.
pub const NF_MOVE_CAP: u32 = 64;

#[cfg(test)]
mod tests {
    use super::{AUTH, CLAIMS, CONFIG, INSTANCE, NF_VAULT, RESOURCE, VAULT};
    use crate::types::PACKAGE_ROLE_BASE;

    /// The band, held from the one side that can drift.
    ///
    /// The other two bands hold themselves: a package's roles are built
    /// by [`package_role`](crate::types::package_role) and cannot land
    /// below the base by construction, and the kernel's are held by a
    /// `const` assertion at each definition. The vocabulary is written
    /// out by hand, so it is the one a careless value could widen into
    /// the band every package numbers from.
    #[test]
    fn the_protocol_vocabulary_stays_under_the_package_band() {
        for role in [VAULT, CLAIMS, CONFIG, AUTH, RESOURCE, NF_VAULT, INSTANCE] {
            assert!(
                role.0 < PACKAGE_ROLE_BASE,
                "{role:?} reaches into the band packages number from"
            );
        }
    }
}

//! Where a recall reaches: any slot a holder keeps value at, in either
//! shape the value takes.
//!
//! The gate is total over slots on purpose. A package holds value at
//! whatever slot of its own it likes, so a reach that could only name
//! the vocabulary's vault would stop at the first deposit into any
//! application — which is the hole the whole design exists to close.
//! What keeps a caller-chosen slot safe is that a value cell is keyed
//! by what it holds, so naming a slot cannot name a cell holding
//! something else, and that a slot naming no value is refused where the
//! argument is evaluated.
//!
//! Both cell shapes, because a balance and a holding are one authority
//! over two representations: a fungible balance is one leaf, and
//! instances are the entries of an interval.

use hyperscale_vm_effects::vocabulary::NF_VAULT;
use hyperscale_vm_effects::{TestHasher, package_slot};
use hyperscale_vm_fixtures::security;
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{Address, Chain, PrincipalAddr, account, package, principal};

/// Whom both fixtures' entries name.
const WARDEN: PrincipalAddr = principal(0xB1);
/// Who holds what is taken back.
const HOLDER: PrincipalAddr = principal(0xB2);
/// Somebody no entry names.
const STRANGER: PrincipalAddr = principal(0xB3);

/// A non-fungible whose instances its issuer can take back, so the
/// interval form of the reach has something to be about.
#[blueprint]
mod bailiff {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Ids, NfBucket, recall_instances};

    /// One instance per deed, which is what makes revocation
    /// holder-by-holder rather than a balance nobody can tell apart.
    #[resource(non_fungible, grants(mint = self, recall = warden))]
    struct Deed;

    /// Who may take one back. An identity rather than a badge, so the
    /// answer is frozen for the life of the resource.
    #[config]
    struct Terms {
        warden: Address,
    }

    #[state]
    struct Bailiff {}

    impl Bailiff {
        /// Issue the deed at `id`.
        pub fn issue(&mut self, id: u64) -> NfBucket {
            Deed::mint(id)
        }

        /// Take the deeds `ids` names out of the interval `holder`
        /// keeps them in at `slot`.
        ///
        /// The interval carries no cap of its own: what the walk costs
        /// is the count of the ids this call names, which is the same
        /// derivation a holder's own withdrawal makes.
        pub fn seize(&mut self, holder: Address, slot: u64, ids: Ids) -> NfBucket {
            recall_instances(holder, slot, Deed::address(), ids)
        }
    }
}

const fn deed_terms() -> bailiff::Terms {
    bailiff::Terms {
        warden: WARDEN.address(),
    }
}

/// A world where the holder keeps three deeds.
fn deeds() -> (Chain, bailiff::client::Bailiff, Address) {
    let mut chain = Chain::native();
    chain.publish(package!(bailiff));
    let issuer = chain.instantiate::<bailiff::client::Bailiff>(WARDEN, deed_terms());
    let deed = issuer.issued_deed(&TestHasher, deed_terms());
    for id in [1u64, 2, 3] {
        chain
            .transact(WARDEN, |b| {
                let minted = issuer.issue(b, id)?;
                account::deposit_nf(b, HOLDER, minted)
            })
            .expect_completed();
    }
    (chain, issuer, deed.into())
}

/// Instances leave a holder's interval the same way a balance leaves
/// their vault: named by the issuer, admitted by the resource's own
/// entry, and with the holder neither consulted nor able to decline.
#[test]
fn a_recall_takes_the_instances_it_names_out_of_a_holders_interval() {
    let (mut chain, issuer, deed) = deeds();
    let slot = u64::from(NF_VAULT.0);

    chain
        .transact(WARDEN, |b| {
            let taken = issuer.seize(b, HOLDER.address(), slot, &[1, 3])?;
            account::deposit_nf(b, WARDEN, taken)
        })
        .expect_completed();

    assert!(!chain.holds(HOLDER, deed, 1));
    assert!(chain.holds(HOLDER, deed, 2), "only what was named left");
    assert!(!chain.holds(HOLDER, deed, 3));
    assert!(chain.holds(WARDEN, deed, 1) && chain.holds(WARDEN, deed, 3));
}

/// And nobody the entry does not name takes anything.
///
/// Refused before anything routes rather than at the node: the composer
/// reads the entry off the record it found, cannot mint the claim it
/// names — the deed's warden is somebody else — and composes no proof,
/// so the call reaches admission asking for authority it never showed.
#[test]
fn a_recall_by_somebody_the_entry_does_not_name_is_refused() {
    let (mut chain, issuer, deed) = deeds();
    let slot = u64::from(NF_VAULT.0);

    let refused = chain
        .try_transact(STRANGER, |b| {
            let taken = issuer.seize(b, HOLDER.address(), slot, &[1])?;
            account::deposit_nf(b, STRANGER, taken)
        })
        .err()
        .expect("a reach nobody admitted");
    let refusal = format!("{refused:?}");
    assert!(
        refusal.contains("MissingEvidence"),
        "the resource's own entry is what admits a reach: {refusal}",
    );
    assert!(chain.holds(HOLDER, deed, 1), "and the deed stands");
}

/// A slot that keeps no value is nobody's to reach.
///
/// The one place the per-slot shape table's judgment is restated: the
/// table has its footing in the slot being a constant, and a slot an
/// argument names has none, so what it may reach is held to the cells
/// value is kept at. A record, a configuration leaf, a governing rule
/// and a halt flag hold facts, and a recall entry says nothing about
/// any of them.
#[test]
fn a_slot_that_keeps_no_value_is_refused_where_the_argument_is_read() {
    let (mut chain, issuer, deed) = deeds();

    for slot in [0u64, 2, 3, 4, 6, 7, 0xFFFE] {
        let refused = chain.try_transact(WARDEN, |b| {
            let taken = issuer.seize(b, HOLDER.address(), slot, &[1])?;
            account::deposit_nf(b, WARDEN, taken)
        });
        let refusal = format!("{:?}", refused.err().expect("a slot nothing reaches"));
        assert!(
            refusal.contains("UnreachableSlot"),
            "slot {slot} keeps no value, and that is the refusal: {refusal}",
        );
    }
    assert!(chain.holds(HOLDER, deed, 1));
}

const fn share_terms() -> security::Terms {
    security::Terms {
        registrar: WARDEN.address(),
    }
}

/// A holder who put the resource aside is still reachable, at the slot
/// they put it aside in.
///
/// The account's quarantine is one of its own package slots, and it is
/// exactly the case a reach naming only the vocabulary's vault would
/// miss: the value is under the holder's prefix, in a cell the
/// protocol derives no key for, and the issuer finds it because the
/// caller says which slot rather than because anybody enumerated one.
#[test]
fn a_recall_finds_value_at_the_slot_the_holder_keeps_it_in() {
    let mut chain = Chain::native();
    chain.publish(package!(security));
    let issuer = chain.instantiate::<security::Security>(WARDEN, share_terms());
    let share = issuer.issued_share(&TestHasher, share_terms());

    // Both parties on the register, since the share class asks the
    // register about the party each movement is under — the recall
    // included, once the value is back in the warden's own hands.
    for who in [WARDEN, HOLDER] {
        chain
            .transact(WARDEN, |b| {
                let warden = account::authorize(b, WARDEN)?;
                let entry = issuer.register(b, warden)?;
                account::deposit(b, who, entry)
            })
            .expect_completed();
    }
    // The holder decides they do not want it, so the deposit lands in
    // the account's own quarantine rather than in the vault.
    chain
        .transact(HOLDER, |b| {
            let holder = account::authorize(b, HOLDER)?;
            account::refuse(b, holder, share)
        })
        .expect_completed();
    chain
        .transact(WARDEN, |b| {
            let shares = issuer.issue(b, 60u128)?;
            account::deposit(b, HOLDER, shares)
        })
        .expect_completed();
    assert_eq!(chain.balance(HOLDER, share), 0, "the vault took none of it");

    let quarantine = u64::from(package_slot(1).0);
    chain
        .transact(WARDEN, |b| {
            let taken = issuer.recall_shares(b, HOLDER.address(), quarantine, 60u128)?;
            account::deposit(b, WARDEN, taken)
        })
        .expect_completed();
    assert_eq!(chain.balance(WARDEN, share), 60);
}

//! Where a recall reaches: any slot a holder keeps value at.
//!
//! The gate is total over slots on purpose. A package holds value at
//! whatever slot of its own it likes, so a reach that could only name
//! the vocabulary's vault would stop at the first deposit into any
//! application — which is the hole the whole design exists to close.
//! What keeps a caller-chosen slot safe is that a value cell is keyed
//! by what it holds, so naming a slot cannot name a cell holding
//! something else, and that a slot naming no value is refused where the
//! argument is evaluated.

use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::vocabulary::NF_VAULT;
use hyperscale_vm_testing::{
    Address, AdmissionError, Chain, EvalError, PrincipalAddr, Refused, Worlds, account, package,
    principal,
};

/// Whom the bailiff's entry names.
const WARDEN: PrincipalAddr = principal(0xB1);
/// Who holds what is taken back.
const HOLDER: PrincipalAddr = principal(0xB2);
/// Somebody no entry names.
const STRANGER: PrincipalAddr = principal(0xB3);

/// A non-fungible whose instances its issuer can take back, so the
/// interval form of the reach has something to be about.
///
/// Written here rather than as a guest of its own, and so running on
/// the native lane alone: a wasm artifact is built from a crate's
/// library, and a `#[blueprint]` in a test file is not in one.
#[blueprint]
mod bailiff {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Ids, NfBucket};

    /// One instance per deed, which is what makes revocation
    /// holder-by-holder rather than a balance nobody can tell apart.
    #[resource(non_fungible, grants(mint = self, recall = config.warden))]
    struct Deed;

    /// Who may take one back. An identity rather than a badge, so the
    /// answer is fixed for the life of the resource.
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
        pub fn recall(&mut self, holder: Address, slot: u64, ids: Ids) -> NfBucket {
            Deed::recall(holder, slot, ids)
        }
    }
}

const fn deed_terms() -> bailiff::client::Terms {
    bailiff::client::Terms {
        warden: WARDEN.address(),
    }
}

/// A world where the holder keeps three deeds.
fn deeds(chain: &mut Chain) -> (bailiff::client::Bailiff, Address) {
    static WORLDS: Worlds<(bailiff::client::Bailiff, Address)> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(bailiff));
        let issuer = chain.instantiate::<bailiff::client::Bailiff>(WARDEN, deed_terms());
        let deed = chain.issued(issuer, bailiff::client::Deed);
        for id in [1u64, 2, 3] {
            chain
                .transact(WARDEN, |b| {
                    let minted = issuer.issue(b, id)?;
                    account::deposit_nf(b, HOLDER, minted)
                })
                .expect_completed();
        }
        (issuer, deed.into())
    })
}

/// Instances leave a holder's interval the same way a balance leaves
/// their vault: named by the issuer, admitted by the resource's own
/// entry, and with the holder neither consulted nor able to decline.
#[hyperscale_vm_testing::test(native)]
fn a_recall_takes_the_instances_it_names_out_of_a_holders_interval(chain: &mut Chain) {
    let (issuer, deed) = deeds(chain);
    let slot = u64::from(NF_VAULT.0);

    chain
        .transact(WARDEN, |b| {
            let taken = issuer.recall(b, HOLDER.address(), slot, &[1, 3])?;
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
#[hyperscale_vm_testing::test(native)]
fn a_recall_by_somebody_the_entry_does_not_name_is_refused(chain: &mut Chain) {
    let (issuer, deed) = deeds(chain);
    let slot = u64::from(NF_VAULT.0);

    let refused = chain
        .try_transact(STRANGER, |b| {
            let taken = issuer.recall(b, HOLDER.address(), slot, &[1])?;
            account::deposit_nf(b, STRANGER, taken)
        })
        .expect_err("a reach nobody admitted");
    assert!(
        matches!(
            refused,
            Refused::Admission(AdmissionError::MissingEvidence { .. })
        ),
        "the resource's own entry is what admits a reach: {refused:?}",
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
#[hyperscale_vm_testing::test(native)]
fn a_slot_that_keeps_no_value_is_refused_where_the_argument_is_read(chain: &mut Chain) {
    let (issuer, deed) = deeds(chain);

    for slot in [
        0u64, 2, 3, 4, 6, 7, 0xFFF7, 0xFFF8, 0xFFF9, 0xFFFA, 0xFFFB, 0xFFFC, 0xFFFD, 0xFFFE,
    ] {
        let refused = chain.try_transact(WARDEN, |b| {
            let taken = issuer.recall(b, HOLDER.address(), slot, &[1])?;
            account::deposit_nf(b, WARDEN, taken)
        });
        let refused = refused.expect_err("a slot nothing reaches");
        assert!(
            matches!(
                refused,
                Refused::Admission(AdmissionError::Eval {
                    source: EvalError::UnreachableSlot { .. },
                    ..
                })
            ),
            "slot {slot} keeps no value, and that is the refusal: {refused:?}",
        );
    }
    assert!(chain.holds(HOLDER, deed, 1));
}

//! Per-transfer approval: an entry that asks about the transaction
//! rather than about the holder.
//!
//! Both questions a movement entry can ask are about the same badge or
//! address, and which one it asks is what the subject makes answerable.
//! **A resource can be held**, so naming one asks a standing fact about
//! the party whose cell moves — a register, read as one leaf under their
//! own prefix with nothing about the caller consulted. **An identity
//! cannot be held**, so naming one asks the only other question there
//! is: did this transaction carry a claim on it.
//!
//! No second spelling says which. The address class answers it, the same
//! reading every other declared address gets — which is why an issuer
//! writes one derivation and a reader of the address learns which
//! posture it committed to.
//!
//! The custodian is the party under test, as it is wherever the movement
//! seam is: it declares no rule, no gate and no approval, and it is
//! bound anyway. What it holds is the security package's `Approved`
//! class, whose `withdraw` and `deposit` entries name the registrar's
//! identity — the per-transfer posture, beside the standing register its
//! `Share` class is.

use custodian_guest::custodian;
use hyperscale_vm_testing::{
    AdmissionError, Chain, PrincipalAddr, Refused, ResourceAddr, Worlds, account, package,
    principal,
};
use security_guest::security;

/// Who the note's `withdraw` entry names.
const OFFICER: PrincipalAddr = principal(0xD1);
/// Who issued the note.
const ISSUER: PrincipalAddr = principal(0xD2);
/// Somebody the entry does not name.
const STRANGER: PrincipalAddr = principal(0xD3);

const fn terms() -> security::client::Terms {
    security::client::Terms {
        registrar: OFFICER.address(),
    }
}

/// A world where a custodian holds notes and cooperates with nothing.
fn world(chain: &mut Chain) -> (custodian::client::Custodian, ResourceAddr) {
    static WORLDS: Worlds<(custodian::client::Custodian, ResourceAddr)> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(security_guest::security));
        chain.publish(package!(custodian_guest::custodian));
        let issuer = chain.instantiate::<security::client::Security>(ISSUER, terms());
        let note = chain.issued(issuer, security::client::Approved);
        let keeper = chain.instantiate::<custodian::client::Custodian>(
            ISSUER,
            custodian::client::Terms {
                asset: note,
                other: note,
                instances: note,
            },
        );
        // Issued by the package that issues them and paid straight into the
        // custodian, which is a movement the registrar signs like any other
        // — the class asks about the transaction and this one is theirs.
        chain
            .transact(OFFICER, |b| {
                let minted = issuer.issue_approved(b, 100u128)?;
                keeper.deposit(b, minted)
            })
            .expect_completed();
        // The side a swap pays out of, seeded directly: no method of the
        // custodian's fills it.
        chain.fund(keeper, custodian::client::OtherTill, 50);
        (keeper, note)
    })
}

/// The desk's signature is what moves the note, out of a vault whose
/// package declares nothing about any of it.
///
/// Nothing here presents anything either. The entry is the note's own,
/// injected where the declaration is evaluated; the composer reads it
/// off the record it found and mints the claim it names, because the
/// party signing is the party the entry names.
#[hyperscale_vm_testing::test]
fn a_note_moves_in_a_transaction_the_desk_signed(chain: &mut Chain) {
    let (keeper, note) = world(chain);

    chain
        .transact(OFFICER, |b| {
            let funds = keeper.withdraw(b, 40u128)?;
            account::deposit(b, OFFICER, funds)
        })
        .expect_completed();

    assert_eq!(chain.balance(OFFICER, note), 40);
    assert_eq!(chain.balance_of(keeper, custodian::client::Till), 60);
}

/// A component's own vault answers for itself, so the desk's signature
/// is asked wherever the note sits.
///
/// The custodian's swap moves value between two of its own vaults with
/// no account in the transaction at all — the case a design that looked
/// at the caller would find a stranger at and bind nothing.
#[hyperscale_vm_testing::test]
fn the_question_follows_the_note_into_a_package_that_declares_nothing(chain: &mut Chain) {
    let (keeper, note) = world(chain);

    chain
        .transact(OFFICER, |b| {
            let funds = keeper.withdraw(b, 10u128)?;
            let back = keeper.swap(b, funds, 10u128)?;
            account::deposit(b, OFFICER, back)
        })
        .expect_completed();
    assert_eq!(chain.balance(OFFICER, note), 10);

    let refused = chain
        .try_transact(STRANGER, |b| {
            let funds = keeper.withdraw(b, 10u128)?;
            let back = keeper.swap(b, funds, 10u128)?;
            account::deposit(b, STRANGER, back)
        })
        .expect_err("a movement nobody approved");
    assert!(
        matches!(
            refused,
            Refused::Admission(AdmissionError::MissingEvidence { .. })
        ),
        "the note's own entry is what admits a movement: {refused:?}",
    );
    assert_eq!(chain.balance_of(keeper, custodian::client::Till), 100);
    assert_eq!(chain.balance_of(keeper, custodian::client::OtherTill), 40);
}

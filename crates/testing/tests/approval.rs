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
//! bound anyway.

use hyperscale_vm_effects::TestHasher;
use hyperscale_vm_fixtures::custodian;
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{
    Chain, Component, PrincipalAddr, ResourceAddr, account, package, principal,
};

/// Who the note's `withdraw` entry names.
const OFFICER: PrincipalAddr = principal(0xD1);
/// Who issued the note.
const ISSUER: PrincipalAddr = principal(0xD2);
/// Somebody the entry does not name.
const STRANGER: PrincipalAddr = principal(0xD3);

/// A note that moves only in a transaction the compliance desk signed.
#[blueprint]
mod desk {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// The asset. Its `withdraw` entry names an identity rather than a
    /// badge, so what it asks is per-transfer rather than standing: not
    /// "is the mover on a register" but "did the desk sign this".
    ///
    /// An issuer wanting a desk they can replace names their own
    /// component here — a rule naming an identity is frozen for the life
    /// of the resource, and a component's identity is frozen at the
    /// component rather than at whoever runs it.
    #[resource(grants(mint = self, withdraw = officer))]
    struct Note;

    /// Who signs off on a movement.
    #[config]
    struct Terms {
        officer: Address,
    }

    #[state]
    struct Desk {}

    impl Desk {
        /// Issue notes.
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Note::mint(amount)
        }
    }
}

const fn terms() -> desk::Terms {
    desk::Terms {
        officer: OFFICER.address(),
    }
}

/// A world where a custodian holds notes and cooperates with nothing.
fn world() -> (Chain, custodian::Custodian, ResourceAddr) {
    let mut chain = Chain::native();
    chain.publish(package!(desk));
    chain.publish(package!(custodian));
    let issuer = chain.instantiate::<desk::client::Desk>(ISSUER, terms());
    let note = issuer.issued_note(&TestHasher, terms());
    let keeper = chain.instantiate::<custodian::Custodian>(
        ISSUER,
        custodian::Terms {
            asset: note,
            other: note,
            instances: note,
        },
    );
    // Seeded rather than transferred in: how the notes got there is not
    // what the case is about, and a deposit would be a second movement
    // to reason about.
    chain.credit(keeper.address(), note, 100);
    (chain, keeper, note)
}

/// The desk's signature is what moves the note, out of a vault whose
/// package declares nothing about any of it.
///
/// Nothing here presents anything either. The entry is the note's own,
/// injected where the declaration is evaluated; the composer reads it
/// off the record it found and mints the claim it names, because the
/// party signing is the party the entry names.
#[test]
fn a_note_moves_in_a_transaction_the_desk_signed() {
    let (mut chain, keeper, note) = world();

    chain
        .transact(OFFICER, |b| {
            let funds = keeper.withdraw(b, 40u128)?;
            account::deposit(b, OFFICER, funds)
        })
        .expect_completed();

    assert_eq!(chain.balance(OFFICER, note), 40);
    assert_eq!(chain.balance(keeper.address(), note), 60);
}

/// And nobody else's does, however the transaction is composed.
///
/// The refusal lands at admission rather than in the leg: a claim reads
/// the node's own signed evidence and nothing else, so the stage that
/// holds the evidence is the stage that decides — before anything routes
/// and before any fee is assured.
#[test]
fn a_note_stands_still_for_anybody_the_entry_does_not_name() {
    let (mut chain, keeper, note) = world();

    let refused = chain
        .try_transact(STRANGER, |b| {
            let funds = keeper.withdraw(b, 40u128)?;
            account::deposit(b, STRANGER, funds)
        })
        .err()
        .expect("a movement nobody approved");
    let refusal = format!("{refused:?}");
    assert!(
        refusal.contains("MissingEvidence"),
        "the note's own entry is what admits a movement: {refusal}",
    );
    assert_eq!(chain.balance(keeper.address(), note), 100);
}

/// A component's own vault answers for itself, so the desk's signature
/// is asked wherever the note sits.
///
/// The custodian's swap moves value between two of its own vaults with
/// no account in the transaction at all — the case a design that looked
/// at the caller would find a stranger at and bind nothing.
#[test]
fn the_question_follows_the_note_into_a_package_that_declares_nothing() {
    let (mut chain, keeper, note) = world();

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
        .err()
        .expect("a movement nobody approved");
    assert!(format!("{refused:?}").contains("MissingEvidence"));
    assert_eq!(chain.balance(keeper.address(), note), 90);
}

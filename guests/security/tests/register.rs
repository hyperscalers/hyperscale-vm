//! The register, read the two ways it can be read: as a standing fact
//! about a holder, and as a claim on the transaction.
//!
//! The share class asks the first — `withdraw` and `deposit` name the
//! badge, so what a movement consults is one leaf under the moving
//! party's own prefix. The approved class asks the second, over the same
//! two entries with the subject swapped. Neither is spelled differently
//! by the package; what tells them apart is the subject's own address
//! class, which is the property this file exists for.

use hyperscale_vm_testing::{
    Chain, Outcome, Presence, PrincipalAddr, TestHasher, UnmetCondition, account, package,
    principal,
};
use security_guest::security;

/// Who keeps the register.
const REGISTRAR: PrincipalAddr = principal(0xA1);
/// A holder on it.
const HOLDER: PrincipalAddr = principal(0xA2);
/// Somebody who is not.
const STRANGER: PrincipalAddr = principal(0xA4);

const fn terms() -> security::client::Terms {
    security::client::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// One registered holder, holding shares of both classes.
fn world(mut chain: Chain) -> (Chain, security::client::Security) {
    chain.publish(package!(security_guest::security));
    let issuer = chain.instantiate::<security::client::Security>(REGISTRAR, terms());
    chain
        .transact(REGISTRAR, |b| {
            let entry = issuer.register(b, 1)?;
            account::deposit_nf(b, HOLDER, entry)
        })
        .expect_completed();
    chain
        .transact(REGISTRAR, |b| {
            let shares = issuer.issue(b, 100u128)?;
            account::deposit(b, HOLDER, shares)
        })
        .expect_completed();
    (chain, issuer)
}

/// A party the register does not name receives nothing.
///
/// `deposit = issued(Registered)` asks about the party whose cell is
/// credited, and the stranger holds no entry. What refuses is the
/// resource's own entry, injected onto the credit because the credit
/// moves it — the account declared nothing about any of this and the
/// sender's own side is never in question.
///
/// It lands at materialization rather than at admission, which is the
/// difference between the two subjects a movement entry can name: a
/// standing fact about a party is a leaf, read where leaves are read,
/// and a claim on a transaction is evidence, answered before anything
/// routes.
#[hyperscale_vm_testing::test]
fn a_share_reaches_nobody_the_register_does_not_name(chain: Chain) {
    let (mut chain, issuer) = world(chain);
    let share = issuer.issued_share(&TestHasher, terms());

    let refused = chain
        .try_transact(HOLDER, |b| {
            let moved = account::withdraw(b, HOLDER, share, 10u128)?;
            account::deposit(b, STRANGER, moved)
        })
        .expect("a party off the register is not a reason to refuse the manifest");
    assert!(
        matches!(
            refused.refused(),
            Some(Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Present,
                    ..
                }
            })
        ),
        "the register is a leaf, and the credit asks whether it is there: {refused:?}",
    );
    assert_eq!(chain.balance(STRANGER, share), 0);
    assert_eq!(chain.balance(HOLDER, share), 100, "and nothing moved");
}

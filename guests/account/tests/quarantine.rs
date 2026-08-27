//! The destination a recipient chooses, and the way back out of it.
//!
//! `deposit` is total — a sender composing a transfer never has to know
//! the recipient's mind — and what makes that affordable is that a
//! refused resource lands somewhere rather than being turned away. The
//! somewhere is the account's own quarantine, which is only a second
//! vault under a slot the protocol derives no key for, so nothing reads
//! it but the account and nothing empties it but its holder.
//!
//! Both cases are about that second door. A quarantine nobody could
//! open would be a burn with extra steps, and an `accept` that emptied
//! it would be a transfer the holder never composed.

use hyperscale_vm_testing::{Chain, PrincipalAddr, ResourceAddr, account, principal, resource};

/// Whoever is paying — an account that has refused nothing, so what
/// arrives back at it lands in the vault.
const SENDER: PrincipalAddr = principal(0x21);
/// The recipient with an opinion.
const HOLDER: PrincipalAddr = principal(0x22);
const ASSET: ResourceAddr = resource(0xA5);

/// Put `ASSET` aside from here on.
fn refuse(chain: &mut Chain) {
    chain
        .transact(HOLDER, |b| account::refuse(b, HOLDER, ASSET))
        .expect_completed();
}

/// Pay the holder `amount`, knowing nothing about any of this.
fn pay(chain: &mut Chain, amount: u128) {
    chain
        .transact(SENDER, |b| {
            let funds = account::withdraw(b, SENDER, ASSET, amount)?;
            account::deposit(b, HOLDER, funds)
        })
        .expect_completed();
}

/// What the quarantine holds comes back out, and it is the holder who
/// takes it out.
///
/// The whole of what makes a refused deposit a redirection rather than a
/// confiscation: the value is still the holder's, still spendable, and
/// what it takes to spend it is the gate a withdrawal already carries.
#[hyperscale_vm_testing::test]
fn a_quarantined_deposit_is_the_holder_s_to_spend(mut chain: Chain) {
    chain.credit(SENDER, ASSET, 100);
    refuse(&mut chain);
    pay(&mut chain, 100);
    assert_eq!(chain.balance(HOLDER, ASSET), 0, "the vault took none of it");
    assert_eq!(chain.balance(SENDER, ASSET), 0, "and the sender paid");

    chain
        .transact(HOLDER, |b| {
            let funds = account::sweep(b, HOLDER, ASSET, 100u128)?;
            account::deposit(b, SENDER, funds)
        })
        .expect_completed();
    assert_eq!(chain.balance(SENDER, ASSET), 100, "the holder sent it back");
}

/// Accepting says where the next deposit lands, and nothing about where
/// the last one went.
///
/// The two cells are independent destinations rather than a state
/// machine over one, so a holder who changes their mind has a vault
/// filling up and a quarantine still holding what arrived before they
/// did — and the only thing that moves the older half is a sweep the
/// holder composes.
#[hyperscale_vm_testing::test]
fn accepting_redirects_the_next_deposit_and_moves_no_earlier_one(mut chain: Chain) {
    chain.credit(SENDER, ASSET, 100);
    refuse(&mut chain);
    pay(&mut chain, 60);

    chain
        .transact(HOLDER, |b| account::accept(b, HOLDER, ASSET))
        .expect_completed();
    pay(&mut chain, 40);
    assert_eq!(
        chain.balance(HOLDER, ASSET),
        40,
        "the vault took the deposit after the change of mind, and only that one",
    );

    // The earlier sixty is still where it was put, and swept into the
    // holder's own hands it lands in the vault this time — same bucket,
    // same method, a destination that moved.
    chain
        .transact(HOLDER, |b| {
            let funds = account::sweep(b, HOLDER, ASSET, 60u128)?;
            account::deposit(b, HOLDER, funds)
        })
        .expect_completed();
    assert_eq!(chain.balance(HOLDER, ASSET), 100);
}

//! Reaching a holder's prefix: the halt flag written into it, and the
//! value taken out of it.
//!
//! One gate carries both, and what makes it worth having is which party
//! can opt out — under a holder-side fence the answer is every party
//! that is not an account, which is every application anybody deposits
//! into. So the issuer reaches the cell itself: a leaf under the
//! holder's prefix, admitted by the resource's own entry and by nothing
//! the holder said.
//!
//! The two halves are here together because they fail differently. A
//! freeze writes a flag every movement of the resource then reads, and
//! the refusal it earns lands before any body runs. A recall takes the
//! value, and what it has to survive is every rule the resource itself
//! carries — the halt fence among them, since the party being reached
//! is by construction the party each of those rules would refuse.

use hyperscale_vm_effects::TestHasher;
use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_fixtures::security;
use hyperscale_vm_testing::{
    Chain, Component, PrincipalAddr, ResourceAddr, account, package, principal,
};

/// Who keeps the register, and whom the share's `freeze` entry names.
const REGISTRAR: PrincipalAddr = principal(0xA1);
/// A holder on the register.
const HOLDER: PrincipalAddr = principal(0xA2);
/// A second registered holder, so a transfer has somewhere to go.
const OTHER: PrincipalAddr = principal(0xA3);

const fn terms() -> security::Terms {
    security::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// A world where both parties are on the register and the holder has
/// shares.
fn world() -> (Chain, security::Security, ResourceAddr) {
    let mut chain = Chain::native();
    chain.publish(package!(security));
    let issuer = chain.instantiate::<security::Security>(REGISTRAR, terms());
    let share = issuer.issued_share(&TestHasher, terms());

    for who in [HOLDER, OTHER] {
        chain
            .transact(REGISTRAR, |b| {
                let registrar = account::authorize(b, REGISTRAR)?;
                let entry = issuer.register(b, registrar)?;
                account::deposit(b, who, entry)
            })
            .expect_completed();
    }
    chain
        .transact(REGISTRAR, |b| {
            let shares = issuer.issue(b, 100u128)?;
            account::deposit(b, HOLDER, shares)
        })
        .expect_completed();
    (chain, issuer, share)
}

/// A registered holder moves the share class freely, and stops the
/// moment the issuer halts them.
///
/// The halt is written under the *holder's* prefix by a package the
/// holder never called, and read by a declaration the holder's account
/// never wrote. Neither party cooperated; both are bound.
#[test]
fn a_halt_stops_a_holder_who_was_moving_freely() {
    let (mut chain, issuer, share) = world();

    let transfer = |chain: &mut Chain| {
        chain.try_transact(HOLDER, |b| {
            let holder = account::authorize(b, HOLDER)?;
            let moved = account::withdraw(b, holder, share, 10u128)?;
            account::deposit(b, OTHER, moved)
        })
    };

    transfer(&mut chain)
        .expect("a registered holder moves it")
        .expect_completed();
    assert_eq!(chain.balance(HOLDER, share), 90);

    // Composed through the raw call: the requirement is the share's own
    // entry, injected at admission rather than declared, so the
    // package's signature says `freeze` admits anyone and its generated
    // client offers no proof-taking form. Attaching the proof is the
    // composer's until the builder resolves grants for itself.
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            b.call_as(registrar, issuer.address(), "freeze", (HOLDER.address(),))?
                .none()
        })
        .expect_completed();

    let refused = transfer(&mut chain);
    assert!(
        refused.is_err() || !refused.expect("a receipt").completed(),
        "a halted holder moves nothing, whatever they hold",
    );
    assert_eq!(chain.balance(HOLDER, share), 90, "and the balance stands");
}

/// Every rule the share class carries, and the recall reaching past all
/// of them.
///
/// One case rather than three, because dropping any one of these
/// silently disables a different issuer power and the others would go
/// on passing. A frozen holder is recalled from, so the halt fence does
/// not fence its own issuer; a holder off the register is recalled
/// from, so a resource nobody unregistered may move is still one the
/// registrar may take back; and the register entry itself is revoked,
/// which `withdraw = nobody` makes impossible any other way.
///
/// What makes all three work is one sentence: a declaration reaching a
/// foreign prefix carries no injected movement requirement at all. Each
/// of those requirements would fire against the party being reached,
/// who by construction fails it.
#[test]
fn a_recall_reaches_past_every_rule_the_resource_carries() {
    let (mut chain, issuer, share) = world();
    let entry = issuer.issued_registered(&TestHasher, terms());
    let slot = u64::from(VAULT.0);

    // A holder nobody registered, holding shares they could never move
    // themselves: `withdraw` names the register and they are not on it.
    let stranger = principal(0xA4);
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            let entry = issuer.register(b, registrar)?;
            account::deposit(b, stranger, entry)
        })
        .expect_completed();
    chain
        .transact(REGISTRAR, |b| {
            let shares = issuer.issue(b, 40u128)?;
            account::deposit(b, stranger, shares)
        })
        .expect_completed();
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            b.call_as(
                registrar,
                issuer.address(),
                "revoke",
                (stranger.address(), slot, 1u128),
            )?
            .one()
            .and_then(|taken| account::deposit(b, REGISTRAR, taken))
        })
        .expect_completed();
    assert_eq!(
        chain.balance(stranger, entry),
        0,
        "the entry is the register"
    );

    // And a holder the issuer has stopped moving anything at all.
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            b.call_as(registrar, issuer.address(), "freeze", (HOLDER.address(),))?
                .none()
        })
        .expect_completed();

    for (holder, taken) in [(HOLDER, 100u128), (stranger, 40u128)] {
        chain
            .transact(REGISTRAR, |b| {
                let registrar = account::authorize(b, REGISTRAR)?;
                b.call_as(
                    registrar,
                    issuer.address(),
                    "recall-shares",
                    (holder.address(), slot, taken),
                )?
                .one()
                .and_then(|shares| account::deposit(b, REGISTRAR, shares))
            })
            .expect_completed();
        assert_eq!(chain.balance(holder, share), 0);
    }
    assert_eq!(chain.balance(REGISTRAR, share), 140);
}

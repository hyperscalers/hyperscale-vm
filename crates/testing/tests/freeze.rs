//! Stopping a holder, through a cell the holder's own package never
//! declares.
//!
//! What a freeze has to be to be worth anything: not a flag a
//! cooperating account checks, but a leaf the issuer writes under the
//! holder's prefix and the protocol reads on every movement. The
//! difference is which party can opt out — and under a holder-side fence
//! the answer is every party that is not an account, which is every
//! application anybody deposits into.
//!
//! So the two halves are here together. The issuer reaches a prefix that
//! is not its own, admitted by the resource's own `freeze` entry and by
//! nothing the holder said; and the movement that is then refused is
//! refused before any body runs, because the read is a feasibility fact
//! rather than a gate.

use hyperscale_vm_effects::TestHasher;
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

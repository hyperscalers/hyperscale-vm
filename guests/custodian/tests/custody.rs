//! The instance half of a custodian: what it files, and what it hands
//! back.
//!
//! Here because a collection is keyed by what it holds. Filing under the
//! edge's own resource rather than the configured one opens a collection
//! nothing takes from — the value goes in, the declaration is sound, the
//! transaction completes, and nothing reaches it again. Only a round
//! trip catches that, which is why the round trip is the case.

use custodian_guest::custodian;
// The module takes an alias so the bare crate path stays what
// `package!` names.
use grammar_guest::grammar as shapes;
use hyperscale_vm_testing::{
    AbortReason, Chain, Component, PrincipalAddr, ResourceAddr, TestHasher, Worlds, account,
    package, principal, resource,
};

/// Who issues the seats this custodian keeps.
const ISSUER: PrincipalAddr = principal(0xC1);
/// Who hands them over and takes them back.
const HOLDER: PrincipalAddr = principal(0xC2);

/// The shapes package's configuration, of which only the seat matters
/// here: what a custodian holds is any instance an issuer can move.
fn shape_terms() -> shapes::client::Terms {
    shapes::client::Terms {
        tiers: hyperscale_vm_sdk::state::Table::new(vec![(1, 10), (2, 20)]),
        fallback: 7,
        sides: vec![principal(0x51).into(), principal(0x52).into()],
        windows: vec![1, 2],
        assets: vec![resource(0xE1), resource(0xE2)],
        marks: Vec::new(),
    }
}

/// A custodian configured for the seats, and a holder with one.
fn world(chain: &mut Chain) -> (custodian::client::Custodian, ResourceAddr) {
    static WORLDS: Worlds<(custodian::client::Custodian, ResourceAddr)> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(grammar_guest::grammar at "../grammar"));
        chain.publish(package!(custodian_guest::custodian));
        let issuer = chain.instantiate::<shapes::client::Grammar>(ISSUER, shape_terms());
        let seat = issuer.issued_seat(&TestHasher);
        let keeper = chain.instantiate::<custodian::client::Custodian>(
            ISSUER,
            custodian::client::Terms {
                asset: seat,
                other: seat,
                instances: seat,
            },
        );
        chain
            .transact(ISSUER, |b| {
                let minted = issuer.seat(b, 7, 0)?;
                account::deposit_nf(b, HOLDER, minted)
            })
            .expect_completed();
        (keeper, seat)
    })
}

/// What is filed comes back out.
///
/// The one property a custodian owes anybody, and the one its
/// declaration cannot state on its own: both halves have to open the
/// same collection, and which collection each opens is a key it
/// computes. `file` computing it from the edge and `release` from the
/// configuration is two collections, and the second is empty.
#[hyperscale_vm_testing::test]
fn instances_filed_with_a_custodian_come_back_out(chain: &mut Chain) {
    let (keeper, seat) = world(chain);
    assert!(chain.holds(HOLDER, seat, 7));

    chain
        .transact(HOLDER, |b| {
            let entry = account::withdraw_nf(b, HOLDER, seat, &[7])?;
            keeper.file(b, entry)
        })
        .expect_completed();
    assert!(
        !chain.holds(HOLDER, seat, 7),
        "the registration left the holder's own interval"
    );
    assert!(chain.holds(keeper.address(), seat, 7));

    chain
        .transact(HOLDER, |b| {
            let back = keeper.release(b, &[7])?;
            account::deposit_nf(b, HOLDER, back)
        })
        .expect_completed();
    assert!(
        chain.holds(HOLDER, seat, 7),
        "what the custodian filed is what it releases"
    );
    assert!(!chain.holds(keeper.address(), seat, 7));
}

/// A custodian configured for one resource does not file another.
///
/// The other half of keying `file` on the configuration: the collection
/// is keyed by what it holds, so an edge carrying anything else has
/// nowhere in this component to go. Keyed on the edge instead it would
/// have somewhere — a collection of its own, which `release` never
/// opens and nothing else ever reaches.
#[hyperscale_vm_testing::test]
fn a_custodian_files_nothing_it_was_not_configured_for(chain: &mut Chain) {
    let (_, seat) = world(chain);
    let other = chain.instantiate::<shapes::client::Grammar>(HOLDER, shape_terms());
    let elsewhere = chain.instantiate::<custodian::client::Custodian>(
        ISSUER,
        custodian::client::Terms {
            asset: other.issued_seat(&TestHasher),
            other: other.issued_seat(&TestHasher),
            instances: other.issued_seat(&TestHasher),
        },
    );
    assert_ne!(
        other.issued_seat(&TestHasher),
        seat,
        "two issuers issue two marks"
    );

    let filed = chain.try_transact(HOLDER, |b| {
        let entry = account::withdraw_nf(b, HOLDER, seat, &[7])?;
        elsewhere.file(b, entry)
    });
    // The graph admits — a declaration keyed by the edge's own resource
    // is sound — and the kernel is the door that refuses: the entry
    // arrives at a cell denominated in the configured seat, holding the
    // other issuer's.
    let outcome = filed.expect("the graph admits; the refusal is the kernel's");
    assert_eq!(
        outcome.aborted(),
        Some(AbortReason::WrongResource),
        "a seat this custodian does not custody has nowhere here to go"
    );
    assert!(chain.holds(HOLDER, seat, 7), "and stays where it was");
}

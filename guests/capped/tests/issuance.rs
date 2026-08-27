//! The three shapes issuance-as-a-rule makes expressible, run.
//!
//! Each is an absence or a rule rather than a mechanism of its own, so
//! what the cases have to establish is that the absence bites and the
//! rule reaches: a supply nothing may add to, a supply that only falls,
//! and a mint the issuer's own address cannot open.

use capped_guest::capped;
use hyperscale_vm_testing::{
    Address, AddressClass, AdmissionError, Chain, GrantedBehaviour, PrincipalAddr, Refused,
    ResourceAddr, TestHasher, Worlds, account, package, principal,
};

const FOUNDER: PrincipalAddr = principal(0x91);
/// Who the seat's `mint` entry names — an identity rather than this
/// package, which is the whole of what "delegated" means here.
const MINTER: PrincipalAddr = principal(0x92);

const fn terms() -> capped::client::Terms {
    capped::client::Terms {
        minter: MINTER.address(),
    }
}

fn world(chain: &mut Chain) -> capped::client::Capped {
    static WORLDS: Worlds<capped::client::Capped> = Worlds::new();
    WORLDS.open(chain, |chain| {
        chain.publish(package!(capped_guest::capped));
        chain.instantiate::<capped::client::Capped>(FOUNDER, terms())
    })
}

/// A component founds every resource its declaration states a supply
/// for, in the one call that makes it actual.
///
/// Two of them here, which is the case a single ambient grant could not
/// reach: the founder walks away holding both, and neither has an entry
/// admitting a later mint.
#[hyperscale_vm_testing::test]
fn a_bring_up_founds_every_supply_its_package_states(chain: &mut Chain) {
    let instance = world(chain);
    let fixed = instance.issued_founded(&TestHasher);
    let retired = instance.issued_retired(&TestHasher);

    assert_eq!(chain.balance(FOUNDER, fixed), 1_000_000);
    assert_eq!(chain.balance(FOUNDER, retired), 500);
    assert_eq!(
        chain.balance(FOUNDER, instance.issued_circulating(&TestHasher)),
        1_000
    );
}

/// Capped supply is an absent entry, and the address is where a holder
/// reads it.
///
/// Both of the founded resources grant no `Mint`, so nothing can add to
/// what creation put there — and neither is `Restricted`, because an
/// authority entry withholds a capability rather than stopping a
/// movement anyone could otherwise make.
#[hyperscale_vm_testing::test]
fn a_founded_supply_grants_no_mint_and_restricts_no_movement(chain: &mut Chain) {
    let instance = world(chain);
    let class = |resource: ResourceAddr| Address::from(resource).class();

    for resource in [
        instance.issued_founded(&TestHasher),
        instance.issued_retired(&TestHasher),
        instance.issued_circulating(&TestHasher),
        instance.issued_seat(&TestHasher, terms()),
    ] {
        assert_eq!(
            class(resource),
            AddressClass::Resource,
            "an authority entry leaves the class plain",
        );
    }
}

/// Burning without minting: the two entries are independent, so a
/// supply can be destroyed by an authority that could never create it.
#[hyperscale_vm_testing::test]
fn a_deflationary_supply_only_ever_falls(chain: &mut Chain) {
    let instance = world(chain);
    let retired = instance.issued_retired(&TestHasher);

    chain
        .transact(FOUNDER, |b| {
            let funds = account::withdraw(b, FOUNDER, retired, 200u128)?;
            instance.retire(b, funds)
        })
        .expect_completed();

    assert_eq!(chain.balance(FOUNDER, retired), 300);
}

/// Destroying is the holder's where minting is the issuer's: a resource
/// granting `burn` to anyone leaves existence through the holder's own
/// account, and the issuer is not a party to it.
///
/// What admits it is the resource's own entry, resolved from the record
/// the transaction presents — so the account, which declares nothing
/// about any resource, is bound by whatever the issuer wrote.
#[hyperscale_vm_testing::test]
fn a_holder_destroys_what_the_resource_lets_them(chain: &mut Chain) {
    let instance = world(chain);
    let circulating = instance.issued_circulating(&TestHasher);

    chain
        .transact(FOUNDER, |b| {
            let funds = account::withdraw(b, FOUNDER, circulating, 400u128)?;
            account::burn(b, FOUNDER, funds)
        })
        .expect_completed();

    assert_eq!(chain.balance(FOUNDER, circulating), 600);
}

/// And a resource granting no `Burn` entry is one nobody may destroy,
/// however they hold it.
///
/// The refusal is admission's rather than the account's: the account
/// declares the destruction and the resource declines it, which is the
/// same shape as a movement seam refusal read from the authority side.
#[hyperscale_vm_testing::test]
fn a_resource_granting_no_burn_is_indestructible(chain: &mut Chain) {
    let instance = world(chain);
    let fixed = instance.issued_founded(&TestHasher);

    let refused = chain.try_transact(FOUNDER, |b| {
        let funds = account::withdraw(b, FOUNDER, fixed, 1u128)?;
        account::burn(b, FOUNDER, funds)
    });
    assert!(
        matches!(
            refused,
            Err(Refused::Admission(AdmissionError::Unadmitted {
                behaviour: GrantedBehaviour::Burn,
                ..
            }))
        ),
        "no entry admits destroying a resource that grants no burn: {refused:?}",
    );
    assert_eq!(chain.balance(FOUNDER, fixed), 1_000_000);
}

/// Minting a seat is the configured minter's, and the issuer's own
/// address does not open it.
///
/// The whole of what "delegated" means: the rule names an identity, and
/// **nothing can present a claim on a component but that component** —
/// so the subtraction that lets an issuer mint its own supply does not
/// apply here, and the requirement reaches the call. The package's code
/// is the same code either way; what changed is who the entry names.
#[hyperscale_vm_testing::test]
fn a_seat_is_minted_by_whoever_the_entry_names(chain: &mut Chain) {
    let instance = world(chain);
    let seat = instance.issued_seat(&TestHasher, terms());

    chain
        .transact(MINTER, |b| {
            let minted = instance.issue(b, 40u128)?;
            account::deposit(b, MINTER, minted)
        })
        .expect_completed();
    assert_eq!(chain.balance(MINTER, seat), 40);
}

/// And nobody else's signature does, the founder's included.
///
/// The founder created the component and holds every founded supply;
/// what they do not hold is the seat's minting entry, which is a fact
/// about the resource rather than about the package that issues it.
#[hyperscale_vm_testing::test]
fn the_issuers_own_founder_cannot_spend_the_mint_it_delegated(chain: &mut Chain) {
    let instance = world(chain);
    let seat = instance.issued_seat(&TestHasher, terms());

    let refused = chain.try_transact(FOUNDER, |b| {
        let minted = instance.issue(b, 40u128)?;
        account::deposit(b, FOUNDER, minted)
    });
    assert!(
        matches!(
            refused,
            Err(Refused::Admission(AdmissionError::MissingEvidence { .. }))
        ),
        "the founder answers for nothing the seat's entry names: {refused:?}",
    );
    assert_eq!(chain.balance(FOUNDER, seat), 0);
}

/// A `burn` entry naming the issuer is not one a holder can spend.
///
/// The pair with `a_holder_destroys_what_the_resource_lets_them`: the
/// same operation, the same account, and the entry's subject is the
/// whole difference. `Circulating` names anyone and `Retired` names the
/// issuing instance, which no account can answer for.
#[hyperscale_vm_testing::test]
fn a_holder_destroys_nothing_whose_burn_names_its_issuer(chain: &mut Chain) {
    let instance = world(chain);
    let retired = instance.issued_retired(&TestHasher);

    let refused = chain.try_transact(FOUNDER, |b| {
        let funds = account::withdraw(b, FOUNDER, retired, 1u128)?;
        account::burn(b, FOUNDER, funds)
    });
    assert!(
        matches!(
            refused,
            Err(Refused::Admission(AdmissionError::MissingEvidence { .. }))
        ),
        "a burn the issuer keeps is not the holder's to make: {refused:?}",
    );
    assert_eq!(chain.balance(FOUNDER, retired), 500);
}

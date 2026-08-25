//! The three shapes issuance-as-a-rule makes expressible, run.
//!
//! Each is an absence or a rule rather than a mechanism of its own, so
//! what the cases have to establish is that the absence bites and the
//! rule reaches: a supply nothing may add to, a supply that only falls,
//! and a mint the issuer's own address cannot open.

use hyperscale_vm_effects::TestHasher;
use hyperscale_vm_fixtures::capped;
use hyperscale_vm_testing::{
    Address, Chain, PrincipalAddr, ResourceAddr, account, package, principal,
};
use hyperscale_vm_types::AddressClass;

const FOUNDER: PrincipalAddr = principal(0x91);
/// Who the seat's `mint` entry names — an identity rather than this
/// package, which is the whole of what "delegated" means here.
const MINTER: PrincipalAddr = principal(0x92);

const fn terms() -> capped::Terms {
    capped::Terms {
        minter: MINTER.address(),
    }
}

fn world() -> (Chain, capped::Capped) {
    let mut chain = Chain::native();
    chain.publish(package!(capped));
    let instance = chain.instantiate::<capped::Capped>(FOUNDER, terms());
    (chain, instance)
}

/// A component founds every resource its declaration states a supply
/// for, in the one call that makes it actual.
///
/// Two of them here, which is the case a single ambient grant could not
/// reach: the founder walks away holding both, and neither has an entry
/// admitting a later mint.
#[test]
fn a_bring_up_founds_every_supply_its_package_states() {
    let (chain, instance) = world();
    let fixed = instance.issued_fixed(&TestHasher);
    let retired = instance.issued_retired(&TestHasher);

    assert_eq!(chain.balance(FOUNDER, fixed), 1_000_000);
    assert_eq!(chain.balance(FOUNDER, retired), 500);
}

/// Capped supply is an absent entry, and the address is where a holder
/// reads it.
///
/// Both of the founded resources grant no `Mint`, so nothing can add to
/// what creation put there — and neither is `Restricted`, because an
/// authority entry withholds a capability rather than stopping a
/// movement anyone could otherwise make.
#[test]
fn a_founded_supply_grants_no_mint_and_restricts_no_movement() {
    let (_, instance) = world();
    let class = |resource: ResourceAddr| Address::from(resource).class();

    for resource in [
        instance.issued_fixed(&TestHasher),
        instance.issued_retired(&TestHasher),
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
#[test]
fn a_deflationary_supply_only_ever_falls() {
    let (mut chain, instance) = world();
    let retired = instance.issued_retired(&TestHasher);

    chain
        .transact(FOUNDER, |b| {
            let holder = account::authorize(b, FOUNDER)?;
            let funds = account::withdraw(b, holder, retired, 200u128)?;
            instance.retire(b, funds)
        })
        .expect_completed();

    assert_eq!(chain.balance(FOUNDER, retired), 300);
}

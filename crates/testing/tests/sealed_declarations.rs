//! A package seals its own resource's rules, so the tier has a minter.
//!
//! A sealed rule is folded into the address it governs: the resource a
//! body mints and the resource a client derives from the declaration are
//! the same address exactly when they agree about the rules, and a
//! package that changed one would be minting a different resource. What
//! makes that checkable here is that the declaration is the only source
//! — the gate that names the badge, the key of the vault it lands in and
//! the grant that mints it all read one registration.

use hyperscale_vm_effects::{
    Presented, ResourceKind, ResourceRules, RoleBytes, SealedBehaviour, StoredRule, TestHasher,
    issued_resource, sealed_issued_resource,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{Address, Chain, PrincipalAddr, account, package, principal};

const FOUNDER: PrincipalAddr = principal(0x71);

#[blueprint]
mod mill {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// The badge the token's sealed recall rule names. Unsealed itself,
    /// which is what a sealed leaf may name: a leaf derives through the
    /// unsealed form, so a badge is nameable before anything seals
    /// against it.
    #[resource(non_fungible, initial(0))]
    struct OwnerBadge;

    /// A token whose holders can be recalled from, by whoever holds the
    /// badge — a rule its address commits and no cell holds.
    #[resource(seals(recall = issued(OwnerBadge, 0)))]
    struct Token;

    #[state]
    struct Mill {}

    impl Mill {
        /// Issue `amount` of the token, at the address its sealed rules
        /// derive.
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Token::mint(amount)
        }
    }
}

/// The rules the declaration says the token's address commits, built
/// here from the protocol's own types rather than from the macro's — so
/// agreement is between two derivations rather than one restated.
fn declared_rules(instance: impl Into<Address>) -> ResourceRules {
    let badge = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        mill::OWNER_BADGE,
    );
    let mut rules = ResourceRules::new();
    rules.set(
        SealedBehaviour::Recall,
        RoleBytes::try_from(&StoredRule::Require(Presented::Instance(badge, 0)))
            .expect("a rule within the caps encodes"),
    );
    rules
}

/// What a body mints lands at the address the declaration's rules
/// derive, and not at the one the same mark would derive unsealed.
#[test]
fn a_sealed_declaration_mints_at_the_address_its_rules_derive() {
    let mut chain = Chain::native();
    chain.publish(package!(mill));
    let instance = chain.instantiate::<mill::client::Mill>(FOUNDER, ());

    chain
        .transact(FOUNDER, |b| {
            let minted = instance.issue(b, 500u128)?;
            account::deposit(b, FOUNDER, minted)
        })
        .expect_completed();

    // The helper the declaration generates, and the same address built
    // out of the protocol's own types — two derivations rather than one
    // restated, which is the whole of what agreement means here.
    let helper = instance.issued_token(&TestHasher);
    let sealed = sealed_issued_resource(
        &TestHasher,
        instance,
        ResourceKind::Fungible,
        &declared_rules(instance),
        mill::TOKEN,
    );
    let unsealed = issued_resource(&TestHasher, instance, ResourceKind::Fungible, mill::TOKEN);

    assert_eq!(
        helper, sealed,
        "the handle's own helper folds the rules its declaration seals",
    );

    assert_ne!(
        sealed, unsealed,
        "sealing rules is what makes it a different resource"
    );
    assert_eq!(
        chain.balance(FOUNDER, sealed),
        500,
        "the mint lands at the address the sealed rules derive",
    );
    assert_eq!(
        chain.balance(FOUNDER, unsealed),
        0,
        "and nothing lands at the address the mark alone would derive",
    );
}

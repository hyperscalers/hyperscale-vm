//! A package grants its own resource's rules, so the tier has a minter.
//!
//! A granted rule is folded into the address it governs: the resource a
//! body mints and the resource a client derives from the declaration are
//! the same address exactly when they agree about the rules, and a
//! package that changed one would be minting a different resource. What
//! makes that checkable here is that the declaration is the only source
//! — the gate that names the badge, the key of the vault it lands in and
//! the grant that mints it all read one registration.

use hyperscale_vm_effects::{
    Clause, Expr, GrantClaim, GrantedBehaviour, Holding, Presented, ResourceGrants, ResourceKind,
    Rule, RuleBytes, RuleLeaf, StoredRule, TestHasher, Value, granting_issued_resource,
    issued_resource,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{Address, Chain, PrincipalAddr, account, package, principal};

const FOUNDER: PrincipalAddr = principal(0x71);

#[blueprint]
mod mill {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// The badge the token's granted recall rule names. It grants
    /// nothing itself, which is what a grant leaf may name: a leaf
    /// derives through the granting-nothing form, so a badge is nameable
    /// before anything grants against it. Granting nothing costs it no
    /// supply — the one instance it comes up holding is founded where
    /// its record is written, which no `Mint` entry governs.
    #[resource(non_fungible, initial(0))]
    struct OwnerBadge;

    /// A token whose holders can be recalled from, by whoever holds the
    /// badge — a rule its address commits and no cell holds.
    #[resource(grants(mint = self, recall = issued(OwnerBadge, 0)))]
    struct Token;

    #[state]
    struct Mill {}

    impl Mill {
        /// Issue `amount` of the token, at the address its granted rules
        /// derive.
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Token::mint(amount)
        }
    }
}

/// `issued(Badge)` names any instance of a non-fungible badge, and it
/// means that wherever it is written.
///
/// The same words reach three sites — a method's own gate, an actor rule
/// its address seals, and a movement rule its address seals — and for a
/// while they meant three different things there: any instance at the
/// gate, a compile error at one grant, and a rule nobody could satisfy
/// at the other, since a movement entry asked the balance cell a
/// non-fungible badge never occupies. One derivation is what keeps them
/// from drifting again, so the case compares them rather than restating
/// any.
#[blueprint]
mod hall {
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    #[resource(non_fungible, initial(0))]
    struct Warden;

    /// Recallable by whoever holds any warden badge, and movable by one
    /// — the same reading the gate below is written with, on both sides
    /// of the table: `recall` asks what the caller presented, `withdraw`
    /// asks what the mover holds.
    #[resource(grants(mint = self, recall = issued(Warden), withdraw = issued(Warden)))]
    struct Seat;

    #[state]
    struct Hall {}

    impl Hall {
        /// Callable by whoever holds any warden badge.
        #[requires(issued(Warden))]
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Seat::mint(amount)
        }
    }
}

#[test]
fn a_badge_named_without_an_instance_means_any_of_it_at_every_site() {
    let metadata = hall::blueprint().metadata();
    let issue = &metadata.methods["issue"];

    // What the gate names, in the declaration's own expression
    // vocabulary.
    let gate = issue
        .effects
        .iter()
        .find_map(|clause| match clause {
            Clause::Requires {
                rule: Rule::Require(RuleLeaf::Claim(Expr::SelfResource { kind, material, .. })),
                ..
            } => Some((*kind, material.clone())),
            _ => None,
        })
        .expect("the gate names a badge this package issues");

    // And what each sealed rule names, in the derivation's.
    let grants = &issue
        .issues
        .first()
        .expect("the method issues the seat")
        .grants;
    let named = |wanted| {
        grants
            .iter()
            .find_map(|(behaviour, rule)| match rule {
                Rule::Require(GrantClaim::SelfBadge { mark, kind, rules })
                    if behaviour == wanted =>
                {
                    Some((*kind, mark.clone(), rules.clone()))
                }
                _ => None,
            })
            .expect("the seat's rule names a badge this package issues")
    };
    let sealed = named(GrantedBehaviour::Recall);
    assert_eq!(
        sealed,
        named(GrantedBehaviour::Withdraw),
        "one spelling, one badge, at both grant sites",
    );
    assert_eq!(
        gate,
        (
            sealed.0,
            vec![Expr::Literal(Value::Bytes(sealed.1.clone()))],
        ),
        "and the gate names the same one",
    );
    assert_eq!(
        gate.0,
        ResourceKind::NonFungible,
        "and it is the non-fungible one"
    );

    // What those two sites *ask*, resolved against an issuer. An actor
    // question asks what the caller presented; a holder question asks
    // the instances the holdings are entries of — never the balance cell
    // a non-fungible badge is never keyed into, which is the rule nobody
    // could have satisfied.
    let issuer = Address::from(principal(0x7A));
    let resolved = grants
        .resolve(&TestHasher, issuer, &[])
        .expect("the seat's rules resolve against its issuer");
    // Through the rules the leaf itself carries: a badge's address is
    // the hash of what it grants, so a leaf deriving it any other way
    // would name an address nothing is ever minted at.
    let badge = granting_issued_resource(
        &TestHasher,
        issuer,
        ResourceKind::NonFungible,
        &sealed
            .2
            .resolve(&TestHasher, issuer, &[])
            .expect("the warden's own rules resolve against its issuer"),
        &sealed.1,
    );
    let asks = |behaviour| {
        resolved
            .get(behaviour)
            .expect("the entry resolved")
            .decode()
            .expect("a sealed rule decodes")
    };
    assert_eq!(
        asks(GrantedBehaviour::Recall),
        StoredRule::claim(Presented::of_subject(badge)),
    );
    assert_eq!(
        asks(GrantedBehaviour::Withdraw),
        StoredRule::held(badge, Holding::AnyInstance),
    );
}

/// The rules the declaration says the token's address commits, built
/// here from the protocol's own types rather than from the macro's — so
/// agreement is between two derivations rather than one restated.
fn declared_rules(instance: impl Into<Address>) -> ResourceGrants {
    let instance = instance.into();
    // The badge grants nothing: its one instance is founded where its
    // record is written, which no `Mint` entry governs.
    let badge = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        mill::OWNER_BADGE,
    );
    let mut rules = ResourceGrants::new();
    // The token, unlike the badge, is minted by a method of its own —
    // so it carries the entry saying who may, and absence would have
    // withheld the capability outright.
    rules.set(
        GrantedBehaviour::Mint,
        RuleBytes::try_from(&StoredRule::claim(
            Presented::of_address(instance).expect("an instance names a claim"),
        ))
        .expect("a rule within the caps encodes"),
    );
    rules.set(
        GrantedBehaviour::Recall,
        RuleBytes::try_from(&StoredRule::claim(Presented::of_instance(badge, 0)))
            .expect("a rule within the caps encodes"),
    );
    rules
}

/// What a body mints lands at the address the declaration's rules
/// derive, and not at the one the same mark would derive granting nothing.
#[test]
fn a_granting_declaration_mints_at_the_address_its_rules_derive() {
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
    let granting = granting_issued_resource(
        &TestHasher,
        instance,
        ResourceKind::Fungible,
        &declared_rules(instance),
        mill::TOKEN,
    );
    let ungranting = issued_resource(&TestHasher, instance, ResourceKind::Fungible, mill::TOKEN);

    assert_eq!(
        helper, granting,
        "the handle's own helper folds the rules its declaration grants",
    );

    assert_ne!(
        granting, ungranting,
        "granting rules is what makes it a different resource"
    );
    assert_eq!(
        chain.balance(FOUNDER, granting),
        500,
        "the mint lands at the address the granted rules derive",
    );
    assert_eq!(
        chain.balance(FOUNDER, ungranting),
        0,
        "and nothing lands at the address the mark alone would derive",
    );
}

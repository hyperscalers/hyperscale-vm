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
//! halt writes a flag every movement of the resource then reads, and
//! the refusal it earns lands before any body runs. A recall takes the
//! value, and what it has to survive is every rule the resource itself
//! carries — the halt fence among them, since the party being reached
//! is by construction the party each of those rules would refuse.

use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::vocabulary::{NF_VAULT, VAULT};
use hyperscale_vm_testing::{
    Chain, Component, Presence, PrincipalAddr, ResourceAddr, TestHasher, UnmetCondition, Verdict,
    account, address_text, package, principal,
};
use security_guest::security;

/// Who keeps the register, and whom the share's `halt` entry names.
const REGISTRAR: PrincipalAddr = principal(0xA1);
/// A holder on the register.
const HOLDER: PrincipalAddr = principal(0xA2);
/// A second registered holder, so a transfer has somewhere to go.
const OTHER: PrincipalAddr = principal(0xA3);

const fn terms() -> security::client::Terms {
    security::client::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// A world where both parties are on the register and the holder has
/// shares.
fn world(mut chain: Chain) -> (Chain, security::client::Security, ResourceAddr) {
    chain.publish(package!(security_guest::security));
    let issuer = chain.instantiate::<security::client::Security>(REGISTRAR, terms());
    let share = issuer.issued_share(&TestHasher, terms());

    for (id, who) in [(1u64, HOLDER), (2, OTHER)] {
        chain
            .transact(REGISTRAR, |b| {
                let registrar = account::authorize(b, REGISTRAR)?;
                let entry = issuer.register(b, registrar, id)?;
                account::deposit_nf(b, who, entry)
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
#[hyperscale_vm_testing::test]
fn a_halt_stops_a_holder_who_was_moving_freely(chain: Chain) {
    let (mut chain, issuer, share) = world(chain);

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
    // package's signature says `halt` admits anyone and its generated
    // client offers no proof-taking form. Attaching the proof is the
    // composer's until the builder resolves grants for itself.
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            b.call_as(registrar, issuer.address(), "halt", (HOLDER.address(),))?
                .none()
        })
        .expect_completed();

    // Admitted and then refused: a halt is a standing fact about the
    // holder, so it is read from committed state before any body runs
    // rather than answered from the signed form.
    let refused = transfer(&mut chain).expect("a halt is not a reason to refuse the manifest");
    assert!(
        matches!(
            refused.refused(),
            Some(Verdict::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Absent,
                    ..
                }
            })
        ),
        "a halted holder moves nothing, whatever they hold: {refused:?}",
    );
    assert_eq!(chain.balance(HOLDER, share), 90, "and the balance stands");

    // And what a test reports when it expected this to complete is the
    // requirement rather than the leaf. The receipt names a key — a
    // hash of the holder and the badge, inverting to neither — so a
    // reader handed that alone has no way back to which resource
    // refused them or why.
    let told = refused.refused_as();
    assert!(told.contains("withdraw"), "the behaviour: {told}");
    assert!(
        told.contains(&address_text(share.address())),
        "the resource: {told}"
    );
    assert!(
        told.contains("not halted"),
        "and the question it asked: {told}"
    );

    // And the flag lifts. A halt whose absence is the unhalted state is
    // one whose end is the ending of a cell rather than a second flag,
    // so what proves it lifted is the movement it was stopping.
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            b.call_as(registrar, issuer.address(), "unhalt", (HOLDER.address(),))?
                .none()
        })
        .expect_completed();
    transfer(&mut chain)
        .expect("the manifest still admits")
        .expect_completed();
    assert_eq!(
        chain.balance(HOLDER, share),
        80,
        "and the holder moves again"
    );
}

/// Every rule the share class carries, and the recall reaching past all
/// of them.
///
/// One case rather than three, because dropping any one of these
/// silently disables a different issuer power and the others would go
/// on passing. A halted holder is recalled from, so the halt fence does
/// not fence its own issuer; a holder off the register is recalled
/// from, so a resource nobody unregistered may move is still one the
/// registrar may take back; and the register entry itself is recalled,
/// which `withdraw = nobody` makes impossible any other way.
///
/// What makes all three work is one sentence: a declaration reaching a
/// foreign prefix carries no injected movement requirement at all. Each
/// of those requirements would fire against the party being reached,
/// who by construction fails it.
#[hyperscale_vm_testing::test]
fn a_recall_reaches_past_every_rule_the_resource_carries(chain: Chain) {
    let (mut chain, issuer, share) = world(chain);
    let entry = issuer.issued_registered(&TestHasher, terms());
    // Two slots, because a holder keeps the two in different cells: the
    // share class is a balance and the register entry is an interval, so
    // an issuer reaching for either names where that one lives.
    let vault = u64::from(VAULT.0);
    let holdings = u64::from(NF_VAULT.0);

    // A holder nobody registered, holding shares they could never move
    // themselves: `withdraw` names the register and they are not on it.
    let stranger = principal(0xA4);
    chain
        .transact(REGISTRAR, |b| {
            let registrar = account::authorize(b, REGISTRAR)?;
            let entry = issuer.register(b, registrar, 3)?;
            account::deposit_nf(b, stranger, entry)
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
            let taken = issuer.recall_registrations(b, stranger.address(), holdings, &[3])?;
            account::deposit_nf(b, REGISTRAR, taken)
        })
        .expect_completed();
    assert!(
        !chain.holds(stranger, entry, 3),
        "the entry is the register, and the registrar named which"
    );

    // And a holder the issuer has stopped moving anything at all.
    chain
        .transact(REGISTRAR, |b| issuer.halt(b, HOLDER.address()))
        .expect_completed();

    for (holder, taken) in [(HOLDER, 100u128), (stranger, 40u128)] {
        chain
            .transact(REGISTRAR, |b| {
                let shares = issuer.recall_shares(b, holder.address(), vault, taken)?;
                account::deposit(b, REGISTRAR, shares)
            })
            .expect_completed();
        assert_eq!(chain.balance(holder, share), 0);
    }
    assert_eq!(chain.balance(REGISTRAR, share), 140);
}

/// An issuer that keeps its own authority, by naming itself.
///
/// Written here rather than as a guest of its own because what it is
/// about is a posture, not a package: the entries name the issuing
/// instance. It runs on the native lane alone, which is what a
/// `#[blueprint]` in a test file can run on — a wasm artifact is built
/// from a crate's library and this is not in one.
#[blueprint]
mod sovereign {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity, halt, recall};

    /// A note whose `halt` and `recall` entries name the issuing
    /// instance rather than a party outside its code.
    ///
    /// The other posture of an authority entry, and the choice is about
    /// who holds the discretion. Naming a badge or an identity puts it
    /// outside the package: a caller presents that party's claim and the
    /// code cannot spend the authority without them. Naming the issuer
    /// puts it in the code, so what decides is the method's own gate —
    /// this one declares none and is open on purpose, because a package
    /// that wanted a gate would write one.
    #[resource(grants(mint = self, halt = self, recall = self))]
    struct Note;

    #[state]
    struct Sovereign {}

    impl Sovereign {
        pub fn issue(&mut self, amount: Quantity) -> Bucket {
            Note::mint(amount)
        }

        pub fn halt(&mut self, holder: Address) {
            halt(holder, Note::address());
        }

        pub fn recall(&mut self, holder: Address, slot: u64, amount: Quantity) -> Bucket {
            recall(holder, slot, Note::address(), amount)
        }
    }
}

/// A frame speaks for itself at a reach, as it does at every other
/// injected authority entry.
///
/// The entry names the issuing instance, and **nothing can present a
/// claim on a component but that component** — so an entry demanded of
/// the frame that already satisfies it is one no caller could ever
/// answer, and the halt would be a capability the issuer declared and
/// could never exercise. The subtraction is the same one an issuance and
/// a destruction get, and it reproduces the derivation gate: being the
/// executing instance is one way a rule admits you.
#[test]
fn an_issuer_whose_entry_names_itself_reaches_presenting_nothing() {
    let holder = principal(0xA7);
    let mut chain = Chain::native();
    chain.publish(package!(sovereign));
    let issuer = chain.instantiate::<sovereign::client::Sovereign>(REGISTRAR, ());
    let note = issuer.issued_note(&TestHasher);
    let slot = u64::from(VAULT.0);

    chain
        .transact(REGISTRAR, |b| {
            let minted = issuer.issue(b, 100u128)?;
            account::deposit(b, holder, minted)
        })
        .expect_completed();

    // Neither call presents anything, and neither has anything it could
    // present: the authority is the component's own.
    chain
        .transact(REGISTRAR, |b| issuer.halt(b, holder.address()))
        .expect_completed();
    chain
        .transact(REGISTRAR, |b| {
            let taken = issuer.recall(b, holder.address(), slot, 40u128)?;
            account::deposit(b, REGISTRAR, taken)
        })
        .expect_completed();

    assert_eq!(chain.balance(holder, note), 60);
    assert_eq!(chain.balance(REGISTRAR, note), 40);
}

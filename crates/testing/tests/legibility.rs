//! What a resource's own record says to whoever is deciding whether to
//! accept it.
//!
//! A declaration is the package's word about itself, and it is the wrong
//! tier for this question twice over. It says `withdraw = config.registrar`
//! and cannot say what that field will name, so it cannot say which
//! question the entry asks; and a holder deciding whether to take
//! delivery of a resource has its address, not its issuer's source.
//!
//! A record settles both. Its rules are sealed — the instance's answer
//! folded in — so every entry reads as one of exactly two questions, and
//! which stage answers it follows from the leaves without anything
//! declaring a stage.

use hyperscale_vm_effects::{
    ResourceMeta, TestHasher, Value, explain_resource, granting_issued_resource,
};
use hyperscale_vm_fixtures::security;
use hyperscale_vm_testing::{Chain, Component, PrincipalAddr, ResourceAddr, package, principal};

/// Who keeps the register, and whom every approval entry names.
const REGISTRAR: PrincipalAddr = principal(0xC1);

const fn terms() -> security::Terms {
    security::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// Every resource the issuer declares, rendered from its record alone.
fn rendered() -> Vec<(ResourceAddr, String)> {
    let mut chain = Chain::native();
    chain.publish(package!(security));
    let issuer = chain.instantiate::<security::Security>(REGISTRAR, terms());
    let instance = issuer.address().address();
    let config = vec![Value::Address(REGISTRAR.address())];
    let metadata = security::metadata();

    metadata
        .methods
        .values()
        .flat_map(|method| &method.issues)
        .map(|issuance| {
            let rules = issuance
                .grants
                .resolve(&TestHasher, instance, &config)
                .expect("the issuer's own marks resolve");
            let address = granting_issued_resource(
                &TestHasher,
                instance,
                issuance.kind,
                &rules,
                &issuance.mark,
            );
            let record = ResourceMeta {
                namespace: instance,
                kind: issuance.kind,
                material: vec![Value::Bytes(issuance.mark.clone()).canonical_bytes()],
                rules,
            };
            (address, explain_resource(&record, &TestHasher))
        })
        .collect()
}

fn of(resource: ResourceAddr) -> String {
    rendered()
        .into_iter()
        .find(|(address, _)| *address == resource)
        .expect("every declared mark renders")
        .1
}

fn issuer() -> security::Security {
    let mut chain = Chain::native();
    chain.publish(package!(security));
    chain.instantiate::<security::Security>(REGISTRAR, terms())
}

/// The two postures of one movement entry, told apart by what a reader
/// is asked to check.
///
/// One authoring word covers both, because the subject decides which
/// question is answerable — so this is the only place a holder can learn
/// which of the two they are in. "The moving party holds a balance of X"
/// is a standing fact about them, true or false before this transaction
/// existed; "approval on Y" is about the transaction and says nothing
/// about them at all.
#[test]
fn a_movement_entry_says_which_of_its_two_questions_it_asks() {
    let register = of(issuer().issued_share(&TestHasher, terms()));
    assert!(
        register.contains("withdraw   the moving party holds a balance of"),
        "{register}"
    );

    let approval = of(issuer().issued_approved(&TestHasher, terms()));
    assert!(approval.contains("withdraw   approval on"), "{approval}");
    assert!(
        !approval.contains("holds"),
        "an identity is not something a party can hold: {approval}"
    );
}

/// And when the holder would hear about a refusal, which is the other
/// half of what the two postures differ in.
///
/// A standing fact is answered from committed state before any body
/// runs, so the whole transaction aborts and no caller committed on it.
/// An approval is answered from what the transaction presented, so it
/// never becomes a transaction and costs a refused sender nothing.
/// Neither is declared; both follow from the leaves.
#[test]
fn an_entry_says_when_its_verdict_would_land() {
    let register = of(issuer().issued_share(&TestHasher, terms()));
    assert!(
        register.contains("balance of restricted:")
            && register.contains("heard before any body runs"),
        "{register}"
    );

    let approval = of(issuer().issued_approved(&TestHasher, terms()));
    assert!(
        approval.contains("heard before it is a transaction"),
        "{approval}"
    );
    assert!(
        !approval.contains("heard before any body runs"),
        "no entry of it reads committed state: {approval}"
    );
}

/// The class byte in a holder's words, and what it follows from.
///
/// The byte is a summary for a machine: a reader of the entries has
/// everything it says and more. What it adds is a promise about cost —
/// a resource nothing can stop a movement of is one a transfer of pays
/// nothing extra for, and the address is what says so without anyone
/// reading the issuer's method list.
#[test]
fn the_class_byte_reads_as_what_the_entries_do() {
    let restricted = of(issuer().issued_share(&TestHasher, terms()));
    assert!(
        restricted.contains("class      restricted — an entry here can stop a movement"),
        "{restricted}"
    );

    // Same issuer, same shape, an authority entry and no movement one.
    let plain = of(issuer().issued_bearer(&TestHasher, terms()));
    assert!(
        plain.contains("class      plain — nothing here can stop a movement"),
        "{plain}"
    );
}

/// The revocable credential, whole, in two lines of its own record.
///
/// Nobody may move it and one party may take it back, which is the
/// entire design of a soulbound register entry — and a reader learns it
/// without the issuer's source, because both facts are folded into the
/// address they were handed.
#[test]
fn a_soulbound_credential_reads_as_one() {
    let entry = of(issuer().issued_registered(&TestHasher, terms()));
    assert!(entry.contains("withdraw   nobody, ever"), "{entry}");
    assert!(entry.contains("recall     approval on"), "{entry}");
}

/// An entry the issuing frame satisfies by being the frame demands
/// nothing, and says so rather than naming an address a reader would
/// have to recognise as the issuer's own.
///
/// Asked through the same door admission injects through, so what this
/// renders as demanding nothing is exactly what nothing is demanded for.
#[test]
fn an_entry_naming_the_issuer_asks_a_caller_for_nothing() {
    let share = of(issuer().issued_share(&TestHasher, terms()));
    assert!(
        share.contains("mint       the issuer's own code, which proves nothing to itself"),
        "{share}"
    );
    // And nothing is heard, because nothing is asked.
    assert!(
        !share.contains("proves nothing to itself — heard"),
        "{share}"
    );
}

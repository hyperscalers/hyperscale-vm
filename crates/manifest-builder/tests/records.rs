//! The records a composition carries, found rather than handed over.
//!
//! A resource whose entries can stop a movement is judged against the
//! record its own address commits, and that record travels in the
//! envelope — so somebody has to find it. The address cannot be looked
//! up: it is the hash of the issuer, the kind, the mark and the rules,
//! and says nothing about who to ask. What answers is the world the
//! composer already holds, the one it resolves every call target
//! against.
//!
//! Run over a declaration rather than over the builder that wrote it,
//! because the party assembling an envelope is not always the party that
//! wrote what it carries. A subintent arrives whole and already signed;
//! the records it needs are readable off it, and attaching them touches
//! nothing that signature covers.

use hyperscale_vm_effects::{
    Hash32, Hasher, InstanceMeta, PackageHash, PresentedGrants, Records, TestHasher, Value,
    admit_presenting,
};
use hyperscale_vm_fixtures::security;
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError, graph_records};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{AddressClass, PrincipalAddr, ResourceAddr};

/// Who keeps the register the share class names.
const REGISTRAR: PrincipalAddr = PrincipalAddr::new([0xC1; 31]);
/// The holder moving shares.
const ALICE: PrincipalAddr = PrincipalAddr::new([0xC2; 31]);
/// Where they go.
const BOB: PrincipalAddr = PrincipalAddr::new([0xC3; 31]);

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

const fn terms() -> security::Terms {
    security::Terms {
        registrar: REGISTRAR.address(),
    }
}

/// A world holding the account and one security issuer, and the share
/// class that issuer's address commits the rules of.
fn world() -> (Records, ResourceAddr) {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(pkg("account"), account::metadata());
    chain
        .packages
        .publish_unchecked(pkg("security"), security::metadata());
    chain.instances.serve_principals(pkg("account"));
    let meta = InstanceMeta {
        package: pkg("security"),
        config: vec![Value::Address(REGISTRAR.address())],
        salt: Hash32([0x5E; 32]),
    };
    let issuer = security::Security::at(meta.address(&TestHasher));
    chain.instances.create(&TestHasher, meta);
    let share = issuer.issued_share(&TestHasher, terms());
    (chain, share)
}

/// One ordinary transfer, declaring nothing about any rule.
fn transfer(chain: &Records, resource: ResourceAddr) -> Result<TypedBuilder<'_>, TypedError> {
    let mut b = TypedBuilder::new(chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut b, ALICE, resource, 40)?;
    account::deposit(&mut b, BOB, funds)?;
    Ok(b)
}

/// The composer finds the record its own transfer will be judged
/// against, and admission accepts the transfer because of it.
///
/// The pair is the point. Withholding the record is not a bypass — a
/// resource whose entries can stop a movement carries the class byte
/// that says so, and moving one with nothing to resolve is refused — so
/// what the composer's own analysis buys is the transfer admitting at
/// all.
#[test]
fn a_composer_finds_the_record_its_own_transfer_is_judged_against() {
    let (chain, share) = world();
    assert_eq!(
        share.address().class(),
        AddressClass::Restricted,
        "the share's entries can stop a movement, so its record cannot be withheld",
    );
    let graph = transfer(&chain, share)
        .and_then(TypedBuilder::build)
        .expect("the transfer types");

    let found = graph_records(&graph, &chain, &TestHasher);
    assert_eq!(
        found
            .iter()
            .map(|record| record.address(&TestHasher))
            .collect::<Vec<_>>(),
        vec![share],
        "the resource the transfer moves, and nothing else",
    );

    assert!(
        admit_presenting(
            &graph,
            ALICE,
            &chain,
            &PresentedGrants::from_presented(&TestHasher, &found),
            &TestHasher
        )
        .is_ok(),
        "what the composer found is what admission resolves the entries against",
    );
    assert!(
        admit_presenting(&graph, ALICE, &chain, PresentedGrants::none(), &TestHasher).is_err(),
        "and withholding it withholds the movement",
    );
}

/// A resource this world cannot say the issuer of is one the composer
/// finds nothing for.
///
/// Not a failure: the record is the address's own commitment, so a
/// composer that never saw the issuance has nothing to present and says
/// so by presenting nothing. Whoever holds the asset holds the record
/// beside it, and hands it over.
#[test]
fn a_resource_no_instance_of_this_world_issues_is_found_by_nothing() {
    let (chain, _) = world();
    let stranger = ResourceAddr::new([0xEE; 31]);
    let graph = transfer(&chain, stranger)
        .and_then(TypedBuilder::build)
        .expect("the transfer types");

    assert!(graph_records(&graph, &chain, &TestHasher).is_empty());
}

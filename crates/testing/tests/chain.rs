//! The chain a package author's test drives.
//!
//! What is under test is the registry seam rather than execution: an
//! address is adopted as a handle only where the chain holds an instance
//! of that handle's own package at it, which is the check every call
//! downstream of a handle rests on.

use hyperscale_vm_effects::{TestHasher, declaration_hash};
use hyperscale_vm_fixtures::{book, lottery};
use hyperscale_vm_testing::{Chain, Component, ComponentAddr, principal};

/// A handle is reached by adopting an address the chain agrees runs that
/// package, and by nothing else — the unchecked `at` is for a holder that
/// established the fact some other way.
#[test]
fn an_address_adopts_as_the_package_the_chain_holds_at_it() {
    let mut chain = Chain::native();
    let hash = |metadata| declaration_hash(&TestHasher, &metadata).expect("a declaration encodes");

    // Created from the package's own declaration hash, which is what an
    // instance address folds in and what adoption compares against.
    let address = chain.instantiate_raw(principal(0xC0), hash(lottery::metadata()), ());

    assert_eq!(
        chain
            .adopt::<lottery::Lottery>(address)
            .map(Component::address),
        Ok(address),
        "the package the chain holds there"
    );

    // Another package's handle over the same address: the address runs
    // one declaration, and it is not this one.
    let wrong = chain
        .adopt::<book::Book>(address)
        .expect_err("a book handle names a book");
    assert_eq!(wrong.address, address);
    assert_eq!(wrong.want, hash(book::metadata()));

    // And an address the chain holds no instance for at all.
    let unknown = ComponentAddr::new([0x5A; 31]);
    assert_eq!(
        chain
            .adopt::<lottery::Lottery>(unknown)
            .unwrap_err()
            .address,
        unknown
    );
}

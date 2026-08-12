//! The envelope tier's contract: any envelope it emits passes
//! [`admit_tree`], and the arithmetic over declarations that admission
//! judges is judged here first.
//!
//! The world is two accounts and the resources they trade, which is all a
//! composition needs: a yield edge is an edge, and what makes it a
//! composition is which graph it crosses.

use hyperscale_vm_effects::stdlib::account_metadata;
use hyperscale_vm_effects::{
    Constraint, EnvelopeTree, Hasher, InstanceRegistry, MetadataCache, PackageHash, PrincipalAddr,
    ResourceAddr, TestHasher, admit_tree,
};
use hyperscale_vm_manifest_builder::native::account;
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, EnvelopeError, Param};
use proptest::prelude::{prop, proptest};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    instances.serve_principals(pkg());
    (cache, instances)
}

fn admits(tree: &EnvelopeTree) {
    let (cache, instances) = world();
    let identity = tree.hash(&TestHasher);
    admit_tree(tree, identity, &cache, &instances, &TestHasher)
        .expect("a composed envelope admits");
}

/// The two-sided trade: each signer withdraws what they pay, exports it,
/// and deposits what the other side yields. Neither graph mentions the
/// other; the envelope is the two edges between them.
fn swap(pay_x: u128, pay_y: u128) -> Result<EnvelopeTree, EnvelopeError> {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);

    let (taken_y, wants_y) = root.declare(RES_Y, [Constraint::MinAmount(pay_y)]);
    let funds = account::withdraw(&mut root, ALICE, RES_X, pay_x)?;
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken_y)?;

    let mut sub = env.subintent(BOB);
    let (taken_x, wants_x) = sub.declare(RES_X, [Constraint::MinAmount(pay_x)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, pay_y)?;
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken_x)?;

    env.seal(root)?;
    env.seal(sub)?;
    env.bind(wants_y, paid_y);
    env.bind(wants_x, paid_x);
    env.build()
}

#[test]
fn a_composed_swap_admits() {
    let tree = swap(100, 10).unwrap();
    assert_eq!(tree.subintents.len(), 1);
    assert_eq!(tree.subintents[0].signer, BOB);
    // The wiring the author never wrote: each side's hole names the other
    // intent's exported edge.
    assert_eq!(tree.root_bindings[0].intent, 1);
    assert_eq!(tree.subintents[0].bindings[0].intent, 0);
    admits(&tree);
}

#[test]
fn a_hole_the_graph_never_consumes_is_refused() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    // Declared and then dropped: the yielded bucket would arrive with
    // nothing to receive it.
    let (_taken, _wants) = root.declare(RES_Y, []);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, ALICE, funds).unwrap();
    assert_eq!(
        env.seal(root),
        Err(EnvelopeError::UnusedYieldParam {
            intent: 0,
            param: 0
        })
    );
}

#[test]
fn a_hole_two_arguments_consume_is_refused() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    let (taken, _wants) = root.declare(RES_Y, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    // One yielded edge cannot be two deposits; the second reference is a
    // `Param` the tier did not mint.
    account::deposit(&mut root, ALICE, Param(0)).unwrap();
    assert_eq!(
        env.seal(root),
        Err(EnvelopeError::YieldParamReused {
            intent: 0,
            param: 0
        })
    );
}

#[test]
fn a_parameter_the_intent_never_declared_is_refused() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    account::deposit(&mut root, ALICE, Param(3)).unwrap();
    assert_eq!(
        env.seal(root),
        Err(EnvelopeError::UnboundParam {
            intent: 0,
            param: 3
        })
    );
}

#[test]
fn a_hole_the_composition_never_bound_is_refused() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    let (taken, _wants) = root.declare(RES_Y, []);
    account::deposit(&mut root, ALICE, taken).unwrap();
    env.seal(root).unwrap();
    // The graph discharged its side of the declaration; the composition
    // never discharged its own.
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnboundYieldParam {
            intent: 0,
            param: 0
        })
    );
}

#[test]
fn an_intent_still_under_construction_is_refused() {
    let (cache, instances) = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut root, ALICE, RES_X, 100).unwrap();
    account::deposit(&mut root, BOB, funds).unwrap();
    let _sub = env.subintent(BOB);
    env.seal(root).unwrap();
    assert_eq!(
        env.build(),
        Err(EnvelopeError::UnsealedIntent { intent: 1 })
    );
}

#[test]
#[should_panic(expected = "bound within the envelope that minted it")]
fn a_handle_from_another_envelope_is_refused() {
    let (cache, instances) = world();
    let (mut mine, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    let (taken, wants) = root.declare(RES_X, []);
    account::deposit(&mut root, ALICE, taken).unwrap();

    let (_theirs, mut other) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);
    let funds = account::withdraw(&mut other, BOB, RES_X, 100).unwrap();
    let elsewhere = other.export(funds);
    mine.bind(wants, elsewhere);
}

proptest! {
    /// The tier's whole contract, over compositions of growing width: a
    /// composer paying each of several counterparties, every side's hole
    /// bound to the other's export.
    #[test]
    fn composed_envelopes_admit(
        legs in prop::collection::vec((100..1000u128, 1..100u128), 1..6),
    ) {
        let (cache, instances) = world();
        let (mut env, mut root) = EnvelopeBuilder::new(&cache, &instances, &TestHasher);

        let mut wiring = Vec::with_capacity(legs.len());
        let mut paid = Vec::with_capacity(legs.len());
        for (pay, _) in &legs {
            let (taken, wants) = root.declare(RES_Y, [Constraint::MinAmount(1)]);
            let funds = account::withdraw(&mut root, ALICE, RES_X, *pay).unwrap();
            paid.push(root.export(funds));
            account::deposit(&mut root, ALICE, taken).unwrap();
            wiring.push(wants);
        }
        env.seal(root).unwrap();

        for (index, (_, receive)) in legs.iter().enumerate() {
            let signer = PrincipalAddr::new([u8::try_from(index).unwrap() + 1; 31]);
            let mut leg = env.subintent(signer);
            let (taken, wants) = leg.declare(RES_X, [Constraint::MinAmount(1)]);
            let funds = account::withdraw(&mut leg, signer, RES_Y, *receive).unwrap();
            let yielded = leg.export(funds);
            account::deposit(&mut leg, signer, taken).unwrap();
            env.seal(leg).unwrap();
            env.bind(wiring.remove(0), yielded);
            env.bind(wants, paid.remove(0));
        }

        let tree = env.build().expect("every hole is bound");
        admits(&tree);
    }
}

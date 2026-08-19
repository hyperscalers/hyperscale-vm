//! What a cell holds, held against the code rather than against the
//! declaration that named it.
//!
//! Every layer above this one reads a package's own metadata: admission
//! judges a manifest against the resources a signature declares, and the
//! tracer refuses a body whose credits disagree with its own cells. Both
//! assume the metadata describes the code. A published package need not —
//! a section is authored bytes, and nothing in an artifact ties the
//! `cell_put` its wasm performs to the parameter its signature said would
//! feed it.
//!
//! So the declaration reaches execution and the movement is judged there.
//! What that buys is the case the layers above cannot reach: a package
//! that declares its vaults honestly and then credits the wrong one. The
//! package that declares nothing at all is turned away earlier, where a
//! declaration becomes capabilities — a movement names what it moves, or
//! there is no handle to move through.

use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::NF_VAULT;
use hyperscale_vm_effects::{
    Address, AddressClass, Declaration, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode,
    Presence, SlotId, SubstateKey, TestHasher, Value, child_key, collection_id,
};
use hyperscale_vm_embed::math::U256;
use hyperscale_vm_kernel::{
    AbortReason, EnvInputs, ISSUER_REP, KernelSession, MaterializeError, MemoryStore, OverlayStore,
    TxHash, encode_amount,
};

const VAULT: SlotId = SlotId(1);
const POOL: Address = Address::new([0x70; 31], AddressClass::Component);
const X: Address = Address::new([0xE1; 31], AddressClass::Component);
const Y: Address = Address::new([0xE2; 31], AddressClass::Component);

fn vault(resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        POOL,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 0,
        randomness: [0; 32],
    }
}

/// A session over the pool's two vaults, denominated as the declaration
/// says — or as `denominations` says, which is the point.
///
/// # Panics
///
/// On a declaration that does not materialize, which is a fixture's own
/// defect wherever the test is about what a movement does rather than
/// about whether one is granted.
fn session(denominations: &[Option<Address>]) -> KernelSession {
    try_session(denominations).expect("the declaration materializes")
}

/// The same, with the materialization verdict left to the caller.
fn try_session(denominations: &[Option<Address>]) -> Result<KernelSession, MaterializeError> {
    let ordered = vec![
        Effect {
            target: EffectTarget::Point(vault(X)),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(vault(Y)),
            mode: Mode::Delta,
        },
    ];
    let mut set = EffectSet::new();
    for effect in &ordered {
        set.insert(*effect).expect("two distinct cells");
    }
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration {
            set,
            ordered,
            denominations: denominations.to_vec(),
            ..Declaration::default()
        },
        TxHash(Hash32([1; 32])),
        env(),
        hash,
    )
}

/// Every way a bucket comes into being, and what it carries out.
///
/// Exhaustive over the producers on purpose. A bucket's resource is
/// stamped where value comes into being, and a producer that stamped
/// nothing would hand out an edge every destination admits — which is
/// the one shape the comparison below cannot catch, because there would
/// be nothing to compare. The stamp is only visible through that
/// comparison, so each edge is offered to the vault that does not hold
/// it.
#[test]
fn every_producer_stamps_what_its_source_held() {
    let absolute = child_key(&TestHasher, POOL, SlotId(20), &[]);
    let commutative = child_key(&TestHasher, POOL, SlotId(21), &[]);
    let reserved = child_key(&TestHasher, POOL, SlotId(22), &[]);
    let ordered = vec![
        Effect {
            target: EffectTarget::Point(absolute),
            mode: Mode::Write {
                requires: Presence::Either,
            },
        },
        Effect {
            target: EffectTarget::Point(commutative),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(reserved),
            mode: Mode::Reserve { amount: 50 },
        },
        // The vault that holds the other resource: what each edge is
        // offered to, and what every one of them must refuse.
        Effect {
            target: EffectTarget::Point(vault(Y)),
            mode: Mode::Delta,
        },
    ];
    let mut set = EffectSet::new();
    for effect in &ordered {
        set.insert(*effect).expect("four distinct cells");
    }
    let mut store = MemoryStore::new();
    for key in [absolute, reserved] {
        store.write(key, encode_amount(100).to_vec()).expect("seed");
    }

    let mut session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set: set.clone(),
            ordered,
            denominations: [Some(X), Some(X), Some(X), Some(Y)].to_vec(),
            ..Declaration::default()
        },
        TxHash(Hash32([2; 32])),
        env(),
        hash,
    )
    .expect("four denominated cells materialize");

    // A debit out of each mode that holds an amount, and the two ways an
    // edge divides once it is in hand.
    let from_absolute = session.write_take(0, 40).expect("the cell covers it");
    let split = session
        .bucket_take(from_absolute, 10)
        .expect("the edge covers it");
    let share = session
        .bucket_split(from_absolute, U256::from_u128(1), U256::from_u128(2))
        .expect("half of what is left");
    let from_commutative = session.delta_take(1, 40).expect("the debit is queued");
    let from_reserved = session.reserve_take(2).expect("the grant is held");

    for (name, funds) in [
        ("write-take", from_absolute),
        ("bucket-take", split),
        ("bucket-split", share),
        ("delta-take", from_commutative),
        ("reserve-take", from_reserved),
    ] {
        assert_eq!(
            session.delta_put(3, funds).map_err(AbortReason::from),
            Err(AbortReason::WrongResource),
            "{name} handed out an edge the other vault admitted"
        );
    }
}

/// The same, for the two producers that hand back named instances.
///
/// Separate because an instance edge lands in a holdings interval rather
/// than an amount cell, so the vault that must refuse it is a different
/// shape — not a different rule.
#[test]
fn every_instance_producer_stamps_what_its_source_held() {
    let held = |resource: Address| {
        collection_id(
            &TestHasher,
            POOL,
            NF_VAULT,
            &[Value::Address(resource).canonical_bytes()],
        )
    };
    let interval = |resource: Address| Effect {
        target: EffectTarget::Range {
            owner: POOL,
            collection: held(resource),
            lo: 0,
            hi: u128::MAX,
            cap: 8,
        },
        mode: Mode::Write {
            requires: Presence::Either,
        },
    };
    let ordered = vec![interval(X), interval(Y)];
    let mut set = EffectSet::new();
    for effect in &ordered {
        set.insert(*effect).expect("two distinct collections");
    }
    let mut store = MemoryStore::new();
    for order in [10u128, 20] {
        store
            .entry_write(POOL, held(X), order, vec![1])
            .expect("seed");
    }

    let mut session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set: set.clone(),
            ordered,
            denominations: [Some(X), Some(Y)].to_vec(),
            ..Declaration::default()
        },
        TxHash(Hash32([3; 32])),
        env(),
        hash,
    )
    .expect("two denominated intervals materialize");

    let taken = session.range_take(0, &[10]).expect("the holder has it");
    session.grant_issuance(X);
    let minted = session
        .mint_instances(ISSUER_REP, &[99])
        .expect("the grant mints");

    for (name, funds) in [("range-take", taken), ("mint-instances", minted)] {
        assert_eq!(
            session.range_put(1, funds, &[1]).map_err(AbortReason::from),
            Err(AbortReason::WrongResource),
            "{name} handed out instances the other holder's interval admitted"
        );
    }
}

/// A debit from one vault credited to the other is refused, whatever the
/// code performing it believed.
///
/// This is the shape a lying package takes: both cells are declared, both
/// capabilities are granted, and the movement between them is the whole
/// of the defect. Nothing about the manifest is wrong, so nothing above
/// execution has anything to judge.
#[test]
fn value_debited_from_one_vault_cannot_be_credited_to_another() {
    let mut session = session(&[Some(X), Some(Y)]);
    let funds = session.delta_take(0, 100).expect("the debit is queued");

    assert_eq!(
        session.delta_put(1, funds).map_err(AbortReason::from),
        Err(AbortReason::WrongResource),
        "the Y vault holds Y and this is X"
    );
}

/// The same movement back into the cell it came from completes.
#[test]
fn value_returns_to_the_vault_that_holds_it() {
    let mut session = session(&[Some(X), Some(Y)]);
    let funds = session.delta_take(0, 100).expect("the debit is queued");
    assert_eq!(session.delta_put(0, funds), Ok(()));
}

/// A merge is the same question with an edge in place of the cell.
///
/// Two edges becoming one is a credit like any other, so the resources
/// have to agree — otherwise the merged edge would carry a total that
/// denominates nothing, and whichever cell it eventually reached would
/// take value it does not hold.
#[test]
fn two_edges_of_different_resources_do_not_merge() {
    let mut session = session(&[Some(X), Some(Y)]);
    let held_x = session.delta_take(0, 100).expect("the X debit is queued");
    let held_y = session.delta_take(1, 100).expect("the Y debit is queued");

    assert_eq!(
        session
            .bucket_put(held_x, held_y)
            .map_err(AbortReason::from),
        Err(AbortReason::WrongResource)
    );
}

/// A declaration that says nothing moves nothing.
///
/// The comparison below it is between two resources, and a cell naming
/// neither would leave nothing to compare — so a movement mode on such a
/// cell is refused where a declaration is turned into capabilities,
/// before any body has a handle to move through. What is closed is the
/// case the comparison cannot reach: not a package that declares its
/// vaults and credits the wrong one, but one that declares no vault at
/// all and moves value anyway.
#[test]
fn a_cell_that_denominates_nothing_moves_nothing() {
    let refused = try_session(&[None, None]).expect_err("a movement names what it moves");
    assert_eq!(refused, MaterializeError::UndenominatedMovement(vault(X)));

    // One end saying nothing is enough: the pair is judged cell by cell.
    assert_eq!(
        try_session(&[Some(X), None]).expect_err("the second says nothing"),
        MaterializeError::UndenominatedMovement(vault(Y))
    );
}

/// A grant names one resource, so it destroys that one.
///
/// Burning through a grant is authority over the resource the grant
/// names; passing another instance's value to it would be destroying
/// value this invocation was never given authority over.
#[test]
fn a_grant_burns_only_what_it_issues() {
    let mut session = session(&[Some(X), Some(Y)]);
    let foreign = session.delta_take(0, 100).expect("the debit is queued");
    session.grant_issuance(Y);

    let issued = session.mint(ISSUER_REP, 5).expect("the grant mints");
    assert_eq!(session.burn(ISSUER_REP, issued), Ok(()));
    assert_eq!(
        session.burn(ISSUER_REP, foreign).map_err(AbortReason::from),
        Err(AbortReason::WrongResource)
    );
}

/// Value a grant mints carries what the grant names, so it credits the
/// cell holding that resource and no other.
#[test]
fn minted_value_lands_only_in_its_own_cell() {
    let mut session = session(&[Some(X), Some(Y)]);
    session.grant_issuance(Y);
    let minted = session.mint(ISSUER_REP, 5).expect("the grant mints");

    assert_eq!(
        session.delta_put(0, minted).map_err(AbortReason::from),
        Err(AbortReason::WrongResource)
    );
    let minted = session.mint(ISSUER_REP, 5).expect("the grant mints");
    assert_eq!(session.delta_put(1, minted), Ok(()));
}

/// A bucket carries what it was debited from across a split, so neither
/// half fits a cell the whole did not.
#[test]
fn a_split_carries_the_resource_into_both_halves() {
    let mut session = session(&[Some(X), Some(Y)]);
    let funds = session.delta_take(0, 100).expect("the debit is queued");
    let part = session
        .bucket_take(funds, 40)
        .expect("a split off the edge");

    assert_eq!(
        session.delta_put(1, part).map_err(AbortReason::from),
        Err(AbortReason::WrongResource)
    );
    assert_eq!(session.delta_put(0, funds), Ok(()));
}

/// The bucket table's own accounting is unchanged: value still has to
/// land somewhere, and a resource tag does not excuse dropping it.
#[test]
fn a_denominated_edge_still_has_to_be_disposed_of() {
    let mut session = session(&[Some(X), Some(Y)]);
    let funds = session.delta_take(0, 100).expect("the debit is queued");
    assert_eq!(
        session.drop_bucket(funds).map_err(AbortReason::from),
        Err(AbortReason::ValueDropped)
    );
    assert_eq!(session.bucket(funds).map(|held| held.quantity()), Ok(100));
}

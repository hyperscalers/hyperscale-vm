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
//! that declares its vaults honestly and then credits the wrong one, and
//! a package that declares nothing at all.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, Value, child_key,
};
use hyperscale_vm_kernel::{
    AbortReason, EnvInputs, ISSUER_REP, KernelSession, MemoryStore, OverlayStore, TxHash,
};

const VAULT: RoleId = RoleId(1);
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
fn session(denominations: &[Option<Address>]) -> KernelSession {
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
        &set,
        &ordered,
        denominations,
        TxHash(Hash32([1; 32])),
        env(),
        hash,
    )
    .expect("two unheld delta cells materialize")
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

/// A declaration that says nothing leaves execution nothing to judge.
///
/// Stated as a test rather than left implied, because it is the honest
/// bound on what this layer gives: a cell nobody denominated is a cell
/// any value fits, and closing that is the declaration's job — the
/// publish gate's and admission's — not this one's.
#[test]
fn an_undenominated_cell_admits_whatever_arrives() {
    let mut session = session(&[None, None]);
    let funds = session.delta_take(0, 100).expect("the debit is queued");
    assert_eq!(session.delta_put(1, funds), Ok(()));
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

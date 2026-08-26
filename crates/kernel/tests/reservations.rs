//! A hold leaves the cell only for a grant that was exercised.
//!
//! A reservation is a floor a transaction buys before it runs: the cell
//! will cover this much, judged against committed state and held so no
//! sibling can take it away. Buying a floor is not spending it. A
//! declaration covers every arm of a conditional and only one arm runs,
//! so a reservation whose branch never executes is what over-declaring
//! normally produces — and the cell it named must come through untouched.
//!
//! What that pins is the debit's source. The amount that leaves is the
//! sum of the grants a body took, never the sum of the grants it was
//! given, and the two differ exactly when a body declined one.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, Value, child_key,
};
use hyperscale_vm_kernel::{
    EnvInputs, KernelSession, MemoryStore, OverlayStore, Substates, decode_amount,
};
use hyperscale_vm_types::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome, ResourceAddr,
    SubstateKey, TxHash, encode_amount,
};

const OWNER: Address = Address::new([0x51; 31], AddressClass::Component);
const UNIT: ResourceAddr = ResourceAddr::new([0xC1; 31]);

const SOURCE: SlotId = SlotId(1);
const SINK: SlotId = SlotId(2);

fn cell(slot: SlotId) -> SubstateKey {
    child_key(
        &TestHasher,
        OWNER,
        slot,
        &[Value::Address(UNIT.address()).canonical_bytes()],
    )
}

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A session over a source cell holding `held`, reserved by one clause
/// per entry in `reserves`, and a sink the taken value can land in.
///
/// The clauses fold to one hold in the set and stay distinct in the
/// clause list, which is the shape the capability table is built from:
/// several grants, one hold, and the question of which were taken.
fn session(held: u128, reserves: &[u128]) -> (KernelSession, u32) {
    let source = cell(SOURCE);
    let sink = cell(SINK);

    let mut ordered: Vec<DeclaredAccess> = reserves
        .iter()
        .map(|amount| DeclaredAccess {
            reach: None,
            effect: Effect {
                target: EffectTarget::Point(source),
                mode: Mode::Reserve { amount: *amount },
            },
            holds: Some(UNIT),
        })
        .collect();
    ordered.push(DeclaredAccess {
        reach: None,
        effect: Effect {
            target: EffectTarget::Point(sink),
            mode: Mode::Delta { moves: Moves::Both },
        },
        holds: Some(UNIT),
    });

    let mut set = EffectSet::new();
    for declared in &ordered {
        set.insert(declared.effect).expect("the clauses fold");
    }

    let mut store = MemoryStore::new();
    store.write(source, encode_amount(held).to_vec());

    // The sink's handle sits one past the reservations, the clause list
    // being what the capability table is indexed by.
    let sink_rep = u32::try_from(reserves.len()).expect("a handful of clauses");
    let session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set,
            ordered,
            ..Declaration::default()
        },
        TxHash(Hash32([7; 32])),
        EnvInputs::unsealed(0),
        hash,
    )
    .expect("the cell covers what the clauses reserve");
    (session, sink_rep)
}

fn finish(session: KernelSession) -> (Outcome, Option<u128>, u128) {
    let (receipt, store) = session.finish(vec![], 0).expect("the oracle stands");
    let settled = receipt
        .delta
        .settles
        .get(&cell(SOURCE))
        .map(|movement| movement.debit);
    let left = store
        .cell(cell(SOURCE))
        .map_or(0, |held| decode_amount(&held).expect("an amount cell"));
    (receipt.outcome, settled, left)
}

/// The case over-declaration produces: a grant the body never reached.
#[test]
fn a_reservation_nobody_took_leaves_the_cell_whole() {
    let (session, _) = session(100, &[50]);
    let (outcome, settled, left) = finish(session);

    assert!(matches!(outcome, Outcome::Completed { .. }));
    assert_eq!(left, 100, "an untaken hold spends nothing");
    assert_eq!(
        settled, None,
        "no value moved, so the receipt carries no debit"
    );
}

/// Several grants, one hold, and only one of them exercised.
#[test]
fn a_partly_taken_hold_debits_only_what_was_taken() {
    let (mut session, sink) = session(100, &[30, 40]);
    let funds = session.reserve_take(0, 0).expect("the first grant is held");
    session
        .cell_put(sink, 0, funds)
        .expect("into the sink it goes");

    let (outcome, settled, left) = finish(session);

    assert!(matches!(outcome, Outcome::Completed { .. }));
    assert_eq!(left, 70, "the untaken 40 stays where it was");
    assert_eq!(settled, Some(30), "the debit is the grant that was taken");
}

/// The case that already worked, unchanged: every grant exercised.
#[test]
fn a_fully_taken_hold_settles_the_whole_of_it() {
    let (mut session, sink) = session(100, &[30, 40]);
    for rep in 0..2 {
        let funds = session.reserve_take(rep, 0).expect("the grant is held");
        session
            .cell_put(sink, 0, funds)
            .expect("into the sink it goes");
    }

    let (outcome, settled, left) = finish(session);

    assert!(matches!(outcome, Outcome::Completed { .. }));
    assert_eq!(left, 30, "both grants spent");
    assert_eq!(settled, Some(70), "the hold settles whole");
}

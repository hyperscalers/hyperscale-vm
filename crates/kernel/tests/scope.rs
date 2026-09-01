//! What a member judges before any body runs is bounded by the shards
//! its execution spans, and by nothing narrower: a leg judges its own
//! shard, a core member every shard of its core, and the capability
//! table is the whole declaration either way.
//!
//! The scope is not the batch's locality. The two coincide for a leg
//! and for a single-shard core, which is exactly why a locality-shaped
//! filter would pass every test but the multi-shard one here.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Condition, Declaration, Hash32, Hasher, JudgedLeaf, Rule, SlotId, TestHasher, child_key,
};
use hyperscale_vm_kernel::{
    Baseline, BatchOutcome, BatchTx, EnvInputs, ExecutionMode, ExecutionScope, KernelSession,
    Locality, MemoryStore, OverlayStore, Receipt, RunResult, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome,
    Presence, ResourceAddr, SubstateKey, TxHash, encode_amount,
};

const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const HERE: u8 = 0xA1;
const THERE: u8 = 0xB1;
const FUEL: u64 = 3;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(1_000)
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

const fn owner(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

/// The vault under an owner.
fn vault(byte: u8) -> SubstateKey {
    child_key(&TestHasher, owner(byte), SlotId(1), &[])
}

/// A byte cell under the same owner, beside the vault rather than on it.
fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, owner(byte), SlotId(2), &[])
}

/// A scope, or a locality, over exactly the owners listed.
fn only(owners: &'static [u8]) -> impl Fn(Address) -> bool + Send + Sync + 'static {
    move |candidate: Address| owners.iter().any(|byte| owner(*byte) == candidate)
}

fn reserve(byte: u8, amount: u128) -> Effect {
    Effect {
        target: EffectTarget::Point(vault(byte)),
        mode: Mode::Reserve { amount },
    }
}

fn write(byte: u8) -> Effect {
    Effect {
        target: EffectTarget::Point(cell(byte)),
        mode: Mode::Write { moves: Moves::Both },
    }
}

/// A condition's leaf is also a declared read, as admission makes it:
/// that is what provisions the state wherever the condition is judged.
fn read(byte: u8) -> Effect {
    Effect {
        target: EffectTarget::Point(cell(byte)),
        mode: Mode::Read,
    }
}

fn present(byte: u8) -> Rule<JudgedLeaf> {
    Rule::Require(JudgedLeaf::Presence {
        target: EffectTarget::Point(cell(byte)),
        expect: Presence::Present,
    })
}

fn declared(effects: &[Effect], conditions: Vec<Condition>) -> Declaration {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    let mut declaration = Declaration::from_set(set).denominated(|effect| {
        matches!(effect.mode, Mode::Delta { .. } | Mode::Reserve { .. }).then_some(RESOURCE)
    });
    declaration.conditions = conditions;
    declaration
}

/// A guest that touches nothing and completes, so every verdict here is
/// materialization's or settlement's own.
const fn idle(_entry: &BatchTx, session: KernelSession) -> RunResult {
    RunResult::Completed {
        session,
        answers: vec![],
        fuel: FUEL,
    }
}

fn run_batch(store: &MemoryStore, entry: BatchTx, locality: &Locality) -> BatchOutcome {
    execute_batch(
        Arc::new(store.clone()) as Arc<dyn Baseline>,
        &[entry],
        &idle,
        test_hash,
        ExecutionMode::Serial,
        locality,
    )
    .unwrap()
}

fn run(store: &MemoryStore, entry: BatchTx, locality: &Locality) -> Receipt {
    let tx = entry.tx;
    run_batch(store, entry, locality).receipts[&tx].clone()
}

/// A leg member holds nothing for a reservation on another shard's
/// cell, and settling afterwards asks nothing of it either — where a
/// whole execution judges the same declaration against a store that
/// never held the cell and refuses it.
#[test]
fn a_reservation_outside_the_scope_is_neither_judged_nor_settled() {
    let mut store = MemoryStore::new();
    store.write(vault(HERE), encode_amount(500).to_vec());
    let entry = || {
        BatchTx::new(
            tx(1),
            declared(&[reserve(HERE, 100), reserve(THERE, 100)], vec![]),
            env(),
        )
    };

    let whole = run(&store, entry(), &Locality::All);
    assert_eq!(
        whole.outcome,
        Outcome::Infeasible {
            key: vault(THERE),
            amount: 100,
        },
        "run whole, the remote cell is an empty balance",
    );

    let batch = run_batch(
        &store,
        entry().with_scope(ExecutionScope::spanning(only(&[HERE]))),
        &Locality::Owned(Arc::new(only(&[HERE]))),
    );
    let leg = &batch.receipts[&tx(1)];
    assert!(matches!(leg.outcome, Outcome::Completed { .. }), "{leg:?}");
    assert!(
        !leg.delta.settles.contains_key(&vault(THERE)),
        "and nothing was settled on a hold nobody took",
    );
    // Nor was one adopted: the remote-reservation path holds a cell at
    // its declared amount for the owning shard to judge, and a cell
    // outside the scope has no such shard in this execution.
    assert_eq!(batch.store.held_reservation(vault(THERE), tx(1)), None);
}

/// A capability's rep is its index into a table built from the whole
/// declaration, so a member that judged less still hands its guest the
/// same handles at the same positions. The one failure here is a valid
/// receipt over the wrong cell, so the equality is pinned directly.
#[test]
fn capability_reps_are_identical_whole_and_decomposed() {
    let mut store = MemoryStore::new();
    store.write(vault(HERE), encode_amount(500).to_vec());
    store.write(vault(THERE), encode_amount(500).to_vec());
    let declaration = declared(
        &[
            reserve(THERE, 100),
            write(THERE),
            reserve(HERE, 100),
            write(HERE),
        ],
        vec![],
    );

    let whole = KernelSession::materialize(
        OverlayStore::new(Arc::new(store.clone())),
        &declaration,
        tx(1),
        env(),
        test_hash,
    )
    .expect("everything is provisioned");
    let leg = KernelSession::materialize_within(
        OverlayStore::new(Arc::new(store)),
        &declaration,
        tx(1),
        env(),
        test_hash,
        &ExecutionScope::spanning(only(&[HERE])),
    )
    .expect("the leg judges only its own");

    assert_eq!(whole.capabilities().len(), declaration.ordered.len());
    assert_eq!(whole.capabilities(), leg.capabilities());
}

/// A condition on a leaf outside the scope is another member's
/// question; one inside is still this member's.
#[test]
fn a_condition_outside_the_scope_is_not_this_members_question() {
    let mut store = MemoryStore::new();
    store.write(cell(HERE), vec![1]);
    let remote = || {
        BatchTx::new(
            tx(2),
            declared(
                &[read(HERE), read(THERE)],
                vec![Condition::declared(present(THERE))],
            ),
            env(),
        )
    };

    assert!(
        matches!(
            run(&store, remote(), &Locality::All).outcome,
            Outcome::ConditionUnmet { .. }
        ),
        "run whole, the absent leaf refuses it",
    );
    assert!(matches!(
        run(
            &store,
            remote().with_scope(ExecutionScope::spanning(only(&[HERE]))),
            &Locality::All,
        )
        .outcome,
        Outcome::Completed { .. }
    ));
    // The same leaf inside a wider scope is judged as ever.
    assert!(matches!(
        run(
            &store,
            remote().with_scope(ExecutionScope::spanning(only(&[HERE, THERE]))),
            &Locality::All,
        )
        .outcome,
        Outcome::ConditionUnmet { .. }
    ));
}

/// A rule with leaves on both sides of the scope is one no member can
/// judge whole, and half a verdict is not a verdict: it refuses as the
/// classifier's defect rather than being answered from what is in reach.
#[test]
fn a_condition_straddling_the_scope_refuses() {
    let mut store = MemoryStore::new();
    store.write(cell(HERE), vec![1]);
    let either = || Rule::CountOf {
        count: 1,
        rules: vec![present(HERE), present(THERE)],
    };
    let entry = || {
        BatchTx::new(
            tx(4),
            declared(
                &[read(HERE), read(THERE)],
                vec![Condition::declared(either())],
            ),
            env(),
        )
    };

    // Met on the local branch alone, run whole.
    assert!(matches!(
        run(&store, entry(), &Locality::All).outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        run(
            &store,
            entry().with_scope(ExecutionScope::spanning(only(&[HERE]))),
            &Locality::All,
        )
        .outcome,
        Outcome::ProtocolError {
            reason: AbortReason::ConditionStraddlesScope,
        },
    );
}

/// A member of a core spanning two shards has both in scope and derives
/// the whole receipt, whichever shard it applies to — so the two
/// members' receipts agree. A reservation on the far shard's cell is
/// held here at its declared amount for that shard to judge, exactly as
/// a whole cross-shard execution holds one; what the scope adds is that
/// a condition on the far leaf is this member's question too.
#[test]
fn a_two_shard_core_judges_both_shards_and_agrees() {
    let mut store = MemoryStore::new();
    store.write(vault(HERE), encode_amount(500).to_vec());
    store.write(vault(THERE), encode_amount(50).to_vec());
    let core = || ExecutionScope::spanning(only(&[HERE, THERE]));
    let here = Locality::Owned(Arc::new(only(&[HERE])));
    let there = Locality::Owned(Arc::new(only(&[THERE])));
    let entry = |amount: u128| {
        BatchTx::new(
            tx(5),
            declared(&[reserve(HERE, 100), reserve(THERE, amount)], vec![]),
            env(),
        )
        .with_scope(core())
    };

    let near = run(&store, entry(10), &here);
    let far = run(&store, entry(10), &there);
    assert!(
        matches!(near.outcome, Outcome::Completed { .. }),
        "{near:?}"
    );
    assert_eq!(near, far, "one execution, two members");

    // The far shard judges its own cell and refuses; the near member
    // held it unjudged at the declared amount, which is the combine's
    // to reconcile.
    let refused = run(&store, entry(60), &there);
    assert_eq!(
        refused.outcome,
        Outcome::Infeasible {
            key: vault(THERE),
            amount: 60,
        },
    );
    let adopted = run_batch(&store, entry(60), &here);
    assert!(matches!(
        adopted.receipts[&tx(5)].outcome,
        Outcome::Completed { .. }
    ));

    // And the far leaf is in scope: a condition on it is judged here,
    // where a leg member would have left it to the far shard.
    let absent = || {
        BatchTx::new(
            tx(6),
            declared(
                &[read(HERE), read(THERE)],
                vec![Condition::declared(present(THERE))],
            ),
            env(),
        )
    };
    assert!(matches!(
        run(&store, absent().with_scope(core()), &here).outcome,
        Outcome::ConditionUnmet { .. }
    ));
    assert!(matches!(
        run(
            &store,
            absent().with_scope(ExecutionScope::spanning(only(&[HERE]))),
            &here,
        )
        .outcome,
        Outcome::Completed { .. }
    ));
}

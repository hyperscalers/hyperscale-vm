//! Declared conditions, judged where their state lives: a presence
//! condition at materialization by the shard holding the leaf, an
//! authority condition at the calling node with that call's evidence.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use hyperscale_vm_effects::{
    AuthBase, AuthCell, Condition, Declaration, Hash32, Hasher, JudgedLeaf, MAX_RULE_BRANCHES,
    MAX_RULE_DEPTH, NodeCall, PRIMARY, PackageHash, Presented, RoleTable, Rule, SlotId, StoredRule,
    TestHasher, child_key,
};
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, Locality, ManifestWalk, MemoryStore, Substates, execute_batch,
};
use hyperscale_vm_types::{
    Address, AddressClass, CallTarget, CollectionId, Effect, EffectSet, EffectTarget, Mode,
    Outcome, Presence, ResourceAddr, SubstateKey, TxHash, UnmetCondition,
};

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 1_000,
        randomness: [1; 32],
    }
}

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

const fn principal(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Principal)
}

fn identity(byte: u8) -> Presented {
    Presented::Identity(CallTarget::try_from(principal(byte)).unwrap())
}

fn cell_of(owner: Address) -> SubstateKey {
    child_key(&TestHasher, owner, SlotId(4), &[])
}

/// A declaration reading `key`, requiring the conditions beside it —
/// the folded set holding the backing access every condition's target
/// has, as the publish check guarantees.
fn declaring(key: SubstateKey, conditions: Vec<Condition>) -> Declaration {
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(key),
        mode: Mode::Read,
    })
    .unwrap();
    let mut declaration = Declaration::from_set(set);
    declaration.conditions = conditions;
    declaration
}

fn run(store: &MemoryStore, batch: &[BatchTx]) -> Outcome {
    run_at(store, batch, &Locality::All)
}

fn run_at(store: &MemoryStore, batch: &[BatchTx], locality: &Locality) -> Outcome {
    let outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &ManifestWalk { backend: &Inert },
        test_hash,
        ExecutionMode::Serial,
        locality,
    )
    .unwrap();
    outcome.receipts[&batch[0].tx].outcome.clone()
}

/// A shard owning exactly the keys whose owner starts with `byte`.
fn owned_by(byte: u8) -> Locality {
    Locality::Owned(Arc::new(move |owner: Address| owner.to_bytes()[0] == byte))
}

/// A backend whose every invocation succeeds and produces nothing: the
/// walk's own judgments — the gate, the required conditions — are what
/// these tests are about, and they run before any body does.
struct Inert;

impl GuestBackend for Inert {
    fn invoke(&self, session: KernelSession, _call: &GuestCall<'_>) -> InvokeResult {
        InvokeResult {
            session,
            fuel: 0,
            result: Invoked::Produced {
                edges: Vec::new(),
                answer: None,
            },
            exhausted: false,
        }
    }
}

/// The one lowered call these fixtures need: no arguments, no edges,
/// judged on its evidence against what it requires.
fn call(target: Address, evidence: Vec<Presented>, requires: Vec<Rule<JudgedLeaf>>) -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target,
        export: "noop".into(),
        args: Vec::new(),
        edges: Vec::new(),
        outputs: Vec::new(),
        issues: None,
        evidence,
        requires,
    }
}

#[test]
fn a_presence_condition_is_judged_against_the_committed_leaf() {
    let owner = principal(1);
    let key = cell_of(owner);
    let holds = |presence| {
        vec![Condition::Holds {
            target: EffectTarget::Point(key),
            presence,
        }]
    };

    let empty = MemoryStore::new();
    let mut occupied = MemoryStore::new();
    occupied.write(key, vec![7]);

    // Required present: met where the leaf is, unmet where it is not.
    let requiring_present = |store| {
        run(
            store,
            &[BatchTx::new(
                tx(1),
                declaring(key, holds(Presence::Present)),
                env(),
            )],
        )
    };
    assert!(matches!(
        requiring_present(&occupied),
        Outcome::Completed { .. }
    ));
    assert_eq!(
        requiring_present(&empty),
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(key),
                required: Presence::Present,
            },
        }
    );

    // Required absent: the mirror.
    let requiring_absent = |store| {
        run(
            store,
            &[BatchTx::new(
                tx(2),
                declaring(key, holds(Presence::Absent)),
                env(),
            )],
        )
    };
    assert!(matches!(
        requiring_absent(&empty),
        Outcome::Completed { .. }
    ));
    assert_eq!(
        requiring_absent(&occupied),
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(key),
                required: Presence::Absent,
            },
        }
    );
}

#[test]
fn a_required_claim_is_judged_with_the_calls_own_evidence() {
    let target = principal(1);
    let key = cell_of(target);
    let requires = vec![Rule::Require(JudgedLeaf::Claim(identity(9)))];

    let judged = |evidence: Vec<Presented>| {
        let mut entry = BatchTx::new(tx(3), declaring(key, Vec::new()), env());
        entry.calls = vec![call(target, evidence, requires.clone())];
        run(&MemoryStore::new(), &[entry])
    };

    assert!(matches!(
        judged(vec![identity(9)]),
        Outcome::Completed { .. }
    ));
    assert_eq!(
        judged(vec![identity(2)]),
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        }
    );
}

/// A stored leaf reads the cell the declaration provisioned and judges
/// the rule the named role selects there — and over an absent cell it
/// judges the virtual rule, the identity the cell's owner derives, which
/// only a key-derived principal can ever present.
#[test]
fn a_stored_leaf_judges_the_stored_rule_and_the_virtual_one() {
    let target = principal(1);
    let key = cell_of(target);
    let requires = vec![Rule::Require(JudgedLeaf::Stored {
        cell: key,
        role: PRIMARY,
    })];

    let judged = |store: &MemoryStore, evidence: Vec<Presented>| {
        let mut entry = BatchTx::new(tx(4), declaring(key, Vec::new()), env());
        entry.calls = vec![call(target, evidence, requires.clone())];
        run(store, &[entry])
    };
    let unmet = Outcome::ConditionUnmet {
        condition: UnmetCondition::Satisfies { node: 0 },
    };

    // Stored: the rule in the cell governs, and the derived identity is
    // no longer one of them.
    let mut securified = MemoryStore::new();
    let roles = RoleTable::uniform(&StoredRule::Require(identity(2))).unwrap();
    let cell = AuthCell::new(AuthBase::new(1_000, roles))
        .to_bytes()
        .unwrap();
    securified.write(key, cell);
    assert!(matches!(
        judged(&securified, vec![identity(2)]),
        Outcome::Completed { .. }
    ));
    assert_eq!(judged(&securified, vec![identity(1)]), unmet);

    // Absent: the virtual rule — the identity the owner's address
    // derives — and nothing else.
    let virtual_store = MemoryStore::new();
    assert!(matches!(
        judged(&virtual_store, vec![identity(1)]),
        Outcome::Completed { .. }
    ));
    assert_eq!(judged(&virtual_store, vec![identity(2)]), unmet);
}

/// A component's address is derived from no key, so its absent table's
/// virtual rule is unsatisfiable: nothing mints its identity without
/// satisfying the same absent cell. Whatever else is presented, an
/// unwritten component table denies.
#[test]
fn an_absent_component_table_denies_whatever_is_presented() {
    let component = Address::new([7; 31], AddressClass::Component);
    let key = cell_of(component);
    let mut entry = BatchTx::new(tx(5), declaring(key, Vec::new()), env());
    entry.calls = vec![call(
        component,
        vec![
            identity(1),
            identity(2),
            Presented::Resource(ResourceAddr::new([3; 31])),
        ],
        vec![Rule::Require(JudgedLeaf::Stored {
            cell: key,
            role: PRIMARY,
        })],
    )];
    assert_eq!(
        run(&MemoryStore::new(), &[entry]),
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        }
    );
}

/// Declared and stored leaves mix in one tree: "this named identity, or
/// whoever the stored rule admits" is one threshold with a leaf of each
/// kind.
#[test]
fn a_rule_mixes_claim_and_stored_leaves() {
    let target = principal(1);
    let key = cell_of(target);
    let requires = vec![Rule::CountOf {
        count: 1,
        rules: vec![
            Rule::Require(JudgedLeaf::Claim(identity(9))),
            Rule::Require(JudgedLeaf::Stored {
                cell: key,
                role: PRIMARY,
            }),
        ],
    }];
    let judged = |evidence: Vec<Presented>| {
        let mut entry = BatchTx::new(tx(6), declaring(key, Vec::new()), env());
        entry.calls = vec![call(target, evidence, requires.clone())];
        run(&MemoryStore::new(), &[entry])
    };

    // The claim arm, the virtual-stored arm, and neither.
    assert!(matches!(
        judged(vec![identity(9)]),
        Outcome::Completed { .. }
    ));
    assert!(matches!(
        judged(vec![identity(1)]),
        Outcome::Completed { .. }
    ));
    assert_eq!(
        judged(vec![identity(3)]),
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Satisfies { node: 0 },
        }
    );
}

/// A store that answers from `MemoryStore` and counts what was asked.
///
/// Reads are the observable of the decode: nothing caches a point read
/// between the layers and the base, so one `cell` call is one decode of
/// the stored table.
#[derive(Debug)]
struct Counting {
    inner: MemoryStore,
    reads: Mutex<BTreeMap<SubstateKey, usize>>,
}

impl Counting {
    const fn over(inner: MemoryStore) -> Self {
        Self {
            inner,
            reads: Mutex::new(BTreeMap::new()),
        }
    }

    fn reads_of(&self, key: SubstateKey) -> usize {
        self.reads.lock().unwrap().get(&key).copied().unwrap_or(0)
    }
}

impl Substates for Counting {
    fn cell(&self, key: SubstateKey) -> Option<Vec<u8>> {
        *self.reads.lock().unwrap().entry(key).or_default() += 1;
        self.inner.cell(key)
    }

    fn entries_in_range(
        &self,
        owner: Address,
        collection: CollectionId,
        lo: u128,
        hi: u128,
        limit: usize,
    ) -> Vec<(u128, Vec<u8>)> {
        self.inner
            .entries_in_range(owner, collection, lo, hi, limit)
    }
}

impl Baseline for Counting {
    fn holds(&self, key: SubstateKey) -> BTreeMap<TxHash, u128> {
        self.inner.holds(key)
    }
}

/// The widest rule the caps admit, every leaf naming one cell: the
/// judgment is priced as the single read the declaration made, so it
/// costs one — the verdict a leaf reaches cannot move under it, because
/// a gate is judged against committed state before any body runs.
#[test]
fn a_rule_naming_one_cell_at_every_leaf_reads_it_once() {
    let target = principal(1);
    let key = cell_of(target);

    // MAX_RULE_BRANCHES^(MAX_RULE_DEPTH - 1) stored leaves, all the
    // same cell and role.
    let leaf = Rule::Require(JudgedLeaf::Stored {
        cell: key,
        role: PRIMARY,
    });
    let widest = (1..MAX_RULE_DEPTH).fold(leaf, |inner: Rule<JudgedLeaf>, _| Rule::CountOf {
        count: u8::try_from(MAX_RULE_BRANCHES).unwrap(),
        rules: vec![inner; MAX_RULE_BRANCHES],
    });
    assert_eq!(
        widest.leaves().count(),
        MAX_RULE_BRANCHES.pow(u32::try_from(MAX_RULE_DEPTH - 1).unwrap())
    );

    let mut securified = MemoryStore::new();
    let roles = RoleTable::uniform(&StoredRule::Require(identity(2))).unwrap();
    securified.write(
        key,
        AuthCell::new(AuthBase::new(1_000, roles))
            .to_bytes()
            .unwrap(),
    );

    let judged = |evidence: Vec<Presented>| {
        let store = Arc::new(Counting::over(securified.clone()));
        let mut entry = BatchTx::new(tx(7), declaring(key, Vec::new()), env());
        entry.calls = vec![call(target, evidence, vec![widest.clone()])];
        let outcome = execute_batch(
            store.clone(),
            &[entry],
            &ManifestWalk { backend: &Inert },
            test_hash,
            ExecutionMode::Serial,
            &Locality::All,
        )
        .unwrap();
        (
            outcome.receipts[&tx(7)].outcome.clone(),
            store.reads_of(key),
        )
    };

    // The verdict the uncached judgment reaches, both ways, and one read
    // of the cell to reach either.
    let cell = securified.cell(key).unwrap();
    for (evidence, expected) in [(identity(2), true), (identity(1), false)] {
        assert_eq!(
            AuthCell::admits(
                &cell,
                target,
                PRIMARY,
                std::slice::from_ref(&evidence),
                env().clock_ms,
            ),
            expected
        );
        let (outcome, reads) = judged(vec![evidence]);
        assert_eq!(matches!(outcome, Outcome::Completed { .. }), expected);
        assert_eq!(reads, 1);
    }
}

/// A condition is judged at every participant, whichever shard owns the
/// cell it reads.
///
/// This is what the whole design rests on: a condition's target is also
/// a declared `Read`, so the state it reads is provisioned to every
/// shard the transaction touches, and a shard owning none of it reaches
/// the verdict the owner reaches rather than skipping the judgment.
#[test]
fn a_condition_over_a_remote_cell_is_judged_where_the_call_runs() {
    let owner = principal(1);
    let key = cell_of(owner);
    // The materializing shard owns nothing under this owner; the cell
    // reaches it as a provision.
    let elsewhere = owned_by(2);
    assert!(!elsewhere.is_local(owner));

    let conditions = vec![Condition::Holds {
        target: EffectTarget::Point(key),
        presence: Presence::Present,
    }];
    let requires = vec![Rule::Require(JudgedLeaf::Stored {
        cell: key,
        role: PRIMARY,
    })];

    let mut securified = MemoryStore::new();
    let roles = RoleTable::uniform(&StoredRule::Require(identity(2))).unwrap();
    securified.write(
        key,
        AuthCell::new(AuthBase::new(1_000, roles))
            .to_bytes()
            .unwrap(),
    );

    let judged = |store: &MemoryStore, locality: &Locality, evidence: Vec<Presented>| {
        let mut entry = BatchTx::new(tx(8), declaring(key, conditions.clone()), env());
        entry.calls = vec![call(owner, evidence, requires.clone())];
        run_at(store, &[entry], locality)
    };

    // Both conditions met, both localities: the presence at
    // materialization and the stored rule at the call.
    for locality in [&Locality::All, &elsewhere] {
        assert!(matches!(
            judged(&securified, locality, vec![identity(2)]),
            Outcome::Completed { .. }
        ));
    }

    // The presence, unmet on both — the shard that owns no part of the
    // cell refuses exactly where the owner does.
    for locality in [&Locality::All, &elsewhere] {
        assert_eq!(
            judged(&MemoryStore::new(), locality, vec![identity(2)]),
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    target: EffectTarget::Point(key),
                    required: Presence::Present,
                },
            }
        );
    }

    // And the stored rule, on the same terms.
    for locality in [&Locality::All, &elsewhere] {
        assert_eq!(
            judged(&securified, locality, vec![identity(9)]),
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { node: 0 },
            }
        );
    }
}

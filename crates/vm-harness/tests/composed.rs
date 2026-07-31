//! The composed-transaction fixture: a two-signer envelope tree —
//! composer and subintent trading across yield edges — admitted,
//! routed, and executed through the batch executor on both runtimes,
//! with the nullifier making the subintent once-only.

use std::collections::BTreeMap;
use std::sync::Arc;

use hyperscale_vm_effects::stdlib::{VAULT, account_metadata};
use hyperscale_vm_effects::{
    Address, AdmittedTree, Constraint, EdgeRef, EffectSet, EnvelopeTree, GraphArg, GraphNode,
    Hasher, InstanceMeta, InstanceRegistry, IntentDecl, ManifestGraph, MetadataCache, Node,
    NodeInput, PackageHash, PrefixShardResolver, ShardId, Subintent, SubstateKey, TestHasher,
    Value, YieldBinding, YieldParam, admit_tree, child_key, route_tree,
};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    BatchOutcome, BatchTx, Capability, EnvInputs, ExecutionMode, GuestRunner, KernelSession,
    Locality, MemoryStore, Outcome, RunResult, SubstateStore, TxHash, decode_amount, encode_amount,
    execute_batch,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::Context;
use wasmtime::{Engine, Result, Store};

const ALICE: Address = Address([0x10; 16]);
const BOB: Address = Address([0x20; 16]);
const CAROL: Address = Address([0x30; 16]);
const RES_X: Address = Address([0xE1; 16]);
const RES_Y: Address = Address([0xE2; 16]);

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 3_000,
        randomness: [6; 32],
    }
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    for account in [ALICE, BOB, CAROL] {
        instances.register(
            account,
            InstanceMeta {
                package: pkg(),
                config: vec![],
            },
        );
    }
    (cache, instances)
}

fn vault(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn withdraw(target: Address, resource: Address, amount: u128) -> GraphNode {
    GraphNode {
        target,
        method: "withdraw".into(),
        args: vec![
            GraphArg::Literal(Value::Address(resource)),
            GraphArg::Literal(Value::U128(amount)),
        ],
    }
}

fn deposit_param(target: Address, param: u32) -> GraphNode {
    GraphNode {
        target,
        method: "deposit".into(),
        args: vec![GraphArg::Param(param)],
    }
}

/// The composition: the composer pays `pay` of X for the subintent's 10
/// Y — each side withdraws its leg and deposits the other's yield.
fn composed_tree(composer: Address, pay: u128) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph: ManifestGraph {
                nodes: vec![withdraw(composer, RES_X, pay), deposit_param(composer, 0)],
            },
            params: vec![YieldParam {
                resource: RES_Y,
                constraints: vec![Constraint::MinAmount(10)],
            }],
        },
        root_bindings: vec![YieldBinding {
            intent: 1,
            edge: EdgeRef {
                producer: 0,
                output: 0,
            },
        }],
        subintents: vec![Subintent {
            decl: IntentDecl {
                graph: ManifestGraph {
                    nodes: vec![withdraw(BOB, RES_Y, 10), deposit_param(BOB, 0)],
                },
                params: vec![YieldParam {
                    resource: RES_X,
                    constraints: vec![Constraint::MinAmount(100)],
                }],
            },
            signer: BOB,
            bindings: vec![YieldBinding {
                intent: 0,
                edge: EdgeRef {
                    producer: 0,
                    output: 0,
                },
            }],
        }],
    }
}

/// Admit and route one envelope into its batch entry, plus the manifest
/// its runner walks.
fn batch_entry(
    world: &(MetadataCache, InstanceRegistry),
    tree: &EnvelopeTree,
) -> Result<(BatchTx, AdmittedTree)> {
    let (cache, instances) = world;
    let identity = tree.hash(&TestHasher);
    let admitted =
        admit_tree(tree, identity, cache, instances, &TestHasher).context("admission")?;
    let routing = route_tree(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )
    .context("routing")?;
    let declared: EffectSet = routing.per_shard[&ShardId(0)].clone();
    let entry = BatchTx {
        tx: TxHash(identity.0),
        declared,
        nullifiers: admitted
            .subintents
            .iter()
            .map(|record| record.nullifier)
            .collect(),
    };
    Ok((entry, admitted))
}

/// One node's guest invocation, resolved from the flattened manifest.
enum NodeCall {
    Withdraw { vault: SubstateKey, amount: Vec<u8> },
    Deposit { vault: SubstateKey, bucket: Vec<u8> },
}

fn resolve_call(node: &Node, outputs: &[Vec<Vec<u8>>]) -> NodeCall {
    match node.method.as_str() {
        "withdraw" => {
            let [
                NodeInput::Literal(Value::Address(resource)),
                NodeInput::Literal(Value::U128(amount)),
            ] = node.inputs.as_slice()
            else {
                panic!("withdraw inputs");
            };
            NodeCall::Withdraw {
                vault: vault(node.target, *resource),
                amount: encode_amount(*amount).to_vec(),
            }
        }
        "deposit" => {
            let [NodeInput::Edge { source, resource }] = node.inputs.as_slice() else {
                panic!("deposit inputs");
            };
            NodeCall::Deposit {
                vault: vault(node.target, *resource),
                bucket: outputs[*source as usize][0].clone(),
            }
        }
        other => panic!("unknown composed node {other}"),
    }
}

fn rep_of(session: &KernelSession, wanted: &Capability) -> u32 {
    u32::try_from(
        session
            .capabilities()
            .iter()
            .position(|c| c == wanted)
            .expect("capability present"),
    )
    .expect("bounded")
}

/// The blessed-engine runner: walks the flattened manifest node by
/// node, one instantiation per call, threading bucket cells along the
/// lowered edges.
struct BlessedComposed {
    engine: Engine,
    component: Component,
    manifests: BTreeMap<TxHash, Vec<Node>>,
}

impl GuestRunner for BlessedComposed {
    fn run(&self, id: TxHash, session: KernelSession) -> RunResult {
        let mut session = session;
        let mut outputs: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut fuel_total = 0;
        for node in &self.manifests[&id] {
            let call = resolve_call(node, &outputs);
            let mut linker = Linker::<SessionHost>::new(&self.engine);
            add_kernel_to_linker(&mut linker).expect("wiring");
            let mut store = Store::new(&self.engine, SessionHost(session));
            store.set_fuel(FUEL).expect("fuel");
            let instance = linker
                .instantiate(&mut store, &self.component)
                .expect("instantiate");
            let result = match &call {
                NodeCall::Withdraw { vault, amount } => {
                    let rep = rep_of(&store.data().0, &Capability::Reserve(*vault));
                    instance
                        .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(
                            &mut store, "withdraw",
                        )
                        .expect("typed")
                        .call(&mut store, (Resource::new_borrow(rep), amount))
                        .map(|(bucket,)| vec![bucket])
                }
                NodeCall::Deposit { vault, bucket } => {
                    let rep = rep_of(&store.data().0, &Capability::Delta(*vault));
                    instance
                        .get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")
                        .expect("typed")
                        .call(&mut store, (Resource::new_borrow(rep), bucket))
                        .map(|()| Vec::new())
                }
            };
            fuel_total += FUEL - store.get_fuel().expect("fuel");
            session = store.into_data().0;
            match result {
                Ok(node_outputs) => outputs.push(node_outputs),
                Err(_trap) => {
                    return RunResult {
                        session,
                        outcome: Outcome::UserError {
                            reason: "guest trap".into(),
                        },
                        fuel: fuel_total,
                    };
                }
            }
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: fuel_total,
        }
    }
}

/// The reference-interpreter runner, mirroring the blessed walk.
struct RefComposed {
    component: RefComponent,
    manifests: BTreeMap<TxHash, Vec<Node>>,
}

impl GuestRunner for RefComposed {
    fn run(&self, id: TxHash, session: KernelSession) -> RunResult {
        let mut session = session;
        let mut outputs: Vec<Vec<Vec<u8>>> = Vec::new();
        let mut fuel_total = 0;
        for node in &self.manifests[&id] {
            let call = resolve_call(node, &outputs);
            let (export, args, has_output) = match &call {
                NodeCall::Withdraw { vault, amount } => (
                    "withdraw",
                    vec![
                        CVal::Borrow(
                            rep_of(&session, &Capability::Reserve(*vault)),
                            ResourceKind::ReserveCell,
                        ),
                        CVal::Bytes(amount.clone()),
                    ],
                    true,
                ),
                NodeCall::Deposit { vault, bucket } => (
                    "deposit",
                    vec![
                        CVal::Borrow(
                            rep_of(&session, &Capability::Delta(*vault)),
                            ResourceKind::DeltaCell,
                        ),
                        CVal::Bytes(bucket.clone()),
                    ],
                    false,
                ),
            };
            let mut instance =
                RefComponentInstance::instantiate(&self.component, SessionHost(session))
                    .expect("instantiate");
            let outcome = instance.invoke(export, &args).expect("invoke");
            fuel_total += instance.fuel_consumed();
            session = instance.into_host().0;
            match outcome {
                Ok(values) => match (has_output, values.as_slice()) {
                    (false, []) => outputs.push(Vec::new()),
                    (true, [CVal::Bytes(bucket)]) => outputs.push(vec![bucket.clone()]),
                    other => panic!("unexpected result shape {other:?}"),
                },
                Err(_trap) => {
                    return RunResult {
                        session,
                        outcome: Outcome::UserError {
                            reason: "guest trap".into(),
                        },
                        fuel: fuel_total,
                    };
                }
            }
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel: fuel_total,
        }
    }
}

fn seeded_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(CAROL, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(BOB, RES_Y), encode_amount(30).to_vec())
        .unwrap();
    store.clear_log();
    store
}

fn cells(outcome: &BatchOutcome) -> BTreeMap<SubstateKey, Vec<u8>> {
    let store = outcome.store.clone().collapse();
    store
        .cells()
        .map(|(key, value)| (key, value.to_vec()))
        .collect()
}

fn amount_of(outcome: &BatchOutcome, key: SubstateKey) -> u128 {
    cells(outcome)
        .get(&key)
        .map_or(0, |cell| decode_amount(cell).unwrap())
}

/// Execute the batch on both runtimes and assert byte-identical
/// receipts and end state; returns the blessed outcome.
fn run_both(
    store: &MemoryStore,
    batch: &[BatchTx],
    manifests: &BTreeMap<TxHash, Vec<Node>>,
) -> Result<BatchOutcome> {
    let bytes = build_guest("account")?;
    validate_component(&bytes).context("profile validation")?;
    let engine = blessed_engine()?;
    let blessed = BlessedComposed {
        component: Component::new(&engine, &bytes)?,
        engine,
        manifests: manifests.clone(),
    };
    let reference = RefComposed {
        component: RefComponent::decode(&bytes)?,
        manifests: manifests.clone(),
    };
    let blessed_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &blessed,
        env(),
        test_hash,
        ExecutionMode::Parallel,
        &Locality::All,
    )
    .unwrap();
    let ref_outcome = execute_batch(
        Arc::new(store.clone()),
        batch,
        &reference,
        env(),
        test_hash,
        ExecutionMode::Serial,
        &Locality::All,
    )
    .unwrap();
    assert_eq!(
        blessed_outcome.receipts, ref_outcome.receipts,
        "lanes diverged"
    );
    assert_eq!(
        cells(&blessed_outcome),
        cells(&ref_outcome),
        "state diverged"
    );
    Ok(blessed_outcome)
}

#[test]
fn a_composed_transaction_settles_on_both_runtimes() -> Result<()> {
    let world = world();
    let tree = composed_tree(ALICE, 100);
    let (entry, admitted) = batch_entry(&world, &tree)?;
    let manifests = BTreeMap::from([(entry.tx, admitted.admitted.manifest.nodes.clone())]);
    let nullifier = admitted.subintents[0].nullifier;

    let outcome = run_both(&seeded_store(), std::slice::from_ref(&entry), &manifests)?;
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_of(&outcome, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&outcome, vault(ALICE, RES_Y)), 10);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_X)), 100);
    // The spent nullifier records the consuming transaction, receipt and
    // state alike.
    assert_eq!(
        cells(&outcome).get(&nullifier),
        Some(&entry.tx.0.0.to_vec())
    );
    assert_eq!(
        outcome.receipts[&entry.tx].delta.cells.get(&nullifier),
        Some(&Some(entry.tx.0.0.to_vec()))
    );
    Ok(())
}

#[test]
fn racing_compositions_commit_exactly_one() -> Result<()> {
    // Two composers carry the same signed subintent: same nullifier,
    // one conflict group, canonical order picks the winner.
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100))?;
    let (carol_entry, carol_admitted) = batch_entry(&world, &composed_tree(CAROL, 120))?;
    assert_eq!(
        alice_admitted.subintents[0].nullifier,
        carol_admitted.subintents[0].nullifier
    );
    let manifests = BTreeMap::from([
        (
            alice_entry.tx,
            alice_admitted.admitted.manifest.nodes.clone(),
        ),
        (carol_entry.tx, carol_admitted.admitted.manifest.nodes),
    ]);

    let alice_wins = alice_entry.tx < carol_entry.tx;
    let batch = vec![alice_entry.clone(), carol_entry.clone()];
    let outcome = run_both(&seeded_store(), &batch, &manifests)?;

    let (winner, loser, pay) = if alice_wins {
        (&alice_entry, &carol_entry, 100)
    } else {
        (&carol_entry, &alice_entry, 120)
    };
    assert!(matches!(
        outcome.receipts[&winner.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(
        outcome.receipts[&loser.tx].outcome,
        Outcome::UserError {
            reason: "subintent nullifier spent".into(),
        }
    );

    let (winner_addr, loser_addr) = if alice_wins {
        (ALICE, CAROL)
    } else {
        (CAROL, ALICE)
    };
    assert_eq!(amount_of(&outcome, vault(winner_addr, RES_X)), 150 - pay);
    assert_eq!(amount_of(&outcome, vault(winner_addr, RES_Y)), 10);
    assert_eq!(amount_of(&outcome, vault(loser_addr, RES_X)), 150);
    assert_eq!(amount_of(&outcome, vault(loser_addr, RES_Y)), 0);
    // The subintent leg settled exactly once.
    assert_eq!(amount_of(&outcome, vault(BOB, RES_Y)), 20);
    assert_eq!(amount_of(&outcome, vault(BOB, RES_X)), pay);
    assert_eq!(
        cells(&outcome).get(&alice_admitted.subintents[0].nullifier),
        Some(&winner.tx.0.0.to_vec())
    );
    Ok(())
}

#[test]
fn a_spent_nullifier_blocks_the_next_batch() -> Result<()> {
    let world = world();
    let (alice_entry, alice_admitted) = batch_entry(&world, &composed_tree(ALICE, 100))?;
    let (carol_entry, carol_admitted) = batch_entry(&world, &composed_tree(CAROL, 120))?;

    let first = run_both(
        &seeded_store(),
        std::slice::from_ref(&alice_entry),
        &BTreeMap::from([(alice_entry.tx, alice_admitted.admitted.manifest.nodes)]),
    )?;
    let committed = first.store.collapse();

    let second = run_both(
        &committed,
        std::slice::from_ref(&carol_entry),
        &BTreeMap::from([(carol_entry.tx, carol_admitted.admitted.manifest.nodes)]),
    )?;
    assert_eq!(
        second.receipts[&carol_entry.tx].outcome,
        Outcome::UserError {
            reason: "subintent nullifier spent".into(),
        }
    );
    assert_eq!(amount_of(&second, vault(CAROL, RES_X)), 150);
    assert_eq!(amount_of(&second, vault(BOB, RES_Y)), 20);
    Ok(())
}

//! The pattern corpus: transfer, AMM swap, and order book end to end —
//! manifest graph → admission → routing → capability materialization →
//! guest execution → receipt — on both runtimes, with the walkthrough's
//! predicted effect profiles and provision shapes asserted exactly.
//!
//! The guests are the real pinned-toolchain components; the driver walks
//! the admitted graph node by node, threading bucket cells along the
//! edges, with one kernel session covering the transaction and the
//! trace-subset oracle standing at every receipt.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use hyperscale_vm_effects::stdlib::{
    ASKS, CLAIMS, CONFIG, FILL_CAP, VAULT, account_metadata, amm_metadata, book_metadata,
};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, Effect, EffectSet, EffectTarget, GraphArg, GraphNode, Hash32,
    Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache, Mode, NodeInput,
    PackageHash, PrefixShardResolver, Routing, ShardId, SnapshotObligation, SubstateKey,
    TestHasher, Value, Window, admit, child_key, fresh_id, route,
};
use hyperscale_vm_harness::fixtures::{build_guest, repo_root};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Outcome, OverlayStore, Receipt,
    SubstateStore, TxHash, decode_amount, encode_amount,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, RangeWrite, ReserveCell, SnapCell, WriteCell, add_kernel_to_linker, blessed_engine,
    validate_component,
};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::{Context, bail};
use wasmtime::{Engine, Result, Store};

const ALICE: Address = Address([0x10; 16]);
const BOB: Address = Address([0x20; 16]);
const POOL: Address = Address([0x30; 16]);
const BOOK: Address = Address([0x40; 16]);
const MAKER: Address = Address([0x50; 16]);
const TAKER: Address = Address([0x60; 16]);
const CAROL: Address = Address([0x70; 16]);
const RES_X: Address = Address([0xE1; 16]);
const RES_Y: Address = Address([0xE2; 16]);
const BASE: Address = Address([0xE3; 16]);
const QUOTE: Address = Address([0xE4; 16]);

const FUEL: u64 = 1_000_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 5_000,
        randomness: [2; 32],
    }
}

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

fn vault(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn claims(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        CLAIMS,
        &[Value::Address(resource).canonical_bytes()],
    )
}

fn config_leaf(owner: Address) -> SubstateKey {
    child_key(&TestHasher, owner, CONFIG, &[])
}

fn world() -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg("account"), account_metadata());
    cache.publish(pkg("amm"), amm_metadata());
    cache.publish(pkg("book"), book_metadata());
    let mut instances = InstanceRegistry::new();
    for account in [ALICE, BOB, MAKER, TAKER, CAROL] {
        instances.register(
            account,
            InstanceMeta {
                package: pkg("account"),
                config: vec![],
            },
        );
    }
    instances.register(
        POOL,
        InstanceMeta {
            package: pkg("amm"),
            config: vec![Value::Address(RES_X), Value::Address(RES_Y)],
        },
    );
    instances.register(
        BOOK,
        InstanceMeta {
            package: pkg("book"),
            config: vec![Value::Address(BASE), Value::Address(QUOTE)],
        },
    );
    (cache, instances)
}

/// Both runtimes' compiled guests.
struct Engines {
    engine: Engine,
    blessed: BTreeMap<&'static str, Component>,
    reference: BTreeMap<&'static str, RefComponent>,
}

impl Engines {
    fn build() -> Result<Self> {
        let engine = blessed_engine()?;
        let mut blessed = BTreeMap::new();
        let mut reference = BTreeMap::new();
        for name in ["account", "amm", "book"] {
            let bytes = build_guest(name)?;
            validate_component(&bytes).with_context(|| format!("profile validation of {name}"))?;
            blessed.insert(name, Component::new(&engine, &bytes)?);
            reference.insert(name, RefComponent::decode(&bytes)?);
        }
        Ok(Self {
            engine,
            blessed,
            reference,
        })
    }
}

const fn guest_for(target: Address) -> &'static str {
    match target.0[0] {
        0x30 => "amm",
        0x40 => "book",
        _ => "account",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Blessed,
    Reference,
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

fn range_rep(session: &KernelSession, one_entry: bool) -> u32 {
    u32::try_from(
        session
            .capabilities()
            .iter()
            .position(
                |c| matches!(c, Capability::RangeWrite { lo, hi, .. } if (lo == hi) == one_entry),
            )
            .expect("range capability present"),
    )
    .expect("bounded")
}

/// One node's guest invocation: the handles it receives (in export
/// parameter order), its scalar params, and the bucket cells flowing in.
enum NodeCall {
    Withdraw {
        vault: SubstateKey,
        amount: Vec<u8>,
    },
    Deposit {
        vault: SubstateKey,
        bucket: Vec<u8>,
    },
    AssertBalance {
        vault: SubstateKey,
        min: Vec<u8>,
    },
    Swap {
        config: SubstateKey,
        reserve_in: SubstateKey,
        reserve_out: SubstateKey,
        input: Vec<u8>,
        min_out: Vec<u8>,
    },
    Place {
        escrow: SubstateKey,
        price: u64,
        seq: u64,
        bucket: Vec<u8>,
    },
    Fill {
        base: SubstateKey,
        quote: SubstateKey,
        budget: Vec<u8>,
    },
}

/// How one transaction ended on a lane.
#[derive(Debug, PartialEq, Eq)]
enum TxResult {
    Completed(Receipt),
    Trapped,
}

/// Execute one admitted manifest: walk the graph's nodes in order,
/// invoking each guest with its capabilities and edge cells, then finish
/// the session into a receipt. Returns the outcome and, when completed,
/// the threaded store for the next transaction.
#[allow(clippy::too_many_lines)] // one dispatch per corpus node shape
fn execute_manifest(
    lane: Lane,
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: MemoryStore,
    graph: &ManifestGraph,
    tx: TxHash,
) -> Result<(TxResult, MemoryStore)> {
    let (cache, instances) = world;
    let admitted = admit(graph, cache, instances, &TestHasher).context("admission")?;
    let routing = route(
        &admitted.manifest,
        admitted.identity,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )
    .context("routing")?;
    let declared = &routing.per_shard[&ShardId(0)];
    let identity = admitted.identity;
    let manifest = admitted.manifest;

    let before = store.clone();
    let mut session = KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        declared,
        tx,
        env(),
        test_hash,
    )
    .expect("corpus manifests are feasible");

    // Per-node outputs: the bucket cells later nodes consume.
    let mut outputs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(graph.nodes.len());
    let mut fuel_total = 0u64;

    for (index, node) in graph.nodes.iter().enumerate() {
        let edge_cell = |edge: &EdgeRef| -> Vec<u8> {
            outputs[edge.producer as usize][edge.output as usize].clone()
        };
        let edge_resource = |edge: &EdgeRef| -> Address {
            // The lowered manifest carries the admitted edge type.
            match &manifest.nodes[index].inputs[node
                .args
                .iter()
                .position(|arg| matches!(arg, GraphArg::Edge { edge: e, .. } if e == edge))
                .expect("edge arg present")]
            {
                NodeInput::Edge { resource, .. } => *resource,
                NodeInput::Literal(_) => unreachable!("edge input"),
            }
        };

        let call = match (guest_for(node.target), node.method.as_str()) {
            ("account", "withdraw") => {
                let (
                    GraphArg::Literal(Value::Address(resource)),
                    GraphArg::Literal(Value::U128(amount)),
                ) = (&node.args[0], &node.args[1])
                else {
                    bail!("withdraw args");
                };
                NodeCall::Withdraw {
                    vault: vault(node.target, *resource),
                    amount: encode_amount(*amount).to_vec(),
                }
            }
            ("account", "deposit") => {
                let GraphArg::Edge { edge, .. } = &node.args[0] else {
                    bail!("deposit args");
                };
                NodeCall::Deposit {
                    vault: vault(node.target, edge_resource(edge)),
                    bucket: edge_cell(edge),
                }
            }
            ("account", "assert-balance") => {
                let (
                    GraphArg::Literal(Value::Address(resource)),
                    GraphArg::Literal(Value::U128(min)),
                ) = (&node.args[0], &node.args[1])
                else {
                    bail!("assert-balance args");
                };
                NodeCall::AssertBalance {
                    vault: vault(node.target, *resource),
                    min: encode_amount(*min).to_vec(),
                }
            }
            ("amm", "swap") => {
                let (GraphArg::Edge { edge, .. }, GraphArg::Literal(Value::U128(min_out))) =
                    (&node.args[0], &node.args[1])
                else {
                    bail!("swap args");
                };
                let input_resource = edge_resource(edge);
                let output_resource = if input_resource == RES_X {
                    RES_Y
                } else {
                    RES_X
                };
                NodeCall::Swap {
                    config: config_leaf(POOL),
                    reserve_in: vault(POOL, input_resource),
                    reserve_out: vault(POOL, output_resource),
                    input: edge_cell(edge),
                    min_out: encode_amount(*min_out).to_vec(),
                }
            }
            ("book", "place_ask") => {
                let (GraphArg::Literal(Value::U64(price)), GraphArg::Edge { edge, .. }) =
                    (&node.args[0], &node.args[1])
                else {
                    bail!("place args");
                };
                let seq = fresh_id(
                    &TestHasher,
                    identity,
                    u32::try_from(index).expect("bounded"),
                    0,
                    0,
                );
                NodeCall::Place {
                    escrow: vault(BOOK, edge_resource(edge)),
                    price: *price,
                    seq,
                    bucket: edge_cell(edge),
                }
            }
            ("book", "fill_asks") => {
                let GraphArg::Edge { edge, .. } = &node.args[2] else {
                    bail!("fill args");
                };
                NodeCall::Fill {
                    base: vault(BOOK, BASE),
                    quote: vault(BOOK, edge_resource(edge)),
                    budget: edge_cell(edge),
                }
            }
            other => bail!("unknown corpus node {other:?}"),
        };

        let guest = guest_for(node.target);
        let invoked = invoke_node(lane, engines, guest, session, &call);
        let (returned_session, node_outputs, fuel) = match invoked {
            Ok(ok) => ok,
            Err(_trap) => return Ok((TxResult::Trapped, before)),
        };
        session = returned_session;
        fuel_total += fuel;
        outputs.push(node_outputs);
    }

    let (receipt, threaded) = session
        .finish(Outcome::Completed { value: None }, fuel_total)
        .expect("the oracle stands on every corpus receipt");
    Ok((TxResult::Completed(receipt), threaded.collapse()))
}

type Invoked = (KernelSession, Vec<Vec<u8>>, u64);

/// Invoke one node's export on the chosen lane. An `Err` is a guest trap;
/// the session is gone with its engine store, and the caller rolls back.
fn invoke_node(
    lane: Lane,
    engines: &Engines,
    guest: &str,
    session: KernelSession,
    call: &NodeCall,
) -> std::result::Result<Invoked, String> {
    match lane {
        Lane::Blessed => invoke_blessed(engines, guest, session, call),
        Lane::Reference => invoke_reference(engines, guest, session, call),
    }
}

#[allow(clippy::too_many_lines)] // one typed invocation per export shape
fn invoke_blessed(
    engines: &Engines,
    guest: &str,
    session: KernelSession,
    call: &NodeCall,
) -> std::result::Result<Invoked, String> {
    let mut linker = Linker::<SessionHost>::new(&engines.engine);
    add_kernel_to_linker(&mut linker).expect("wiring");
    let mut store = Store::new(&engines.engine, SessionHost(session));
    store.set_fuel(FUEL).expect("fuel");
    let instance = linker
        .instantiate(&mut store, &engines.blessed[guest])
        .expect("instantiate");

    let outputs = match call {
        NodeCall::Withdraw { vault, amount } => {
            let rep = rep_of(&store.data().0, &Capability::Reserve(*vault));
            let f = instance
                .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(
                    &mut store, "withdraw",
                )
                .expect("typed");
            f.call(&mut store, (Resource::new_borrow(rep), amount))
                .map(|(v,)| vec![v])
        }
        NodeCall::Deposit { vault, bucket } => {
            let rep = rep_of(&store.data().0, &Capability::Delta(*vault));
            let f = instance
                .get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")
                .expect("typed");
            f.call(&mut store, (Resource::new_borrow(rep), bucket))
                .map(|()| Vec::new())
        }
        NodeCall::AssertBalance { vault, min } => {
            let rep = rep_of(&store.data().0, &Capability::Snapshot(*vault));
            let f = instance
                .get_typed_func::<(Resource<SnapCell>, &[u8]), ()>(&mut store, "assert-balance")
                .expect("typed");
            f.call(&mut store, (Resource::new_borrow(rep), min))
                .map(|()| Vec::new())
        }
        NodeCall::Swap {
            config,
            reserve_in,
            reserve_out,
            input,
            min_out,
        } => {
            let c = rep_of(&store.data().0, &Capability::Snapshot(*config));
            let rin = rep_of(&store.data().0, &Capability::Write(*reserve_in));
            let rout = rep_of(&store.data().0, &Capability::Write(*reserve_out));
            let f = instance
                .get_typed_func::<(
                    Resource<SnapCell>,
                    Resource<WriteCell>,
                    Resource<WriteCell>,
                    &[u8],
                    &[u8],
                ), (Vec<u8>,)>(&mut store, "swap")
                .expect("typed");
            f.call(
                &mut store,
                (
                    Resource::new_borrow(c),
                    Resource::new_borrow(rin),
                    Resource::new_borrow(rout),
                    input,
                    min_out,
                ),
            )
            .map(|(v,)| vec![v])
        }
        NodeCall::Place {
            escrow,
            price,
            seq,
            bucket,
        } => {
            let range = range_rep(&store.data().0, true);
            let vault_rep = rep_of(&store.data().0, &Capability::Delta(*escrow));
            let f = instance
                .get_typed_func::<(Resource<RangeWrite>, Resource<DeltaCell>, u64, u64, &[u8]), ()>(
                    &mut store, "place",
                )
                .expect("typed");
            f.call(
                &mut store,
                (
                    Resource::new_borrow(range),
                    Resource::new_borrow(vault_rep),
                    *price,
                    *seq,
                    bucket,
                ),
            )
            .map(|()| Vec::new())
        }
        NodeCall::Fill {
            base,
            quote,
            budget,
        } => {
            let range = range_rep(&store.data().0, false);
            let base_rep = rep_of(&store.data().0, &Capability::Delta(*base));
            let quote_rep = rep_of(&store.data().0, &Capability::Delta(*quote));
            let f = instance
                .get_typed_func::<(
                    Resource<RangeWrite>,
                    Resource<DeltaCell>,
                    Resource<DeltaCell>,
                    &[u8],
                ), (Vec<u8>,)>(&mut store, "fill")
                .expect("typed");
            f.call(
                &mut store,
                (
                    Resource::new_borrow(range),
                    Resource::new_borrow(base_rep),
                    Resource::new_borrow(quote_rep),
                    budget,
                ),
            )
            .map(|(both,)| vec![both[..16].to_vec(), both[16..].to_vec()])
        }
    };

    let fuel = FUEL - store.get_fuel().expect("fuel");
    match outputs {
        Ok(outputs) => Ok((store.into_data().0, outputs, fuel)),
        Err(trap) => Err(format!("{trap:#}")),
    }
}

#[allow(clippy::too_many_lines)] // one argument shape per export
fn invoke_reference(
    engines: &Engines,
    guest: &str,
    session: KernelSession,
    call: &NodeCall,
) -> std::result::Result<Invoked, String> {
    let borrow = |session: &KernelSession, cap: &Capability, kind: ResourceKind| {
        CVal::Borrow(rep_of(session, cap), kind)
    };
    let (export, args, splits) = match call {
        NodeCall::Withdraw { vault, amount } => (
            "withdraw",
            vec![
                borrow(
                    &session,
                    &Capability::Reserve(*vault),
                    ResourceKind::ReserveCell,
                ),
                CVal::Bytes(amount.clone()),
            ],
            1,
        ),
        NodeCall::Deposit { vault, bucket } => (
            "deposit",
            vec![
                borrow(
                    &session,
                    &Capability::Delta(*vault),
                    ResourceKind::DeltaCell,
                ),
                CVal::Bytes(bucket.clone()),
            ],
            0,
        ),
        NodeCall::AssertBalance { vault, min } => (
            "assert-balance",
            vec![
                borrow(
                    &session,
                    &Capability::Snapshot(*vault),
                    ResourceKind::SnapCell,
                ),
                CVal::Bytes(min.clone()),
            ],
            0,
        ),
        NodeCall::Swap {
            config,
            reserve_in,
            reserve_out,
            input,
            min_out,
        } => (
            "swap",
            vec![
                borrow(
                    &session,
                    &Capability::Snapshot(*config),
                    ResourceKind::SnapCell,
                ),
                borrow(
                    &session,
                    &Capability::Write(*reserve_in),
                    ResourceKind::WriteCell,
                ),
                borrow(
                    &session,
                    &Capability::Write(*reserve_out),
                    ResourceKind::WriteCell,
                ),
                CVal::Bytes(input.clone()),
                CVal::Bytes(min_out.clone()),
            ],
            1,
        ),
        NodeCall::Place {
            escrow,
            price,
            seq,
            bucket,
        } => (
            "place",
            vec![
                CVal::Borrow(range_rep(&session, true), ResourceKind::RangeWrite),
                borrow(
                    &session,
                    &Capability::Delta(*escrow),
                    ResourceKind::DeltaCell,
                ),
                CVal::U64(*price),
                CVal::U64(*seq),
                CVal::Bytes(bucket.clone()),
            ],
            0,
        ),
        NodeCall::Fill {
            base,
            quote,
            budget,
        } => (
            "fill",
            vec![
                CVal::Borrow(range_rep(&session, false), ResourceKind::RangeWrite),
                borrow(&session, &Capability::Delta(*base), ResourceKind::DeltaCell),
                borrow(
                    &session,
                    &Capability::Delta(*quote),
                    ResourceKind::DeltaCell,
                ),
                CVal::Bytes(budget.clone()),
            ],
            2,
        ),
    };
    let mut instance =
        RefComponentInstance::instantiate(&engines.reference[guest], SessionHost(session))
            .expect("instantiate");
    let outcome = instance.invoke(export, &args).expect("invoke");
    let fuel = instance.fuel_consumed();
    match outcome {
        Ok(values) => {
            let outputs = match (splits, values.as_slice()) {
                (0, []) => Vec::new(),
                (1, [CVal::Bytes(single)]) => vec![single.clone()],
                (2, [CVal::Bytes(both)]) => vec![both[..16].to_vec(), both[16..].to_vec()],
                other => return Err(format!("unexpected result shape {other:?}")),
            };
            Ok((instance.into_host().0, outputs, fuel))
        }
        Err(trap) => Err(format!("{trap:?}")),
    }
}

const fn point(key: SubstateKey, mode: Mode) -> Effect {
    Effect {
        target: EffectTarget::Point(key),
        mode,
    }
}

fn set(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    set
}

fn shard_of(address: Address) -> ShardId {
    ShardId(u16::from(address.0[0]))
}

fn sharded_routing(world: &(MetadataCache, InstanceRegistry), graph: &ManifestGraph) -> Routing {
    let (cache, instances) = world;
    let admitted = admit(graph, cache, instances, &TestHasher).expect("admits");
    let first = route(
        &admitted.manifest,
        admitted.identity,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .expect("routes");
    let second = route(
        &admitted.manifest,
        admitted.identity,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 8 },
    )
    .expect("routes");
    assert_eq!(first, second, "route is a function over the corpus");
    first
}

fn run_both(
    engines: &Engines,
    world: &(MetadataCache, InstanceRegistry),
    store: &MemoryStore,
    transactions: &[(&ManifestGraph, TxHash)],
) -> (Vec<TxResult>, MemoryStore) {
    let mut lanes = Vec::new();
    for lane in [Lane::Blessed, Lane::Reference] {
        let mut results = Vec::new();
        let mut threaded = store.clone();
        for (graph, tx) in transactions {
            let (result, next) =
                execute_manifest(lane, engines, world, threaded, graph, *tx).expect("driver");
            results.push(result);
            threaded = next;
        }
        lanes.push((results, threaded));
    }
    let (reference, ref_store) = lanes.pop().unwrap();
    let (blessed, blessed_store) = lanes.pop().unwrap();
    assert_eq!(blessed, reference, "lanes diverged");
    let cells = |store: &MemoryStore| -> BTreeMap<SubstateKey, Vec<u8>> {
        store.cells().map(|(k, v)| (k, v.to_vec())).collect()
    };
    assert_eq!(cells(&blessed_store), cells(&ref_store), "state diverged");
    (blessed, blessed_store)
}

fn amount_of(store: &mut MemoryStore, key: SubstateKey) -> u128 {
    store
        .read(key)
        .unwrap()
        .map_or(0, |cell| decode_amount(&cell).unwrap())
}

fn transfer_graph() -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(100)),
                ],
            },
            GraphNode {
                target: BOB,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(RES_X)],
                }],
            },
        ],
    }
}

#[test]
fn transfer_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &transfer_graph());

    // The walkthrough's profile: one reservation at the sender, the vault
    // and claims deltas at the recipient — the balance cells and nothing
    // else.
    let expected: BTreeMap<ShardId, EffectSet> = BTreeMap::from([
        (
            shard_of(ALICE),
            set(&[point(vault(ALICE, RES_X), Mode::Reserve { amount: 100 })]),
        ),
        (
            shard_of(BOB),
            set(&[
                point(vault(BOB, RES_X), Mode::Delta),
                point(claims(BOB, RES_X), Mode::Delta),
            ]),
        ),
    ]);
    assert_eq!(routing.per_shard, expected);

    // The acceptance test, executable: a commutative-only transfer
    // provisions nothing at all — on either side.
    for set in routing.per_shard.values() {
        assert!(set.provision_targets().is_empty());
    }
}

#[test]
fn transfer_executes_end_to_end_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store.clear_log();

    let graph = transfer_graph();
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&graph, TxHash(Hash32([0x01; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("transfer must complete");
    };
    assert_eq!(receipt.delta.settles.get(&vault(ALICE, RES_X)), Some(&100));
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(BOB, RES_X))
            .unwrap()
            .credit,
        100
    );
    assert!(receipt.delta.cells.is_empty());
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 50);
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 100);
    Ok(())
}

/// A transfer gated on a third account's pinned balance: the guard runs
/// first, so an uncovered balance refuses before anything moves.
fn guarded_transfer_graph(min: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: CAROL,
                method: "assert-balance".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(min)),
                    GraphArg::Literal(Value::U64(8)),
                ],
            },
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(100)),
                ],
            },
            GraphNode {
                target: BOB,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(RES_X)],
                }],
            },
        ],
    }
}

#[test]
fn snapshot_guard_profile_is_read_only_and_carries_its_obligation() {
    let world = world();
    let routing = sharded_routing(&world, &guarded_transfer_graph(40));

    // The guarded shard holds exactly the pinned read: no lock-taking
    // mode, nothing to provision, nothing to commit.
    assert_eq!(
        routing.per_shard[&shard_of(CAROL)],
        set(&[point(
            vault(CAROL, RES_X),
            Mode::Snapshot {
                window: Window::Bounded(8)
            },
        )])
    );
    assert_eq!(
        routing.snapshot_obligations,
        BTreeSet::from([SnapshotObligation {
            target: EffectTarget::Point(vault(CAROL, RES_X)),
            window: 8,
        }])
    );
    for set in routing.per_shard.values() {
        assert!(set.provision_targets().is_empty());
    }
}

#[test]
fn the_snapshot_guard_admits_or_refuses_by_the_pinned_balance() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(150).to_vec())
        .unwrap();
    store
        .write(vault(CAROL, RES_X), encode_amount(50).to_vec())
        .unwrap();
    store.clear_log();

    // A covered guard: the transfer settles and the guarded vault leaves
    // no trace in the receipt — no cell, no movement, no settle.
    let covered = guarded_transfer_graph(40);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&covered, TxHash(Hash32([0x0A; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("covered guard must complete");
    };
    assert!(!receipt.delta.cells.contains_key(&vault(CAROL, RES_X)));
    assert!(!receipt.delta.movements.contains_key(&vault(CAROL, RES_X)));
    assert!(!receipt.delta.settles.contains_key(&vault(CAROL, RES_X)));
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 100);
    assert_eq!(amount_of(&mut final_store, vault(CAROL, RES_X)), 50);

    // An uncovered guard traps deterministically and moves nothing.
    let uncovered = guarded_transfer_graph(60);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[(&uncovered, TxHash(Hash32([0x0B; 32])))],
    );
    assert_eq!(results[0], TxResult::Trapped);
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 150);
    assert_eq!(amount_of(&mut final_store, vault(BOB, RES_X)), 0);
    Ok(())
}

fn swap_graph(min_out: u128) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: ALICE,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES_X)),
                    GraphArg::Literal(Value::U128(500)),
                ],
            },
            GraphNode {
                target: POOL,
                method: "swap".into(),
                args: vec![
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![],
                    },
                    GraphArg::Literal(Value::U128(min_out)),
                ],
            },
            GraphNode {
                target: ALICE,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(RES_Y)],
                }],
            },
        ],
    }
}

fn swap_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store
        .write(vault(ALICE, RES_X), encode_amount(600).to_vec())
        .unwrap();
    store
        .write(vault(POOL, RES_X), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(vault(POOL, RES_Y), encode_amount(1_000).to_vec())
        .unwrap();
    store
        .write(config_leaf(POOL), 30u16.to_le_bytes().to_vec())
        .unwrap();
    store.lock(config_leaf(POOL)).unwrap();
    store.clear_log();
    store
}

#[test]
fn swap_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &swap_graph(300));

    let pool_set = &routing.per_shard[&shard_of(POOL)];
    assert_eq!(
        *pool_set,
        set(&[
            point(
                config_leaf(POOL),
                Mode::Snapshot {
                    window: Window::Unbounded,
                },
            ),
            point(vault(POOL, RES_X), Mode::Write),
            point(vault(POOL, RES_Y), Mode::Write),
        ])
    );
    // The pool-shard provision carries the two balance cells and nothing
    // else: the reserves are read-modify-writes, the config snapshot is
    // verified-once and free.
    assert_eq!(
        pool_set.provision_targets(),
        [
            EffectTarget::Point(vault(POOL, RES_X)),
            EffectTarget::Point(vault(POOL, RES_Y)),
        ]
        .into_iter()
        .collect()
    );
    // The user's commutative side provisions nothing.
    assert!(
        routing.per_shard[&shard_of(ALICE)]
            .provision_targets()
            .is_empty()
    );
}

#[test]
fn swap_executes_with_real_pool_math_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let graph = swap_graph(300);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x02; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("swap must complete");
    };

    // The constant-product math, computed independently: 30 bps fee on
    // 500 in gives 498 effective; out = 1000 * 498 / 1498 = 332.
    assert_eq!(
        receipt.delta.cells.get(&vault(POOL, RES_X)),
        Some(&Some(encode_amount(1_500).to_vec()))
    );
    assert_eq!(
        receipt.delta.cells.get(&vault(POOL, RES_Y)),
        Some(&Some(encode_amount(668).to_vec()))
    );
    assert_eq!(receipt.delta.settles.get(&vault(ALICE, RES_X)), Some(&500));
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(ALICE, RES_Y))
            .unwrap()
            .credit,
        332
    );
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_Y)), 332);
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 100);
    Ok(())
}

#[test]
fn a_violated_output_floor_traps_identically() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    // 332 out cannot cover a 400 floor: the guest's assert is a
    // deterministic user-error trap on both runtimes, and no state moves.
    let graph = swap_graph(400);
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x03; 32])))],
    );
    assert_eq!(results[0], TxResult::Trapped);
    assert_eq!(amount_of(&mut final_store, vault(POOL, RES_X)), 1_000);
    assert_eq!(amount_of(&mut final_store, vault(ALICE, RES_X)), 600);
    Ok(())
}

fn place_graph() -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: MAKER,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(BASE)),
                    GraphArg::Literal(Value::U128(50)),
                ],
            },
            GraphNode {
                target: BOOK,
                method: "place_ask".into(),
                args: vec![
                    GraphArg::Literal(Value::U64(3)),
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![],
                    },
                ],
            },
        ],
    }
}

fn fill_graph() -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: TAKER,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(QUOTE)),
                    GraphArg::Literal(Value::U128(100)),
                ],
            },
            GraphNode {
                target: BOOK,
                method: "fill_asks".into(),
                args: vec![
                    GraphArg::Literal(Value::U64(3)),
                    GraphArg::Literal(Value::U64(5)),
                    GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![],
                    },
                ],
            },
            GraphNode {
                target: TAKER,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(BASE)],
                }],
            },
            GraphNode {
                target: TAKER,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 1,
                        output: 1,
                    },
                    constraints: vec![Constraint::ResourceIs(QUOTE)],
                }],
            },
        ],
    }
}

#[test]
fn fill_provisions_only_the_interval() {
    let world = world();
    let routing = sharded_routing(&world, &fill_graph());
    let book_set = &routing.per_shard[&shard_of(BOOK)];
    // The write interval is the only provisioned target: the escrow legs
    // are deltas and carry nothing.
    assert_eq!(
        book_set.provision_targets(),
        std::iter::once(EffectTarget::Range {
            owner: BOOK,
            collection: ASKS,
            lo: 3u128 << 64,
            hi: (5u128 << 64) | u128::from(u64::MAX),
            cap: FILL_CAP,
        })
        .collect()
    );
}

#[test]
fn the_order_book_matches_by_price_time_priority_on_both_runtimes() -> Result<()> {
    let world = world();
    let engines = Engines::build()?;
    let mut store = MemoryStore::new();
    store
        .write(vault(MAKER, BASE), encode_amount(60).to_vec())
        .unwrap();
    store
        .write(vault(TAKER, QUOTE), encode_amount(150).to_vec())
        .unwrap();
    // A resting ask at price 5 from an earlier session, escrow included.
    store
        .entry_write(BOOK, ASKS, (5u128 << 64) | 7, encode_amount(10).to_vec())
        .unwrap();
    store
        .write(vault(BOOK, BASE), encode_amount(10).to_vec())
        .unwrap();
    store.clear_log();

    let place = place_graph();
    let fill = fill_graph();
    let (results, mut final_store) = run_both(
        &engines,
        &world,
        &store,
        &[
            (&place, TxHash(Hash32([0x04; 32]))),
            (&fill, TxHash(Hash32([0x05; 32]))),
        ],
    );

    let TxResult::Completed(place_receipt) = &results[0] else {
        panic!("place must complete");
    };
    let TxResult::Completed(fill_receipt) = &results[1] else {
        panic!("fill must complete");
    };

    // The placed ask landed at the declared fresh sequence.
    let admitted = admit(&place, &world.0, &world.1, &TestHasher).unwrap();
    let seq = fresh_id(&TestHasher, admitted.identity, 1, 0, 0);
    let placed_order = (3u128 << 64) | u128::from(seq);
    assert_eq!(
        place_receipt.delta.entries.get(&(BOOK, ASKS, placed_order)),
        Some(&Some(encode_amount(50).to_vec()))
    );

    // The fill: budget 100 at price 3 buys 33 (cost 99), leaving change 1;
    // the price-5 ask is untouched. Partial fill rewrote the entry.
    assert_eq!(
        fill_receipt.delta.entries.get(&(BOOK, ASKS, placed_order)),
        Some(&Some(encode_amount(17).to_vec()))
    );
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(BOOK, BASE))
            .unwrap()
            .debit,
        33
    );
    assert_eq!(
        fill_receipt
            .delta
            .movements
            .get(&vault(BOOK, QUOTE))
            .unwrap()
            .credit,
        99
    );

    assert_eq!(amount_of(&mut final_store, vault(TAKER, BASE)), 33);
    assert_eq!(amount_of(&mut final_store, vault(TAKER, QUOTE)), 51);
    assert_eq!(amount_of(&mut final_store, vault(BOOK, BASE)), 27);
    assert_eq!(amount_of(&mut final_store, vault(BOOK, QUOTE)), 99);
    assert_eq!(amount_of(&mut final_store, vault(MAKER, BASE)), 10);
    let entries: BTreeMap<_, _> = final_store
        .collection_entries()
        .map(|(k, v)| (k, v.to_vec()))
        .collect();
    assert_eq!(
        entries.get(&(BOOK, ASKS, placed_order)),
        Some(&encode_amount(17).to_vec())
    );
    assert_eq!(
        entries.get(&(BOOK, ASKS, (5u128 << 64) | 7)),
        Some(&encode_amount(10).to_vec())
    );
    Ok(())
}

#[test]
fn every_guest_builds_against_the_canonical_world() -> Result<()> {
    let canonical = std::fs::read(repo_root().join("crates/vm-runtime/wit/kernel.wit"))?;
    for guest in ["transfer", "account", "amm", "book"] {
        let copy =
            std::fs::read(repo_root().join(format!("guests/{guest}/wit/deps/kernel/kernel.wit")))?;
        assert_eq!(canonical, copy, "{guest} kernel.wit drifted");
    }
    Ok(())
}

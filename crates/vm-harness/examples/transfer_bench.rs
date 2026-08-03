//! Single-core transfer throughput on the blessed engine: the account
//! guest's withdraw + deposit through the full kernel pipeline.
//!
//! Three sections, each scaled to expose its cost shape rather than a
//! single flattering number: the static pipeline (admission + routing,
//! what every node pays at gossip); the session pipeline (materialize,
//! two guest invocations via `InstancePre`, finish — the execution path);
//! and the batch executor (judge, conflict-group, execute, apply). Wall
//! clock is observability here, never a verdict; run with `--release`.

use std::sync::Arc;
use std::time::Instant;

use hyperscale_vm_effects::stdlib::{VAULT, account_metadata};
use hyperscale_vm_effects::{
    Address, Constraint, EdgeRef, Effect, EffectSet, EffectTarget, GraphArg, GraphNode, Hash32,
    Hasher, InstanceMeta, InstanceRegistry, ManifestGraph, MetadataCache, Mode, PackageHash,
    PrefixShardResolver, SubstateKey, TestHasher, Value, admit, child_key, route,
};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Base, BatchTx, Capability, EnvInputs, ExecutionMode, GuestRunner, KernelSession, Locality,
    MemoryStore, Outcome, OverlayStore, RunResult, SubstateStore, TxHash, encode_amount,
    execute_batch,
};
use hyperscale_vm_runtime::{
    DeltaCell, ReserveCell, add_kernel_to_linker, blessed_engine, validate_component,
};
use wasmtime::component::{Component, InstancePre, Linker, Resource};
use wasmtime::error::Context;
use wasmtime::{Engine, Result, Store};

const RES: Address = Address([0xE1; 16]);
const RECIPIENT: Address = Address([0xFE; 16]);
const AMOUNT: u128 = 100;
const FUEL: u64 = 10_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn env() -> EnvInputs {
    EnvInputs {
        clock_ms: 1,
        randomness: [1; 32],
    }
}

fn sender(index: u32) -> Address {
    let mut bytes = [0x10u8; 16];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    Address(bytes)
}

fn tx(index: u32) -> TxHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    TxHash(Hash32(bytes))
}

fn vault(owner: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(RES).canonical_bytes()],
    )
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world(senders: u32) -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    for index in 0..senders {
        instances.register(
            sender(index),
            InstanceMeta {
                package: pkg(),
                config: vec![],
            },
        );
    }
    instances.register(
        RECIPIENT,
        InstanceMeta {
            package: pkg(),
            config: vec![],
        },
    );
    (cache, instances)
}

fn transfer_graph(from: Address) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![
            GraphNode {
                target: from,
                method: "withdraw".into(),
                args: vec![
                    GraphArg::Literal(Value::Address(RES)),
                    GraphArg::Literal(Value::U128(AMOUNT)),
                ],
            },
            GraphNode {
                target: RECIPIENT,
                method: "deposit".into(),
                args: vec![GraphArg::Edge {
                    edge: EdgeRef {
                        producer: 0,
                        output: 0,
                    },
                    constraints: vec![Constraint::ResourceIs(RES)],
                }],
            },
        ],
    }
}

fn declared(from: Address) -> EffectSet {
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(vault(from)),
        mode: Mode::Reserve { amount: AMOUNT },
    })
    .unwrap();
    set.insert(Effect {
        target: EffectTarget::Point(vault(RECIPIENT)),
        mode: Mode::Delta,
    })
    .unwrap();
    set
}

fn funded_store(senders: u32) -> MemoryStore {
    let mut store = MemoryStore::new();
    for index in 0..senders {
        store
            .write(vault(sender(index)), encode_amount(1_000).to_vec())
            .unwrap();
    }
    store.clear_log();
    store
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

struct Bench {
    engine: Engine,
    pre: InstancePre<SessionHost>,
}

impl Bench {
    fn build() -> Result<Self> {
        let engine = blessed_engine()?;
        let bytes = build_guest("account")?;
        validate_component(&bytes).context("profile")?;
        let component = Component::new(&engine, &bytes)?;
        let mut linker = Linker::<SessionHost>::new(&engine);
        add_kernel_to_linker(&mut linker)?;
        let pre = linker.instantiate_pre(&component)?;
        Ok(Self { engine, pre })
    }

    /// The execution path of one transfer: two guest invocations against
    /// the session — withdraw returning the bucket cell, deposit crediting
    /// it. Returns the session and the fuel consumed.
    fn run_transfer(&self, from: Address, session: KernelSession) -> (KernelSession, u64) {
        let reserve = rep_of(&session, &Capability::Reserve(vault(from)));
        let delta = rep_of(&session, &Capability::Delta(vault(RECIPIENT)));
        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(FUEL).expect("fuel");
        let instance = self.pre.instantiate(&mut store).expect("instantiate");
        let withdraw = instance
            .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(&mut store, "withdraw")
            .expect("typed");
        let (bucket,) = withdraw
            .call(
                &mut store,
                (Resource::new_borrow(reserve), &encode_amount(AMOUNT)),
            )
            .expect("withdraw");
        let consumed = FUEL - store.get_fuel().expect("fuel");
        let session = store.into_data().0;

        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(FUEL).expect("fuel");
        let instance = self.pre.instantiate(&mut store).expect("instantiate");
        let deposit = instance
            .get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")
            .expect("typed");
        deposit
            .call(&mut store, (Resource::new_borrow(delta), &bucket))
            .expect("deposit");
        let consumed = consumed + (FUEL - store.get_fuel().expect("fuel"));
        (store.into_data().0, consumed)
    }
}

impl GuestRunner for Bench {
    fn run(&self, id: TxHash, session: KernelSession) -> RunResult {
        let mut index_bytes = [0u8; 4];
        index_bytes.copy_from_slice(&id.0.0[..4]);
        let from = sender(u32::from_le_bytes(index_bytes));
        let (session, fuel) = self.run_transfer(from, session);
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel,
        }
    }
}

fn per_tx(elapsed: std::time::Duration, count: u32) -> String {
    let micros = elapsed.as_secs_f64() * 1e6 / f64::from(count);
    let rate = f64::from(count) / elapsed.as_secs_f64();
    format!("{micros:8.2} us/tx  {rate:9.0} tx/s")
}

#[allow(clippy::too_many_lines)] // one timed section per pipeline stage
fn main() -> Result<()> {
    let bench = Bench::build()?;
    println!("single-core transfer baseline (blessed engine, account guest)\n");

    // Section 1: the static pipeline — admission + routing per transfer,
    // what every node derives at gossip. Metadata-cache-hot, as designed.
    {
        let count = 2_000u32;
        let (cache, instances) = world(count);
        let resolver = PrefixShardResolver { bits: 0 };
        // Warmup.
        for index in 0..200 {
            let admitted = admit(
                &transfer_graph(sender(index)),
                &cache,
                &instances,
                &TestHasher,
            )?;
            std::hint::black_box(route(
                &admitted,
                &cache,
                &instances,
                &TestHasher,
                &resolver,
            )?);
        }
        let start = Instant::now();
        for index in 0..count {
            let admitted = admit(
                &transfer_graph(sender(index)),
                &cache,
                &instances,
                &TestHasher,
            )?;
            std::hint::black_box(route(
                &admitted,
                &cache,
                &instances,
                &TestHasher,
                &resolver,
            )?);
        }
        println!(
            "admit + route                      {}",
            per_tx(start.elapsed(), count)
        );
    }

    // Section 2: the session pipeline — materialize, two guest calls,
    // finish — threading one store like a block, at growing store sizes so
    // any state-size scaling in the kernel shows.
    println!();
    for senders in [100u32, 1_000, 4_000] {
        let mut store = OverlayStore::new(Arc::new(funded_store(senders)));
        let start = Instant::now();
        for index in 0..senders {
            let from = sender(index);
            let session = KernelSession::materialize(
                store,
                &declared(from),
                &declared(from).iter().collect::<Vec<_>>(),
                tx(index),
                env(),
                test_hash,
            )
            .expect("feasible");
            let (session, fuel) = bench.run_transfer(from, session);
            let (_receipt, threaded) = session
                .finish(Outcome::Completed { value: None }, fuel)
                .expect("oracle");
            store = threaded;
        }
        println!(
            "session pipeline, store={senders:5}    {}",
            per_tx(start.elapsed(), senders)
        );
    }

    // Section 3: the batch executor — judge, conflict-group, execute,
    // apply — at two batch sizes to expose the pairwise grouping curve.
    println!();
    for batch_size in [100u32, 1_000] {
        let store = funded_store(batch_size);
        let batch: Vec<BatchTx> = (0..batch_size)
            .map(|index| {
                BatchTx::new(
                    tx(index),
                    declared(sender(index)),
                    env().clock_ms,
                    env().randomness,
                )
            })
            .collect();
        let start = Instant::now();
        let outcome = execute_batch(
            Arc::new(store),
            &batch,
            &bench,
            test_hash,
            ExecutionMode::Serial,
            &Locality::All,
        )
        .expect("batch");
        let elapsed = start.elapsed();
        assert!(
            outcome
                .receipts
                .values()
                .all(|r| matches!(r.outcome, Outcome::Completed { .. }))
        );
        println!(
            "batch executor, B={batch_size:5}         {}",
            per_tx(elapsed, batch_size)
        );
    }

    // The wasm floor: instantiation plus the two shim calls against a
    // fixed tiny session, isolating engine cost from kernel state cost.
    println!();
    {
        let count = 2_000u32;
        let base = Arc::new(funded_store(1));
        let sessions: Vec<KernelSession> = (0..count)
            .map(|index| {
                KernelSession::materialize(
                    OverlayStore::new(Arc::clone(&base) as Arc<dyn Base>),
                    &declared(sender(0)),
                    &declared(sender(0)).iter().collect::<Vec<_>>(),
                    tx(index),
                    env(),
                    test_hash,
                )
                .expect("feasible")
            })
            .collect();
        let start = Instant::now();
        for session in sessions {
            std::hint::black_box(bench.run_transfer(sender(0), session));
        }
        println!(
            "wasm floor (2 calls + 2 inst)      {}",
            per_tx(start.elapsed(), count)
        );
    }

    let fuel_check = {
        let store = OverlayStore::new(Arc::new(funded_store(1)));
        let session = KernelSession::materialize(
            store,
            &declared(sender(0)),
            &declared(sender(0)).iter().collect::<Vec<_>>(),
            tx(0),
            env(),
            test_hash,
        )
        .expect("feasible");
        bench.run_transfer(sender(0), session).1
    };
    println!("\nfuel per transfer: {fuel_check} (engine schedule + boundary supplement)");
    Ok(())
}

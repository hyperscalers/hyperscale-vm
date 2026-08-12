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
    Address, Declaration, Hash32, Hasher, InstanceRegistry, ManifestGraph, MetadataCache, NodeCall,
    PackageHash, PrefixShardResolver, PrincipalAddr, ResourceAddr, SubstateKey, TestHasher, Value,
    admit, child_key, route,
};
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Base, BatchTx, CellKind, EnvInputs, ExecutionMode, GuestArg, GuestBackend, GuestCall,
    GuestRunner, InvokeResult, KernelSession, Locality, ManifestWalk, MemoryStore, Outcome,
    OverlayStore, SubstateStore, TxHash, encode_amount, execute_batch,
};
use hyperscale_vm_manifest_builder::GraphBuilder;
use hyperscale_vm_runtime::{
    CellKind as HostCellKind, HostArg, add_kernel_to_linker, blessed_engine, call_export,
    validate_component,
};
use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::error::Context;
use wasmtime::{Engine, Result, Store};

const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RECIPIENT: PrincipalAddr = PrincipalAddr::new([0xFE; 31]);
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

fn sender(index: u32) -> PrincipalAddr {
    let mut bytes = [0x10u8; 31];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    PrincipalAddr::new(bytes)
}

fn tx(index: u32) -> TxHash {
    let mut bytes = [0u8; 32];
    bytes[..4].copy_from_slice(&index.to_le_bytes());
    TxHash(Hash32(bytes))
}

fn vault(owner: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(RES.address()).canonical_bytes()],
    )
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world(_senders: u32) -> (MetadataCache, InstanceRegistry) {
    let mut cache = MetadataCache::new();
    cache.publish(pkg(), account_metadata());
    let mut instances = InstanceRegistry::new();
    // Senders and the recipient are principals: one record serves every
    // account, so the bench's population costs the registry nothing.
    instances.serve_principals(pkg());
    (cache, instances)
}

fn transfer_graph(from: PrincipalAddr) -> ManifestGraph {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(from, "withdraw", (RES, AMOUNT));
    let [] = b.call(RECIPIENT, "deposit", (funds.resource_is(RES),));
    b.build().expect("every output is consumed")
}

/// One transfer as the chain derives it: both views of the declaration
/// and the lowered invocations the walk performs.
///
/// Taken from routing rather than hand-built, because the capability
/// table a handle's rep indexes into is the clause order routing emits —
/// a restated set would measure a pipeline nothing runs.
struct Routed {
    declaration: Declaration,
    calls: Vec<NodeCall>,
}

fn routed(world: &(MetadataCache, InstanceRegistry), from: PrincipalAddr) -> Result<Routed> {
    let (cache, instances) = world;
    let admitted = admit(&transfer_graph(from), cache, instances, &TestHasher)?;
    let routing = route(
        &admitted,
        cache,
        instances,
        &TestHasher,
        &PrefixShardResolver { bits: 0 },
    )?;
    Ok(Routed {
        declaration: routing.declaration()?,
        calls: routing.calls,
    })
}

fn entry_for(index: u32, routed: &Routed) -> BatchTx {
    BatchTx::new(
        tx(index),
        routed.declaration.clone(),
        env().clock_ms,
        env().randomness,
    )
    .with_calls(routed.calls.clone())
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
}

impl GuestBackend for Bench {
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        let mut store = Store::new(&self.engine, SessionHost(session));
        store.set_fuel(call.fuel_budget.min(FUEL)).expect("fuel");
        let instance = self.pre.instantiate(&mut store).expect("instantiate");
        let args: Vec<HostArg<'_>> = call
            .args
            .iter()
            .map(|arg| match arg {
                GuestArg::Handle { rep, kind } => HostArg::Handle {
                    rep: *rep,
                    kind: host_kind(*kind),
                },
                GuestArg::U64(scalar) => HostArg::U64(*scalar),
                GuestArg::Bytes(bytes) => HostArg::Bytes(bytes),
            })
            .collect();
        let result = call_export(&mut store, &instance, call.export, &args, call.returns)
            .map_err(|trap| format!("{trap:#}"));
        let fuel = call.fuel_budget.min(FUEL) - store.get_fuel().expect("fuel");
        let exhausted = store.get_fuel().expect("fuel") == 0 && result.is_err();
        InvokeResult {
            session: store.into_data().0,
            fuel,
            result,
            exhausted,
        }
    }
}

const fn host_kind(kind: CellKind) -> HostCellKind {
    match kind {
        CellKind::Read => HostCellKind::Read,
        CellKind::Locked => HostCellKind::Locked,
        CellKind::Write => HostCellKind::Write,
        CellKind::Delta => HostCellKind::Delta,
        CellKind::Reserve => HostCellKind::Reserve,
        CellKind::RangeRead => HostCellKind::RangeRead,
        CellKind::RangeWrite => HostCellKind::RangeWrite,
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
    let walk = ManifestWalk { backend: &bench };
    for senders in [100u32, 1_000, 4_000] {
        let (cache, instances) = world(senders);
        let entries: Vec<BatchTx> = (0..senders)
            .map(|index| {
                Ok(entry_for(
                    index,
                    &routed(&(cache.clone(), instances.clone()), sender(index))?,
                ))
            })
            .collect::<Result<_>>()?;
        let mut store = OverlayStore::new(Arc::new(funded_store(senders)));
        let start = Instant::now();
        for entry in &entries {
            let session = KernelSession::materialize(
                store,
                &entry.declared,
                &entry.ordered,
                entry.tx,
                env(),
                test_hash,
            )
            .expect("feasible");
            let run = walk.run(entry, session);
            let (_receipt, threaded) = run.session.finish(run.outcome, run.fuel).expect("oracle");
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
        let world = world(batch_size);
        let batch: Vec<BatchTx> = (0..batch_size)
            .map(|index| Ok(entry_for(index, &routed(&world, sender(index))?)))
            .collect::<Result<_>>()?;
        let start = Instant::now();
        let outcome = execute_batch(
            Arc::new(store),
            &batch,
            &walk,
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
        let entries: Vec<BatchTx> = (0..count)
            .map(|index| Ok(entry_for(index, &routed(&world(1), sender(0))?)))
            .collect::<Result<_>>()?;
        let sessions: Vec<KernelSession> = entries
            .iter()
            .map(|entry| {
                KernelSession::materialize(
                    OverlayStore::new(Arc::clone(&base) as Arc<dyn Base>),
                    &entry.declared,
                    &entry.ordered,
                    entry.tx,
                    env(),
                    test_hash,
                )
                .expect("feasible")
            })
            .collect();
        let start = Instant::now();
        for (entry, session) in entries.iter().zip(sessions) {
            std::hint::black_box(walk.run(entry, session));
        }
        println!(
            "wasm floor (2 calls + 2 inst)      {}",
            per_tx(start.elapsed(), count)
        );
    }

    let fuel_check = {
        let entry = entry_for(0, &routed(&world(1), sender(0))?);
        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(funded_store(1))),
            &entry.declared,
            &entry.ordered,
            entry.tx,
            env(),
            test_hash,
        )
        .expect("feasible");
        walk.run(&entry, session).fuel
    };
    println!("\nfuel per transfer: {fuel_check} (engine schedule + boundary supplement)");
    Ok(())
}

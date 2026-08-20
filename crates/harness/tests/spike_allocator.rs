//! Allocation-strategy probe: instantiation cost per invocation under
//! the blessed engine's profile-sized memory mapping, wasmtime's default
//! mapping, and the pooling allocator — and the pin that no mapping
//! strategy can reach a receipt.
//!
//! Findings: the mapped span per linear memory dominates the cost;
//! copy-on-write images buy nothing (the committed artifacts carry tens
//! of bytes of active data); pooling trails on-demand even with slot
//! pages kept resident; parallel invocation roughly doubles the
//! profile-sized mapping's lead, because mapping syscalls serialize on
//! the address-space lock. Numbers are printed for the record; the
//! assertions are a generous sanity ceiling and receipt identity across
//! every strategy. Measure with `--release`.

use std::thread;
use std::time::Instant;

use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_fixtures::lottery_artifact;
use hyperscale_vm_harness::dual::{materialize, rep_where};
use hyperscale_vm_kernel::{
    Capability, EnvInputs, GuestArg, Invoked, KernelSession, MemoryStore, Receipt,
};
use hyperscale_vm_runtime::{
    InstantiationCharges, add_kernel_to_linker, blessed_config, blessed_engine,
    instantiate_charged, instantiation_charges, invoke_export,
};
use hyperscale_vm_stdlib::{account_artifact, staking_artifact};
use hyperscale_vm_types::{
    Address, AddressClass, CellKind, Denomination, Effect, EffectSet, EffectTarget, Mode,
    ResourceAddr, TxHash, encode_amount,
};
use wasmtime::component::{Component, InstancePre, Linker};
use wasmtime::{Engine, InstanceAllocationStrategy, PoolingAllocationConfig, Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;
const WARMUP: u32 = 500;
const ITERS: u32 = 10_000;

/// The blessed semantics under wasmtime's default mapping: a 4 GiB
/// reservation and 32 MiB guards per linear memory.
fn default_mapping_engine() -> Result<Engine> {
    let mut config = blessed_config();
    config.memory_reservation(4 << 30);
    config.memory_guard_size(32 << 20);
    Engine::new(&config)
}

/// The blessed semantics on the pooling allocator, tuned as its own best
/// case: slot memories at the profile ceiling, slot pages kept resident
/// so reuse is a memset rather than an madvise round trip.
fn pooled_engine() -> Result<Engine> {
    let mut config = blessed_config();
    let mut pool = PoolingAllocationConfig::default();
    pool.max_memory_size(16 << 20);
    pool.linear_memory_keep_resident(1 << 20);
    pool.table_keep_resident(1 << 20);
    config.allocation_strategy(InstanceAllocationStrategy::Pooling(pool));
    Engine::new(&config)
}

/// The strategies under comparison, the blessed engine among them.
fn engines() -> Result<Vec<(&'static str, Engine)>> {
    Ok(vec![
        ("blessed (profile-sized)", blessed_engine()?),
        ("default 4GiB mapping", default_mapping_engine()?),
        ("pooling resident", pooled_engine()?),
    ])
}

/// A fresh empty session: what every measured iteration instantiates over.
fn session(base: &MemoryStore) -> KernelSession {
    materialize(
        base,
        &EffectSet::new(),
        &[],
        TxHash(Hash32([0x55; 32])),
        EnvInputs {
            clock_ms: 0,
            randomness: [0; 32],
        },
    )
}

/// One production-shaped invocation prefix: fresh session, fresh store,
/// charge-replayed instantiation.
fn one_instantiation(
    engine: &Engine,
    pre: &InstancePre<KernelSession>,
    charges: &InstantiationCharges,
    base: &MemoryStore,
) -> Result<()> {
    let mut store = Store::new(engine, session(base));
    instantiate_charged(&mut store, FUEL, charges, |s| pre.instantiate(s))?;
    Ok(())
}

/// The transfer fixture from the stdlib conformance lane: a reserve on the
/// sender's balance slot, a delta on the recipient's.
const SENDER: Address = Address::new([1; 31], AddressClass::Component);
const RECIPIENT: Address = Address::new([2; 31], AddressClass::Component);
const RESOURCE: Denomination = Denomination::Resource(ResourceAddr::new([0xE1; 31]));
const AMOUNT: u128 = 100;

/// A funded transfer session: sender reserved, recipient open for credit.
fn transfer_session() -> KernelSession {
    let sender = child_key(&TestHasher, SENDER, SlotId(1), &[]);
    let recipient = child_key(&TestHasher, RECIPIENT, SlotId(1), &[]);
    let mut declared = EffectSet::new();
    declared
        .insert(Effect {
            target: EffectTarget::Point(sender),
            mode: Mode::Reserve { amount: AMOUNT },
        })
        .unwrap();
    declared
        .insert(Effect {
            target: EffectTarget::Point(recipient),
            mode: Mode::Delta,
        })
        .unwrap();
    let mut store = MemoryStore::new();
    store
        .write(sender, encode_amount(500).to_vec())
        .expect("seed sender balance");
    let mut session = materialize(
        &store,
        &declared,
        &[Some(RESOURCE), Some(RESOURCE)],
        TxHash(Hash32([0x77; 32])),
        EnvInputs {
            clock_ms: 77,
            randomness: [3; 32],
        },
    );
    session.enter_invocation(SENDER);
    session
}

/// One whole transfer the way execution runs it: two fresh stores, two
/// charged instantiations, withdraw then deposit, then the receipt.
fn one_transfer(
    engine: &Engine,
    pre: &InstancePre<KernelSession>,
    charges: &InstantiationCharges,
) -> Result<Receipt> {
    let session = transfer_session();
    let sender_key = child_key(&TestHasher, SENDER, SlotId(1), &[]);
    let sender_rep = rep_where(
        &session,
        |c| matches!(c, Capability::Reserve { key, .. } if *key == sender_key),
    );
    let mut store = Store::new(engine, session);
    let instance = instantiate_charged(&mut store, FUEL, charges, |s| pre.instantiate(s))?;
    let withdraw = invoke_export(
        &mut store,
        &instance,
        "withdraw",
        &[GuestArg::Handle {
            rep: sender_rep,
            kind: CellKind::Reserve,
        }],
        FUEL,
    );
    let Invoked::Produced(reps) = withdraw.result else {
        panic!("withdraw did not produce: {:?}", withdraw.result);
    };
    let funds = reps[0];

    let mut session = store.into_data();
    session.enter_invocation(RECIPIENT);
    let recipient_key = child_key(&TestHasher, RECIPIENT, SlotId(1), &[]);
    let recipient_rep = rep_where(&session, |c| *c == Capability::Delta(recipient_key));
    let mut store = Store::new(engine, session);
    let instance = instantiate_charged(&mut store, FUEL, charges, |s| pre.instantiate(s))?;
    let deposit = invoke_export(
        &mut store,
        &instance,
        "deposit",
        &[
            GuestArg::Handle {
                rep: recipient_rep,
                kind: CellKind::Delta,
            },
            GuestArg::Bucket(funds),
        ],
        FUEL,
    );
    assert!(
        matches!(deposit.result, Invoked::Produced(_)),
        "deposit did not produce: {:?}",
        deposit.result
    );

    let (receipt, _) = store
        .into_data()
        .finish(None, withdraw.fuel + deposit.fuel)
        .expect("oracle clean");
    Ok(receipt)
}

fn measure(label: &str, mut f: impl FnMut() -> Result<()>) -> Result<f64> {
    for _ in 0..WARMUP {
        f()?;
    }
    let start = Instant::now();
    for _ in 0..ITERS {
        f()?;
    }
    let nanos_per = start.elapsed().as_secs_f64() * 1e9 / f64::from(ITERS);
    println!("{label:48} {nanos_per:>10.0} ns");
    Ok(nanos_per)
}

/// Compile `artifact` for `engine` the way the production backend does.
fn compiled(
    engine: &Engine,
    artifact: &[u8],
) -> Result<(InstancePre<KernelSession>, InstantiationCharges)> {
    let component = Component::new(engine, artifact)?;
    let mut linker = Linker::<KernelSession>::new(engine);
    add_kernel_to_linker(&mut linker)?;
    Ok((
        linker.instantiate_pre(&component)?,
        instantiation_charges(artifact)?,
    ))
}

#[test]
fn per_invocation_allocation_cost() -> Result<()> {
    let artifacts: [(&str, &[u8]); 3] = [
        ("account", account_artifact()),
        ("staking", staking_artifact()),
        ("lottery", lottery_artifact()),
    ];
    let base = MemoryStore::new();

    // The allocator-independent floor: what building the session alone costs.
    let session_only = measure("session only", || {
        let _ = session(&base);
        Ok(())
    })?;

    // Decomposition guests: the component machinery alone, and one linear
    // memory on top of it.
    let empty_wat = parse_str("(component)")?;
    let memory_wat =
        parse_str("(component (core module $m (memory 1)) (core instance (instantiate $m)))")?;
    let probes: [(&str, &[u8]); 2] = [("empty", &empty_wat), ("one memory", &memory_wat)];

    let mut ceiling_checks = vec![("session", session_only)];
    for (config_label, engine) in &engines()? {
        let store_only = measure(&format!("{config_label} store only"), || {
            let _ = Store::new(engine, session(&base));
            Ok(())
        })?;
        ceiling_checks.push(("store", store_only));
        for (name, artifact) in probes.iter().copied().chain(artifacts) {
            let (pre, charges) = compiled(engine, artifact)?;
            let label = format!("{config_label} {name} (charge {})", charges.total());
            let ns = measure(&label, || one_instantiation(engine, &pre, &charges, &base))?;
            ceiling_checks.push(("instantiation", ns));
        }
    }

    // Generous sanity ceiling: per-invocation instantiation must be
    // microseconds, not milliseconds.
    for (label, ns) in ceiling_checks {
        assert!(ns < 1_000_000.0, "{label} costs {ns} ns per invocation");
    }
    Ok(())
}

/// Instantiation under parallel invocation: what the executor's thread
/// pool actually does. Reported per thread: perfectly parallel matches
/// the single-thread figure, contention shows as the excess over it.
#[test]
fn concurrent_instantiation_cost() -> Result<()> {
    const THREADS: u32 = 8;
    const PER_THREAD: u32 = 3_000;
    let artifact = account_artifact();
    for (config_label, engine) in &engines()? {
        let (pre, charges) = compiled(engine, artifact)?;
        let base = MemoryStore::new();
        for _ in 0..WARMUP {
            one_instantiation(engine, &pre, &charges, &base)?;
        }
        let start = Instant::now();
        thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    let base = MemoryStore::new();
                    for _ in 0..PER_THREAD {
                        one_instantiation(engine, &pre, &charges, &base)
                            .expect("warmed instantiation succeeds");
                    }
                });
            }
        });
        let nanos_per = start.elapsed().as_secs_f64() * 1e9 / f64::from(PER_THREAD);
        println!("{config_label:48} {nanos_per:>10.0} ns/inst per thread x{THREADS}");
        assert!(
            nanos_per < 1_000_000.0,
            "{config_label} costs {nanos_per} ns"
        );
    }
    Ok(())
}

/// A whole transfer per strategy — and the pin that matters: every
/// allocation strategy produces the byte-identical receipt, fuel
/// included, so the mapping choice is provably host-local.
#[test]
fn per_transfer_allocation_cost() -> Result<()> {
    let artifact = account_artifact();
    let engines = engines()?;
    let mut receipts: Vec<Receipt> = Vec::new();
    for (config_label, engine) in &engines {
        let (pre, charges) = compiled(engine, artifact)?;
        receipts.push(one_transfer(engine, &pre, &charges)?);
        let label = format!("{config_label} transfer");
        let ns = measure(&label, || one_transfer(engine, &pre, &charges).map(|_| ()))?;
        assert!(ns < 1_000_000.0, "a transfer costs {ns} ns");
    }
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(
            receipt, &receipts[0],
            "receipts diverged across allocation strategies: {} vs {}",
            engines[index].0, engines[0].0
        );
    }
    Ok(())
}

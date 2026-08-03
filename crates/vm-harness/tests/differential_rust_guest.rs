//! Differential lane 2 over the realistic guest: the wit-bindgen transfer
//! component runs under the blessed engine and the reference interpreter
//! with the same kernel session as host; outcomes, access logs, fuel, and
//! receipts must agree.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId, SubstateKey,
    TestHasher, child_key,
};
use hyperscale_vm_harness::fixtures::build_transfer_component;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, KernelSession, MemoryStore, Movement, Outcome, OverlayStore,
    SubstateStore, TxHash, encode_amount,
};
use hyperscale_vm_ref::{
    CVal, ExecError, RefComponent, RefComponentInstance, ResourceKind, Trap as RefTrap,
};
use hyperscale_vm_runtime::{DeltaCell, ReserveCell, add_kernel_to_linker, blessed_engine};
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::{Result, Store, Trap};

const CLOCK_MS: u64 = 777_000;
const RANDOMNESS: [u8; 32] = [3; 32];
const FUEL: u64 = 100_000_000;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn keys() -> (SubstateKey, SubstateKey) {
    (
        child_key(&TestHasher, Address([1; 16]), RoleId(1), &[]),
        child_key(&TestHasher, Address([2; 16]), RoleId(1), &[]),
    )
}

fn session(committed: u128, reserve: u128) -> KernelSession {
    let (sender, recipient) = keys();
    let mut store = MemoryStore::new();
    store
        .write(sender, encode_amount(committed).to_vec())
        .unwrap();
    store.clear_log();
    let mut set = EffectSet::new();
    set.insert(Effect {
        target: EffectTarget::Point(sender),
        mode: Mode::Reserve { amount: reserve },
    })
    .unwrap();
    set.insert(Effect {
        target: EffectTarget::Point(recipient),
        mode: Mode::Delta,
    })
    .unwrap();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &set,
        &set.iter().collect::<Vec<_>>(),
        TxHash(Hash32([0x55; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: RANDOMNESS,
        },
        test_hash,
    )
    .expect("feasible fixture")
}

fn reps(session: &KernelSession) -> (u32, u32) {
    let (sender, recipient) = keys();
    let position = |wanted: Capability| {
        u32::try_from(
            session
                .capabilities()
                .iter()
                .position(|c| *c == wanted)
                .expect("capability present"),
        )
        .expect("bounded")
    };
    (
        position(Capability::Reserve(sender)),
        position(Capability::Delta(recipient)),
    )
}

#[derive(Debug, PartialEq, Eq)]
enum LaneOutcome {
    Value(u64),
    Unreachable,
    Other(String),
}

fn blessed(
    component: &[u8],
    committed: u128,
    reserve: u128,
    min: u64,
) -> Result<(LaneOutcome, SessionHost, u64)> {
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, component)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let host = SessionHost(session(committed, reserve));
    let (sender_rep, recipient_rep) = reps(&host.0);
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let run = instance
        .get_typed_func::<(Resource<ReserveCell>, Resource<DeltaCell>, u64), (u64,)>(
            &mut store, "run",
        )?;
    let result = run
        .call(
            &mut store,
            (
                Resource::new_borrow(sender_rep),
                Resource::new_borrow(recipient_rep),
                min,
            ),
        )
        .map(|(v,)| v);
    let outcome = match result {
        Ok(v) => LaneOutcome::Value(v),
        Err(e) => {
            if e.downcast_ref::<Trap>() == Some(&Trap::UnreachableCodeReached) {
                LaneOutcome::Unreachable
            } else {
                LaneOutcome::Other(format!("{e:#}"))
            }
        }
    };
    let fuel = FUEL - store.get_fuel()?;
    Ok((outcome, store.into_data(), fuel))
}

fn reference(
    component: &[u8],
    committed: u128,
    reserve: u128,
    min: u64,
) -> Result<(LaneOutcome, SessionHost, u64)> {
    let comp = RefComponent::decode(component)?;
    let host = SessionHost(session(committed, reserve));
    let (sender_rep, recipient_rep) = reps(&host.0);
    let mut instance = RefComponentInstance::instantiate(&comp, host)?;
    let outcome = match instance.invoke(
        "run",
        &[
            CVal::Borrow(sender_rep, ResourceKind::ReserveCell),
            CVal::Borrow(recipient_rep, ResourceKind::DeltaCell),
            CVal::U64(min),
        ],
    )? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(v)] => LaneOutcome::Value(*v),
            other => LaneOutcome::Other(format!("unexpected values {other:?}")),
        },
        Err(ExecError::Trap(RefTrap::Unreachable)) => LaneOutcome::Unreachable,
        Err(e) => LaneOutcome::Other(format!("{e:?}")),
    };
    let fuel = instance.fuel_consumed();
    Ok((outcome, instance.into_host(), fuel))
}

#[test]
fn the_rust_guest_agrees_between_blessed_engine_and_vm_ref() -> Result<()> {
    let component = build_transfer_component()?;
    let (sender, recipient) = keys();

    // The happy transfer, the exact-amount edge, and the floor panic.
    for (committed, reserve, min) in [(500u128, 100u128, 1u64), (500, 500, 500), (500, 100, 200)] {
        let (b, b_host, b_fuel) = blessed(&component, committed, reserve, min)?;
        let (r, r_host, r_fuel) = reference(&component, committed, reserve, min)?;
        assert_eq!(b, r, "outcome diverged for reserve={reserve} min={min}");
        assert_eq!(
            b_host.0.store().access_log(),
            r_host.0.store().access_log(),
            "access log diverged for reserve={reserve} min={min}"
        );
        assert_eq!(
            b_fuel, r_fuel,
            "fuel diverged for reserve={reserve} min={min}"
        );

        if let LaneOutcome::Value(v) = b {
            // The expected tag, computed independently of both
            // implementations.
            let digest = test_hash(&RANDOMNESS);
            let reserved = u64::try_from(reserve).expect("fixture fits");
            assert_eq!(v, CLOCK_MS + reserved + u64::from(digest[0]));

            // Byte-identical receipts, oracle clean on both sides.
            let outcome = Outcome::Completed { value: Some(v) };
            let (b_receipt, _) = b_host.0.finish(outcome.clone(), b_fuel).expect("oracle");
            let (r_receipt, _) = r_host.0.finish(outcome, r_fuel).expect("oracle");
            assert_eq!(b_receipt, r_receipt);
            assert_eq!(b_receipt.delta.settles.get(&sender), Some(&reserve));
            assert_eq!(
                b_receipt.delta.movements.get(&recipient),
                Some(&Movement {
                    credit: reserve,
                    debit: 0,
                })
            );
        }
    }
    Ok(())
}

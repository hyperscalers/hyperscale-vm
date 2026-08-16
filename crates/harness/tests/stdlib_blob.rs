//! The committed artifacts' conformance lane.
//!
//! `hyperscale-vm-stdlib` and `hyperscale-vm-fixtures` ship each guest as
//! committed bytes, and the committed bytes — not a rebuild — are what
//! consumers hold, so this lane runs those exact bytes: profile
//! validation, then a withdraw+deposit transfer with a pinned balance
//! guard, and a lottery round settling on the transaction's draw — each
//! on the blessed engine and the reference interpreter, receipts and
//! fuel byte-identical. A separate digest test — Linux-only, since
//! Linux is the canonical builder of the committed bytes — proves those
//! bytes are what the sources build, which is what makes the sources
//! trustworthy as documentation of the blobs.

use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode,
    RoleId, SubstateKey, TestHasher, Value, child_key, collection_id, order_key,
};
use hyperscale_vm_fixtures::{LOTTERY_COMPONENT, lottery};
#[cfg(target_os = "linux")]
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, Event, KernelSession, MemoryStore, Movement, Outcome, OverlayStore,
    Receipt, TxHash, WorkingStore, encode_amount,
};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    DeltaCell, RangeRead, RangeWrite, ReserveCell, WriteCell, add_kernel_to_linker, blessed_engine,
    validate_component,
};
use hyperscale_vm_stdlib::ACCOUNT_COMPONENT;
#[cfg(target_os = "linux")]
use hyperscale_vm_stdlib::STAKING_COMPONENT;
use wasmtime::component::{Component, Linker, Resource};
use wasmtime::error::Context;
use wasmtime::{Result, Store};

const CLOCK_MS: u64 = 77;
const RANDOMNESS: [u8; 32] = [3; 32];
const FUEL: u64 = 10_000_000;
const AMOUNT: u128 = 100;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// The account that withdraws, guards, and stamps.
const SENDER: Address = Address::new([1; 31], AddressClass::Component);
/// The account that receives.
const RECIPIENT: Address = Address::new([2; 31], AddressClass::Component);

fn keys() -> (SubstateKey, SubstateKey) {
    (
        child_key(&TestHasher, SENDER, RoleId(1), &[]),
        child_key(&TestHasher, RECIPIENT, RoleId(1), &[]),
    )
}

/// Enter the account whose method runs next. Emission is stamped from
/// here, so the caller driving the sequence is what supplies it.
const fn entering(mut host: SessionHost, who: Address) -> SessionHost {
    host.0.enter_invocation(who);
    host
}

fn session() -> KernelSession {
    let (sender, recipient) = keys();
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
    store.clear_log();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declared,
        &declared.iter().collect::<Vec<_>>(),
        TxHash(Hash32([0x77; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: RANDOMNESS,
        },
        test_hash,
    )
    .expect("feasible")
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

fn finish(session: KernelSession, fuel: u64) -> Receipt {
    session
        .finish(Outcome::Completed { value: None }, fuel)
        .expect("oracle clean")
        .0
}

/// Withdraw, deposit, then the pinned balance guard on the blessed
/// engine — one instantiation per call, the session threaded through, as
/// execution invokes guests.
fn blessed_transfer() -> Result<(Receipt, u64)> {
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, ACCOUNT_COMPONENT)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let host = entering(SessionHost(session()), SENDER);
    let (sender, recipient) = keys();
    let sender_rep = rep_of(
        &host.0,
        &Capability::Reserve {
            key: sender,
            amount: AMOUNT,
        },
    );
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let withdraw = instance
        .get_typed_func::<(Resource<ReserveCell>, &[u8]), (Vec<u8>,)>(&mut store, "withdraw")?;
    let (bucket,) = withdraw.call(
        &mut store,
        (
            Resource::new_borrow(sender_rep),
            encode_amount(AMOUNT).as_slice(),
        ),
    )?;
    assert_eq!(bucket, encode_amount(AMOUNT).to_vec());
    let withdraw_fuel = FUEL - store.get_fuel()?;
    let host = entering(store.into_data(), RECIPIENT);

    let recipient_rep = rep_of(&host.0, &Capability::Delta(recipient));
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let deposit =
        instance.get_typed_func::<(Resource<DeltaCell>, &[u8]), ()>(&mut store, "deposit")?;
    deposit.call(&mut store, (Resource::new_borrow(recipient_rep), &bucket))?;
    let deposit_fuel = FUEL - store.get_fuel()?;
    let fuel = withdraw_fuel + deposit_fuel;

    Ok((finish(store.into_data().0, fuel), fuel))
}

/// The same transfer on the reference interpreter, instantiated per call
/// with the session threaded through.
fn reference_transfer() -> Result<(Receipt, u64)> {
    let component = RefComponent::decode(ACCOUNT_COMPONENT)?;
    let (sender, recipient) = keys();

    let host = entering(SessionHost(session()), SENDER);
    let sender_rep = rep_of(
        &host.0,
        &Capability::Reserve {
            key: sender,
            amount: AMOUNT,
        },
    );
    let mut instance =
        RefComponentInstance::instantiate(&component, host).map_err(|(_, error)| error)?;
    let outcome = instance.invoke(
        "withdraw",
        &[
            CVal::Borrow(sender_rep, ResourceKind::ReserveCell),
            CVal::Bytes(encode_amount(AMOUNT).to_vec()),
        ],
    )?;
    let values =
        outcome.map_err(|trap| wasmtime::error::format_err!("withdraw trapped: {trap:?}"))?;
    let [CVal::Bytes(bucket)] = values.as_slice() else {
        wasmtime::error::bail!("unexpected withdraw result shape");
    };
    assert_eq!(*bucket, encode_amount(AMOUNT).to_vec());
    let bucket = bucket.clone();
    let withdraw_fuel = instance.fuel_consumed();
    let host = entering(instance.into_host(), RECIPIENT);

    let recipient_rep = rep_of(&host.0, &Capability::Delta(recipient));
    let mut instance =
        RefComponentInstance::instantiate(&component, host).map_err(|(_, error)| error)?;
    let outcome = instance.invoke(
        "deposit",
        &[
            CVal::Borrow(recipient_rep, ResourceKind::DeltaCell),
            CVal::Bytes(bucket),
        ],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("deposit trapped: {trap:?}"))?;
    let deposit_fuel = instance.fuel_consumed();
    let fuel = withdraw_fuel + deposit_fuel;

    Ok((finish(instance.into_host().0, fuel), fuel))
}

#[test]
fn the_committed_blob_validates_and_transfers_on_both_runtimes() -> Result<()> {
    validate_component(ACCOUNT_COMPONENT).context("profile validation of the committed blob")?;

    let (blessed_receipt, blessed_fuel) = blessed_transfer()?;
    let (sender, recipient) = keys();
    assert_eq!(blessed_receipt.delta.settles.get(&sender), Some(&AMOUNT));
    assert_eq!(
        blessed_receipt.delta.movements.get(&recipient),
        Some(&Movement {
            credit: AMOUNT,
            debit: 0,
        })
    );
    // Each leg's event carries the account that ran, not the account the
    // guest could name — and the two legs of a transfer sit on different
    // shards, which is what the attribution decides.
    assert_eq!(
        blessed_receipt.events,
        vec![
            Event {
                emitter: SENDER,
                event_type: 0,
                payload: encode_amount(AMOUNT).to_vec(),
            },
            Event {
                emitter: RECIPIENT,
                event_type: 1,
                payload: encode_amount(AMOUNT).to_vec(),
            },
        ],
    );

    let (reference_receipt, reference_fuel) = reference_transfer()?;
    assert_eq!(
        blessed_receipt, reference_receipt,
        "receipts must be byte-identical across runtimes"
    );
    assert_eq!(
        blessed_fuel, reference_fuel,
        "fuel must be identical across runtimes"
    );
    Ok(())
}

/// The committed blobs are what their sources build on the canonical
/// builder platform.
///
/// The blob is the protocol artifact and the source is the thing people
/// edit; without this equality an edited guest passes every behavioural
/// test — those run the committed bytes — while the committed bytes
/// quietly stop being what the repository says they are. The guest
/// build is reproducible per platform (pinned toolchain,
/// `immediate-abort` panics, no host paths in the artifact) but not
/// across platforms: toolchains emit the same code in different
/// function order per host OS. Linux owns the bytes —
/// `scripts/regenerate-stdlib.sh` produces them in a pinned container —
/// so the equality check runs only where the canonical builder lives.
#[test]
#[cfg(target_os = "linux")]
fn the_committed_blobs_are_what_their_sources_build() -> Result<()> {
    for (name, committed) in [
        ("account", ACCOUNT_COMPONENT),
        ("staking", STAKING_COMPONENT),
        ("lottery", LOTTERY_COMPONENT),
    ] {
        let built = build_guest(name)?;
        assert!(
            built == committed,
            "{name}: the committed blob ({} bytes) is not what the source builds \
             ({} bytes) — if the change is deliberate, run \
             scripts/regenerate-stdlib.sh and commit the result\n{}",
            committed.len(),
            built.len(),
            diff_report(committed, &built),
        );
    }
    Ok(())
}

/// Hex context around the first differing byte ranges, so a mismatch on
/// a machine whose artifact we cannot fetch (CI) still shows what its
/// build produced where it diverges.
#[cfg(target_os = "linux")]
fn diff_report(committed: &[u8], built: &[u8]) -> String {
    use std::fmt::Write;
    const MAX_RANGES: usize = 8;
    const CONTEXT: usize = 8;
    let n = committed.len().min(built.len());
    let mut out = String::new();
    let mut i = 0;
    let mut shown = 0;
    while i < n && shown < MAX_RANGES {
        if committed[i] == built[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && committed[i] != built[i] {
            i += 1;
        }
        let lo = start.saturating_sub(CONTEXT);
        let hi = (i + CONTEXT).min(n);
        let hex = |b: &[u8]| {
            b.iter().fold(String::new(), |mut s, x| {
                let _ = write!(s, "{x:02x}");
                s
            })
        };
        let _ = writeln!(
            out,
            "  diff at {start}..{i}:\n    committed[{lo}..{hi}] = {}\n    built    [{lo}..{hi}] = {}",
            hex(&committed[lo..hi]),
            hex(&built[lo..hi]),
        );
        shown += 1;
    }
    if committed.len() != built.len() {
        let _ = writeln!(
            out,
            "  lengths differ: committed {} vs built {}",
            committed.len(),
            built.len(),
        );
    }
    out
}

/// The lottery instance the round below settles.
const LOTTERY: Address = Address::new([4; 31], AddressClass::Component);
/// The entrant whose ticket the round holds.
const ENTRANT: Address = Address::new([5; 31], AddressClass::Component);

/// The lottery's settled-round cell and its entrants collection.
fn draw_key() -> SubstateKey {
    child_key(&TestHasher, LOTTERY, lottery::DRAW, &[])
}

fn ticket_collection() -> CollectionId {
    collection_id(&TestHasher, LOTTERY, lottery::TICKETS, &[])
}

fn ticket_order() -> u128 {
    order_key(
        &TestHasher,
        LOTTERY,
        lottery::TICKETS,
        &[Value::Address(ENTRANT).canonical_bytes()],
    )
}

/// A session over one entered round: the ticket entry, the pot, the
/// result cell, and the interval a draw reads.
fn lottery_session() -> KernelSession {
    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Entry {
                owner: LOTTERY,
                collection: ticket_collection(),
                order: ticket_order(),
            },
            mode: Mode::Write,
        },
        Effect {
            target: EffectTarget::Point(child_key(&TestHasher, LOTTERY, VAULT, &[])),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(draw_key()),
            mode: Mode::Write,
        },
        Effect {
            target: EffectTarget::Range {
                owner: LOTTERY,
                collection: ticket_collection(),
                lo: 0,
                hi: u128::MAX,
                cap: lottery::ROUND_CAP,
            },
            mode: Mode::Read,
        },
    ] {
        declared.insert(effect).unwrap();
    }
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &declared,
        &declared.iter().collect::<Vec<_>>(),
        TxHash(Hash32([0x78; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: RANDOMNESS,
        },
        test_hash,
    )
    .expect("feasible")
}

/// What the round settles to: the draw the environment fixed, then the
/// one entrant it can select.
fn settled() -> Vec<u8> {
    let mut out = RANDOMNESS.to_vec();
    out.extend_from_slice(&ENTRANT.to_bytes());
    out
}

fn blessed_round() -> Result<(Receipt, u64)> {
    let engine = blessed_engine()?;
    let compiled = Component::new(&engine, LOTTERY_COMPONENT)?;
    let mut linker = Linker::new(&engine);
    add_kernel_to_linker(&mut linker)?;

    let host = entering(SessionHost(lottery_session()), LOTTERY);
    let entry_rep = rep_of(
        &host.0,
        &Capability::RangeWrite {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: ticket_order(),
            hi: ticket_order(),
            cap: 1,
        },
    );
    let pot_rep = rep_of(
        &host.0,
        &Capability::Delta(child_key(&TestHasher, LOTTERY, VAULT, &[])),
    );
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let enter = instance.get_typed_func::<(
        Resource<RangeWrite>,
        Resource<DeltaCell>,
        &[u8],
        &[u8],
        &[u8],
    ), ()>(&mut store, "enter")?;
    enter.call(
        &mut store,
        (
            Resource::new_borrow(entry_rep),
            Resource::new_borrow(pot_rep),
            &ticket_order().to_le_bytes()[..],
            &ENTRANT.to_bytes()[..],
            &encode_amount(AMOUNT)[..],
        ),
    )?;
    let enter_fuel = FUEL - store.get_fuel()?;
    let host = entering(store.into_data(), LOTTERY);

    let outcome_rep = rep_of(&host.0, &Capability::Write(draw_key()));
    let round_rep = rep_of(
        &host.0,
        &Capability::RangeRead {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: 0,
            hi: u128::MAX,
            cap: lottery::ROUND_CAP,
        },
    );
    let mut store = Store::new(&engine, host);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &compiled)?;
    let draw = instance
        .get_typed_func::<(Resource<RangeRead>, Resource<WriteCell>), ()>(&mut store, "draw")?;
    draw.call(
        &mut store,
        (
            Resource::new_borrow(round_rep),
            Resource::new_borrow(outcome_rep),
        ),
    )?;
    let fuel = enter_fuel + (FUEL - store.get_fuel()?);

    Ok((finish(store.into_data().0, fuel), fuel))
}

fn reference_round() -> Result<(Receipt, u64)> {
    let component = RefComponent::decode(LOTTERY_COMPONENT)?;
    let host = entering(SessionHost(lottery_session()), LOTTERY);
    let entry_rep = rep_of(
        &host.0,
        &Capability::RangeWrite {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: ticket_order(),
            hi: ticket_order(),
            cap: 1,
        },
    );
    let pot_rep = rep_of(
        &host.0,
        &Capability::Delta(child_key(&TestHasher, LOTTERY, VAULT, &[])),
    );
    let mut instance =
        RefComponentInstance::instantiate(&component, host).map_err(|(_, error)| error)?;
    let outcome = instance.invoke(
        "enter",
        &[
            CVal::Borrow(entry_rep, ResourceKind::RangeWrite),
            CVal::Borrow(pot_rep, ResourceKind::DeltaCell),
            CVal::Bytes(ticket_order().to_le_bytes().to_vec()),
            CVal::Bytes(ENTRANT.to_bytes().to_vec()),
            CVal::Bytes(encode_amount(AMOUNT).to_vec()),
        ],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("enter trapped: {trap:?}"))?;
    let enter_fuel = instance.fuel_consumed();
    let host = entering(instance.into_host(), LOTTERY);

    let outcome_rep = rep_of(&host.0, &Capability::Write(draw_key()));
    let round_rep = rep_of(
        &host.0,
        &Capability::RangeRead {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: 0,
            hi: u128::MAX,
            cap: lottery::ROUND_CAP,
        },
    );
    let mut instance =
        RefComponentInstance::instantiate(&component, host).map_err(|(_, error)| error)?;
    let outcome = instance.invoke(
        "draw",
        &[
            CVal::Borrow(round_rep, ResourceKind::RangeRead),
            CVal::Borrow(outcome_rep, ResourceKind::WriteCell),
        ],
    )?;
    outcome.map_err(|trap| wasmtime::error::format_err!("draw trapped: {trap:?}"))?;
    let fuel = enter_fuel + instance.fuel_consumed();

    Ok((finish(instance.into_host().0, fuel), fuel))
}

/// Randomness reaching the committed bytes, identically on both
/// runtimes.
///
/// The draw is the one input no signer supplies and no store holds, so
/// it is the one an implementation could plausibly disagree about. The
/// round settles to the environment's own draw beside the entrant it
/// selects, byte-identical across the two, at identical fuel.
#[test]
fn the_committed_lottery_settles_a_round_identically_on_both_runtimes() -> Result<()> {
    validate_component(LOTTERY_COMPONENT).context("profile validation of the committed blob")?;

    let (blessed_receipt, blessed_fuel) = blessed_round()?;
    assert_eq!(
        blessed_receipt.delta.cells.get(&draw_key()),
        Some(&Some(settled())),
        "the round records the draw the environment fixed"
    );

    let (reference_receipt, reference_fuel) = reference_round()?;
    assert_eq!(
        blessed_receipt, reference_receipt,
        "receipts must be byte-identical across runtimes"
    );
    assert_eq!(
        blessed_fuel, reference_fuel,
        "fuel must be identical across runtimes"
    );
    Ok(())
}

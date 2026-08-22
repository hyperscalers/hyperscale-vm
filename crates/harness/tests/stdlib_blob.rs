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

use std::sync::{Arc, LazyLock};

use hyperscale_vm_effects::vocabulary::VAULT;
use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, Value, child_key,
    collection_id, order_key,
};
use hyperscale_vm_fixtures::{LOTTERY_COMPONENT, lottery};
use hyperscale_vm_harness::dual::DualGuest;
#[cfg(target_os = "linux")]
use hyperscale_vm_harness::fixtures::build_guest;
use hyperscale_vm_kernel::{
    Capability, EnvInputs, Held, Interval, KernelSession, MemoryStore, OverlayStore, Receipt,
};
use hyperscale_vm_ref::{CVal, HandleKind};
use hyperscale_vm_runtime::validate_component;
use hyperscale_vm_sdk::hbor::to_vec;
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, STAKING_COMPONENT};
use hyperscale_vm_types::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Event, Mode, Movement,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use wasmtime::Result;
use wasmtime::error::Context;

const CLOCK_MS: u64 = 77;
const RANDOMNESS: [u8; 32] = [3; 32];
const FUEL: u64 = 10_000_000;
const AMOUNT: u128 = 100;
/// What the vaults in these fixtures hold.
const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// The account that withdraws, guards, and stamps.
const SENDER: Address = Address::new([1; 31], AddressClass::Component);
/// The account that receives.
const RECIPIENT: Address = Address::new([2; 31], AddressClass::Component);

fn keys() -> (SubstateKey, SubstateKey) {
    (
        child_key(&TestHasher, SENDER, SlotId(1), &[]),
        child_key(&TestHasher, RECIPIENT, SlotId(1), &[]),
    )
}

/// Enter the account whose method runs next. Emission is stamped from
/// here, so the caller driving the sequence is what supplies it.
const fn entering(mut host: KernelSession, who: Address) -> KernelSession {
    host.enter_invocation(who);
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
    store.write(sender, encode_amount(500).to_vec());
    // Both cells the transfer moves between hold the same resource,
    // which is what makes the credit a transfer rather than a
    // conversion.
    let denominations: Vec<_> = declared.iter().map(|_| Some(RESOURCE)).collect();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set: declared.clone(),
            ordered: declared
                .iter()
                .zip(denominations)
                .map(|(effect, holds)| DeclaredAccess { effect, holds })
                .collect(),
            ..Declaration::default()
        },
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
    session.finish(vec![], fuel).expect("oracle clean").0
}

/// The account blob in both engines' forms, compiled once per binary.
static ACCOUNT: LazyLock<DualGuest> = LazyLock::new(|| {
    DualGuest::compile(ACCOUNT_COMPONENT).expect("the committed account blob compiles")
});

/// Withdraw, deposit, then the pinned balance guard — one instantiation
/// per call, the session threaded through, as execution invokes guests,
/// on both runtimes at once.
fn dual_transfer() -> Result<(Receipt, u64)> {
    let (sender, recipient) = keys();
    let probe = entering(session(), SENDER);
    let sender_rep = rep_of(
        &probe,
        &Capability::Reserve {
            key: sender,
            amount: AMOUNT,
        },
    );
    let mut dual = ACCOUNT.instantiate(FUEL, || entering(session(), SENDER))?;
    // The grant is the bucket, so the withdrawal names no amount and
    // what comes back is the value itself rather than a reading of it.
    let funds = dual
        .invoke_both(
            "withdraw",
            &[CVal::Borrow(sender_rep, HandleKind::ReserveCell)],
        )?
        .bucket()?;
    let (blessed, reference) = dual.finish()?;
    let withdraw_fuel = blessed.fuel;

    let blessed_host = entering(blessed.session, RECIPIENT);
    let reference_host = entering(reference.session, RECIPIENT);
    let recipient_rep = rep_of(&blessed_host, &Capability::Delta(recipient));
    let mut dual = ACCOUNT.instantiate_pair(FUEL, blessed_host, reference_host)?;
    dual.invoke_both(
        "deposit",
        &[
            CVal::Borrow(recipient_rep, HandleKind::DeltaCell),
            CVal::Own(funds),
        ],
    )?;
    let (blessed, reference) = dual.finish()?;
    let fuel = withdraw_fuel + blessed.fuel;

    let receipt = finish(blessed.session, fuel);
    assert_eq!(
        receipt,
        finish(reference.session, fuel),
        "receipts must be byte-identical across runtimes"
    );
    Ok((receipt, fuel))
}

#[test]
fn the_committed_blob_validates_and_transfers_on_both_runtimes() -> Result<()> {
    let (blessed_receipt, _) = dual_transfer()?;
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

    Ok(())
}

/// No committed blob carries a path from the machine that built it.
///
/// The bytes are the protocol artifact, and a path in them is a property
/// of somebody's checkout rather than of the package: two builds of one
/// source at two directories would publish under two addresses. The
/// build already strips the name section for this reason; a panic
/// `Location` is the same leak by another route, which is why this asks
/// the artifact rather than trusting the flags that should have stopped
/// it.
///
/// Unlike the equality below, this holds on every platform — so it fails
/// where the leak is introduced rather than only where the canonical
/// builder runs.
#[test]
fn no_committed_blob_carries_a_build_path() {
    for (name, blob) in [
        ("account", ACCOUNT_COMPONENT),
        ("staking", STAKING_COMPONENT),
        ("lottery", LOTTERY_COMPONENT),
    ] {
        let found = absolute_paths(blob);
        assert!(
            found.is_empty(),
            "{name}: the committed blob carries {} build path(s): {found:?}",
            found.len(),
        );
    }
}

/// Every absolute path the bytes spell out, as a reader would find them.
///
/// Printable runs rather than a wasm parse: what a path leaks through is
/// whichever section happens to hold it, and the question is whether the
/// bytes contain one at all.
fn absolute_paths(blob: &[u8]) -> Vec<String> {
    const ROOTS: [&str; 4] = ["/home/", "/Users/", "/work/", "/root/"];
    let mut found = Vec::new();
    let mut run = Vec::new();
    for &byte in blob.iter().chain(std::iter::once(&0)) {
        if byte.is_ascii_graphic() || byte == b' ' {
            run.push(byte);
            continue;
        }
        if run.len() >= 6
            && let Ok(text) = std::str::from_utf8(&run)
            && let Some(at) = ROOTS.iter().find_map(|root| text.find(root))
        {
            found.push(text[at..].to_owned());
        }
        run.clear();
    }
    found
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
    child_key(&TestHasher, LOTTERY, lottery::OUTCOME, &[])
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
    // The pot is the one cell here that holds value; the ticket entries
    // and the settled draw are records the round writes.
    let denominations: Vec<_> = declared
        .iter()
        .map(|effect| matches!(effect.mode, Mode::Delta).then_some(RESOURCE))
        .collect();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration {
            set: declared.clone(),
            ordered: declared
                .iter()
                .zip(denominations)
                .map(|(effect, holds)| DeclaredAccess { effect, holds })
                .collect(),
            ..Declaration::default()
        },
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
/// The settled round as the package encodes it, built through that
/// package's own type rather than spliced here.
fn settled() -> Vec<u8> {
    to_vec(&lottery::Outcome {
        draw: RANDOMNESS,
        winner: Some(ENTRANT),
    })
    .expect("an outcome encodes")
}

/// The lottery blob in both engines' forms, compiled once per binary.
static LOTTERY_GUEST: LazyLock<DualGuest> = LazyLock::new(|| {
    DualGuest::compile(LOTTERY_COMPONENT).expect("the committed lottery blob compiles")
});

/// Enter, then draw — the session threaded through, on both runtimes at
/// once. The entrant crosses as the world's own address record, which the
/// dual lowering spells for both engines.
fn dual_round() -> Result<(Receipt, u64)> {
    let entered = || {
        let mut host = entering(lottery_session(), LOTTERY);
        host.open_bucket(Held::Amount(AMOUNT), RESOURCE);
        host
    };
    let mut probe = entering(lottery_session(), LOTTERY);
    let funds = probe.open_bucket(Held::Amount(AMOUNT), RESOURCE);
    let entry_rep = rep_of(
        &probe,
        &Capability::RangeWrite(Interval {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: ticket_order(),
            hi: ticket_order(),
            cap: 1,
        }),
    );
    let pot_rep = rep_of(
        &probe,
        &Capability::Delta(child_key(&TestHasher, LOTTERY, VAULT, &[])),
    );
    let mut dual = LOTTERY_GUEST.instantiate(FUEL, entered)?;
    dual.invoke_both(
        "enter",
        &[
            CVal::Borrow(entry_rep, HandleKind::RangeWrite),
            CVal::Borrow(pot_rep, HandleKind::DeltaCell),
            CVal::Bytes(ticket_order().to_le_bytes().to_vec()),
            CVal::Address(ENTRANT.to_bytes()),
            CVal::Own(funds),
        ],
    )?;
    let (blessed, reference) = dual.finish()?;
    let enter_fuel = blessed.fuel;

    let blessed_host = entering(blessed.session, LOTTERY);
    let reference_host = entering(reference.session, LOTTERY);
    let outcome_rep = rep_of(&blessed_host, &Capability::Write(draw_key()));
    let round_rep = rep_of(
        &blessed_host,
        &Capability::RangeRead(Interval {
            owner: LOTTERY,
            collection: ticket_collection(),
            lo: 0,
            hi: u128::MAX,
            cap: lottery::ROUND_CAP,
        }),
    );
    let mut dual = LOTTERY_GUEST.instantiate_pair(FUEL, blessed_host, reference_host)?;
    dual.invoke_both(
        "draw",
        &[
            CVal::Borrow(round_rep, HandleKind::RangeRead),
            CVal::Borrow(outcome_rep, HandleKind::WriteCell),
        ],
    )?;
    let (blessed, reference) = dual.finish()?;
    let fuel = enter_fuel + blessed.fuel;

    let receipt = finish(blessed.session, fuel);
    assert_eq!(
        receipt,
        finish(reference.session, fuel),
        "receipts must be byte-identical across runtimes"
    );
    Ok((receipt, fuel))
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

    let (blessed_receipt, _) = dual_round()?;
    assert_eq!(
        blessed_receipt.delta.cells.get(&draw_key()),
        Some(&Some(settled())),
        "the round records the draw the environment fixed"
    );
    Ok(())
}

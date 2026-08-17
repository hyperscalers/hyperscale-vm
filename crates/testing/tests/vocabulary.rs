//! The state vocabulary, executed.
//!
//! A contract body is written in [`hyperscale_vm_sdk::state`], and on the
//! host every accessor in it used to be a panic. These call the same
//! types against a real session over a real store, with no macro in the
//! way — so what is under test is the vocabulary itself rather than the
//! lowering that rewrites bodies into it.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, EntryKey, Hash32, Hasher,
    Mode, RoleId, SubstateKey, TestHasher, child_key, collection_id,
};
use hyperscale_vm_kernel::{
    EnvInputs, KernelSession, MemoryStore, Outcome, OverlayStore, TxHash, WorkingStore,
    encode_amount,
};
use hyperscale_vm_sdk::handle::Handle;
use hyperscale_vm_sdk::host::{Refusal, with_kernel};
use hyperscale_vm_sdk::state::{self, Bucket, Entry, Interval, OrderKey, Quantity, Slot, Vault};

const OWNER: Address = Address::new([0x11; 31], AddressClass::Component);
const CLOCK_MS: u64 = 4_000;

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn key(tag: u8) -> SubstateKey {
    child_key(&TestHasher, OWNER, RoleId(u16::from(tag)), &[])
}

fn collection() -> CollectionId {
    collection_id(&TestHasher, OWNER, RoleId(9), &[])
}

/// A session holding one cell per mode the vocabulary can name, and one
/// interval.
fn session(store: MemoryStore, effects: Vec<Effect>) -> KernelSession {
    let mut declared = EffectSet::new();
    for effect in effects {
        declared.insert(effect).expect("the effect set takes it");
    }
    let ordered: Vec<_> = declared.iter().collect();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declared,
        &ordered,
        &[],
        TxHash(Hash32([9; 32])),
        EnvInputs {
            clock_ms: CLOCK_MS,
            randomness: [3; 32],
        },
        hash,
    )
    .expect("the declaration materializes")
}

const fn point(key: SubstateKey, mode: Mode) -> Effect {
    Effect {
        target: EffectTarget::Point(key),
        mode,
    }
}

/// The whole of the collection's order-key space, at a cap no test
/// reaches.
fn range(mode: Mode) -> Effect {
    Effect {
        target: EffectTarget::Range {
            owner: OWNER,
            collection: collection(),
            lo: 0,
            hi: 100,
            cap: 8,
        },
        mode,
    }
}

/// A collection holding three entries, one order key apart.
fn seeded() -> MemoryStore {
    let mut store = MemoryStore::new();
    for (order, value) in [(1u128, 10u64), (2, 20), (3, 30)] {
        store
            .entry_write(OWNER, collection(), order, value.to_le_bytes().to_vec())
            .expect("the store takes an entry");
    }
    store.clear_log();
    store
}

#[test]
fn a_write_cell_reads_back_what_it_was_set_to() {
    let cell = key(1);
    let session = session(MemoryStore::new(), vec![point(cell, Mode::Write)]);

    let (session, ()) = with_kernel(session, || {
        let mut slot = Slot::<Quantity>::at(Handle::Write(0));
        assert_eq!(
            slot.get(),
            Quantity::from_subunits(0),
            "an absent cell reads as its zero"
        );
        slot.set(Quantity::from_subunits(42));
        assert_eq!(slot.get(), Quantity::from_subunits(42));
    });

    let (receipt, _) = session
        .finish(Outcome::Completed { value: None }, 0)
        .expect("nothing outside the declared set was touched");
    assert_eq!(
        receipt.delta.cells.get(&cell),
        Some(&Some(encode_amount(42).to_vec()))
    );
}

/// Value moves as one operation: what leaves the cell is what the bucket
/// carries, and the body names the amount once.
#[test]
fn value_taken_from_a_cell_is_the_value_in_hand() {
    let vault = key(2);
    let mut store = MemoryStore::new();
    store
        .write(vault, encode_amount(100).to_vec())
        .expect("the store takes it");
    store.clear_log();
    let session = session(store, vec![point(vault, Mode::Write)]);

    let (_, held) = with_kernel(session, || {
        let mut slot = Slot::<Vault>::at(Handle::Write(0));
        let funds = slot.take(Quantity::from_subunits(30));
        let held = funds.quantity();
        slot.put(funds);
        held
    });

    assert_eq!(held, Quantity::from_subunits(30));
}

/// A bucket splits and merges without a cell in between.
#[test]
fn a_bucket_divides_into_what_comes_off_and_what_is_left() {
    let vault = key(3);
    let mut store = MemoryStore::new();
    store
        .write(vault, encode_amount(100).to_vec())
        .expect("the store takes it");
    store.clear_log();
    let session = session(store, vec![point(vault, Mode::Write)]);

    let (_, (split, rest)) = with_kernel(session, || {
        let mut slot = Slot::<Vault>::at(Handle::Write(0));
        let mut funds = slot.take(Quantity::from_subunits(50));
        let part = funds.take(Quantity::from_subunits(20));
        (part.quantity(), funds.quantity())
    });

    assert_eq!(
        (split, rest),
        (Quantity::from_subunits(20), Quantity::from_subunits(30))
    );
}

/// An interval walks its entries in order, and writes land in the store.
#[test]
fn an_interval_reads_and_writes_the_entries_it_covers() {
    let session = session(seeded(), vec![range(Mode::Write)]);

    let (session, (count, orders, second)) = with_kernel(session, || {
        let mut interval = Interval::<u64>::at(Handle::RangeWrite(0));
        let count = interval.count();
        let orders: Vec<OrderKey> = (0..count).map(|index| interval.order(index)).collect();
        let second = interval.entry(1);
        interval.set(1, 99);
        (count, orders, second)
    });

    assert_eq!(count, 3);
    assert_eq!(orders, vec![1, 2, 3]);
    assert_eq!(second, 20);
    let (receipt, _) = session
        .finish(Outcome::Completed { value: None }, 0)
        .expect("nothing outside the declared set was touched");
    assert_eq!(receipt.delta.entries.len(), 1, "one entry was rewritten");
}

/// A removal takes the entry out of the collection rather than blanking
/// it: the interval closes over the gap, and the delta carries the
/// removal itself.
#[test]
fn an_interval_removes_the_entry_it_names() {
    let session = session(seeded(), vec![range(Mode::Write)]);

    let (session, (left, orders)) = with_kernel(session, || {
        let mut interval = Interval::<u64>::at(Handle::RangeWrite(0));
        interval.remove(1);
        let left = interval.count();
        let orders: Vec<OrderKey> = (0..left).map(|index| interval.order(index)).collect();
        (left, orders)
    });

    assert_eq!(left, 2);
    assert_eq!(orders, vec![1, 3]);
    let (receipt, _) = session
        .finish(Outcome::Completed { value: None }, 0)
        .expect("nothing outside the declared set was touched");
    assert_eq!(receipt.delta.entries.len(), 1);
    assert_eq!(
        receipt.delta.entries.get(&EntryKey {
            owner: OWNER,
            collection: collection(),
            order: 2,
        }),
        Some(&None),
        "the delta carries a removal, not a blanked value"
    );
}

/// An entry names its own order key within the interval the kernel
/// materialized, and writing one that is not there creates it.
#[test]
fn an_entry_writes_at_the_order_it_names() {
    let session = session(MemoryStore::new(), vec![range(Mode::Write)]);

    let (session, read) = with_kernel(session, || {
        let mut entry = Entry::<u64>::at(Handle::RangeWrite(0), 7);
        entry.set(1234);
        entry.get()
    });

    assert_eq!(read, 1234);
    let (receipt, _) = session
        .finish(Outcome::Completed { value: None }, 0)
        .expect("nothing outside the declared set was touched");
    assert_eq!(receipt.delta.entries.len(), 1);
}

/// The deterministic environment answers from the session, not from the
/// machine the test runs on.
#[test]
fn the_environment_is_the_transactions_own() {
    let session = session(MemoryStore::new(), Vec::new());

    let (_, (clock, randomness, digest)) = with_kernel(session, || {
        (state::clock_ms(), state::randomness(), state::hash(b"abc"))
    });

    assert_eq!(clock, CLOCK_MS);
    assert_eq!(randomness, vec![3; 32]);
    assert_eq!(digest, hash(b"abc").to_vec());
}

/// A kernel refusal unwinds as the class the receipt would carry — the
/// trap a guest would take, with no engine to raise one.
#[test]
fn a_refused_operation_carries_its_class_out() {
    let vault = key(4);
    let session = session(MemoryStore::new(), vec![point(vault, Mode::Write)]);

    let refusal = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        with_kernel(session, || {
            // Nothing is in the cell, so there is nothing to take.
            let mut slot = Slot::<Vault>::at(Handle::Write(0));
            let _: Bucket = slot.take(Quantity::from_subunits(1));
        });
    }))
    .expect_err("an unfunded take refuses");

    assert!(
        refusal.downcast_ref::<Refusal>().is_some(),
        "the panic carries the kernel's own class"
    );
}

/// A refusal that unwinds past the scope leaves the thread as it found
/// it.
///
/// The engines catch inside the scope and never reach this, but a caller
/// driving bodies itself can, and a thread that kept the interrupted
/// kernel would fail the *next* invocation on it — a report naming the
/// scope that met the mess rather than the one that made it.
#[test]
fn a_thread_a_refusal_unwound_through_runs_the_next_invocation() {
    let vault = key(5);
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let session = session(MemoryStore::new(), vec![point(vault, Mode::Write)]);
        with_kernel(session, || {
            let mut slot = Slot::<Vault>::at(Handle::Write(0));
            let _: Bucket = slot.take(Quantity::from_subunits(1));
        });
    }));
    assert!(refused.is_err(), "an unfunded take refuses");

    let session = session(MemoryStore::new(), vec![point(vault, Mode::Write)]);
    let (_, read) = with_kernel(session, || Slot::<Quantity>::at(Handle::Write(0)).get());

    assert_eq!(
        read,
        Quantity::ZERO,
        "the second scope reaches its own kernel"
    );
}

//! Guest pointers: every offset the boundary takes from a guest, judged by
//! the blessed engine and the reference interpreter against the same
//! session.
//!
//! A pointer that crosses the boundary carries one obligation — the range
//! it names, at the length beside it, stays inside the memory — and no
//! wasm instruction checks it: the guest hands over a number and the
//! dispatch reads through it. There is no alignment rule; the boundary
//! reads and writes unaligned. So an interpreter that read where the
//! engine refuses would not be lenient, it would be a second opinion
//! about what a transaction did.
//!
//! Three doors, because there are three ways a pointer arrives: a range
//! the guest hands in, an out-pointer a fixed-width result is written
//! back through, and a register the guest collects into.

use std::sync::{Arc, LazyLock};

use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, child_key,
};
use hyperscale_vm_embed::abi::{ABI, MEMORY, STATE};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_harness::dual::{DualGuest, Ended};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Mode, Moves,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use wasmtime::Result;
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;
const OWNER: Address = Address::new([0x80; 31], AddressClass::Component);
const HOLDINGS: CollectionId = CollectionId([9; 16]);
/// What the instances in the fixture's collection are instances of.
const RESOURCE: ResourceAddr = ResourceAddr::new([0x80; 31]);
/// The orders the fixture holds, and the balance behind the amount cell.
const INSTANCES: [u128; 3] = [10, 20, 30];
const BALANCE: u128 = 42;

/// The interval and the amount cell, at their positions in the session's
/// capability table.
const INTERVAL: GuestArg<'static> = GuestArg::Site { site: 0 };
const CELL: GuestArg<'static> = GuestArg::Site { site: 1 };

/// The first byte outside the guest's one page.
const END: u64 = 65_536;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn cell() -> SubstateKey {
    child_key(&TestHasher, OWNER, SlotId(16), &[])
}

/// A session holding one collection of instances and one amount cell.
fn session() -> KernelSession {
    let mut store = MemoryStore::new();
    for order in INSTANCES {
        store.entry_write(OWNER, HOLDINGS, order, b"x".to_vec());
    }
    store.write(cell(), encode_amount(BALANCE).to_vec());

    let write = Mode::Write { moves: Moves::Both };
    let effects = [
        Effect {
            target: EffectTarget::Range {
                owner: OWNER,
                collection: HOLDINGS,
                lo: 0,
                hi: u128::MAX,
                cap: 8,
            },
            mode: write,
        },
        Effect {
            target: EffectTarget::Point(cell()),
            mode: write,
        },
    ];
    let mut declared = EffectSet::default();
    for effect in effects {
        declared.insert(effect).expect("the set takes it");
    }
    // Both cells hold value: one an interval of instances, one a balance.
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set: declared.clone(),
            ordered: effects
                .iter()
                .map(|effect| DeclaredAccess {
                    reach: None,
                    effect: *effect,
                    holds: Some(RESOURCE),
                    clause: None,
                })
                .collect(),
            ..Declaration::default()
        },
        TxHash(Hash32([0x55; 32])),
        EnvInputs::unsealed(1),
        test_hash,
    )
    .expect("the declaration materializes")
}

/// One guest whose every export takes its pointers as parameters, so a
/// case is a call rather than another module.
///
/// The pointers are `u64` parameters the guest narrows to the `i32` the
/// import takes: what the boundary judges is the number it is handed,
/// and the caller chooses it.
fn guest() -> String {
    format!(
        r#"
(module
  (import "{STATE}" "site-instance-take"
    (func $site_instance_take (param i32 i32 i32 i32) (result i32)))
  (import "{STATE}" "site-balance" (func $site_balance (param i32 i32 i32)))
  (import "{STATE}" "site-entry" (func $site_entry (param i32 i32 i32) (result i32)))
  (import "{STATE}" "site-set" (func $site_set (param i32 i32 i32 i32)))
  (import "{ABI}" "arg" (func $arg (param i32 i32)))
  (import "{ABI}" "take" (func $take (param i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  ;; One id an honest call names, written eight-aligned at 96 and again
  ;; unaligned at 121; the caller says where the list is and how long.
  ;; The bucket taken is the edge.
  (func (export "take") (param $r i32) (param $ptr i64) (param $count i64)
    (i64.store (i32.const 96) (i64.const 10))
    (i64.store (i32.const 121) (i64.const 10))
    (i32.store (i32.const 200)
      (call $site_instance_take (local.get $r) (i32.const 0)
        (i32.wrap_i64 (local.get $ptr)) (i32.wrap_i64 (local.get $count))))
    (call $reply (i32.const 200) (i32.const 1)))

  ;; Bytes for a cell, from a range the caller chooses.
  (func (export "set") (param $c i32) (param $ptr i64) (param $len i64)
    (call $site_set (local.get $c) (i32.const 0)
      (i32.wrap_i64 (local.get $ptr)) (i32.wrap_i64 (local.get $len)))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; The balance through an out-pointer the caller chooses, its low
  ;; eight bytes answered back.
  (func (export "weigh") (param $c i32) (param $out i64)
    (call $site_balance (local.get $c) (i32.const 0) (i32.wrap_i64 (local.get $out)))
    (call $answer (i32.wrap_i64 (local.get $out)) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; Entry 0 fills the answer register; collect it where the caller
  ;; says and answer what was collected.
  (func (export "collect") (param $r i32) (param $ptr i64)
    (local $len i32)
    (local.set $len (call $site_entry (local.get $r) (i32.const 0) (i32.const 0)))
    (call $take (i32.wrap_i64 (local.get $ptr)))
    (call $answer (i32.wrap_i64 (local.get $ptr)) (local.get $len))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; The bytes argument, collected where the caller says and answered.
  (func (export "collect-arg") (param $payload i32) (param $ptr i64)
    (call $arg (i32.const 0) (i32.wrap_i64 (local.get $ptr)))
    (call $answer (i32.wrap_i64 (local.get $ptr)) (local.get $payload))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; A site parameter carries no register.
  (func (export "scalar-arg") (param $c i32)
    (call $arg (i32.const 0) (i32.const 0))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; Nothing filled the answer register.
  (func (export "stale")
    (call $take (i32.const 0))
    (call $reply (i32.const 0) (i32.const 0))))
"#
    )
}

static GUEST: LazyLock<DualGuest> = LazyLock::new(|| {
    DualGuest::compile(&parse_str(guest()).expect("the fixture parses"))
        .expect("the fixture compiles on both engines")
});

/// One call on a fresh instance per engine, ending the same on both.
fn both(export: &str, args: &[GuestArg<'_>]) -> Result<Invocation> {
    let mut dual = GUEST.instantiate(FUEL, session)?;
    let ended = dual.invoke_both(export, args)?;
    dual.finish()?;
    Ok(ended)
}

/// The call is refused as the guest's violation, before any host body
/// could answer, on both engines.
fn violates(why: &str, export: &str, args: &[GuestArg<'_>]) -> Result<()> {
    let ended = both(export, args)?;
    assert_eq!(
        ended.result,
        Invoked::Aborted(AbortReason::AbiViolation),
        "{why}: a range the boundary cannot read through"
    );
    assert!(!ended.exhausted, "{why}");
    Ok(())
}

// ─── the range a guest hands in ────────────────────────────────────────

/// An id list is `count` ids at `ptr`, eight bytes each, and bytes for a
/// cell are `len` at `ptr`; both are bounded by the memory they sit in,
/// and neither bound is something a wasm instruction checks.
#[test]
fn a_range_handed_in_is_judged_the_same_by_both() -> Result<()> {
    // The honest call, which both engines run: one id, taken into a
    // bucket of one instance on each side.
    let mut dual = GUEST.instantiate(FUEL, session)?;
    let ended = dual.invoke_both("take", &[INTERVAL, GuestArg::U64(96), GuestArg::U64(1)])?;
    let rep = ended.bucket()?;
    let (blessed, reference) = dual.finish()?;
    assert_eq!(blessed.session.bucket(rep)?.quantity(), 1);
    assert_eq!(reference.session.bucket(rep)?.quantity(), 1);

    // The same id at an unaligned address reads the same: there is no
    // alignment rule to refuse it.
    both("take", &[INTERVAL, GuestArg::U64(121), GuestArg::U64(1)])?.bucket()?;

    // A list that starts inside and runs past the end, one that starts
    // at the end, and a count whose byte width overflows the length:
    // all three are the boundary declining to read rather than a load
    // the guest executed, so all three are the same violation on both
    // sides.
    for (why, ptr, count) in [
        ("past the end", END - 8, 4),
        ("at the end", END, 1),
        ("length overflow", 8, u64::from(u32::MAX / 4)),
    ] {
        violates(
            why,
            "take",
            &[INTERVAL, GuestArg::U64(ptr), GuestArg::U64(count)],
        )?;
    }
    violates(
        "bytes past the end",
        "set",
        &[CELL, GuestArg::U64(END - 6), GuestArg::U64(16)],
    )
}

// ─── the out-pointer a result is written through ───────────────────────

/// A fixed-width result travels through a pointer the guest chose, on the
/// same terms as one it hands in: the write is judged when the host has
/// answered, and it is the guest's violation all the same.
#[test]
fn an_out_pointer_is_judged_the_same_by_both() -> Result<()> {
    let ended = both("weigh", &[CELL, GuestArg::U64(96)])?;
    assert_eq!(u128::from(ended.scalar()?), BALANCE);
    let ended = both("weigh", &[CELL, GuestArg::U64(101)])?;
    assert_eq!(u128::from(ended.scalar()?), BALANCE, "unaligned");
    violates("past the end", "weigh", &[CELL, GuestArg::U64(END - 2)])
}

// ─── and the register a guest collects into ────────────────────────────

/// A register is collected at a pointer the guest chose, and only a
/// filled one: an unfilled register — never filled, or a parameter that
/// carries none — is a violation on the same terms as a range outside
/// the memory.
#[test]
fn a_register_is_judged_the_same_by_both() -> Result<()> {
    let ended = both("collect", &[INTERVAL, GuestArg::U64(96)])?;
    assert_eq!(
        ended.result,
        Invoked::Produced {
            edges: vec![],
            answer: Some(b"x".to_vec()),
        }
    );
    let ended = both(
        "collect-arg",
        &[GuestArg::Bytes(b"payload"), GuestArg::U64(96)],
    )?;
    assert_eq!(
        ended.result,
        Invoked::Produced {
            edges: vec![],
            answer: Some(b"payload".to_vec()),
        }
    );

    violates(
        "the answer register at the end",
        "collect",
        &[INTERVAL, GuestArg::U64(END)],
    )?;
    violates(
        "an input register past the end",
        "collect-arg",
        &[GuestArg::Bytes(b"payload"), GuestArg::U64(END - 6)],
    )?;
    violates("a parameter with no register", "scalar-arg", &[CELL])?;
    violates("an answer register never filled", "stale", &[])
}

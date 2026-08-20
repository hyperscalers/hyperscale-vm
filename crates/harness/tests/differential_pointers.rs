//! Differential lane 5, guest pointers: every offset the canonical ABI
//! takes from a guest, judged by the blessed engine and the reference
//! interpreter against the same session.
//!
//! A pointer that crosses the boundary carries two obligations — an
//! alignment for what sits at it, and a length that stays inside memory —
//! and neither is checked by any wasm instruction: the guest hands over a
//! number and the ABI reads through it. So an interpreter that read where
//! the engine refuses would not be lenient, it would be a second opinion
//! about what a transaction did.
//!
//! Three doors, because there are three ways a pointer arrives: a list
//! lifted out of guest memory, the area a spilled result is written back
//! to, and what `realloc` hands over when a list is lowered in.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, child_key,
};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_ref::{CVal, RefComponent, RefComponentInstance, ResourceKind};
use hyperscale_vm_runtime::{
    AmountCell, Bucket, InstanceRange, add_kernel_to_linker, blessed_engine, classify,
    validate_component,
};
use hyperscale_vm_types::{
    Address, AddressClass, CollectionId, Denomination, Effect, EffectSet, EffectTarget, Mode,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use wasmtime::component::{Component, Instance, Linker, Resource};
use wasmtime::{Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;
const OWNER: Address = Address::new([0x80; 31], AddressClass::Component);
const HOLDINGS: CollectionId = CollectionId([9; 16]);
/// What the instances in the fixture's collection are instances of.
const RESOURCE: Denomination = Denomination::Resource(ResourceAddr::new([0x80; 31]));
/// The orders the fixture holds, and the balance behind the amount cell.
const INSTANCES: [u128; 3] = [10, 20, 30];
const BALANCE: u128 = 42;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn cell() -> SubstateKey {
    child_key(&TestHasher, OWNER, SlotId(16), &[])
}

/// How a lane ended, in the terms the two engines both answer in.
///
/// The abort class rather than the message: what a receipt records is the
/// class, so that is what the two have to agree on.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Ran,
    Aborted(String),
}

/// A session holding one collection of instances and one amount cell.
fn session() -> KernelSession {
    let mut store = MemoryStore::new();
    for order in INSTANCES {
        store
            .entry_write(OWNER, HOLDINGS, order, b"x".to_vec())
            .expect("the fixture seeds");
    }
    store
        .write(cell(), encode_amount(BALANCE).to_vec())
        .expect("the fixture seeds");

    let write = Mode::Write;
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
                    effect: *effect,
                    holds: Some(RESOURCE),
                })
                .collect(),
            ..Declaration::default()
        },
        TxHash(Hash32([0x55; 32])),
        EnvInputs {
            clock_ms: 1,
            randomness: [3; 32],
        },
        test_hash,
    )
    .expect("the declaration materializes")
}

/// Run one component under both engines and answer their verdicts.
fn both<T>(
    source: &str,
    export: &str,
    args: &[CVal],
    call: impl FnOnce(&Instance, &mut Store<KernelSession>) -> Result<T>,
) -> Result<(Verdict, Verdict)> {
    let bytes = parse_str(source)?;
    validate_component(&bytes)?;

    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<KernelSession>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, session());
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;
    let blessed = match call(&instance, &mut store) {
        Ok(_) => Verdict::Ran,
        Err(error) => Verdict::Aborted(format!("{:?}", classify(&error))),
    };

    let comp = RefComponent::decode(&bytes)?;
    let mut interpreted = RefComponentInstance::instantiate(&comp, session(), u64::MAX)
        .map_err(|(_, error)| error)?;
    let reference = match interpreted.invoke(export, args)? {
        Ok(_) => Verdict::Ran,
        Err(error) => Verdict::Aborted(format!("{:?}", error.abort_reason())),
    };
    Ok((blessed, reference))
}

// ─── the list a guest hands over ───────────────────────────────────────

/// `take` names instances at a `(pointer, length)` the caller chooses.
fn lifting(ptr: i32, len: i32) -> String {
    format!(
        r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "bucket" (type $bk (sub resource)))
    (export "instance-range" (type $rw (sub resource)))
    (export "instance-range-take"
      (func (param "r" (borrow $rw)) (param "ids" (list u64)) (result (own $bk))))))
  (alias export $state "bucket" (type $bucket))
  (alias export $state "instance-range" (type $wrange))
  (alias export $state "instance-range-take" (func $take))

  (core module $alloc
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 1024))
  (core instance $a (instantiate $alloc))
  (core func $take_l (canon lower (func $take) (memory $a "mem")))
  (core func $drop_r (canon resource.drop $wrange))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "take" (func $take (param i32 i32 i32) (result i32)))
    (import "k" "drop" (func $drop (param i32)))
    ;; One id an honest call would name, written eight-aligned.
    (func (export "take") (param i32) (result i32)
      (local $out i32)
      i32.const 96
      i64.const 10
      i64.store
      local.get 0
      i32.const {ptr}
      i32.const {len}
      call $take
      local.set $out
      local.get 0
      call $drop
      local.get $out))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance (export "take" (func $take_l)) (export "drop" (func $drop_r))))))

  (func (export "take")
    (param "r" (borrow $wrange)) (result (own $bucket))
    (canon lift (core func $i "take"))))
"#
    )
}

fn lift_verdicts(ptr: i32, len: i32) -> Result<(Verdict, Verdict)> {
    both(
        &lifting(ptr, len),
        "take",
        &[CVal::Borrow(0, ResourceKind::InstanceRange)],
        |instance, store| {
            instance
                .get_typed_func::<(Resource<InstanceRange>,), (Resource<Bucket>,)>(
                    &mut *store,
                    "take",
                )?
                .call(store, (Resource::new_borrow(0),))
        },
    )
}

/// A `list<u64>` is eight-aligned and bounded by the memory it sits in,
/// and neither is something a wasm instruction checks — the guest hands
/// over two numbers and the ABI reads through them.
#[test]
fn a_lifted_list_is_judged_the_same_by_both() -> Result<()> {
    // The honest call, which both engines run.
    let (blessed, reference) = lift_verdicts(96, 1)?;
    assert_eq!(blessed, Verdict::Ran);
    assert_eq!(reference, Verdict::Ran);

    // One past an eight-aligned slot, past the end of memory, and a
    // length whose byte width runs past it. All three are the ABI
    // declining to read rather than a load the guest executed, so all
    // three abort as the same violation on both sides.
    for (why, ptr, len) in [
        ("misaligned", 101, 1),
        ("out of bounds", 65_528, 4),
        ("length past the end", 8, i32::MAX),
    ] {
        let (blessed, reference) = lift_verdicts(ptr, len)?;
        assert_eq!(blessed, reference, "{why}");
        assert_eq!(
            blessed,
            Verdict::Aborted("AbiViolation".into()),
            "{why}: a pointer the ABI cannot read through"
        );
    }
    Ok(())
}

// ─── the area a result is written back to ──────────────────────────────

/// `weigh` asks a balance into a return area the caller chooses.
fn returning(retptr: i32) -> String {
    format!(
        r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "amount-cell" (type $ac (sub resource)))
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "amount-cell-balance" (func (param "c" (borrow $ac)) (result $amt)))))
  (alias export $state "amount-cell" (type $acell))
  (alias export $state "amount-cell-balance" (func $balance))

  (core module $alloc
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 1024))
  (core instance $a (instantiate $alloc))
  (core func $balance_l (canon lower (func $balance) (memory $a "mem")))
  (core func $drop_c (canon resource.drop $acell))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "balance" (func $balance (param i32 i32)))
    (import "k" "drop" (func $drop (param i32)))
    (func (export "weigh") (param i32) (result i64)
      (local $out i64)
      local.get 0
      i32.const {retptr}
      call $balance
      i32.const {retptr}
      i64.load align=1
      local.set $out
      local.get 0
      call $drop
      local.get $out))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance (export "balance" (func $balance_l)) (export "drop" (func $drop_c))))))

  (func (export "weigh")
    (param "c" (borrow $acell)) (result u64)
    (canon lift (core func $i "weigh"))))
"#
    )
}

/// A spilled result travels through a pointer the guest chose, on the
/// same terms as one it hands in.
#[test]
fn a_return_area_is_judged_the_same_by_both() -> Result<()> {
    let verdicts = |retptr: i32| {
        both(
            &returning(retptr),
            "weigh",
            &[CVal::Borrow(1, ResourceKind::AmountCell)],
            |instance, store| {
                instance
                    .get_typed_func::<(Resource<AmountCell>,), (u64,)>(&mut *store, "weigh")?
                    .call(store, (Resource::new_borrow(1),))
            },
        )
    };

    // An `amount` is a record of two `u64`s, so its area is eight-aligned.
    let (blessed, reference) = verdicts(96)?;
    assert_eq!(blessed, Verdict::Ran);
    assert_eq!(reference, Verdict::Ran);

    for (why, retptr) in [("misaligned", 101), ("out of bounds", 65_534)] {
        let (blessed, reference) = verdicts(retptr)?;
        assert_eq!(blessed, reference, "{why}");
        assert_eq!(blessed, Verdict::Aborted("AbiViolation".into()), "{why}");
    }
    Ok(())
}

// ─── and what realloc hands over ───────────────────────────────────────

/// `count` takes a list the host lowers in, through a `realloc` that
/// answers `at` whatever it was asked for.
fn allocating(at: i32) -> String {
    format!(
        r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "instance-range" (type $rw (sub resource)))
    (export "instance-range-count" (func (param "r" (borrow $rw)) (result u32)))))
  (alias export $state "instance-range" (type $wrange))
  (alias export $state "instance-range-count" (func $count))

  (core module $alloc
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const {at}))
  (core instance $a (instantiate $alloc))
  (core func $count_l (canon lower (func $count)))
  (core func $drop_r (canon resource.drop $wrange))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "count" (func $count (param i32) (result i32)))
    (import "k" "drop" (func $drop (param i32)))
    (func (export "count") (param i32 i32 i32) (result i32)
      (local $out i32)
      local.get 0
      call $count
      local.set $out
      local.get 0
      call $drop
      local.get $out))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance (export "count" (func $count_l)) (export "drop" (func $drop_r))))))

  (func (export "count")
    (param "r" (borrow $wrange)) (param "ids" (list u64)) (result u32)
    (canon lift (core func $i "count") (memory $a "mem") (realloc (func $a "realloc")))))
"#
    )
}

/// The pointer a guest's own allocator answers with is a guest pointer
/// like any other: the ABI is about to write a `list<u64>` through it.
#[test]
fn a_realloc_result_is_judged_the_same_by_both() -> Result<()> {
    let verdicts = |at: i32| {
        both(
            &allocating(at),
            "count",
            &[
                CVal::Borrow(0, ResourceKind::InstanceRange),
                CVal::Ids(vec![10, 20]),
            ],
            |instance, store| {
                instance
                    .get_typed_func::<(Resource<InstanceRange>, &[u64]), (u32,)>(
                        &mut *store,
                        "count",
                    )?
                    .call(store, (Resource::new_borrow(0), &[10u64, 20][..]))
            },
        )
    };

    let (blessed, reference) = verdicts(1024)?;
    assert_eq!(blessed, Verdict::Ran);
    assert_eq!(reference, Verdict::Ran);

    // An allocator that answers an offset the elements cannot sit at.
    let (blessed, reference) = verdicts(1025)?;
    assert_eq!(blessed, reference);
    assert_eq!(blessed, Verdict::Aborted("AbiViolation".into()));
    Ok(())
}

//! What a body can reach, and what bounds it.
//!
//! A site is an `i32` the guest writes, so a body can name any site it
//! likes — and what stands between a written number and a cell is the
//! kernel's own table, checked at every operation. Four questions
//! decide it, and this lane asks each of them directly rather than
//! through a package that happens to behave.
//!
//! **The frame bounds reach.** Materialization seeds one site per
//! declared capability, in table order, and the seeded sites belong to
//! no frame: a frame resolves exactly the sites the walk bound for it,
//! plus the buckets it was lent or opened. A body handed one site and
//! naming another is refused as outside its frame — the seeded number
//! of the very cell it was handed included, since the frame reaches
//! that cell by the site it was lent and by nothing else. In a composed
//! transaction that is what keeps one node's body out of another's
//! cells: `node_reach.rs` states it over two packages of one manifest,
//! `subintent_reach.rs` over two signers, and `bucket_reach.rs` over
//! the value an earlier node left in flight.
//!
//! What still bounds a site the frame does reach is unchanged: a rep no
//! site occupies is unknown, judged before reach, and an operation the
//! capability never granted is refused at every operation.
//!
//! **No frame, no bound.** A session nobody entered resolves every
//! seeded site, which is what lets a session be acted through the
//! moment it exists and what the direct-invocation lanes rely on. The
//! last case pins that carve-out as one: production always enters a
//! frame through the walk, and a driver that enters one lends what it
//! hands.
//!
//! Shard scope is the axis this lane does not cover: a capability on a
//! cell another member judges is refused as `OutsideScope`, which
//! `kernel/tests/scope.rs` pins over the executions that can differ on
//! it.

use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_embed::abi::{ABI, MEMORY, STATE};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_harness::dual::{DualGuest, Ended, materialize, rep_where};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, SubstateKey,
    TxHash,
};
use wasmtime::Result;
use wat::parse_str;

const FUEL: u64 = 1_000_000;

/// What the readable cell holds; its length is what a body that reached
/// it answers with, and no other cell in the fixture is this wide.
const READABLE: &[u8] = b"alpha";

/// What the writable cell holds, at a length nothing else shares.
const WRITABLE: &[u8] = b"bb";

/// A rep no capability sits at: the table has two entries.
const PAST_THE_TABLE: u32 = 9_999;

/// The instance whose frame the lane enters; the emitter it stamps, and
/// nothing this lane reads.
const INSTANCE: Address = Address::new([0x4C; 31], AddressClass::Component);

const fn tx() -> TxHash {
    TxHash(Hash32([0x4C; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(7_000)
}

fn key(slot: u16) -> SubstateKey {
    child_key(&TestHasher, INSTANCE, SlotId(slot), &[])
}

/// Two declared cells under one transaction: one lent for reading, one
/// for writing.
///
/// Two modes rather than two reads, so the lane can ask the same site
/// for an operation its capability never granted.
struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    readable: SubstateKey,
    writable: SubstateKey,
}

fn fixture() -> Fixture {
    let (readable, writable) = (key(1), key(2));
    let mut store = MemoryStore::new();
    store.write(readable, READABLE.to_vec());
    store.write(writable, WRITABLE.to_vec());

    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(writable),
            mode: Mode::Write { moves: Moves::Both },
        },
    ] {
        declared.insert(effect).expect("the set takes it");
    }

    Fixture {
        declared,
        store,
        readable,
        writable,
    }
}

fn session(fx: &Fixture) -> KernelSession {
    let denominations = vec![None; fx.declared.iter().count()];
    materialize(&fx.store, &fx.declared, &denominations, tx(), env())
}

/// The rep of the capability over `wanted`, in the mode it was declared
/// at.
fn rep_of(session: &KernelSession, wanted: SubstateKey, mode: Mode) -> u32 {
    rep_where(session, |capability| match (mode, capability) {
        (Mode::Read, Capability::Read(key))
        | (Mode::Write { .. }, Capability::Write(key) | Capability::Amount { key, .. }) => {
            *key == wanted
        }
        _ => false,
    })
}

/// A guest whose `read` names `site` in its own text, whatever site it
/// is handed, and whose `-handed` exports act through what they were
/// given.
///
/// The number is baked in at authorship, which is the whole point: a
/// body does not have to be given a site to name one.
fn guest(site: u32) -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site_get" (func $site_get (param i32 i32) (result i32)))
  (import "{STATE}" "site_set" (func $site_set (param i32 i32 i32 i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  ;; The eight bytes at 512 are the answer, and there are no edges.
  (func $answered (param $value i64)
    (i64.store (i32.const 512) (local.get $value))
    (call $answer (i32.const 512) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; Read the site named here, and answer what it holds the length of.
  ;; The register the read fills is left uncollected, which costs the
  ;; call nothing and is what the length alone needs.
  (func (export "read") (param $handed i32)
    (call $answered
      (i64.extend_i32_u (call $site_get (i32.const {site}) (i32.const 0)))))

  ;; The same read, at a rep the table has no entry for.
  (func (export "read-past-the-table") (param $handed i32)
    (call $answered
      (i64.extend_i32_u (call $site_get (i32.const {PAST_THE_TABLE}) (i32.const 0)))))

  ;; The same read, through the site the body was handed.
  (func (export "read-handed") (param $handed i32)
    (call $answered
      (i64.extend_i32_u (call $site_get (local.get $handed) (i32.const 0)))))

  ;; A write through the site the body was handed, whatever mode it was
  ;; declared at.
  (func (export "write-handed") (param $handed i32)
    (call $site_set (local.get $handed) (i32.const 0) (i32.const 0) (i32.const 1))
    (call $answered (i64.const 0))))
"#
    );
    parse_str(&text).expect("the fixture parses")
}

/// Enter a frame and lend it the one site over `handed`, the way the
/// walk lends a node its handle parameters; answers the session and
/// the site the frame reaches the cell at.
fn framed(fx: &Fixture, handed: u32) -> (KernelSession, u32) {
    let mut session = session(fx);
    session.enter_invocation(INSTANCE);
    let site = session.bind_site(vec![Some(handed)]);
    (session, site)
}

/// Invoke `export` on both engines inside a frame lent `handed` and
/// nothing else.
fn invoked(fx: &Fixture, site: u32, export: &str, handed: u32) -> Result<Invocation> {
    let compiled = DualGuest::compile(&guest(site))?;
    let (_, lent) = framed(fx, handed);
    let mut dual = compiled.instantiate(FUEL, || framed(fx, handed).0)?;
    let ended = dual.invoke_both(export, &[GuestArg::Site { site: lent }])?;
    dual.finish()?;
    Ok(ended)
}

/// Invoke `export` on both engines with no frame entered: the session as
/// it was materialized, handed a seeded site directly.
fn invoked_unframed(fx: &Fixture, site: u32, export: &str, handed: u32) -> Result<Invocation> {
    let compiled = DualGuest::compile(&guest(site))?;
    let mut dual = compiled.instantiate(FUEL, || session(fx))?;
    let ended = dual.invoke_both(export, &[GuestArg::Site { site: handed }])?;
    dual.finish()?;
    Ok(ended)
}

/// A body reaches the site it was handed and no other: a site it was
/// not handed is outside its frame, and so is the seeded number of the
/// cell it was handed.
///
/// The site it names belongs to the same transaction and to no argument
/// of this call. In a composed manifest that is another node's site,
/// and possibly another package's — so what bounds a package is its
/// own frame rather than the transaction's whole declaration.
#[test]
fn a_body_cannot_reach_a_site_it_was_not_handed() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let writable = rep_of(&probe, fx.writable, Mode::Write { moves: Moves::Both });
    assert_ne!(readable, writable, "the fixture declares two capabilities");

    let ended = invoked(&fx, readable, "read", writable)?;
    assert_eq!(
        ended.result,
        Invoked::Aborted(AbortReason::HandleOutsideFrame),
        "the body named a site its frame was never lent"
    );

    // The seeded site over the very cell it was handed is outside the
    // frame too: the frame reaches the cell by the site it was lent.
    let ended = invoked(&fx, readable, "read", readable)?;
    assert_eq!(
        ended.result,
        Invoked::Aborted(AbortReason::HandleOutsideFrame)
    );

    // And through the site it was handed, the same cell answers.
    let answered = invoked(&fx, readable, "read-handed", readable)?.scalar()?;
    assert_eq!(
        answered,
        READABLE.len() as u64,
        "the frame reaches what it was lent"
    );
    Ok(())
}

/// A site the table has no entry for is unknown, judged before reach:
/// what keeps reach inside the declaration and what keeps it inside the
/// frame are two fences, and a receipt says which answered.
#[test]
fn a_site_past_the_table_is_refused() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);

    let ended = invoked(&fx, readable, "read-past-the-table", readable)?;
    assert_eq!(ended.result, Invoked::Aborted(AbortReason::HandleUnknown));
    Ok(())
}

/// A site the declaration lent for reading refuses the write, however
/// it was reached.
///
/// Reaching a site and being granted an operation on it are two
/// questions, and the second is asked at every operation: a frame that
/// reaches a capability is not thereby exercising one.
#[test]
fn a_site_refuses_the_operation_it_never_granted() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let writable = rep_of(&probe, fx.writable, Mode::Write { moves: Moves::Both });

    let ended = invoked(&fx, readable, "write-handed", readable)?;
    assert_eq!(ended.result, Invoked::Aborted(AbortReason::HandleWrongMode));

    // And the same body handed the site that does grant it completes,
    // so what the refusal above answered is the mode and not the reach.
    let ended = invoked(&fx, readable, "write-handed", writable)?;
    assert!(
        matches!(ended.result, Invoked::Produced { .. }),
        "{:?}",
        ended.result
    );
    Ok(())
}

/// A session nobody entered resolves its seeded sites, which is the one
/// deliberate carve-out: no frame, no bound.
///
/// Production always enters a frame through the walk. What this keeps
/// is a session that is actable the moment it exists, for the lanes and
/// unit tests that drive one directly and lend nothing.
#[test]
fn a_session_nobody_entered_reaches_its_seeded_sites() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let writable = rep_of(&probe, fx.writable, Mode::Write { moves: Moves::Both });

    let answered = invoked_unframed(&fx, readable, "read", writable)?.scalar()?;
    assert_eq!(
        answered,
        READABLE.len() as u64,
        "with no frame entered, the body read the seeded site it named"
    );
    assert_ne!(
        answered,
        WRITABLE.len() as u64,
        "the two cells differ in width, so the figure says which was read"
    );
    Ok(())
}

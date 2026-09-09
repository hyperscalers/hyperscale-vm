//! What a body can reach, and what bounds it.
//!
//! A site is an `i32` the guest writes, so a body can name any site it
//! likes — and what stands between a written number and a cell is the
//! kernel's own table, checked at every operation. Three questions
//! decide it, and this lane asks each of them directly rather than
//! through a package that happens to behave.
//!
//! **The declaration bounds reach. The call's arguments do not.**
//! Materialization seeds one site per declared capability, in table
//! order, so every capability the transaction declared is reachable from
//! the first instruction of any body — including a body that was handed
//! a different site, or none, which is what the first case below shows.
//!
//! A composed transaction is where that has teeth. The walk binds one
//! capability table for the whole transaction and cannot tell whose call
//! is running, so the seeded sites a body may name are every node's, not
//! its own node's. Reach is the transaction's declaration, which
//! admission judged and the signer signed; it is not the argument list
//! the node named. The case below fixes the rule rather than that
//! consequence: a lane over two nodes of one manifest would state it
//! outright, and is worth having before the rule is relied on.
//!
//! Whether it should be narrower than that is a design question. What
//! this lane does is fix the answer in place, so a change to it is
//! deliberate rather than noticed later.
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

const fn tx() -> TxHash {
    TxHash(Hash32([0x4C; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(7_000)
}

fn key(slot: u16) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([0x4C; 31], AddressClass::Component),
        SlotId(slot),
        &[],
    )
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

/// A guest whose every export names `site` in its own text, whatever
/// site it is handed.
///
/// The number is baked in at authorship, which is the whole point: a
/// body does not have to be given a site to name one.
fn guest(site: u32) -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-get" (func $site_get (param i32 i32) (result i32)))
  (import "{STATE}" "site-set" (func $site_set (param i32 i32 i32 i32)))
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

  ;; A write at the site named here, whatever mode it was declared at.
  (func (export "write") (param $handed i32)
    (call $site_set (i32.const {site}) (i32.const 0) (i32.const 0) (i32.const 1))
    (call $answered (i64.const 0))))
"#
    );
    parse_str(&text).expect("the fixture parses")
}

/// Invoke `export` on both engines, handing it `handed` and nothing
/// else.
fn invoked(fx: &Fixture, site: u32, export: &str, handed: u32) -> Result<Invocation> {
    let compiled = DualGuest::compile(&guest(site))?;
    let mut dual = compiled.instantiate(FUEL, || session(fx))?;
    let ended = dual.invoke_both(export, &[GuestArg::Site { site: handed }])?;
    dual.finish()?;
    Ok(ended)
}

/// A body reads a site it was never handed, and the kernel serves it.
///
/// The site it names belongs to the same transaction and to no argument
/// of this call. In a composed manifest that is another node's site,
/// and possibly another package's — so what bounds a package here is
/// the transaction's whole declaration rather than the arguments its
/// own node named.
#[test]
fn a_body_reaches_a_site_it_was_not_handed() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let writable = rep_of(&probe, fx.writable, Mode::Write { moves: Moves::Both });
    assert_ne!(readable, writable, "the fixture declares two capabilities");

    let answered = invoked(&fx, readable, "read", writable)?.scalar()?;
    assert_eq!(
        answered,
        READABLE.len() as u64,
        "the body read the site it named, not the one it was handed"
    );
    assert_ne!(
        answered,
        WRITABLE.len() as u64,
        "the two cells differ in width, so the figure says which was read"
    );
    Ok(())
}

/// And a site the table has no entry for is refused, which is what
/// keeps reach inside the declaration rather than merely inside the
/// integers.
#[test]
fn a_site_past_the_table_is_refused() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);

    let ended = invoked(&fx, readable, "read-past-the-table", readable)?;
    assert_eq!(ended.result, Invoked::Aborted(AbortReason::HandleUnknown));
    Ok(())
}

/// A site the declaration lent for reading refuses the write, whoever
/// names it.
///
/// Naming a site and being granted an operation on it are two
/// questions, and the second is asked at every operation: reaching a
/// capability is not exercising one.
#[test]
fn a_site_refuses_the_operation_it_never_granted() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let writable = rep_of(&probe, fx.writable, Mode::Write { moves: Moves::Both });

    let ended = invoked(&fx, readable, "write", writable)?;
    assert_eq!(ended.result, Invoked::Aborted(AbortReason::HandleWrongMode));

    // And the same body against the site that does grant it completes,
    // so what the refusal above answered is the mode and not the name.
    let ended = invoked(&fx, writable, "write", readable)?;
    assert!(
        matches!(ended.result, Invoked::Produced { .. }),
        "{:?}",
        ended.result
    );
    Ok(())
}

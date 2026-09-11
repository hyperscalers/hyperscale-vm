//! The core boundary as a shared verdict: hand-written modules run under
//! the blessed engine and the reference interpreter against the same
//! kernel session, and every ending — the verdict, the fuel, the
//! exhaustion flag — must agree.
//!
//! The dispatch is one piece of code on both sides, so what this lane
//! holds together is everything around it: each engine's memory, its
//! counter, its call path, and the module's own execution.

use std::fmt::Write as _;
use std::sync::LazyLock;

use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_embed::abi::{IMPORTS, MEMORY};
use hyperscale_vm_embed::{GuestArg, Invoked};
use hyperscale_vm_harness::dual::{DualGuest, materialize, rep_where};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore};
use hyperscale_vm_meter::PAGE;
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, ResourceAddr,
    SubstateKey, TxHash, encode_amount,
};
use wasmtime::Result;
use wat::parse_str;

const FUEL: u64 = 1_000_000;
const BALANCE: u128 = 100;
const RESOURCE: ResourceAddr = ResourceAddr::new([0x71; 31]);

const fn tx() -> TxHash {
    TxHash(Hash32([0x71; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(4_242)
}

/// Every kernel import at the kernel's type, the memory, and `body`.
fn module(body: &str) -> Vec<u8> {
    let mut wat = String::from("(module\n");
    for (module, name, params, results) in IMPORTS {
        let _ = write!(
            wat,
            "  (import \"{module}\" \"{name}\" (func ${}",
            name.replace('-', "_")
        );
        for param in *params {
            wat.push_str(&format!(" (param {param:?})").to_lowercase());
        }
        for result in *results {
            wat.push_str(&format!(" (result {result:?})").to_lowercase());
        }
        wat.push_str("))\n");
    }
    let _ = write!(wat, "  (memory (export \"{MEMORY}\") 1 1)\n{body})");
    parse_str(wat).expect("the fixture parses")
}

/// The one module every lane runs: bytes through the registers, value
/// through handles, and every way a call can end.
static GUEST: LazyLock<DualGuest> = LazyLock::new(|| {
    DualGuest::compile(&module(
        r#"
  (func (export "copy") (param $a i32) (param $b i32) (param $payload i32)
    (local $len i32)
    i32.const 2 i32.const 0 call $arg
    local.get $b i32.const 0 i32.const 0 local.get $payload call $site_set
    local.get $a i32.const 0 call $site_get local.set $len
    i32.const 256 call $take
    i32.const 256 local.get $len i32.const 512 call $hash
    i32.const 256 local.get $len call $answer
    i32.const 0 i32.const 0 call $reply)
  (func (export "pay") (param $vault i32) (param $take i64) (result i32)
    (local $b i32)
    local.get $vault i32.const 0 i32.const 0 call $site_balance
    i32.const 16 local.get $take i64.store
    local.get $vault i32.const 0 i32.const 16 call $site_take local.set $b
    local.get $b i32.const 32 call $bucket_amount
    i32.const 48 local.get $b i32.store
    i32.const 48 i32.const 1 call $reply
    i32.const 0)
  (func (export "no") (param $code i64) (result i32)
    local.get $code i32.wrap_i64 i32.const 1 i32.add)
  (func (export "silent"))
  (func (export "stale") i32.const 0 call $take)
  (func (export "trap") unreachable)
  (func (export "refused") i32.const 99 i32.const 0 call $site_get drop)
  (func (export "spin") (loop br 0))
  (func (export "figures")
    i32.const 0 i64.const 6 i64.store
    i32.const 32 i64.const 3 i64.store
    i32.const 0 i32.const 32 i32.const 32 i32.const 0 i32.const 64 call $mul_div
    i32.const 0 i32.const 0 i32.const 96 call $geometric_mean
    i32.const 128 call $clock i64.store
    i32.const 0 i32.const 136 call $answer
    i32.const 0 i32.const 0 call $reply)"#,
    ))
    .expect("the fixture compiles on both engines")
});

struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    readable: SubstateKey,
    scratch: SubstateKey,
    vault: SubstateKey,
}

fn fixture() -> Fixture {
    let key = |slot: u16| {
        child_key(
            &TestHasher,
            Address::new([0x61; 31], AddressClass::Component),
            SlotId(slot),
            &[],
        )
    };
    let (readable, scratch, vault) = (key(1), key(2), key(3));
    let mut store = MemoryStore::new();
    store.write(readable, b"alpha".to_vec());
    store.write(scratch, vec![1, 2, 3]);
    store.write(vault, encode_amount(BALANCE).to_vec());
    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(scratch),
            mode: Mode::Write { moves: Moves::Both },
        },
        Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write { moves: Moves::Both },
        },
    ] {
        declared.insert(effect).unwrap();
    }
    Fixture {
        declared,
        store,
        readable,
        scratch,
        vault,
    }
}

fn session(fx: &Fixture) -> KernelSession {
    let denominations: Vec<Option<ResourceAddr>> = fx
        .declared
        .iter()
        .map(|effect| match effect.target {
            EffectTarget::Point(key) if key == fx.vault => Some(RESOURCE),
            _ => None,
        })
        .collect();
    materialize(&fx.store, &fx.declared, &denominations, tx(), env())
}

fn rep_of(host: &KernelSession, wanted: SubstateKey, mode: Mode) -> u32 {
    rep_where(host, |c| match (mode, c) {
        (Mode::Read, Capability::Read(key))
        | (Mode::Write { .. }, Capability::Write(key) | Capability::Amount { key, .. }) => {
            *key == wanted
        }
        _ => false,
    })
}

/// Bytes cross the same way on both engines: the register paths, the
/// hash, and the answer.
#[test]
fn bytes_cross_identically() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let (readable, scratch) = (
        rep_of(&probe, fx.readable, Mode::Read),
        rep_of(&probe, fx.scratch, Mode::Write { moves: Moves::Both }),
    );
    let mut dual = GUEST.instantiate(FUEL, || session(&fx))?;
    let ended = dual.invoke_both(
        "copy",
        &[
            GuestArg::Site { site: readable },
            GuestArg::Site { site: scratch },
            GuestArg::Bytes(b"payload"),
        ],
    )?;
    assert_eq!(
        ended.result,
        Invoked::Produced {
            edges: vec![],
            answer: Some(b"alpha".to_vec()),
        }
    );
    let (blessed, reference) = dual.finish()?;
    assert_eq!(blessed.fuel, reference.fuel);
    assert!(blessed.fuel > 0);
    Ok(())
}

/// Value moves the same way: the debit, the bucket it seats, and the
/// edge the reply hands back.
#[test]
fn value_moves_identically() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let vault = rep_of(&probe, fx.vault, Mode::Write { moves: Moves::Both });
    let mut dual = GUEST.instantiate(FUEL, || session(&fx))?;
    let ended = dual.invoke_both("pay", &[GuestArg::Site { site: vault }, GuestArg::U64(30)])?;
    let Invoked::Produced {
        edges,
        answer: None,
    } = ended.result
    else {
        panic!("{:?}", ended.result);
    };
    assert_eq!(edges.len(), 1);
    let (blessed, reference) = dual.finish()?;
    let rep = edges[0];
    assert_eq!(
        blessed.session.bucket(rep)?.quantity(),
        reference.session.bucket(rep)?.quantity()
    );
    assert_eq!(blessed.session.bucket(rep)?.quantity(), 30);
    Ok(())
}

/// Every other ending is shared: a decline, a return outside the
/// convention, a register violation, a trap, a refusal, and exhaustion.
#[test]
fn every_ending_is_shared() -> Result<()> {
    let fx = fixture();
    let cases: [(&str, &[GuestArg<'_>], Invoked); 6] = [
        ("no", &[GuestArg::U64(4)], Invoked::Declined(4)),
        ("silent", &[], Invoked::Aborted(AbortReason::BadReturnShape)),
        ("stale", &[], Invoked::Aborted(AbortReason::AbiViolation)),
        ("trap", &[], Invoked::Aborted(AbortReason::Unreachable)),
        ("refused", &[], Invoked::Aborted(AbortReason::HandleUnknown)),
        ("absent", &[], Invoked::Aborted(AbortReason::ExportMissing)),
    ];
    for (export, args, expected) in cases {
        let mut dual = GUEST.instantiate(FUEL, || session(&fx))?;
        let ended = dual.invoke_both(export, args)?;
        assert_eq!(ended.result, expected, "{export}");
        dual.finish()?;
    }
    let mut dual = GUEST.instantiate(PAGE + 10_000, || session(&fx))?;
    let ended = dual.invoke_both("spin", &[])?;
    assert_eq!(ended.result, Invoked::Aborted(AbortReason::OutOfGas));
    assert_eq!(
        ended.fuel,
        PAGE + 10_000,
        "exhaustion spends the counter whole"
    );
    Ok(())
}

/// Fixed-width results and the clock land identically.
#[test]
fn figures_agree() -> Result<()> {
    let fx = fixture();
    let mut dual = GUEST.instantiate(FUEL, || session(&fx))?;
    let ended = dual.invoke_both("figures", &[])?;
    let Invoked::Produced {
        answer: Some(answer),
        ..
    } = ended.result
    else {
        panic!("{:?}", ended.result);
    };
    assert_eq!(&answer[64..72], &6u64.to_le_bytes(), "mul_div");
    assert_eq!(&answer[96..104], &6u64.to_le_bytes(), "geometric_mean");
    assert_eq!(&answer[128..136], &4_242u64.to_le_bytes(), "clock");
    dual.finish()?;
    Ok(())
}

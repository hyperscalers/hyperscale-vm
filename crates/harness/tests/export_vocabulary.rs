//! The export parameter vocabulary, closed across the layers that carry
//! it.
//!
//! The gate demands parameter kinds; the profile validator decides what
//! deploys; the executable spec decides what runs. A core signature says
//! only widths — a site, a bucket and the length of a register argument
//! are all one `i32` — so the kinds are held to the widths through one
//! table, [`ParamKind::core_type`], and a kind one layer admits while
//! another refuses is an artifact that classifies, deploys, and then
//! cannot execute, or one that builds cleanly and bounces at deploy. So
//! every kind the gate can demand and every ending the convention folds
//! is held to all three at once here, and the guard verdict — the one
//! kind that is a value rather than a handle or a register — is run on
//! both engines to the same ending.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32};
use hyperscale_vm_embed::abi::{ABI, CoreType, MEMORY, ParamKind};
use hyperscale_vm_embed::{GuestArg, Invoked};
use hyperscale_vm_harness::driver::test_hash;
use hyperscale_vm_harness::dual::{DualGuest, Ended as _};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_ref::RefModule;
use hyperscale_vm_runtime::{ModuleExport, module_exports, validate_module};
use hyperscale_vm_types::{EffectSet, TxHash};
use wasmtime::Result;
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

/// The kinds a `handles` export takes: a borrowed site.
const HANDLES: &[ParamKind] = &[ParamKind::Site];

/// The kinds an `edge` export takes: an owned bucket.
const EDGE: &[ParamKind] = &[ParamKind::Bucket];

/// The kinds a `values` export takes: the verdict, the scalar, and the
/// three register arguments.
const VALUES: &[ParamKind] = &[
    ParamKind::Flag,
    ParamKind::U64,
    ParamKind::Bytes,
    ParamKind::Address,
    ParamKind::Ids,
];

const fn wat_type(ty: CoreType) -> &'static str {
    match ty {
        CoreType::I32 => "i32",
        CoreType::I64 => "i64",
    }
}

/// The parameter list an export of `kinds` declares, in text.
fn params(kinds: &[ParamKind]) -> String {
    kinds
        .iter()
        .map(|kind| format!("(param {})", wat_type(kind.core_type())))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The core types an export of `kinds` is read at.
fn core_types(kinds: &[ParamKind]) -> Vec<CoreType> {
    kinds.iter().map(|kind| kind.core_type()).collect()
}

/// A module importing the two register calls a guest ends with,
/// exporting its memory, and carrying `body`.
fn module(body: &str) -> Vec<u8> {
    let text = format!(
        r#"(module
             (import "{ABI}" "reply" (func $reply (param i32 i32)))
             (import "{ABI}" "answer" (func $answer (param i32 i32)))
             (memory (export "{MEMORY}") 1 1)
             {body})"#
    );
    parse_str(text).expect("the fixture parses")
}

/// Every kind the gate can demand deploys, decodes, and reads as its
/// own width: the profile validator, the executable spec, and the
/// export reader agree on the whole vocabulary at once.
#[test]
fn every_kind_the_gate_can_demand_deploys_and_decodes() {
    let bytes = module(&format!(
        r#"(func (export "handles") {})
           (func (export "edge") {})
           (func (export "values") {})"#,
        params(HANDLES),
        params(EDGE),
        params(VALUES),
    ));
    validate_module(&bytes).expect("the profile admits every kind the gate can demand");
    RefModule::decode(&bytes).expect("the executable spec models every admitted kind");

    let exports = module_exports(&bytes).expect("the exports read");
    for (name, kinds) in [("handles", HANDLES), ("edge", EDGE), ("values", VALUES)] {
        assert_eq!(
            exports[name],
            ModuleExport {
                params: core_types(kinds),
                declines: false,
            },
            "{name}"
        );
    }
    assert_eq!(exports.len(), 3, "the memory is not an export shape");
}

/// A module whose exports end every way the convention folds: a
/// completed call, a decline, and an answer carried out of a completed
/// call — over both result shapes an export may declare.
fn endings() -> Vec<u8> {
    module(
        r#"(func (export "settle")
             i32.const 0 i32.const 0 call $reply)
           (func (export "decline") (result i32)
             i32.const 3)
           (func (export "answer") (result i32)
             i32.const 0 i64.const 42 i64.store
             i32.const 0 i32.const 8 call $answer
             i32.const 0 i32.const 0 call $reply
             i32.const 0)"#,
    )
}

/// Every ending the convention folds deploys, decodes, and reads as
/// itself: whether the export can decline is its result shape, and
/// what it produced is the reply — the gate reads the first, both
/// engines agree on the second.
#[test]
fn every_ending_the_convention_folds_deploys_and_decodes() -> Result<()> {
    let bytes = endings();
    validate_module(&bytes).expect("the profile admits every ending the convention folds");
    RefModule::decode(&bytes).expect("the executable spec models every admitted ending");

    let exports = module_exports(&bytes).expect("the exports read");
    for (name, declines) in [("settle", false), ("decline", true), ("answer", true)] {
        assert_eq!(exports[name].params, vec![], "{name} params");
        assert_eq!(exports[name].declines, declines, "{name} declines");
    }

    let guest = DualGuest::compile(&bytes)?;
    for (name, expected) in [
        (
            "settle",
            Invoked::Produced {
                edges: vec![],
                answer: None,
            },
        ),
        ("decline", Invoked::Declined(2)),
        (
            "answer",
            Invoked::Produced {
                edges: vec![],
                answer: Some(42u64.to_le_bytes().to_vec()),
            },
        ),
    ] {
        let mut dual = guest.instantiate(FUEL, session)?;
        let ended = dual.invoke_both(name, &[])?;
        assert_eq!(ended.result, expected, "{name}");
        dual.finish()?;
    }
    Ok(())
}

/// The endings the convention cannot fold refuse at deploy: a wide
/// result, two results, and a float parameter are shapes no receipt
/// has a reading of, so no such method deploys to abort per call.
#[test]
fn a_shape_the_convention_cannot_fold_refuses_at_deploy() {
    for (label, export) in [
        (
            "an i64 result",
            "(func (export \"f\") (result i64) i64.const 0)",
        ),
        (
            "two results",
            "(func (export \"f\") (result i32 i32) i32.const 0 i32.const 0)",
        ),
        ("an f64 parameter", "(func (export \"f\") (param f64))"),
    ] {
        let text = format!("(module (memory (export \"{MEMORY}\") 1 1) {export})");
        let bytes = parse_str(text).expect("the refusal fixture parses");
        assert!(
            validate_module(&bytes).is_err(),
            "{label} must refuse at deploy"
        );
    }
}

/// A session over no declared state: the verdict lane's guest reads and
/// writes nothing, so the fixture is the argument itself.
fn session() -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration::from_set(EffectSet::new()),
        TxHash(Hash32([0x21; 32])),
        EnvInputs::unsealed(424_242),
        test_hash,
    )
    .expect("an empty declaration materializes")
}

/// A guard verdict crosses both engines as the same core value: the
/// `i32` a flag lowers to picks the same arm on both, to the fuel.
#[test]
fn a_guard_verdict_crosses_both_engines_identically() -> Result<()> {
    let bytes = module(
        r#"(func (export "pick") (param $verdict i32)
             i32.const 0
             (select (i64.const 7) (i64.const 3) (local.get $verdict))
             i64.store
             i32.const 0 i32.const 8 call $answer
             i32.const 0 i32.const 0 call $reply)"#,
    );

    let guest = DualGuest::compile(&bytes)?;
    let mut dual = guest.instantiate(FUEL, session)?;
    assert_eq!(
        dual.invoke_both("pick", &[GuestArg::Bool(true)])?
            .scalar()?,
        7
    );
    assert_eq!(
        dual.invoke_both("pick", &[GuestArg::Bool(false)])?
            .scalar()?,
        3
    );
    dual.finish()?;
    Ok(())
}

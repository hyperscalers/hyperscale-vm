//! The export parameter vocabulary, closed across the layers that carry
//! it.
//!
//! The gate demands parameter shapes; the profile validator decides what
//! deploys; the executable spec decides what runs. Three lists that can
//! drift — and a shape one layer admits while another refuses is an
//! artifact that classifies, deploys, and then cannot execute, or one
//! that builds cleanly and bounces at deploy. So every shape the gate
//! can demand is held to all three at once here, and the one shape that
//! only recently joined the profile — the guard verdict `bool` — is run
//! on both engines to the same ending.

use std::fmt::Write as _;
use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32};
use hyperscale_vm_harness::driver::test_hash;
use hyperscale_vm_harness::dual::DualGuest;
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_ref::{CVal, RefComponent};
use hyperscale_vm_runtime::{ExportParam, component_exports, validate_component};
use hyperscale_vm_types::{EffectSet, TxHash};
use wasmtime::Result;
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

/// The state resources a clause can materialize a borrow of, by the name
/// the kernel world exports each under.
const HANDLE_KINDS: &[&str] = &[
    "read-cell",
    "locked-cell",
    "write-cell",
    "amount-cell",
    "amount-read",
    "delta-cell",
    "reserve-cell",
    "range-read",
    "range-write",
    "instance-range",
];

/// A component whose exports take every parameter shape the gate can
/// demand: a borrow of each state resource plus the issuance grant, an
/// owned bucket, and the derived values — verdict, scalar, bytes, and
/// the address record.
fn vocabulary_component() -> Vec<u8> {
    let mut resources = String::new();
    let mut aliases = String::new();
    let mut params = String::new();
    let mut core_params = String::new();
    for (index, kind) in HANDLE_KINDS.iter().enumerate() {
        writeln!(
            resources,
            "(export \"{kind}\" (type $r{index} (sub resource)))"
        )
        .expect("writing to a string");
        writeln!(aliases, "(alias export $state \"{kind}\" (type $h{index}))")
            .expect("writing to a string");
        write!(params, "(param \"p{index}\" (borrow $h{index})) ").expect("writing to a string");
        core_params.push_str("i32 ");
    }
    let text = format!(
        r#"(component
             (import "hyperscale:kernel/state" (instance $state
               {resources}
               (export "bucket" (type $bk (sub resource)))
               (export "issuer" (type $is (sub resource)))))
             {aliases}
             (alias export $state "bucket" (type $bucket))
             (alias export $state "issuer" (type $issuer))
             (type $addr_decl (record
               (field "a" u64) (field "b" u64) (field "c" u64) (field "d" u64)))
             (import "address" (type $address (eq $addr_decl)))
             (type $bytes (list u8))

             (core module $m
               (func (export "handles") (param {core_params}))
               (func (export "grant") (param i32))
               (func (export "edge") (param i32))
               (func (export "values") (param i32 i64 i32 i32 i64 i64 i64 i64))
               (memory (export "mem") 1 1)
               (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                 i32.const 1024))
             (core instance $i (instantiate $m))

             (func (export "handles") {params}
               (canon lift (core func $i "handles")))
             (func (export "grant") (param "authority" (borrow $issuer))
               (canon lift (core func $i "grant")))
             (func (export "edge") (param "funds" (own $bucket))
               (canon lift (core func $i "edge")))
             (func (export "values")
               (param "verdict" bool) (param "count" u64)
               (param "key" $bytes) (param "at" $address)
               (canon lift (core func $i "values")
                 (memory $i "mem") (realloc (func $i "realloc")))))"#,
    );
    parse_str(&text).expect("the vocabulary fixture parses")
}

/// Every parameter shape the gate can demand deploys, decodes, and
/// classifies as itself: the profile validator, the executable spec, and
/// the export reader agree on the whole vocabulary at once.
#[test]
fn every_shape_the_gate_can_demand_deploys_and_decodes() {
    let bytes = vocabulary_component();
    validate_component(&bytes).expect("the profile admits every shape the gate can demand");
    RefComponent::decode(&bytes).expect("the executable spec models every admitted shape");

    let exports = component_exports(&bytes).expect("the exports classify");
    let handles: Vec<ExportParam> = HANDLE_KINDS
        .iter()
        .map(|kind| ExportParam::Handle((*kind).to_string()))
        .collect();
    assert_eq!(exports["handles"].params, handles);
    assert_eq!(
        exports["grant"].params,
        vec![ExportParam::Handle("issuer".to_string())]
    );
    assert_eq!(exports["edge"].params, vec![ExportParam::Bucket]);
    assert_eq!(
        exports["values"].params,
        vec![
            ExportParam::Flag,
            ExportParam::U64,
            ExportParam::Bytes,
            ExportParam::Address,
        ]
    );
}

/// A session over no declared state: the verdict lane's guest reads and
/// writes nothing, so the fixture is the argument itself.
fn session() -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration::from_set(EffectSet::new()),
        TxHash(Hash32([0x21; 32])),
        EnvInputs {
            clock_ms: 424_242,
            randomness: [7; 32],
        },
        test_hash,
    )
    .expect("an empty declaration materializes")
}

/// A guard verdict crosses both engines as the same core value: the
/// blessed lowering of `bool` and the spec's despecialization to an
/// `i32` pick the same arm, to the fuel.
#[test]
fn a_guard_verdict_crosses_both_engines_identically() -> Result<()> {
    let bytes = parse_str(
        r#"(component
             (core module $m
               (func (export "pick") (param i32) (result i64)
                 (select (i64.const 7) (i64.const 3) (local.get 0))))
             (core instance $i (instantiate $m))
             (func (export "pick") (param "verdict" bool) (result u64)
               (canon lift (core func $i "pick"))))"#,
    )
    .expect("the verdict fixture parses");

    let guest = DualGuest::compile(&bytes)?;
    let mut dual = guest.instantiate(FUEL, session)?;
    assert_eq!(dual.invoke_both("pick", &[CVal::Bool(true)])?.scalar()?, 7);
    assert_eq!(dual.invoke_both("pick", &[CVal::Bool(false)])?.scalar()?, 3);
    dual.finish()?;
    Ok(())
}

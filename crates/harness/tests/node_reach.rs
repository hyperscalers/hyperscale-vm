//! One transaction, two nodes, two packages: what the second one can
//! reach of the first one's.
//!
//! [`capability_reach`] fixes the rule — a body reaches every capability
//! the transaction declared, not the sites its own call was handed. This
//! lane states the consequence the rule was worth writing down for,
//! because it is the shape a composition actually takes: two packages in
//! one manifest, each node lent its own site, and the second node's body
//! naming the first node's instead.
//!
//! The walk binds one capability table for the whole transaction and
//! cannot tell whose call is running, so the site the prowler names is
//! served — it reads the keeper's cell, and writes it. Both are inside
//! what the transaction declared and the signer signed, and neither is
//! inside what the prowler's own node was given.
//!
//! What still bounds it, and is asserted beside the reach so the lane
//! reads as a fence with one gap rather than as an absence of fences:
//! the mode the capability carries. A prowler that names a cell declared
//! for reading cannot write it, whoever declared it.
//!
//! The reach is not searchable. A rep past the table is a refusal, and a
//! refusal ends the transaction rather than the call, so a body gets one
//! guess and cannot enumerate the table — it has to know the layout,
//! which whoever composed the manifest does. [`capability_reach`] pins
//! that refusal.

use std::sync::Arc;

use hyperscale_vm_effects::{
    CallArg, Declaration, Hash32, Hasher, NodeCall, PackageHash, SlotId, TestHasher, child_key,
};
use hyperscale_vm_embed::abi::{ABI, MEMORY, STATE};
use hyperscale_vm_harness::driver::{Lanes, test_hash};
use hyperscale_vm_harness::dual::rep_where;
use hyperscale_vm_kernel::{
    BatchTx, Capability, EnvInputs, GuestBackend, GuestRunner, KernelSession, ManifestWalk,
    MemoryStore, OverlayStore, RunResult,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Answer, Effect, EffectSet, EffectTarget, Mode, Moves,
    Outcome, SubstateKey, TxHash,
};
use wasmtime::Result;
use wasmtime::error::bail;
use wat::parse_str;

/// What the keeper's cell holds: the bytes only its own node was lent a
/// site for, at a width no other cell in the fixture shares.
const KEPT: &[u8] = b"the-keepers-own";

/// What the prowler's cell holds, at its own width.
const PROWLED: &[u8] = b"pp";

/// The byte a prowler writes over the keeper's cell, recognisable in a
/// receipt.
const OVERWRITTEN: u8 = 0x5A;

const fn tx() -> TxHash {
    TxHash(Hash32([0x2E; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(11_000)
}

fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

/// The instance a node targets; the emitter its frame stamps, and
/// nothing this lane reads.
const fn instance(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

fn key(slot: u16) -> SubstateKey {
    child_key(&TestHasher, instance(0x2E), SlotId(slot), &[])
}

/// Two cells under one transaction, one declared for each node.
struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    kept: SubstateKey,
    prowled: SubstateKey,
}

fn fixture() -> Fixture {
    let (kept, prowled) = (key(1), key(2));
    let mut store = MemoryStore::new();
    store.write(kept, KEPT.to_vec());
    store.write(prowled, PROWLED.to_vec());

    let mut declared = EffectSet::new();
    for effect in [
        // The keeper's, lent for writing: what a node that means to
        // rewrite its own cell declares.
        Effect {
            target: EffectTarget::Point(kept),
            mode: Mode::Write { moves: Moves::Both },
        },
        // The prowler's own, and all its node names.
        Effect {
            target: EffectTarget::Point(prowled),
            mode: Mode::Read,
        },
    ] {
        declared.insert(effect).expect("the set takes it");
    }

    Fixture {
        declared,
        store,
        kept,
        prowled,
    }
}

fn declaration(fx: &Fixture) -> Declaration {
    Declaration::from_set(fx.declared.clone())
}

fn session(fx: &Fixture) -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(fx.store.clone())),
        &declaration(fx),
        tx(),
        env(),
        test_hash,
    )
    .expect("the declaration materializes")
}

/// The rep of the capability over `wanted`.
fn rep_of(session: &KernelSession, wanted: SubstateKey) -> u32 {
    rep_where(session, |capability| match capability {
        Capability::Read(key) | Capability::Write(key) => *key == wanted,
        _ => false,
    })
}

/// The keeper: a package that reads the site it was handed and nothing
/// else, which is the whole of what its node lent it.
fn keeper() -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-get" (func $site_get (param i32 i32) (result i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  (func $answered (param $value i64)
    (i64.store (i32.const 512) (local.get $value))
    (call $answer (i32.const 512) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0)))

  (func (export "keep") (param $site i32)
    (call $answered
      (i64.extend_i32_u (call $site_get (local.get $site) (i32.const 0))))))
"#
    );
    parse_str(&text).expect("the keeper parses")
}

/// The prowler: a package that ignores the site its node was given and
/// names `foreign` instead.
///
/// The number is in its text, which is where a body that knows the
/// manifest's shape would put it: reps are the table's order, and
/// whoever composed the manifest knows what it declared.
fn prowler(foreign: u32) -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-get" (func $site_get (param i32 i32) (result i32)))
  (import "{STATE}" "site-set" (func $site_set (param i32 i32 i32 i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  (func $answered (param $value i64)
    (i64.store (i32.const 512) (local.get $value))
    (call $answer (i32.const 512) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; Read the other node's cell, and answer what it holds the length of.
  (func (export "read-foreign") (param $site i32)
    (call $answered
      (i64.extend_i32_u (call $site_get (i32.const {foreign}) (i32.const 0)))))

  ;; Write one byte over it.
  (func (export "write-foreign") (param $site i32)
    (i32.store8 (i32.const 0) (i32.const {OVERWRITTEN}))
    (call $site_set (i32.const {foreign}) (i32.const 0) (i32.const 0) (i32.const 1))
    (call $answered (i64.const 0))))
"#
    );
    parse_str(&text).expect("the prowler parses")
}

/// One node's lowered call: the package, the export, and the one site
/// its node was lent.
fn node(package: PackageHash, target: Address, export: &str, site: u32) -> NodeCall {
    NodeCall {
        package,
        target,
        export: export.to_owned(),
        args: vec![CallArg::Site {
            entries: vec![Some(site)],
        }],
        edges: Vec::new(),
        outputs: Vec::new(),
        answers: true,
        issues: Vec::new(),
        evidence: Vec::new(),
        requires: Vec::new(),
    }
}

/// The two nodes of this lane's manifest: the keeper on its own site,
/// then the prowler on `export`, lent only its own.
fn manifest(fx: &Fixture, probe: &KernelSession, export: &str) -> Vec<NodeCall> {
    vec![
        node(
            pkg("keeper"),
            instance(0xA1),
            "keep",
            rep_of(probe, fx.kept),
        ),
        node(
            pkg("prowler"),
            instance(0xB1),
            export,
            rep_of(probe, fx.prowled),
        ),
    ]
}

/// Walk the two nodes on `backend`, answering what each node answered
/// and the session they left.
fn walked(
    fx: &Fixture,
    calls: Vec<NodeCall>,
    backend: &dyn GuestBackend,
) -> Result<(Vec<Answer>, KernelSession, u64)> {
    let entry = BatchTx::new(tx(), declaration(fx), env()).with_calls(calls);
    let run = ManifestWalk { backend }
        .run(&entry, session(fx))
        .expect("both packages are seeded on both engines");
    match run {
        RunResult::Completed {
            session,
            answers,
            fuel,
        } => Ok((answers, session, fuel)),
        RunResult::Aborted { outcome, .. } => bail!("the walk aborted: {outcome:?}"),
    }
}

/// Both engines, each seeded with the two packages this lane composes.
fn lanes(foreign: u32) -> Lanes {
    let mut lanes = Lanes::new();
    lanes.seed(pkg("keeper"), &keeper());
    lanes.seed(pkg("prowler"), &prowler(foreign));
    lanes
}

/// What one node answered, as the `u64` its export handed back.
fn answered(answers: &[Answer], node: u32) -> Result<u64> {
    let Some(answer) = answers.iter().find(|answer| answer.node == node) else {
        bail!("node {node} answered nothing: {answers:?}");
    };
    let bytes: [u8; 8] = answer
        .value
        .as_slice()
        .try_into()
        .map_err(|_| wasmtime::error::format_err!("node {node} answered {:?}", answer.value))?;
    Ok(u64::from_le_bytes(bytes))
}

/// The prowler reads the keeper's cell, and both engines serve it.
///
/// Its own node was lent one site and it named the other. The width it
/// answers is the keeper's cell, which is the whole finding: the site a
/// body may name is the transaction's, not its node's.
#[test]
fn a_node_reads_a_cell_declared_for_another_node() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let kept = rep_of(&probe, fx.kept);
    let prowled = rep_of(&probe, fx.prowled);
    assert_ne!(kept, prowled, "the two nodes are lent different sites");

    let lanes = lanes(kept);
    for backend in lanes.engine_backends() {
        let (answers, _, _) = walked(&fx, manifest(&fx, &probe, "read-foreign"), backend)?;

        // The keeper read what it was lent, which is the same cell —
        // so the two nodes agreeing is what says the prowler reached it
        // rather than merely answering a number.
        assert_eq!(answered(&answers, 0)?, KEPT.len() as u64, "the keeper");
        assert_eq!(
            answered(&answers, 1)?,
            KEPT.len() as u64,
            "the prowler read the keeper's cell"
        );
        assert_ne!(
            answered(&answers, 1)?,
            PROWLED.len() as u64,
            "the two cells differ in width, so the figure says which was read"
        );
    }
    Ok(())
}

/// And it writes it: the keeper's cell carries the prowler's byte when
/// the transaction settles.
///
/// The mode was declared for the keeper's own node, and the capability
/// carries it for the whole transaction — so what the prowler needed in
/// order to rewrite a cell it was never lent was the number.
#[test]
fn a_node_writes_a_cell_declared_for_another_node() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let kept = rep_of(&probe, fx.kept);

    let lanes = lanes(kept);
    for backend in lanes.engine_backends() {
        let (answers, session, fuel) =
            walked(&fx, manifest(&fx, &probe, "write-foreign"), backend)?;
        let (receipt, _) = session.finish(answers, fuel).expect("the oracle is clean");

        assert!(
            matches!(receipt.outcome, Outcome::Completed { .. }),
            "{:?}",
            receipt.outcome
        );
        assert_eq!(
            receipt.delta.cells.get(&fx.kept).cloned().flatten(),
            Some(vec![OVERWRITTEN]),
            "the prowler rewrote the keeper's cell"
        );
    }
    Ok(())
}

/// The mode still holds: a cell declared for reading refuses the write,
/// whichever node names it.
///
/// Reaching a capability and being granted an operation on it stay two
/// questions, and the second is asked at every operation — so what
/// widened is which cells a body can name, not what it may do to them.
#[test]
fn a_prowler_cannot_exceed_the_mode_the_cell_was_declared_at() -> Result<()> {
    let fx = fixture();
    let probe = session(&fx);
    let prowled = rep_of(&probe, fx.prowled);

    // The prowler names the read-only cell this time, which is the one
    // its own node was lent — so what refuses is the mode alone.
    let lanes = lanes(prowled);
    for backend in lanes.engine_backends() {
        let entry = BatchTx::new(tx(), declaration(&fx), env()).with_calls(manifest(
            &fx,
            &probe,
            "write-foreign",
        ));
        let run = ManifestWalk { backend }
            .run(&entry, session(&fx))
            .expect("both packages are seeded on both engines");
        let RunResult::Aborted { outcome, .. } = run else {
            bail!("a write through a read capability completed");
        };
        assert_eq!(
            outcome,
            Outcome::UserError {
                reason: AbortReason::HandleWrongMode
            }
        );
    }
    Ok(())
}

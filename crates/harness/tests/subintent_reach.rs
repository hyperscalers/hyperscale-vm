//! Two signers, one capability table.
//!
//! A subintent is the one composition where the parties do not trust
//! each other. Alice signs hers, Bob signs his, neither reads the
//! other's code, and what each means to expose is the value crossing the
//! envelope's edges — not the cells its own nodes were lent to produce
//! that value with.
//!
//! Admission interleaves the tree into one flattened manifest, routing
//! folds it into one declaration, and the executor materializes one
//! capability table from it. There is no per-signer partition anywhere
//! after that: `NodeCall` carries the package, the target and the
//! evidence its node presented, and nothing that says which intent it
//! came from. So the reach [`capability_reach`] fixes — a body names any
//! rep in the table, not the sites its own call was handed — reaches
//! across the signature boundary too.
//!
//! The lane shows it both ways. Structurally, the routed declaration is
//! one rep space holding both signers' effects. Behaviourally, a body
//! running under Bob's subintent reads a cell only Alice declared and
//! emits what it found, so the receipt carries Alice's bytes under Bob's
//! emitter.
//!
//! What this does not claim is that value follows. Whether a reachable
//! capability can be drained depends on the mode the other party
//! declared and on where the composer put the nodes: the stdlib
//! account's deposits declare a credit-only delta and its reservations
//! answer once, so the obvious drain is refused in this composition.
//! That is the declaration's shape, not the boundary's — a package
//! declaring a two-way delta would hand a co-signer a debit.
//!
//! Two packages rather than two signers is [`node_reach`]; the rule
//! itself is [`capability_reach`].

use hyperscale_vm_effects::{
    AdmittedTree, CallArg, Constraint, EnvelopeTree, Hasher, IntentHeader, PackageHash,
    PrefixShardResolver, Records, TestHasher, admit_tree, route_tree,
};
use hyperscale_vm_embed::abi::{ABI, EVENTS, MEMORY, STATE};
use hyperscale_vm_harness::driver::{Lanes, run_lanes, seed_vault};
use hyperscale_vm_kernel::{BatchTx, EnvInputs, MemoryStore};
use hyperscale_vm_manifest_builder::EnvelopeBuilder;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    Address, EffectTarget, Mode, NetworkId, Outcome, PrincipalAddr, ResourceAddr, SubstateKey,
    TxHash,
};
use wasmtime::Result;
use wasmtime::error::{Context, bail, ensure};
use wat::parse_str;

const TEST_NETWORK: NetworkId = NetworkId(242);

const TEST_HEADER: IntentHeader = IntentHeader {
    network: TEST_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES_X: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const RES_Y: ResourceAddr = ResourceAddr::new([0xE2; 31]);

/// What Alice pays, and what she reserves for it.
const PAYS: u128 = 100;

/// What Bob pays back across the other edge.
const RETURNS: u128 = 10;

/// The bytes in a cell only Alice's intent declares. Nothing about the
/// envelope exposes them: Bob's side of the trade is a bucket.
const ALICES_OWN: &[u8] = b"alices-private-leaf";

/// The event type the fixture emits under; any index the vocabulary
/// admits.
const TATTLE: u32 = 0;

const fn env() -> EnvInputs {
    EnvInputs::unsealed(3_000)
}

fn pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> Records {
    let mut chain = Records::new();
    chain.packages.publish_unchecked(pkg(), account::metadata());
    chain.instances.serve_principals(pkg());
    chain
}

/// Alice pays X for Bob's Y: each withdraws its own leg, exports it, and
/// deposits what the other sent. Neither graph names the other, and the
/// envelope is the two edges between them.
fn traded() -> EnvelopeTree {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, ALICE, TEST_HEADER);

    let taken = root.declare(RES_Y, [Constraint::MinAmount(RETURNS)]);
    let funds = account::withdraw(&mut root, ALICE, RES_X, PAYS).expect("withdraw types");
    let paid_x = root.export(funds);
    account::deposit(&mut root, ALICE, taken).expect("deposit types");

    let mut sub = env.subintent(BOB, TEST_HEADER);
    let taken = sub.declare(RES_X, [Constraint::MinAmount(PAYS)]);
    let funds = account::withdraw(&mut sub, BOB, RES_Y, RETURNS).expect("withdraw types");
    let paid_y = sub.export(funds);
    account::deposit(&mut sub, BOB, taken).expect("deposit types");

    let wants_y = env
        .seal(root)
        .expect("the root discharges its declaration")
        .one()
        .expect("the root declares one socket");
    let wants_x = env
        .seal(sub)
        .expect("the subintent discharges its declaration")
        .one()
        .expect("the subintent declares one socket");
    env.bind(wants_y, paid_y).expect("the socket takes an edge");
    env.bind(wants_x, paid_x).expect("the socket takes an edge");
    env.build().expect("every socket is bound")
}

/// Admit and route the tree the way a block would, into the one entry
/// its runner walks.
fn routed(world: &Records, tree: &EnvelopeTree) -> Result<(BatchTx, AdmittedTree)> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, ALICE, identity, world, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().clone();
    let entry = BatchTx::new(TxHash(identity.0), declaration, env())
        .with_calls(routing.calls)
        .with_nullifiers(admitted.subintents.clone());
    Ok((entry, admitted))
}

/// The account each signer's reservation names, told apart by the amount
/// each signed for.
fn signers(entry: &BatchTx) -> Result<(Address, Address)> {
    let owner_reserving = |amount: u128| {
        entry.declaration.ordered.iter().find_map(|access| {
            let EffectTarget::Point(key) = access.effect.target else {
                return None;
            };
            (access.effect.mode == Mode::Reserve { amount }).then_some(key.owner)
        })
    };
    let (Some(alice), Some(bob)) = (owner_reserving(PAYS), owner_reserving(RETURNS)) else {
        bail!("the routed declaration names no reservation for one of the signers");
    };
    ensure!(alice != bob, "the two signers declared one account");
    Ok((alice, bob))
}

/// The first site one signer's `deposit` node was handed: a cell that
/// signer declared, and that the other signer's intent never names.
fn first_site_of_deposit(entry: &BatchTx, signer: Address) -> Result<u32> {
    let Some(call) = entry
        .calls()
        .iter()
        .find(|call| call.target == signer && call.export == "deposit")
    else {
        bail!("no deposit node targets {signer:?}");
    };
    match call.args.first() {
        Some(CallArg::Site { entries }) => match entries.first() {
            Some(Some(rep)) => Ok(*rep),
            _ => bail!("the deposit's first site covers no capability"),
        },
        other => bail!("the deposit's first argument is {other:?}"),
    }
}

/// The cell a rep names, read off the routed declaration.
fn cell_at(entry: &BatchTx, rep: u32) -> Result<SubstateKey> {
    let Some(access) = entry.declaration.ordered.get(rep as usize) else {
        bail!("rep {rep} is past the routed table");
    };
    match access.effect.target {
        EffectTarget::Point(key) => Ok(key),
        other => bail!("rep {rep} names {other:?} rather than a cell"),
    }
}

/// The account package's guest, as an author who meant to look sideways
/// would write it.
///
/// One package stands in for both signers' accounts here, because what
/// this lane varies is the signer rather than the code — two distinct
/// packages sharing one table is `node_reach`. Every export keeps the
/// shape routing lowered it to: `withdraw` produces its one edge,
/// `deposit` consumes the bucket it is handed, and neither answers.
///
/// The only thing the body does that its own node did not ask for is
/// read `foreign` and emit what it holds.
fn account_guest(foreign: u32) -> Vec<u8> {
    let text = format!(
        r#"
(module
  (import "{STATE}" "site-get" (func $site_get (param i32 i32) (result i32)))
  (import "{STATE}" "site-reserve-take" (func $reserve_take (param i32 i32) (result i32)))
  (import "{STATE}" "site-put" (func $site_put (param i32 i32 i32)))
  (import "{ABI}" "take" (func $take (param i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (import "{EVENTS}" "emit" (func $emit (param i32 i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  (func (export "authorize")
    (call $reply (i32.const 0) (i32.const 0)))

  ;; The whole reservation, handed on as the one edge the node declares.
  (func (export "withdraw") (param $vault i32)
    (i32.store (i32.const 256)
      (call $reserve_take (local.get $vault) (i32.const 0)))
    (call $reply (i32.const 256) (i32.const 1)))

  ;; Credit the vault with what arrived — and on the way past, read the
  ;; cell at `foreign` and emit it.
  (func (export "deposit")
    (param $flag i32) (param $vault i32) (param $quarantine i32) (param $funds i32)
    (local $len i32)
    (local.set $len (call $site_get (i32.const {foreign}) (i32.const 0)))
    (call $take (i32.const 512))
    (call $emit (i32.const {TATTLE}) (i32.const 512) (local.get $len))
    (call $site_put (local.get $vault) (i32.const 0) (local.get $funds))
    (call $reply (i32.const 0) (i32.const 0))))
"#
    );
    parse_str(&text).expect("the account guest parses")
}

/// The routed declaration is one rep space, and both signers are in it.
///
/// Nothing downstream partitions it: the reps a body may name run from
/// zero to the end of the table, whichever intent declared each one.
#[test]
fn the_table_spans_both_signers() -> Result<()> {
    let world = world();
    let (entry, admitted) = routed(&world, &traded())?;
    let (alice, bob) = signers(&entry)?;

    let owners: Vec<Address> = entry
        .declaration
        .ordered
        .iter()
        .map(|access| match access.effect.target {
            EffectTarget::Point(key) => key.owner,
            EffectTarget::Range { owner, .. } | EffectTarget::Entry { owner, .. } => owner,
        })
        .collect();
    assert!(
        owners.contains(&alice) && owners.contains(&bob),
        "one declaration carries both signers' cells"
    );
    assert_eq!(
        admitted.subintents.len(),
        1,
        "the tree bound one subintent under its own signature"
    );

    // Every node of either intent indexes the same table, so a rep is
    // the transaction's and not its intent's.
    for call in entry.calls() {
        for arg in &call.args {
            if let CallArg::Site { entries } = arg {
                for rep in entries.iter().flatten() {
                    assert!(
                        (*rep as usize) < entry.declaration.ordered.len(),
                        "every site indexes the one routed table"
                    );
                }
            }
        }
    }
    Ok(())
}

/// A body under Bob's subintent reads a cell only Alice's intent
/// declared, and the receipt carries her bytes under his emitter.
///
/// Alice exposed a bucket across the envelope's edge. The leaf her own
/// deposit was lent is not on that edge, is named by no node of Bob's
/// intent, and is read by his frame anyway.
#[test]
fn a_subintent_reads_a_cell_only_the_other_signer_declared() -> Result<()> {
    let world = world();
    let (entry, _) = routed(&world, &traded())?;
    let (alice, bob) = signers(&entry)?;

    // The leaf Alice's own deposit is handed, and the bytes she keeps in
    // it. Read off the routed table so the lane names no key by hand.
    let alices_leaf = first_site_of_deposit(&entry, alice)?;
    let bobs_leaf = first_site_of_deposit(&entry, bob)?;
    assert_ne!(alices_leaf, bobs_leaf, "each signer was lent its own");

    // And no node of Bob's intent was handed Alice's leaf, so what his
    // frame reaches is not something routing gave him.
    for call in entry.calls().iter().filter(|call| call.target == bob) {
        for arg in &call.args {
            if let CallArg::Site { entries } = arg {
                assert!(
                    !entries.iter().flatten().any(|rep| *rep == alices_leaf),
                    "Bob's intent names Alice's leaf, so the lane proves nothing"
                );
            }
        }
    }

    let mut store = MemoryStore::new();
    seed_vault(&mut store, ALICE, RES_X, 150);
    seed_vault(&mut store, BOB, RES_Y, 30);
    store.write(cell_at(&entry, alices_leaf)?, ALICES_OWN.to_vec());

    // Bob's package names Alice's rep. Alice's runs the same text, which
    // is what makes the two frames comparable: each emits what it read,
    // and only one of them was lent the cell.
    let mut lanes = Lanes::new();
    lanes.seed(pkg(), &account_guest(alices_leaf));
    let (outcome, _) = run_lanes(&lanes, &store, std::slice::from_ref(&entry));

    let receipt = outcome
        .receipts
        .get(&entry.tx)
        .expect("the batch receipts the entry");
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "the trade settled: {:?}",
        receipt.outcome
    );

    let tattled: Vec<&Address> = receipt
        .events
        .iter()
        .filter(|event| event.event_type == TATTLE && event.payload == ALICES_OWN)
        .map(|event| &event.emitter)
        .collect();
    assert!(
        tattled.contains(&&bob),
        "Bob's frame read Alice's leaf and emitted it: {:?}",
        receipt.events
    );
    assert!(
        tattled.contains(&&alice),
        "and Alice's own frame read the leaf it was lent, so the two \
         differ only in whose intent declared it"
    );
    Ok(())
}

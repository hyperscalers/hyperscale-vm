//! Whether a package may declare an effect on a cell it does not own.
//!
//! Every stdlib clause targets a child of `SelfAddr`, so a package only
//! ever reaches its own prefix. Whether that is a rule or a convention is
//! what this asks: a published package writes its clause target as an
//! expression, and `Expr::Arg` is one of the forms an expression may take.
//!
//! The question is settled at the capability, not at the guest. A handle
//! is what a guest can act through, and the kernel materializes one per
//! declared clause — so if a clause naming a stranger's vault yielded a
//! `Delta` capability, the funds would be reachable and only the guest's
//! own code would stand between the declaration and the balance.
//!
//! Routing refuses the declaration, so both tests below return before
//! reaching their assertions. They are written to run the whole way
//! anyway: a rule that stopped refusing would carry them to a capability
//! and a debit, which is what they say must not exist.

use std::sync::Arc;

use hyperscale_hbor::{Capped, Name};
use hyperscale_vm_effects::{
    AdmissionError, Admitted, COMMITTED_TX_SLOT, CROSSING_CLAIM_SLOT, CROSSING_DECLINE_SLOT,
    ChainRecords, Clause, Declaration, DeclarationError, ESCROW_RECORD_SLOT, EvalError, Expr,
    GraphArg, GraphNode, Hash32, Hasher, InstanceMeta, Intent, IntentHeader, IntentTree,
    ManifestGraph, MethodSignature, ModeExpr, PackageHash, PackageMetadata, ParamType,
    READ_FRONTIER_SLOT, Records, SlotId, SlotRef, TargetExpr, TestHasher, Totality, Value,
    admit_tree, check_declarations, child_key,
};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, Moves, NetworkId, PrincipalAddr, SubstateKey, TxHash,
    encode_amount,
};

/// Any window; nothing here validates one against a clock.
const HEADER: IntentHeader = IntentHeader {
    network: NetworkId(242),
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

/// Admit `graph` as a tree of one leaf acting as `account`, attested by
/// that account's own key.
fn admit_leaf(
    graph: &ManifestGraph,
    account: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let tree = IntentTree::of_one(Intent::leaf(HEADER, account, graph.clone()));
    admit_tree(&tree, tree.hash(hasher), chain, hasher)
}

/// The role the stdlib account keeps its balances under.
const VAULT: SlotId = SlotId(1);

const VICTIM: PrincipalAddr = PrincipalAddr::new([0x11; 31]);
const ATTACKER: PrincipalAddr = PrincipalAddr::new([0x22; 31]);
const TOKEN: Address = Address::new([0xE1; 31], AddressClass::Resource);

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn package() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"predator"]))
}

fn vault_of(owner: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(TOKEN).canonical_bytes()],
    )
}

/// A package whose one method declares a `Delta` on a vault belonging to
/// whoever its caller names.
///
/// Nothing about this is hidden: the target is the same `child_key` form
/// the stdlib account uses, with `Expr::Arg(0)` where the account writes
/// `Expr::SelfAddr`.
fn predator() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        Name::declared("drain"),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Address],
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Arg(0)),
                    slot: SlotRef::Fixed(VAULT),
                    material: vec![Expr::Literal(Value::Address(TOKEN))],
                }),
                mode: ModeExpr::Delta { moves: Moves::Both },
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    methods
}

fn world() -> (Records, ComponentAddr) {
    let mut chain = Records::new();
    chain.packages.publish_unchecked(package(), predator());
    let instance = chain.instances.create(
        &TestHasher,
        InstanceMeta {
            package: package(),
            config: Capped::empty(),
            salt: Hash32([7; 32]),
        },
    );
    (chain, instance)
}

/// The attacker's whole transaction: one node, on their own component,
/// naming the victim.
fn drain_graph(instance: ComponentAddr) -> ManifestGraph {
    ManifestGraph {
        nodes: Capped::from_array([GraphNode::new(
            instance,
            "drain",
            vec![GraphArg::Literal(Value::Address(VICTIM.address()))],
        )]),
    }
}

#[test]
fn a_package_cannot_declare_an_effect_on_a_cell_it_does_not_own() {
    let (chain, instance) = world();
    let graph = drain_graph(instance);

    // Admission judges the shape. The method is public — nothing about
    // it requires authority — so nothing here is an authority question.
    let Ok(admitted) = admit_leaf(&graph, ATTACKER, &chain, &TestHasher) else {
        return; // Refused before routing: the gap is closed at admission.
    };
    let declaration = admitted.declaration().clone();

    // The victim's balance, committed before the attacker's transaction
    // exists.
    let mut base = MemoryStore::new();
    base.write(vault_of(VICTIM), encode_amount(10_000).to_vec());
    let store = OverlayStore::new(Arc::new(base));

    let Ok(session) = KernelSession::materialize(
        store,
        &Declaration {
            ordered: declaration.ordered,
            ..Declaration::from_set(declaration.set)
        },
        TxHash(Hash32([0x01; 32])),
        EnvInputs::unsealed(0),
        test_hash,
    ) else {
        return; // Refused at materialization: the gap is closed there.
    };

    // A capability on the victim's vault, handed to a package the victim
    // never named.
    let granted = session.capabilities().to_vec();
    assert!(
        !granted.iter().any(
            |capability| matches!(capability, Capability::Delta { key, .. } if *key == vault_of(VICTIM))
        ),
        "a package declared a delta on a stranger's vault and the kernel \
         materialized it: {granted:?}"
    );
}

/// The same declaration, carried through to the balance.
///
/// Separate from the capability assertion because they fail for different
/// reasons: the first says a handle exists, this says the handle spends.
#[test]
fn a_capability_on_a_strangers_vault_cannot_spend_it() {
    let (chain, instance) = world();
    let graph = drain_graph(instance);

    let Ok(admitted) = admit_leaf(&graph, ATTACKER, &chain, &TestHasher) else {
        return;
    };
    let declaration = admitted.declaration().clone();

    let mut base = MemoryStore::new();
    base.write(vault_of(VICTIM), encode_amount(10_000).to_vec());
    let store = OverlayStore::new(Arc::new(base));

    let Ok(mut session) = KernelSession::materialize(
        store,
        &Declaration {
            ordered: declaration.ordered,
            ..Declaration::from_set(declaration.set)
        },
        TxHash(Hash32([0x01; 32])),
        EnvInputs::unsealed(0),
        test_hash,
    ) else {
        return;
    };

    let Some(rep) = session.capabilities().iter().position(
        |capability| matches!(capability, Capability::Delta { key, .. } if *key == vault_of(VICTIM)),
    ) else {
        return; // No handle on the victim's cell: nothing to spend through.
    };
    let rep = u32::try_from(rep).expect("one clause");

    let spent = session.delta_sub(rep, 0, 5_000);
    assert!(
        spent.is_err(),
        "a stranger's vault was debited through a declared delta"
    );
}

/// A signature writing `slot` under the package's own prefix.
fn writing(slot: SlotId) -> MethodSignature {
    MethodSignature {
        totality: Totality::Fallible,
        effects: vec![Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotRef::Fixed(slot),
                material: vec![],
            }),
            mode: ModeExpr::Read,
            denomination: None,
        }],
        ..MethodSignature::default()
    }
}

/// A package whose one method reaches whatever slot its caller names
/// under the package's own prefix.
fn reaching() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    methods.methods.insert(
        Name::declared("reach"),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::U64],
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotRef::Reached(Box::new(Expr::Arg(0))),
                    material: vec![],
                }),
                mode: ModeExpr::Read,
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    methods
}

/// A protocol slot under a package's own prefix is nobody's to name:
/// refused at publish, where a signature fixes it, and when reached,
/// where an argument names it.
///
/// The crossing and committed slots sit under a producing node's
/// target, a consuming node's target and a shard's own owner, and a
/// package's instances hold those cells under the same address as their
/// own. What keeps a package from writing one is the kernel band
/// covering the slot, and nothing else: the key material a declaration
/// derives is framed differently from what the kernel hashes, so a
/// collision needs grinding, but the band is what refuses the slot at
/// all.
fn a_marker_slot_is_refused(slot: SlotId) {
    assert_eq!(
        check_declarations(&writing(slot)),
        Err(DeclarationError::ReservedSlot {
            clause: 0,
            slot: slot.0,
        }),
        "{slot:?} is accepted at publish",
    );

    let mut chain = Records::new();
    chain.packages.publish_unchecked(package(), reaching());
    let instance = chain.instances.create(
        &TestHasher,
        InstanceMeta {
            package: package(),
            config: Capped::empty(),
            salt: Hash32([7; 32]),
        },
    );
    let graph = ManifestGraph {
        nodes: Capped::from_array([GraphNode::new(
            instance,
            "reach",
            vec![GraphArg::Literal(Value::U64(u64::from(slot.0)))],
        )]),
    };
    let refused = admit_leaf(&graph, ATTACKER, &chain, &TestHasher)
        .expect_err("a reached marker slot is admitted");
    assert!(
        matches!(
            refused,
            AdmissionError::Eval {
                source: EvalError::UnreachableSlot(named),
                ..
            } if named == u64::from(slot.0)
        ),
        "{slot:?} reached is refused for another reason: {refused:?}",
    );
}

#[test]
fn the_record_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(ESCROW_RECORD_SLOT);
}

#[test]
fn the_committed_tx_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(COMMITTED_TX_SLOT);
}

#[test]
fn the_claim_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(CROSSING_CLAIM_SLOT);
}

#[test]
fn the_decline_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(CROSSING_DECLINE_SLOT);
}

/// The retired slot between the decline's and the read frontier's stays
/// in the band: retired, never reused, and never a package's to name.
#[test]
fn the_retired_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(SlotId(0xFFF9));
}

#[test]
fn the_read_frontier_slot_is_refused_under_a_packages_prefix() {
    a_marker_slot_is_refused(READ_FRONTIER_SLOT);
}

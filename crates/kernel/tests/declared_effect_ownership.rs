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

use hyperscale_vm_effects::{
    Clause, Declaration, Expr, GraphArg, GraphNode, Hash32, Hasher, InstanceMeta, ManifestGraph,
    MethodSignature, ModeExpr, PackageHash, PackageMetadata, ParamType, PrefixShardResolver,
    Records, SlotId, TargetExpr, TestHasher, Totality, Value, admit, child_key, route,
};
use hyperscale_vm_kernel::{Capability, EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_types::{
    Address, AddressClass, ComponentAddr, PrincipalAddr, SubstateKey, TxHash, encode_amount,
};

/// The role the stdlib account keeps its balances under.
const VAULT: SlotId = SlotId(1);

const VICTIM: PrincipalAddr = PrincipalAddr::new([0x11; 31]);
const ATTACKER: PrincipalAddr = PrincipalAddr::new([0x22; 31]);
const XRD: Address = Address::new([0xE1; 31], AddressClass::Resource);

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
        &[Value::Address(XRD).canonical_bytes()],
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
        "drain".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Address],
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Arg(0)),
                    slot: VAULT,
                    material: vec![Expr::Literal(Value::Address(XRD))],
                }),
                mode: ModeExpr::Delta,
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
            config: Vec::new(),
            salt: Hash32([7; 32]),
        },
    );
    (chain, instance)
}

/// The attacker's whole transaction: one node, on their own component,
/// naming the victim.
fn drain_graph(instance: ComponentAddr) -> ManifestGraph {
    ManifestGraph {
        nodes: vec![GraphNode::new(
            instance,
            "drain",
            vec![GraphArg::Literal(Value::Address(VICTIM.address()))],
        )],
    }
}

#[test]
fn a_package_cannot_declare_an_effect_on_a_cell_it_does_not_own() {
    let (chain, instance) = world();
    let graph = drain_graph(instance);

    // Admission judges the shape. The method is public — nothing about
    // it requires authority — so nothing here is an authority question.
    let Ok(admitted) = admit(&graph, ATTACKER, &chain, &TestHasher) else {
        return; // Refused before routing: the gap is closed at admission.
    };
    let routing = route(&admitted, &PrefixShardResolver { bits: 0 });
    let declaration = routing.declaration().clone();

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
        EnvInputs {
            clock_ms: 0,
            randomness: [0; 32],
        },
        test_hash,
    ) else {
        return; // Refused at materialization: the gap is closed there.
    };

    // A capability on the victim's vault, handed to a package the victim
    // never named.
    let granted = session.capabilities().to_vec();
    assert!(
        !granted.iter().any(
            |capability| matches!(capability, Capability::Delta(key) if *key == vault_of(VICTIM))
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

    let Ok(admitted) = admit(&graph, ATTACKER, &chain, &TestHasher) else {
        return;
    };
    let routing = route(&admitted, &PrefixShardResolver { bits: 0 });
    let declaration = routing.declaration().clone();

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
        EnvInputs {
            clock_ms: 0,
            randomness: [0; 32],
        },
        test_hash,
    ) else {
        return;
    };

    let Some(rep) = session.capabilities().iter().position(
        |capability| matches!(capability, Capability::Delta(key) if *key == vault_of(VICTIM)),
    ) else {
        return; // No handle on the victim's cell: nothing to spend through.
    };
    let rep = u32::try_from(rep).expect("one clause");

    let spent = session.delta_sub(rep, 5_000);
    assert!(
        spent.is_err(),
        "a stranger's vault was debited through a declared delta"
    );
}

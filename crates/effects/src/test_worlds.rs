//! Shared test worlds: small published packages, their instances, and
//! the manifests that call them.

use hyperscale_vm_types::{Address, AddressClass, ComponentAddr, Denomination, ResourceAddr};

use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::hash::{Hash32, Hasher, TestHasher};
use crate::instance::{InstanceMeta, InstanceRegistry};
use crate::manifest::{Bounds, Manifest, Node, NodeInput};
use crate::metadata::{MetadataCache, PackageHash, PackageMetadata};
use crate::route::PrefixShardResolver;
use crate::signature::{MethodSignature, ParamType, Totality};
use crate::types::{EdgeContent, SlotId, Value, resource_address};

pub fn pkg(name: &str) -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
}

pub fn addr(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

/// The record a fixture's instance of `package` carries.
pub fn meta_of(package: &str) -> InstanceMeta {
    InstanceMeta {
        package: pkg(package),
        config: vec![],
        salt: Hash32([0; 32]),
    }
}

/// The address that record derives — what the fixture names, and
/// what the registry resolves back to the record.
pub fn instance_of(package: &str) -> ComponentAddr {
    meta_of(package).address(&TestHasher)
}

/// The resource an instance of `package` issues from empty material —
/// what a fixture producer's `SelfResource` output evaluates to.
pub fn issued_by(package: &str) -> Denomination {
    resource_address(&TestHasher, instance_of(package), &[]).into()
}

/// A resource-class literal, for a fixture that names one directly.
///
/// Typed at the class the constructor settles, so a denomination position
/// takes it infallibly and an address position forgets it.
pub const fn resource(byte: u8) -> ResourceAddr {
    ResourceAddr::new([byte; 31])
}

pub fn self_point(slot: SlotId, mode: ModeExpr) -> Clause {
    Clause::Effect {
        guard: None,
        target: TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot,
            material: vec![],
        }),
        mode,
        denomination: None,
    }
}

pub fn method(effects: Vec<Clause>) -> MethodSignature {
    MethodSignature {
        totality: Totality::Fallible,
        effects,
        ..MethodSignature::default()
    }
}

pub fn resolver() -> PrefixShardResolver {
    PrefixShardResolver { bits: 8 }
}

/// The star in its canonical shape: a reservation-shaped source, a
/// venue in the middle whose output the source's value feeds, and a
/// sink whose totality the caller chooses.
///
/// Three nodes rather than two because the sink has to be a node the
/// core does not consume from, which is exactly what makes it a leg.
pub fn star_world(sink: Totality) -> (MetadataCache, InstanceRegistry, Manifest) {
    let mut cache = MetadataCache::new();
    let mut vault_pkg = PackageMetadata::default();
    vault_pkg.methods.insert(
        "withdraw".into(),
        MethodSignature {
            outputs: vec![Expr::SelfResource { material: vec![] }],
            effects: vec![self_point(SlotId(1), ModeExpr::Reserve(Expr::Arg(0)))],
            ..MethodSignature::default()
        },
    );
    let mut venue_pkg = PackageMetadata::default();
    venue_pkg.methods.insert(
        "swap".into(),
        MethodSignature {
            outputs: vec![Expr::SelfResource { material: vec![] }],
            effects: vec![self_point(SlotId(2), ModeExpr::Write)],
            ..MethodSignature::default()
        },
    );
    let mut sink_pkg = PackageMetadata::default();
    sink_pkg.methods.insert(
        "deposit".into(),
        MethodSignature {
            totality: sink,
            effects: vec![self_point(SlotId(3), ModeExpr::Delta)],
            ..MethodSignature::default()
        },
    );
    cache.publish_unchecked(pkg("vault"), vault_pkg);
    cache.publish_unchecked(pkg("venue"), venue_pkg);
    cache.publish_unchecked(pkg("sink"), sink_pkg);
    let mut instances = InstanceRegistry::new();
    for name in ["vault", "venue", "sink"] {
        instances.create(&TestHasher, meta_of(name));
    }

    let edge = |source: u32, resource: Denomination| NodeInput::Edge {
        source,
        output: 0,
        resource,
        content: EdgeContent::Fungible,
        bounds: Bounds::default(),
    };
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: instance_of("vault").into(),
                method: "withdraw".into(),
                inputs: vec![NodeInput::Literal(Value::U128(5))],
                evidence: Vec::new(),
            },
            Node {
                target: instance_of("venue").into(),
                method: "swap".into(),
                inputs: vec![edge(0, issued_by("vault"))],
                evidence: Vec::new(),
            },
            Node {
                target: instance_of("sink").into(),
                method: "deposit".into(),
                inputs: vec![edge(1, issued_by("venue"))],
                evidence: Vec::new(),
            },
        ],
    };
    (cache, instances, manifest)
}

/// A payer and a payee on different shards, joined by a value edge:
/// two manifest nodes, one crossing between them.
pub fn payer_payee_world() -> (MetadataCache, InstanceRegistry, Manifest) {
    let mut cache = MetadataCache::new();
    let mut sender_pkg = PackageMetadata::default();
    sender_pkg.methods.insert(
        "pay".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Address, ParamType::U128],
            outputs: vec![Expr::Literal(Value::Address(resource(0xE1).address()))],
            effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
            ..MethodSignature::default()
        },
    );
    let mut receiver_pkg = PackageMetadata::default();
    receiver_pkg.methods.insert(
        "recv".into(),
        MethodSignature {
            totality: Totality::Fallible,
            params: vec![ParamType::Bucket],
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotId(2),
                    material: vec![],
                }),
                mode: ModeExpr::Delta,
                denomination: None,
            }],
            ..MethodSignature::default()
        },
    );
    cache.publish_unchecked(pkg("payer"), sender_pkg);
    cache.publish_unchecked(pkg("payee"), receiver_pkg);
    let mut instances = InstanceRegistry::new();
    instances.create(&TestHasher, meta_of("payer"));
    instances.create(&TestHasher, meta_of("payee"));
    let manifest = Manifest {
        nodes: vec![
            Node {
                target: instance_of("payer").into(),
                method: "pay".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(instance_of("payee").into())),
                    NodeInput::Literal(Value::U128(9)),
                ],
                evidence: Vec::new(),
            },
            Node {
                target: instance_of("payee").into(),
                method: "recv".into(),
                inputs: vec![NodeInput::Edge {
                    source: 0,
                    output: 0,
                    resource: resource(0xE1).into(),
                    content: EdgeContent::Fungible,
                    bounds: Bounds::default(),
                }],
                evidence: Vec::new(),
            },
        ],
    };
    (cache, instances, manifest)
}

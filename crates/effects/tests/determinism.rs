//! Purity and determinism, property-tested: expression evaluation and the
//! routing fold are functions — the same inputs give the same output (or
//! the identical error), with no evaluation path able to touch state.

mod common;

use common::{account_metadata, pkg, resolver, shard_of, vault};
use hyperscale_vm_effects::{
    Address, AddressClass, CallSite, EdgeRef, Effect, EffectTarget, EvalInputs, Expr, GraphArg,
    GraphNode, Hash32, InstanceMeta, InstanceRegistry, ManifestGraph, ManifestHash, MetadataCache,
    MethodSignature, Mode, PackageMetadata, ParamType, RoleId, TestHasher, Value, admit,
    evaluate_expr, route,
};
use proptest::collection::vec;
use proptest::prelude::{Just, Strategy, any, prop_oneof, proptest};

/// A creation salt in a named lane, so two instances of one package can
/// never collide however a generator picks their seeds.
const fn salt(lane: u8, seed: u8) -> Hash32 {
    let mut bytes = [0u8; 32];
    bytes[0] = lane;
    bytes[1] = seed;
    Hash32(bytes)
}

/// An instance of `package`, at the address its record derives.
fn instance(instances: &mut InstanceRegistry, package: &str, lane: u8, seed: u8) -> Address {
    instances.create(
        &TestHasher,
        InstanceMeta {
            package: pkg(package),
            config: vec![],
            salt: salt(lane, seed),
        },
    )
}

fn arb_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        any::<u64>().prop_map(Value::U64),
        any::<u128>().prop_map(Value::U128),
        vec(any::<u8>(), 0..8).prop_map(Value::Bytes),
        any::<u8>()
            .prop_map(|byte| Value::Address(Address::new([byte; 31], AddressClass::Component))),
        any::<u8>().prop_map(|byte| Value::Bucket {
            resource: Address::new([byte; 31], AddressClass::Component),
        }),
    ];
    leaf.prop_recursive(2, 8, 3, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..3).prop_map(Value::Tuple),
            vec(inner, 0..3).prop_map(Value::List),
        ]
    })
}

fn arb_expr() -> impl Strategy<Value = Expr> {
    let leaf = prop_oneof![
        arb_value().prop_map(Expr::Literal),
        (0u32..6).prop_map(Expr::Arg),
        (0u32..4).prop_map(Expr::Config),
        (0u32..3).prop_map(Expr::Binding),
        Just(Expr::SelfAddr),
        (0u32..4).prop_map(|slot| Expr::FreshId { slot }),
        (0u32..4).prop_map(|slot| Expr::FreshKey { slot }),
    ];
    leaf.prop_recursive(3, 16, 3, |inner| {
        prop_oneof![
            (inner.clone(), 0u32..4).prop_map(|(expr, index)| Expr::Field(Box::new(expr), index)),
            inner
                .clone()
                .prop_map(|expr| Expr::ResourceOf(Box::new(expr))),
            (inner.clone(), inner.clone()).prop_map(|(map, key)| Expr::Lookup {
                map: Box::new(map),
                key: Box::new(key),
            }),
            (inner.clone(), 0u16..4, vec(inner.clone(), 0..3)).prop_map(
                |(owner, role, material)| Expr::ChildKey {
                    owner: Box::new(owner),
                    role: RoleId(role),
                    material,
                }
            ),
            (inner.clone(), inner).prop_map(|(hi, lo)| Expr::Pack {
                hi: Box::new(hi),
                lo: Box::new(lo),
            }),
        ]
    })
}

proptest! {
    #[test]
    fn expression_evaluation_is_a_function(
        expr in arb_expr(),
        args in vec(arb_value(), 0..6),
        config in vec(arb_value(), 0..4),
        self_byte in any::<u8>(),
        node_index in any::<u32>(),
        seed in any::<[u8; 32]>(),
    ) {
        let inputs = EvalInputs {
            self_addr: Address::new([self_byte; 31], AddressClass::Component),
            args: &args,
            config: &config,
            node_index,
            frame: 0,
            identity: ManifestHash(Hash32(seed)),
        };
        let first = evaluate_expr(&expr, &inputs, &TestHasher);
        let second = evaluate_expr(&expr, &inputs, &TestHasher);
        assert_eq!(first, second);
    }

    #[test]
    fn transfer_routing_is_a_function(
        amount in any::<u128>(),
        sender_byte in any::<u8>(),
        recipient_byte in any::<u8>(),
        resource_byte in any::<u8>(),
    ) {
        let resource = Address::new([resource_byte; 31], AddressClass::Component);
        let mut cache = MetadataCache::new();
        cache.publish(pkg("account"), account_metadata());
        let mut instances = InstanceRegistry::new();
        let sender = instance(&mut instances, "account", 0, sender_byte);
        let recipient = instance(&mut instances, "account", 1, recipient_byte);
        let graph = ManifestGraph {
            nodes: vec![
                GraphNode {
                    target: sender,
                    method: "withdraw".into(),
                    args: vec![
                        GraphArg::Literal(Value::Address(resource)),
                        GraphArg::Literal(Value::U128(amount)),
                    ],
                },
                GraphNode {
                    target: recipient,
                    method: "deposit".into(),
                    args: vec![GraphArg::Edge {
                        edge: EdgeRef { producer: 0, output: 0 },
                        constraints: vec![],
                    }],
                },
            ],
        };
        let admitted = admit(&graph, &cache, &instances, &TestHasher).unwrap();
        let first = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();
        let second = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();
        assert_eq!(first, second);

        let sender_set = &first.per_shard[&shard_of(sender)];
        assert!(sender_set.contains(&Effect {
            target: EffectTarget::Point(vault(sender, resource)),
            mode: Mode::Reserve { amount },
        }));
        let recipient_set = &first.per_shard[&shard_of(recipient)];
        assert!(recipient_set.contains(&Effect {
            target: EffectTarget::Point(vault(recipient, resource)),
            mode: Mode::Delta,
        }));
    }

    #[test]
    fn argument_forwarded_calls_route_as_a_function(
        recipient_byte in any::<u8>(),
        resource_byte in any::<u8>(),
    ) {
        let resource = Address::new([resource_byte; 31], AddressClass::Component);
        let mut cache = MetadataCache::new();
        cache.publish(pkg("account"), account_metadata());
        let mut forward = PackageMetadata::default();
        forward.methods.insert(
            "forward".into(),
            MethodSignature {
                params: vec![ParamType::Address, ParamType::Bucket],
                calls: vec![CallSite {
                    target: Expr::Arg(0),
                    method: "deposit".into(),
                    args: vec![Expr::Arg(1)],
                }],
                ..MethodSignature::default()
            },
        );
        cache.publish(pkg("router"), forward);
        // Each instance sits at the address its own record derives, so
        // distinct salt lanes are what keep the router, the sender and
        // any generated recipient apart — no address is picked.
        let mut instances = InstanceRegistry::new();
        let router = instance(&mut instances, "router", 0, 0);
        let recipient = instance(&mut instances, "account", 1, recipient_byte);
        let sender = instance(&mut instances, "account", 0, 0);
        let graph = ManifestGraph {
            nodes: vec![
                GraphNode {
                    target: sender,
                    method: "withdraw".into(),
                    args: vec![
                        GraphArg::Literal(Value::Address(resource)),
                        GraphArg::Literal(Value::U128(1)),
                    ],
                },
                GraphNode {
                    target: router,
                    method: "forward".into(),
                    args: vec![
                        GraphArg::Literal(Value::Address(recipient)),
                        GraphArg::Edge {
                            edge: EdgeRef { producer: 0, output: 0 },
                            constraints: vec![],
                        },
                    ],
                },
            ],
        };
        let admitted = admit(&graph, &cache, &instances, &TestHasher).unwrap();
        let first = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();
        let second = route(&admitted, &cache, &instances, &TestHasher, &resolver()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.call_graph.edges.len(), 1);
        assert!(first.per_shard[&shard_of(recipient)].contains(&Effect {
            target: EffectTarget::Point(vault(recipient, resource)),
            mode: Mode::Delta,
        }));
    }
}

/// Digests pinned by value, not by self-comparison.
///
/// The proptests above prove evaluation is a function; they cannot notice
/// the function changing. These do: every one is a hash the protocol
/// commits to — a transaction identity, a child address, a fresh key — so
/// a shift in any encoding under them moves a value here rather than
/// passing quietly.
mod golden {
    use hyperscale_vm_effects::{
        Address, AddressClass, EdgeRef, GraphArg, GraphNode, ManifestGraph, RoleId, TestHasher,
        Value, child_key, fresh_id, fresh_local,
    };

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    #[test]
    fn child_addresses_are_pinned() {
        let owner = Address::new([0x11; 31], AddressClass::Component);
        assert_eq!(
            hex(&child_key(&TestHasher, owner, RoleId(1), &[]).local.0),
            "e199cd48f5bff4daeaed5bf184f8ee12"
        );
        assert_eq!(
            hex(&child_key(
                &TestHasher,
                owner,
                RoleId(1),
                &[
                    Value::Address(Address::new([0xE1; 31], AddressClass::Component))
                        .canonical_bytes()
                ],
            )
            .local
            .0),
            "5660dedc7bf25483d739f1994544ef53"
        );
    }

    #[test]
    fn fresh_derivations_are_pinned() {
        let graph = ManifestGraph {
            nodes: vec![
                GraphNode {
                    target: Address::new([0x10; 31], AddressClass::Component),
                    method: "withdraw".into(),
                    args: vec![GraphArg::Literal(Value::U128(7))],
                },
                GraphNode {
                    target: Address::new([0x20; 31], AddressClass::Component),
                    method: "deposit".into(),
                    args: vec![GraphArg::Edge {
                        edge: EdgeRef {
                            producer: 0,
                            output: 0,
                        },
                        constraints: vec![],
                    }],
                },
            ],
        };
        let identity = graph.hash(&TestHasher);
        assert_eq!(
            hex(&identity.0.0),
            "9657c3c40eb8079b108b84c4500b93efcc7c0771927dc4f5d3aae1b183eddb30"
        );
        assert_eq!(
            format!("{:016x}", fresh_id(&TestHasher, identity, 1, 0, 0)),
            "09356acabd228b6a"
        );
        assert_eq!(
            hex(&fresh_local(&TestHasher, identity, 1, 0, 0).0),
            "6a8b22bdca6a350921396181f8e14011"
        );
    }
}

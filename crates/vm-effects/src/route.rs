//! The routing fold: from a manifest to per-shard effect sets, snapshot
//! proof obligations, and the static call graph.
//!
//! Routing is a pure function of the manifest and content-addressed
//! metadata, evaluable by any node — validator, RPC, wallet, relay — with
//! no state. Shard resolution comes through the [`ShardResolver`] seam; the
//! beacon fold's shard trie binds there at integration.

use std::collections::{BTreeMap, BTreeSet};

use crate::admission::Admitted;
use crate::dsl::{EvalError, EvalInputs, evaluate_effects, evaluate_expr};
use crate::hash::Hasher;
use crate::manifest::{ManifestHash, NodeInput};
use crate::metadata::{InstanceRegistry, MetadataCache, PackageHash};
use crate::types::{Address, EffectSet, EffectTarget, Mode, ShardId, Value, Window};

/// Resolves an owner prefix to the shard holding it.
pub trait ShardResolver {
    /// The shard whose key space contains `owner`'s prefix.
    fn shard_of(&self, owner: Address) -> ShardId;
}

/// Test-grade resolver: a uniform trie of depth `bits`, the shard being
/// the leaf whose path is the address's top `bits` bits. Stands in for the
/// beacon fold's shard trie.
///
/// Emits the leaf's heap index `(1 << depth) | path` rather than the bare
/// path, which is what a trie leaf's identity actually is: without the
/// depth marker the root and the all-zero leaf below it — and every
/// all-zero leaf under that — would share an id. The stand-in models that
/// so a resolver swapped in behind it cannot find the seam narrower than
/// its own identities.
#[derive(Clone, Copy, Debug)]
pub struct PrefixShardResolver {
    /// The uniform trie's depth: how many leading bits of the prefix name
    /// the leaf. `0` is the root, which holds every address; values past
    /// 63 clamp, matching the depth bound a heap index can carry.
    pub bits: u8,
}

impl ShardResolver for PrefixShardResolver {
    fn shard_of(&self, owner: Address) -> ShardId {
        let depth = u32::from(self.bits.min(63));
        let head = u64::from_be_bytes(owner.0[..8].try_into().expect("an address is 16 bytes"));
        // At depth zero the shift is the full width, which `checked_shr`
        // reports rather than wrapping: the root's path is empty.
        let path = head.checked_shr(64 - depth).unwrap_or(0);
        ShardId((1 << depth) | path)
    }
}

/// A method on an instance — a static call graph vertex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MethodRef {
    /// The instance the method runs on.
    pub instance: Address,
    /// The method name.
    pub method: String,
}

/// One static call edge.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct CallEdge {
    /// The calling method.
    pub caller: MethodRef,
    /// The called method.
    pub callee: MethodRef,
}

/// The transaction's static call graph: manifest-invoked roots plus every
/// transitive call edge. Acyclic — a cycle is a routing error, so the
/// transitive effect fold is a DAG fold.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallGraph {
    /// The methods the manifest invokes directly.
    pub roots: BTreeSet<MethodRef>,
    /// Every caller-to-callee edge reached from the roots.
    pub edges: BTreeSet<CallEdge>,
}

/// A proof the transaction must carry: a bounded-window snapshot read.
/// Unbounded-window reads are locked substates — verified once, cached
/// process-wide — and carry no per-transaction obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SnapshotObligation {
    /// The declared snapshot target.
    pub target: EffectTarget,
    /// The declared staleness window, in versions.
    pub window: u64,
}

/// A routed transaction: what admission, scheduling, provisioning, and fee
/// estimation consume.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routing {
    /// The declared effect set of every participating shard.
    pub per_shard: BTreeMap<ShardId, EffectSet>,
    /// Every bounded-window snapshot the transaction must prove.
    pub snapshot_obligations: BTreeSet<SnapshotObligation>,
    /// The static call graph.
    pub call_graph: CallGraph,
}

impl Routing {
    /// The participating shards, ascending.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.per_shard.keys().copied()
    }
}

/// The bound on manifest nodes admission or routing will address.
pub const MAX_MANIFEST_NODES: usize = 4096;

/// The bound on call-site evaluations across one routing fold — a totality
/// backstop against fan-out blowup in pathological metadata.
///
/// Every manifest node costs at least one evaluation, so the budget has to
/// dominate [`MAX_MANIFEST_NODES`] or an admissible manifest could fail
/// routing on arithmetic alone; the surplus is the transitive fan-out
/// allowance the whole fold shares.
pub const MAX_CALL_EVALUATIONS: usize = 16 * MAX_MANIFEST_NODES;

const _: () = assert!(
    MAX_CALL_EVALUATIONS > MAX_MANIFEST_NODES,
    "a manifest at the node cap must be routable"
);

/// The bound on static call chain depth.
///
/// Separate from [`MAX_CALL_EVALUATIONS`] because the fold recurses per
/// frame: depth is what native stack consumption follows, and no
/// legitimate composition approaches it.
pub const MAX_CALL_DEPTH: usize = 64;

/// Why routing rejected a transaction. Deterministic: every node reaches
/// the identical verdict.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RouteError {
    /// More nodes than a routing index can address.
    #[error("manifest has more nodes than a routing index can address")]
    TooManyNodes,
    /// An edge consumed before its producer.
    #[error("node {node} consumes an edge from node {producer}, which is not earlier")]
    EdgeOrder {
        /// The consuming node.
        node: u32,
        /// The claimed producing node.
        producer: u32,
    },
    /// A call target with no registered instance.
    #[error("no instance at {0:?}")]
    UnknownInstance(Address),
    /// An instance whose package is not in the metadata cache.
    #[error("no package {0:?} in the metadata cache")]
    UnknownPackage(PackageHash),
    /// A method the target package does not declare.
    #[error("package {package:?} has no method `{method}`")]
    UnknownMethod {
        /// The package consulted.
        package: PackageHash,
        /// The method requested.
        method: String,
    },
    /// A cycle in the static call graph.
    #[error("static call graph cycle at {package:?}::{method}")]
    CyclicCalls {
        /// The package whose method re-entered the fold.
        package: PackageHash,
        /// The re-entered method.
        method: String,
    },
    /// The transitive fold exceeded [`MAX_CALL_EVALUATIONS`].
    #[error("transitive signature fold exceeded {MAX_CALL_EVALUATIONS} call evaluations")]
    CallBudgetExhausted,
    /// A static call chain deeper than [`MAX_CALL_DEPTH`].
    #[error("static call chain exceeds {MAX_CALL_DEPTH} frames")]
    CallDepthExceeded,
    /// Folding reserve amounts across shards overflowed.
    #[error("declared reserve amounts overflow")]
    ReserveOverflow,
    /// Signature evaluation failed.
    #[error("evaluating `{method}` for node {node}")]
    Eval {
        /// The manifest node being routed.
        node: u32,
        /// The method whose signature failed.
        method: String,
        /// The evaluation failure.
        #[source]
        source: EvalError,
    },
}

/// Route an admitted transaction: evaluate every node's transitive effect
/// signature and fold the results into per-shard effect sets, snapshot
/// obligations, and the static call graph.
///
/// Admission and routing evaluate fresh derivations at one root — the
/// signed form's hash, carried on the [`Admitted`] — so declared and routed
/// fresh keys agree by construction.
///
/// # Errors
///
/// Any [`RouteError`]; verdicts are deterministic and identical on every
/// node.
pub fn route(
    admitted: &Admitted,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
) -> Result<Routing, RouteError> {
    let manifest = admitted.manifest();
    let identity = admitted.identity();
    if manifest.nodes.len() > MAX_MANIFEST_NODES {
        return Err(RouteError::TooManyNodes);
    }
    let mut fold = Fold {
        cache,
        instances,
        hasher,
        shards,
        identity,
        per_shard: BTreeMap::new(),
        edges: BTreeSet::new(),
        evaluations: 0,
        frames: 0,
    };
    let mut roots = BTreeSet::new();
    for (index, node) in manifest.nodes.iter().enumerate() {
        let node_index = u32::try_from(index).map_err(|_| RouteError::TooManyNodes)?;
        let mut args = Vec::with_capacity(node.inputs.len());
        for input in &node.inputs {
            match input {
                NodeInput::Literal(value) => args.push(value.clone()),
                NodeInput::Edge { source, resource } => {
                    if *source >= node_index {
                        return Err(RouteError::EdgeOrder {
                            node: node_index,
                            producer: *source,
                        });
                    }
                    args.push(Value::Bucket {
                        resource: *resource,
                    });
                }
            }
        }
        roots.insert(MethodRef {
            instance: node.target,
            method: node.method.clone(),
        });
        let mut stack = Vec::new();
        fold.frames = 0;
        fold.call(
            node.target,
            &node.method,
            &args,
            node_index,
            None,
            &mut stack,
        )?;
    }

    let mut snapshot_obligations = BTreeSet::new();
    for set in fold.per_shard.values() {
        for effect in set.iter() {
            if let Mode::Snapshot {
                window: Window::Bounded(window),
            } = effect.mode
            {
                snapshot_obligations.insert(SnapshotObligation {
                    target: effect.target,
                    window,
                });
            }
        }
    }

    Ok(Routing {
        per_shard: fold.per_shard,
        snapshot_obligations,
        call_graph: CallGraph {
            roots,
            edges: fold.edges,
        },
    })
}

struct Fold<'a> {
    cache: &'a MetadataCache,
    instances: &'a InstanceRegistry,
    hasher: &'a dyn Hasher,
    shards: &'a dyn ShardResolver,
    identity: ManifestHash,
    per_shard: BTreeMap<ShardId, EffectSet>,
    edges: BTreeSet<CallEdge>,
    evaluations: usize,
    // The current node's frame ordinal: preorder over its call tree, reset
    // per root node, the node's own frame being zero.
    frames: u32,
}

impl Fold<'_> {
    fn call(
        &mut self,
        instance: Address,
        method: &str,
        args: &[Value],
        node_index: u32,
        caller: Option<&MethodRef>,
        stack: &mut Vec<(PackageHash, String)>,
    ) -> Result<(), RouteError> {
        self.evaluations += 1;
        if self.evaluations > MAX_CALL_EVALUATIONS {
            return Err(RouteError::CallBudgetExhausted);
        }
        if stack.len() >= MAX_CALL_DEPTH {
            return Err(RouteError::CallDepthExceeded);
        }
        let frame = self.frames;
        self.frames += 1;
        let meta = self
            .instances
            .get(instance)
            .ok_or(RouteError::UnknownInstance(instance))?;
        let package = self
            .cache
            .get(meta.package)
            .ok_or(RouteError::UnknownPackage(meta.package))?;
        let signature = package
            .methods
            .get(method)
            .ok_or_else(|| RouteError::UnknownMethod {
                package: meta.package,
                method: method.to_owned(),
            })?;
        let vertex = (meta.package, method.to_owned());
        if stack.contains(&vertex) {
            return Err(RouteError::CyclicCalls {
                package: meta.package,
                method: method.to_owned(),
            });
        }
        stack.push(vertex);

        let inputs = EvalInputs {
            self_addr: instance,
            args,
            config: &meta.config,
            node_index,
            frame,
            identity: self.identity,
        };
        let eval_context = |source| RouteError::Eval {
            node: node_index,
            method: method.to_owned(),
            source,
        };
        let effects =
            evaluate_effects(&signature.effects, &inputs, self.hasher).map_err(eval_context)?;
        for effect in effects.iter() {
            let shard = self.shards.shard_of(effect.target.owner());
            self.per_shard
                .entry(shard)
                .or_default()
                .insert(effect)
                .map_err(|_| RouteError::ReserveOverflow)?;
        }

        let this_ref = MethodRef {
            instance,
            method: method.to_owned(),
        };
        if let Some(caller) = caller {
            self.edges.insert(CallEdge {
                caller: caller.clone(),
                callee: this_ref.clone(),
            });
        }
        for site in &signature.calls {
            let target = evaluate_expr(&site.target, &inputs, self.hasher)
                .map_err(eval_context)
                .and_then(|value| match value {
                    Value::Address(addr) => Ok(addr),
                    other => Err(eval_context(EvalError::TypeMismatch {
                        expected: "address",
                        found: other.kind(),
                    })),
                })?;
            let mut call_args = Vec::with_capacity(site.args.len());
            for expr in &site.args {
                call_args.push(evaluate_expr(expr, &inputs, self.hasher).map_err(eval_context)?);
            }
            self.call(
                target,
                &site.method,
                &call_args,
                node_index,
                Some(&this_ref),
                stack,
            )?;
        }

        stack.pop();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        Admitted, CallEdge, MAX_CALL_DEPTH, MAX_MANIFEST_NODES, MethodRef, PrefixShardResolver,
        RouteError, ShardResolver, SnapshotObligation, route,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr, WindowExpr, fresh_id};
    use crate::hash::{Hash32, Hasher, TestHasher};
    use crate::manifest::{Manifest, ManifestHash, Node, NodeInput};
    use crate::metadata::{
        CallSite, InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature, PackageHash,
        PackageMetadata,
    };
    use crate::types::{Address, Effect, EffectTarget, Mode, RoleId, ShardId, Value, child_key};

    fn pkg(name: &str) -> PackageHash {
        PackageHash(TestHasher.hash(b"package", &[name.as_bytes()]))
    }

    fn identity() -> ManifestHash {
        ManifestHash(Hash32([0x1D; 32]))
    }

    /// Routing's own defences have to hold for manifests admission would
    /// never produce — a forward edge, a metadata cycle — so these tests
    /// build the admitted form directly rather than through `admit`.
    fn admitted(manifest: &Manifest) -> Admitted {
        Admitted::new(manifest.clone(), identity())
    }

    fn addr(byte: u8) -> Address {
        Address([byte; 16])
    }

    fn point(owner: Address, role: RoleId) -> EffectTarget {
        EffectTarget::Point(child_key(&TestHasher, owner, role, &[]))
    }

    fn self_point(role: RoleId, mode: ModeExpr) -> Clause {
        Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role,
                material: vec![],
            }),
            mode,
        }
    }

    fn method(effects: Vec<Clause>, calls: Vec<CallSite>) -> MethodSignature {
        MethodSignature {
            effects,
            calls,
            ..MethodSignature::default()
        }
    }

    fn resolver() -> PrefixShardResolver {
        PrefixShardResolver { bits: 8 }
    }

    #[test]
    fn transitive_fold_unions_effects_and_records_edges() {
        let mut cache = MetadataCache::new();
        let mut sender_pkg = PackageMetadata::default();
        sender_pkg.methods.insert(
            "pay".into(),
            method(
                vec![self_point(RoleId(1), ModeExpr::Delta)],
                vec![CallSite {
                    target: Expr::Arg(0),
                    method: "recv".into(),
                    args: vec![Expr::Arg(1)],
                }],
            ),
        );
        let mut receiver_pkg = PackageMetadata::default();
        receiver_pkg.methods.insert(
            "recv".into(),
            method(
                vec![Clause::Effect {
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        role: RoleId(2),
                        material: vec![],
                    }),
                    mode: ModeExpr::Reserve(Expr::Arg(0)),
                }],
                vec![],
            ),
        );
        cache.publish(pkg("payer"), sender_pkg);
        cache.publish(pkg("payee"), receiver_pkg);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(0x11),
            InstanceMeta {
                package: pkg("payer"),
                config: vec![],
            },
        );
        instances.register(
            addr(0x22),
            InstanceMeta {
                package: pkg("payee"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(0x11),
                method: "pay".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(addr(0x22))),
                    NodeInput::Literal(Value::U128(9)),
                ],
            }],
        };

        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        // Asked of the resolver rather than restated: what a shard is
        // called is its business, and the claim here is that the two
        // instances land apart and keep their own effects.
        let (sender, recipient) = (
            resolver().shard_of(addr(0x11)),
            resolver().shard_of(addr(0x22)),
        );
        assert_ne!(sender, recipient);
        let shards: Vec<_> = routing.shards().collect();
        assert_eq!(shards, vec![sender, recipient]);
        assert!(routing.per_shard[&sender].contains(&Effect {
            target: point(addr(0x11), RoleId(1)),
            mode: Mode::Delta,
        }));
        assert!(routing.per_shard[&recipient].contains(&Effect {
            target: point(addr(0x22), RoleId(2)),
            mode: Mode::Reserve { amount: 9 },
        }));
        let pay_ref = MethodRef {
            instance: addr(0x11),
            method: "pay".into(),
        };
        let recv_ref = MethodRef {
            instance: addr(0x22),
            method: "recv".into(),
        };
        assert_eq!(routing.call_graph.roots, BTreeSet::from([pay_ref.clone()]));
        assert_eq!(
            routing.call_graph.edges,
            BTreeSet::from([CallEdge {
                caller: pay_ref,
                callee: recv_ref,
            }])
        );
    }

    #[test]
    fn caller_and_callee_fresh_slots_never_collide() {
        // One package's slot 0 and its callee's slot 0 are authored
        // independently; the frame ordinal keeps their fresh IDs apart even
        // under a shared literal owner.
        let ledger = addr(0x33);
        let fresh_entry = || Clause::Effect {
            target: TargetExpr::Entry {
                owner: Expr::Literal(Value::Address(ledger)),
                collection: RoleId(6),
                order: Expr::Pack {
                    hi: Box::new(Expr::Literal(Value::U64(0))),
                    lo: Box::new(Expr::FreshId { slot: 0 }),
                },
            },
            mode: ModeExpr::Write,
        };
        let mut cache = MetadataCache::new();
        let mut maker = PackageMetadata::default();
        maker.methods.insert(
            "make".into(),
            method(
                vec![fresh_entry()],
                vec![CallSite {
                    target: Expr::Literal(Value::Address(addr(2))),
                    method: "assist".into(),
                    args: vec![],
                }],
            ),
        );
        let mut helper = PackageMetadata::default();
        helper
            .methods
            .insert("assist".into(), method(vec![fresh_entry()], vec![]));
        cache.publish(pkg("maker"), maker);
        cache.publish(pkg("helper"), helper);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("maker"),
                config: vec![],
            },
        );
        instances.register(
            addr(2),
            InstanceMeta {
                package: pkg("helper"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "make".into(),
                inputs: vec![],
            }],
        };

        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        let orders: Vec<u128> = (0..2u32)
            .map(|frame| u128::from(fresh_id(&TestHasher, identity(), 0, frame, 0)))
            .collect();
        assert_ne!(orders[0], orders[1]);
        let set = &routing.per_shard[&resolver().shard_of(ledger)];
        for order in orders {
            assert!(set.contains(&Effect {
                target: EffectTarget::Entry {
                    owner: ledger,
                    collection: RoleId(6),
                    order,
                },
                mode: Mode::Write,
            }));
        }
    }

    #[test]
    fn self_recursion_is_a_cycle() {
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "m".into(),
            method(
                vec![],
                vec![CallSite {
                    target: Expr::SelfAddr,
                    method: "m".into(),
                    args: vec![],
                }],
            ),
        );
        cache.publish(pkg("loop"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("loop"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "m".into(),
                inputs: vec![],
            }],
        };
        assert_eq!(
            route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::CyclicCalls {
                package: pkg("loop"),
                method: "m".into(),
            })
        );
    }

    #[test]
    fn mutual_recursion_is_a_cycle() {
        let mut cache = MetadataCache::new();
        let mut first = PackageMetadata::default();
        first.methods.insert(
            "m".into(),
            method(
                vec![],
                vec![CallSite {
                    target: Expr::Literal(Value::Address(addr(2))),
                    method: "n".into(),
                    args: vec![],
                }],
            ),
        );
        let mut second = PackageMetadata::default();
        second.methods.insert(
            "n".into(),
            method(
                vec![],
                vec![CallSite {
                    target: Expr::Literal(Value::Address(addr(1))),
                    method: "m".into(),
                    args: vec![],
                }],
            ),
        );
        cache.publish(pkg("first"), first);
        cache.publish(pkg("second"), second);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("first"),
                config: vec![],
            },
        );
        instances.register(
            addr(2),
            InstanceMeta {
                package: pkg("second"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "m".into(),
                inputs: vec![],
            }],
        };
        assert_eq!(
            route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::CyclicCalls {
                package: pkg("first"),
                method: "m".into(),
            })
        );
    }

    #[test]
    fn a_diamond_is_not_a_cycle() {
        let mut cache = MetadataCache::new();
        let call = |target: u8, name: &str| CallSite {
            target: Expr::Literal(Value::Address(addr(target))),
            method: name.into(),
            args: vec![],
        };
        let mut root = PackageMetadata::default();
        root.methods
            .insert("r".into(), method(vec![], vec![call(2, "p"), call(3, "q")]));
        let mut left = PackageMetadata::default();
        left.methods
            .insert("p".into(), method(vec![], vec![call(4, "h")]));
        let mut right = PackageMetadata::default();
        right
            .methods
            .insert("q".into(), method(vec![], vec![call(4, "h")]));
        let mut shared = PackageMetadata::default();
        shared.methods.insert(
            "h".into(),
            method(vec![self_point(RoleId(7), ModeExpr::Delta)], vec![]),
        );
        cache.publish(pkg("root"), root);
        cache.publish(pkg("left"), left);
        cache.publish(pkg("right"), right);
        cache.publish(pkg("shared"), shared);
        let mut instances = InstanceRegistry::new();
        for (byte, name) in [(1, "root"), (2, "left"), (3, "right"), (4, "shared")] {
            instances.register(
                addr(byte),
                InstanceMeta {
                    package: pkg(name),
                    config: vec![],
                },
            );
        }
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "r".into(),
                inputs: vec![],
            }],
        };
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert_eq!(routing.call_graph.edges.len(), 4);
    }

    #[test]
    fn edges_must_come_from_earlier_nodes() {
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "m".into(),
                inputs: vec![NodeInput::Edge {
                    source: 0,
                    resource: addr(9),
                }],
            }],
        };
        assert_eq!(
            route(
                &admitted(&manifest),
                &MetadataCache::new(),
                &InstanceRegistry::new(),
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::EdgeOrder {
                node: 0,
                producer: 0,
            })
        );
    }

    #[test]
    fn unknown_lookups_are_distinct_errors() {
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "m".into(),
                inputs: vec![],
            }],
        };
        let empty = route(
            &admitted(&manifest),
            &MetadataCache::new(),
            &InstanceRegistry::new(),
            &TestHasher,
            &resolver(),
        );
        assert_eq!(empty, Err(RouteError::UnknownInstance(addr(1))));

        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("ghost"),
                config: vec![],
            },
        );
        let missing_pkg = route(
            &admitted(&manifest),
            &MetadataCache::new(),
            &instances,
            &TestHasher,
            &resolver(),
        );
        assert_eq!(missing_pkg, Err(RouteError::UnknownPackage(pkg("ghost"))));

        let mut cache = MetadataCache::new();
        cache.publish(pkg("ghost"), PackageMetadata::default());
        let missing_method = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        );
        assert_eq!(
            missing_method,
            Err(RouteError::UnknownMethod {
                package: pkg("ghost"),
                method: "m".into(),
            })
        );
    }

    #[test]
    fn only_bounded_snapshots_carry_obligations() {
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "peek".into(),
            method(
                vec![
                    self_point(
                        RoleId(1),
                        ModeExpr::Snapshot(WindowExpr::Bounded(Expr::Literal(Value::U64(8)))),
                    ),
                    self_point(RoleId(2), ModeExpr::Snapshot(WindowExpr::Unbounded)),
                ],
                vec![],
            ),
        );
        cache.publish(pkg("oracle"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(5),
            InstanceMeta {
                package: pkg("oracle"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(5),
                method: "peek".into(),
                inputs: vec![],
            }],
        };
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert_eq!(
            routing.snapshot_obligations,
            BTreeSet::from([SnapshotObligation {
                target: point(addr(5), RoleId(1)),
                window: 8,
            }])
        );
    }

    #[test]
    fn fan_out_exhausts_the_call_budget() {
        // Wide but shallow: 256 mid methods each calling the same 256
        // leaves re-evaluates every leaf per caller — 65,793 evaluations
        // at depth 3, over the budget.
        const WIDTH: usize = 256;
        let mut meta = PackageMetadata::default();
        let self_call = |name: String| CallSite {
            target: Expr::SelfAddr,
            method: name,
            args: vec![],
        };
        meta.methods.insert(
            "root".into(),
            method(
                vec![],
                (0..WIDTH).map(|i| self_call(format!("mid{i}"))).collect(),
            ),
        );
        for mid in 0..WIDTH {
            meta.methods.insert(
                format!("mid{mid}"),
                method(
                    vec![],
                    (0..WIDTH).map(|i| self_call(format!("leaf{i}"))).collect(),
                ),
            );
        }
        for leaf in 0..WIDTH {
            meta.methods
                .insert(format!("leaf{leaf}"), method(vec![], vec![]));
        }
        let mut cache = MetadataCache::new();
        cache.publish(pkg("wide"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("wide"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "root".into(),
                inputs: vec![],
            }],
        };
        assert_eq!(
            route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::CallBudgetExhausted)
        );
    }

    #[test]
    fn deep_chains_exhaust_the_depth_bound() {
        let mut meta = PackageMetadata::default();
        for index in 0..=MAX_CALL_DEPTH {
            let calls = vec![CallSite {
                target: Expr::SelfAddr,
                method: format!("m{}", index + 1),
                args: vec![],
            }];
            meta.methods
                .insert(format!("m{index}"), method(vec![], calls));
        }
        let mut cache = MetadataCache::new();
        cache.publish(pkg("chain"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("chain"),
                config: vec![],
            },
        );
        let manifest = Manifest {
            nodes: vec![Node {
                target: addr(1),
                method: "m0".into(),
                inputs: vec![],
            }],
        };
        assert_eq!(
            route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::CallDepthExceeded)
        );
    }

    #[test]
    fn a_manifest_at_the_node_cap_routes_within_the_budget() {
        // Every node costs one evaluation, so a call-free manifest at the
        // node cap must route: the budget is sized from the cap, and a
        // manifest one node past it is rejected for its size, never for
        // arithmetic.
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert("m".into(), method(vec![], vec![]));
        cache.publish(pkg("wide"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("wide"),
                config: vec![],
            },
        );
        let nodes = |count: usize| Manifest {
            nodes: (0..count)
                .map(|_| Node {
                    target: addr(1),
                    method: "m".into(),
                    inputs: vec![],
                })
                .collect(),
        };
        let route_at = |count: usize| {
            route(
                &admitted(&nodes(count)),
                &cache,
                &instances,
                &TestHasher,
                &resolver(),
            )
        };

        // The size at which the old budget started refusing admissible
        // manifests.
        assert!(route_at(1_025).is_ok());
        assert!(route_at(MAX_MANIFEST_NODES).is_ok());
        assert_eq!(
            route_at(MAX_MANIFEST_NODES + 1),
            Err(RouteError::TooManyNodes)
        );
    }

    #[test]
    fn folded_reserve_amounts_report_their_overflow() {
        // The effect set sums reserves on one target, so two maximal
        // declarations on the same cell leave `u128` — a routing verdict,
        // not a panic.
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "take".into(),
            method(
                vec![Clause::Effect {
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        role: RoleId(1),
                        material: vec![],
                    }),
                    mode: ModeExpr::Reserve(Expr::Arg(0)),
                }],
                vec![],
            ),
        );
        cache.publish(pkg("vault"), meta);
        let mut instances = InstanceRegistry::new();
        instances.register(
            addr(1),
            InstanceMeta {
                package: pkg("vault"),
                config: vec![],
            },
        );
        let node = || Node {
            target: addr(1),
            method: "take".into(),
            inputs: vec![NodeInput::Literal(Value::U128(u128::MAX))],
        };
        assert_eq!(
            route(
                &admitted(&Manifest {
                    nodes: vec![node(), node()],
                }),
                &cache,
                &instances,
                &TestHasher,
                &resolver()
            ),
            Err(RouteError::ReserveOverflow)
        );
    }

    #[test]
    fn prefix_resolver_names_the_leaf_at_its_depth() {
        // `(1 << depth) | path`: the depth marker above the prefix bits.
        assert_eq!(
            PrefixShardResolver { bits: 4 }.shard_of(Address([0xAB; 16])),
            ShardId(0x1A)
        );
        assert_eq!(
            PrefixShardResolver { bits: 0 }.shard_of(Address([0xFF; 16])),
            ShardId(1),
            "the root holds every address, and is a leaf like any other"
        );
        assert_eq!(
            PrefixShardResolver { bits: 16 }.shard_of(Address([0xAB; 16])),
            ShardId(0x1_ABAB)
        );
    }

    #[test]
    fn leaves_at_different_depths_never_share_an_id() {
        // The failure a narrow id makes silent. An all-zero prefix sits in
        // the leftmost leaf at every depth, so those leaves differ only by
        // their depth marker — and past depth 15 the marker alone leaves
        // `u16`. Truncated, every one of them would read as the same
        // shard, and one shard would be credited with all their effects.
        let zeros = Address([0; 16]);
        let ids: Vec<ShardId> = (0..=63)
            .map(|bits| PrefixShardResolver { bits }.shard_of(zeros))
            .collect();
        let unique: BTreeSet<ShardId> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len(), "two depths collided on one id");
        assert_eq!(ids[63], ShardId(1 << 63), "the deepest leaf fills `u64`");
        assert!(
            ids.iter().filter(|id| id.0 > u64::from(u16::MAX)).count() > 0,
            "the range past `u16` must actually be reached, or this proves nothing"
        );
    }

    #[test]
    fn a_depth_past_the_bound_clamps_rather_than_wrapping() {
        // 64 would shift the marker off the top; the resolver pins at the
        // deepest leaf a heap index can name instead.
        let deepest = PrefixShardResolver { bits: 63 }.shard_of(Address([0xAB; 16]));
        for bits in [64, 128, 255] {
            assert_eq!(
                PrefixShardResolver { bits }.shard_of(Address([0xAB; 16])),
                deepest
            );
        }
    }
}

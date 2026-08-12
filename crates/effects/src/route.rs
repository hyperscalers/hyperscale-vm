//! The routing fold: from a manifest to per-shard effect sets, the
//! proof obligations, and the static call graph.
//!
//! Routing is a pure function of the manifest and content-addressed
//! metadata, evaluable by any node — validator, RPC, wallet, relay — with
//! no state. Shard resolution comes through the [`ShardResolver`] seam; the
//! beacon fold's shard trie binds there at integration.

use std::collections::{BTreeMap, BTreeSet};

use crate::admission::Admitted;
use crate::dsl::{Declaration, EvalError, EvalInputs, evaluate_declaration, evaluate_expr};
use crate::hash::Hasher;
use crate::invoke::{CallArg, EdgeBound, NodeCall};
use crate::manifest::{ManifestHash, NodeInput};
use crate::metadata::{
    AbiError, AbiParam, CallSite, InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature,
    PackageHash, check_abi,
};
use crate::types::{Address, CallTarget, Effect, EffectSet, ShardId, Value};

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
        let bytes = owner.to_bytes();
        let head = u64::from_be_bytes(bytes[..8].try_into().expect("an address is 32 bytes"));
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

/// A routed transaction: what admission, scheduling, provisioning, and fee
/// estimation consume.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Routing {
    /// The declared effect set of every participating shard.
    pub per_shard: BTreeMap<ShardId, EffectSet>,
    /// Every evaluated frame's declaration, in preorder.
    pub frames: Vec<FrameDeclaration>,
    /// One lowered invocation per manifest node, in node order: the
    /// export to call and where each of its ABI arguments comes from.
    ///
    /// Shard-invariant, like the capability table the handle positions
    /// index into: every participant of a cross-shard transaction lowers
    /// the identical call list, and locality scopes what is *applied*
    /// rather than what is invoked.
    pub calls: Vec<NodeCall>,
    /// Effects no signature declared: the kernel synthesizes them from the
    /// envelope rather than from a method body — today, the nullifier write
    /// of every subintent the transaction commits.
    ///
    /// Materialized after every frame, so a frame's handle slice keeps the
    /// position its signature gives it however many subintents the envelope
    /// carries.
    pub kernel_effects: Vec<Effect>,
    /// The static call graph.
    pub call_graph: CallGraph,
}

/// One frame's contribution to the transaction's declaration.
///
/// A frame is one signature evaluation: a manifest node, or one of its
/// transitive callees. Frames appear in [`Routing::frames`] in preorder —
/// node index, then the node's own frame ordinal — which is the order the
/// kernel materializes capabilities in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDeclaration {
    /// The invoking manifest node.
    pub node: u32,
    /// The frame's preorder position in that node's call tree; the node's
    /// own frame is zero.
    pub frame: u32,
    /// The method this frame evaluated.
    pub method: MethodRef,
    /// This frame's effects in clause order — one entry per clause the
    /// evaluation reached, `for-each` bodies expanded in place.
    ///
    /// A frame's handles occupy a contiguous run of the capability table,
    /// so a generated guest's positional parameters are this slice.
    pub ordered: Vec<Effect>,
}

impl Routing {
    /// The participating shards, ascending.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.per_shard.keys().copied()
    }

    /// The transaction's whole declaration, both views.
    ///
    /// `ordered` is every frame's clauses concatenated in preorder — the
    /// order capability materialization builds its table in, and therefore
    /// the order a guest's handle parameters are in. It is deliberately not
    /// filtered by shard: the table is shard-invariant so that every
    /// participant of a cross-shard transaction agrees on which rep is
    /// which, and locality scopes what is *applied* rather than what is
    /// materialized.
    ///
    /// # Errors
    ///
    /// [`RouteError::ReserveOverflow`] if folding two reservations on one
    /// target exceeds `u128`.
    pub fn declaration(&self) -> Result<Declaration, RouteError> {
        let mut set = EffectSet::new();
        let mut ordered = Vec::new();
        let frame_effects = self.frames.iter().flat_map(|frame| frame.ordered.iter());
        for effect in frame_effects.chain(self.kernel_effects.iter()) {
            set.insert(*effect)
                .map_err(|_| RouteError::ReserveOverflow)?;
            ordered.push(*effect);
        }
        Ok(Declaration {
            set,
            ordered,
            // A clause index is a method's; this is every frame's clauses
            // concatenated, so there is no clause to index.
            clause_spans: Vec::new(),
        })
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
    /// A handle binding naming a clause that did not evaluate to exactly
    /// one declared access.
    ///
    /// A handle is one capability, and a `for-each` clause expands over
    /// the target's creation-fixed configuration — so whether a clause
    /// can back a handle is a property of the instance, not of the
    /// signature, and cannot be settled when the package publishes.
    #[error(
        "node {node}: `{method}` binds ABI parameter {param} to effect clause {clause}, which \
         declared {effects} accesses rather than one"
    )]
    AmbiguousClause {
        /// The manifest node being routed.
        node: u32,
        /// The method whose binding this is.
        method: String,
        /// The ABI parameter position.
        param: u32,
        /// The effect clause it names.
        clause: u32,
        /// How many accesses that clause declared.
        effects: u32,
    },
    /// A signature whose ABI binding is not well-formed against its own
    /// declaration.
    #[error("node {node}: `{method}` has a malformed ABI binding")]
    MalformedAbi {
        /// The manifest node being routed.
        node: u32,
        /// The method whose binding this is.
        method: String,
        /// What is wrong with it.
        #[source]
        source: AbiError,
    },
    /// An ABI argument the node's bound inputs cannot supply.
    #[error("node {node}: `{method}` cannot bind ABI parameter {param}: {reason}")]
    UnbindableAbiParam {
        /// The manifest node being routed.
        node: u32,
        /// The method whose binding this is.
        method: String,
        /// The ABI parameter position.
        param: u32,
        /// What could not be supplied.
        reason: String,
    },
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
/// signature and fold the results into per-shard effect sets, the
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
        frames_log: Vec::new(),
        calls: Vec::new(),
        table_len: 0,
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
                NodeInput::Edge {
                    source, resource, ..
                } => {
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
            &Frame {
                instance: node.target,
                method: &node.method,
                args: &args,
                node_index,
                node_inputs: Some(&node.inputs),
                caller: None,
            },
            &mut stack,
        )?;
    }

    Ok(Routing {
        per_shard: fold.per_shard,
        frames: fold.frames_log,
        calls: fold.calls,
        kernel_effects: Vec::new(),
        call_graph: CallGraph {
            roots,
            edges: fold.edges,
        },
    })
}

/// Lower one node's ABI binding against the inputs bound to it.
///
/// Everything a binding names is settled here except a bucket's amount,
/// which does not exist until its producer runs — that stays an edge for
/// the walk to read. A handle resolves through the clause it names, which
/// is why the binding names a clause rather than a table position: a
/// guest's parameter list is a function of its own signature, and table
/// positions past the first would depend on the instance configuration a
/// `for-each` clause maps over.
/// What lowering one frame's binding needs beyond the frame itself.
struct Lowering<'a> {
    package: PackageHash,
    declaration: &'a Declaration,
    offset: u32,
    node_inputs: &'a [NodeInput],
    inputs: &'a EvalInputs<'a>,
    hasher: &'a dyn Hasher,
}

fn lower_call(
    site: &Frame<'_>,
    signature: &MethodSignature,
    lowering: &Lowering<'_>,
) -> Result<NodeCall, RouteError> {
    let Frame {
        instance,
        method,
        node_index,
        ..
    } = *site;
    let Lowering {
        package,
        declaration,
        offset,
        node_inputs,
        inputs,
        hasher,
    } = *lowering;
    // The publish gate judges this first, from the artifact's bytes
    // alone. Judging it again here is what makes it hold for a package
    // that reached the cache without one — a genesis static, a
    // hand-authored fixture — so no arrangement of metadata leaves a
    // consumed edge with no bucket argument to carry its bounds.
    check_abi(signature).map_err(|source| RouteError::MalformedAbi {
        node: node_index,
        method: method.to_owned(),
        source,
    })?;
    let mut args = Vec::with_capacity(signature.abi.len());
    for (position, binding) in signature.abi.iter().enumerate() {
        let param = u32::try_from(position).unwrap_or(u32::MAX);
        let unbindable = |reason: String| RouteError::UnbindableAbiParam {
            node: node_index,
            method: method.to_owned(),
            param,
            reason,
        };
        args.push(match binding {
            AbiParam::Handle(clause) => {
                let span = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| declaration.clause_spans.get(index))
                    .copied()
                    .ok_or_else(|| {
                        unbindable(format!("no effect clause {clause} in the signature"))
                    })?;
                let (start, len) = span;
                if len != 1 {
                    return Err(RouteError::AmbiguousClause {
                        node: node_index,
                        method: method.to_owned(),
                        param,
                        clause: *clause,
                        effects: len,
                    });
                }
                CallArg::Handle(
                    offset
                        .checked_add(start)
                        .ok_or_else(|| unbindable("capability table overflows".into()))?,
                )
            }
            AbiParam::Bucket(declared) => {
                let input = usize::try_from(*declared)
                    .ok()
                    .and_then(|index| node_inputs.get(index))
                    .ok_or_else(|| unbindable(format!("no bound input {declared}")))?;
                match input {
                    NodeInput::Edge { source, output, .. } => CallArg::Bucket {
                        source: *source,
                        output: *output,
                    },
                    NodeInput::Literal(_) => {
                        return Err(unbindable(format!(
                            "input {declared} is a literal, not a value edge"
                        )));
                    }
                }
            }
            AbiParam::Derived(expr) => {
                let value =
                    evaluate_expr(expr, inputs, hasher).map_err(|source| RouteError::Eval {
                        node: node_index,
                        method: method.to_owned(),
                        source,
                    })?;
                guest_arg(&value).ok_or_else(|| {
                    unbindable(format!("a {} has no guest representation", value.kind()))
                })?
            }
        });
    }
    Ok(NodeCall {
        package,
        target: instance,
        export: method.to_owned(),
        args,
        edges: edge_bounds(node_inputs),
        outputs: u32::try_from(signature.outputs.len()).unwrap_or(u32::MAX),
    })
}

/// Every value edge a node consumes, with the bound its consumer signed.
///
/// Taken from the node's bound inputs rather than from its ABI binding,
/// because the two are not the same set: a method that forwards its
/// funds to a callee reads no amount, so nothing in its own ABI carries
/// the edge — and the signed bound is owed a check all the same.
fn edge_bounds(node_inputs: &[NodeInput]) -> Vec<EdgeBound> {
    node_inputs
        .iter()
        .enumerate()
        .filter_map(|(position, input)| match input {
            NodeInput::Edge {
                source,
                output,
                bounds,
                ..
            } => Some(EdgeBound {
                source: *source,
                output: *output,
                param: u32::try_from(position).unwrap_or(u32::MAX),
                bounds: *bounds,
            }),
            NodeInput::Literal(_) => None,
        })
        .collect()
}

/// A derived value's guest form. Amounts and addresses cross as their
/// canonical fixed-width bytes; the compound kinds have no ABI shape and
/// refuse rather than picking an encoding the two runtimes would have to
/// agree on separately.
fn guest_arg(value: &Value) -> Option<CallArg> {
    match value {
        Value::U64(scalar) => Some(CallArg::U64(*scalar)),
        Value::U128(amount) => Some(CallArg::Bytes(amount.to_le_bytes().to_vec())),
        Value::Address(address) => Some(CallArg::Bytes(address.to_bytes().to_vec())),
        Value::Bytes(bytes) => Some(CallArg::Bytes(bytes.clone())),
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) | Value::List(_) => None,
    }
}

struct Fold<'a> {
    cache: &'a MetadataCache,
    instances: &'a InstanceRegistry,
    hasher: &'a dyn Hasher,
    shards: &'a dyn ShardResolver,
    identity: ManifestHash,
    per_shard: BTreeMap<ShardId, EffectSet>,
    frames_log: Vec<FrameDeclaration>,
    calls: Vec<NodeCall>,
    // Effects logged so far across every frame: the offset the next
    // frame's clause spans are relative to, and therefore the base of
    // every handle position that frame's binding resolves to.
    table_len: u32,
    edges: BTreeSet<CallEdge>,
    evaluations: usize,
    // The current node's frame ordinal: preorder over its call tree, reset
    // per root node, the node's own frame being zero.
    frames: u32,
}

/// One frame to evaluate: whose method, over what inputs, under which
/// manifest node.
struct Frame<'a> {
    instance: Address,
    method: &'a str,
    args: &'a [Value],
    node_index: u32,
    /// Present only for a manifest node's own frame: a callee is invoked
    /// by its caller's code, so there is no lowered invocation for the
    /// walk to perform.
    node_inputs: Option<&'a [NodeInput]>,
    caller: Option<&'a MethodRef>,
}

impl Fold<'_> {
    /// The record serving `instance`, whose class the fold has to check
    /// itself.
    ///
    /// A callee's address is evaluated from its caller's inputs and
    /// configuration, so unlike a manifest node's target it arrives
    /// unclassified. An address that answers no calls is an address no
    /// record serves, which is the refusal it already had.
    fn record_of(
        instances: &InstanceRegistry,
        instance: Address,
    ) -> Result<&InstanceMeta, RouteError> {
        let target =
            CallTarget::try_from(instance).map_err(|_| RouteError::UnknownInstance(instance))?;
        instances
            .get(target)
            .ok_or(RouteError::UnknownInstance(instance))
    }

    fn call(
        &mut self,
        site: &Frame<'_>,
        stack: &mut Vec<(PackageHash, String)>,
    ) -> Result<(), RouteError> {
        let Frame {
            instance,
            method,
            args,
            node_index,
            node_inputs,
            caller,
        } = *site;
        self.evaluations += 1;
        if self.evaluations > MAX_CALL_EVALUATIONS {
            return Err(RouteError::CallBudgetExhausted);
        }
        if stack.len() >= MAX_CALL_DEPTH {
            return Err(RouteError::CallDepthExceeded);
        }
        let frame = self.frames;
        self.frames += 1;
        let meta = Self::record_of(self.instances, instance)?;
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
        let declaration =
            evaluate_declaration(&signature.effects, &inputs, self.hasher).map_err(eval_context)?;
        // The frame's handles occupy the run of the table starting here,
        // so the offset has to be taken before the frame is logged.
        let offset = self.table_len;
        if let Some(node_inputs) = node_inputs {
            let lowering = Lowering {
                package: meta.package,
                declaration: &declaration,
                offset,
                node_inputs,
                inputs: &inputs,
                hasher: self.hasher,
            };
            self.calls.push(lower_call(site, signature, &lowering)?);
        }
        self.table_len = offset
            .checked_add(u32::try_from(declaration.ordered.len()).unwrap_or(u32::MAX))
            .ok_or(RouteError::CallBudgetExhausted)?;
        // Recorded before descending into callees, so the log is preorder
        // — the order capability materialization walks.
        self.frames_log.push(FrameDeclaration {
            node: node_index,
            frame,
            method: MethodRef {
                instance,
                method: method.to_owned(),
            },
            ordered: declaration.ordered,
        });
        for effect in declaration.set.iter() {
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
        self.descend(&signature.calls, &this_ref, &inputs, node_index, stack)?;

        stack.pop();
        Ok(())
    }

    /// Fold the frame's static call sites: each callee's target and
    /// arguments evaluated over this frame's inputs, then recursed into.
    fn descend(
        &mut self,
        sites: &[CallSite],
        caller: &MethodRef,
        inputs: &EvalInputs<'_>,
        node_index: u32,
        stack: &mut Vec<(PackageHash, String)>,
    ) -> Result<(), RouteError> {
        let eval_context = |source| RouteError::Eval {
            node: node_index,
            method: caller.method.clone(),
            source,
        };
        for site in sites {
            let target = evaluate_expr(&site.target, inputs, self.hasher)
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
                call_args.push(evaluate_expr(expr, inputs, self.hasher).map_err(eval_context)?);
            }
            self.call(
                &Frame {
                    instance: target,
                    method: &site.method,
                    args: &call_args,
                    node_index,
                    node_inputs: None,
                    caller: Some(caller),
                },
                stack,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        AbiParam, Admitted, CallArg, CallEdge, EdgeBound, MAX_CALL_DEPTH, MAX_MANIFEST_NODES,
        MethodRef, PrefixShardResolver, RouteError, ShardResolver, route,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr, fresh_id};
    use crate::hash::{Hash32, Hasher, TestHasher};
    use crate::manifest::{Bounds, Manifest, ManifestHash, Node, NodeInput};
    use crate::metadata::{
        CallSite, InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature, PackageHash,
        PackageMetadata, ParamType,
    };
    use crate::types::{
        Address, AddressClass, ComponentAddr, Effect, EffectSet, EffectTarget, Mode, RoleId,
        ShardId, Value, child_key,
    };

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
        Address::new([byte; 31], AddressClass::Component)
    }

    /// The record a fixture's instance of `package` carries.
    fn meta_of(package: &str) -> InstanceMeta {
        InstanceMeta {
            package: pkg(package),
            config: vec![],
            salt: Hash32([0; 32]),
        }
    }

    /// The address that record derives — what the fixture names, and
    /// where creation puts it, without either being told the other.
    fn instance_of(package: &str) -> ComponentAddr {
        meta_of(package).address(&TestHasher)
    }

    fn point(owner: impl Into<Address>, role: RoleId) -> EffectTarget {
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

    /// A payer calling a payee: one manifest node, one transitive callee,
    /// and the two instances landing on different shards.
    fn payer_payee_world() -> (MetadataCache, InstanceRegistry, Manifest) {
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
        instances.create(&TestHasher, meta_of("payer"));
        instances.create(&TestHasher, meta_of("payee"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("payer").into(),
                method: "pay".into(),
                inputs: vec![
                    NodeInput::Literal(Value::Address(instance_of("payee").into())),
                    NodeInput::Literal(Value::U128(9)),
                ],
            }],
        };
        (cache, instances, manifest)
    }

    #[test]
    fn transitive_fold_unions_effects_and_records_edges() {
        let (cache, instances, manifest) = payer_payee_world();
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
            resolver().shard_of(instance_of("payer").into()),
            resolver().shard_of(instance_of("payee").into()),
        );
        assert_ne!(sender, recipient);
        // `shards()` is ascending, so the claim is the participating set
        // rather than the order two derived addresses happen to sort in.
        let shards: BTreeSet<_> = routing.shards().collect();
        assert_eq!(shards, BTreeSet::from([sender, recipient]));
        assert!(routing.per_shard[&sender].contains(&Effect {
            target: point(instance_of("payer"), RoleId(1)),
            mode: Mode::Delta,
        }));
        assert!(routing.per_shard[&recipient].contains(&Effect {
            target: point(instance_of("payee"), RoleId(2)),
            mode: Mode::Reserve { amount: 9 },
        }));
        let pay_ref = MethodRef {
            instance: instance_of("payer").into(),
            method: "pay".into(),
        };
        let recv_ref = MethodRef {
            instance: instance_of("payee").into(),
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
    fn frames_carry_the_clause_order_materialization_walks() {
        let (cache, instances, manifest) = payer_payee_world();
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();

        // Preorder: the caller's frame before the callee it reached. This
        // is the order `KernelSession::materialize` builds its capability
        // table in, so it is the order a generated guest's handle
        // parameters are in.
        assert_eq!(
            routing
                .frames
                .iter()
                .map(|frame| (frame.node, frame.frame, frame.method.method.clone()))
                .collect::<Vec<_>>(),
            vec![(0, 0, "pay".to_owned()), (0, 1, "recv".to_owned())],
        );

        // The transaction-wide declaration reaches every effect routing
        // placed on a shard and folds back to exactly that union — the
        // property a consumer building a kernel batch depends on, and the
        // one `execute_batch` rechecks before running anything.
        let declaration = routing.declaration().unwrap();
        let mut union = EffectSet::new();
        for set in routing.per_shard.values() {
            for effect in set.iter() {
                union.insert(effect).unwrap();
            }
        }
        assert_eq!(declaration.set, union);
        assert_eq!(
            declaration.ordered,
            vec![
                Effect {
                    target: point(instance_of("payer"), RoleId(1)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: point(instance_of("payee"), RoleId(2)),
                    mode: Mode::Reserve { amount: 9 },
                },
            ],
            "the caller's clause first, then its callee's"
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
        // An address is a function of the record, so a package can name
        // an instance created after it.
        let helper_meta = InstanceMeta {
            package: pkg("helper"),
            config: vec![],
            salt: Hash32([4; 32]),
        };
        let a_2 = helper_meta.address(&TestHasher);
        let mut maker = PackageMetadata::default();
        maker.methods.insert(
            "make".into(),
            method(
                vec![fresh_entry()],
                vec![CallSite {
                    target: Expr::Literal(Value::Address(a_2.into())),
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
        instances.create(&TestHasher, meta_of("maker"));
        assert_eq!(instances.create(&TestHasher, helper_meta), a_2);
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("maker").into(),
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
        instances.create(&TestHasher, meta_of("loop"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("loop").into(),
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
        // Two instances naming each other: the addresses derive from the
        // records, which name no address, so there is no cycle to break
        // — only an order to respect.
        let first_meta = InstanceMeta {
            package: pkg("first"),
            config: vec![],
            salt: Hash32([6; 32]),
        };
        let second_meta = InstanceMeta {
            package: pkg("second"),
            config: vec![],
            salt: Hash32([7; 32]),
        };
        let a_1_3 = first_meta.address(&TestHasher);
        let a_2_2 = second_meta.address(&TestHasher);
        let mut first = PackageMetadata::default();
        first.methods.insert(
            "m".into(),
            method(
                vec![],
                vec![CallSite {
                    target: Expr::Literal(Value::Address(a_2_2.into())),
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
                    target: Expr::Literal(Value::Address(a_1_3.into())),
                    method: "m".into(),
                    args: vec![],
                }],
            ),
        );
        cache.publish(pkg("first"), first);
        cache.publish(pkg("second"), second);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, first_meta);
        instances.create(&TestHasher, second_meta);
        let manifest = Manifest {
            nodes: vec![Node {
                target: a_1_3.into(),
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
        let call = |target: &str, name: &str| CallSite {
            target: Expr::Literal(Value::Address(instance_of(target).into())),
            method: name.into(),
            args: vec![],
        };
        let mut root = PackageMetadata::default();
        root.methods.insert(
            "r".into(),
            method(vec![], vec![call("left", "p"), call("right", "q")]),
        );
        let mut left = PackageMetadata::default();
        left.methods
            .insert("p".into(), method(vec![], vec![call("shared", "h")]));
        let mut right = PackageMetadata::default();
        right
            .methods
            .insert("q".into(), method(vec![], vec![call("shared", "h")]));
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
        for name in ["root", "left", "right", "shared"] {
            instances.create(&TestHasher, meta_of(name));
        }
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("root").into(),
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
                    output: 0,
                    resource: addr(9),
                    bounds: Bounds::default(),
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
        let ghost_meta = InstanceMeta {
            package: pkg("ghost"),
            config: vec![],
            salt: Hash32([8; 32]),
        };
        let a_1_4 = ghost_meta.address(&TestHasher);
        let manifest = Manifest {
            nodes: vec![Node {
                target: a_1_4.into(),
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
        assert_eq!(empty, Err(RouteError::UnknownInstance(a_1_4.into())));

        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, ghost_meta);
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
    fn a_locked_read_declares_its_target() {
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "peek".into(),
            method(
                vec![
                    self_point(RoleId(1), ModeExpr::Locked),
                    self_point(RoleId(2), ModeExpr::Locked),
                ],
                vec![],
            ),
        );
        cache.publish(pkg("oracle"), meta);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("oracle"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("oracle").into(),
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
        // A locked read declares its target like any other mode; whether the
        // target is actually locked is the kernel's to refuse, since only
        // the store knows.
        let declared = routing.per_shard.values().next().unwrap();
        assert_eq!(declared.iter().count(), 2);
        for role in [RoleId(1), RoleId(2)] {
            assert!(declared.contains(&Effect {
                target: point(instance_of("oracle"), role),
                mode: Mode::Locked,
            }));
        }
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
        instances.create(&TestHasher, meta_of("wide"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("wide").into(),
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
        instances.create(&TestHasher, meta_of("chain"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("chain").into(),
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
        instances.create(&TestHasher, meta_of("wide"));
        let nodes = |count: usize| Manifest {
            nodes: (0..count)
                .map(|_| Node {
                    target: instance_of("wide").into(),
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
        instances.create(&TestHasher, meta_of("vault"));
        let node = || Node {
            target: instance_of("vault").into(),
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
            PrefixShardResolver { bits: 4 }
                .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
            ShardId(0x1A)
        );
        assert_eq!(
            PrefixShardResolver { bits: 0 }
                .shard_of(Address::new([0xFF; 31], AddressClass::Component)),
            ShardId(1),
            "the root holds every address, and is a leaf like any other"
        );
        assert_eq!(
            PrefixShardResolver { bits: 16 }
                .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
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
        let zeros = Address::new([0; 31], AddressClass::Component);
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
        let deepest = PrefixShardResolver { bits: 63 }
            .shard_of(Address::new([0xAB; 31], AddressClass::Component));
        for bits in [64, 128, 255] {
            assert_eq!(
                PrefixShardResolver { bits }
                    .shard_of(Address::new([0xAB; 31], AddressClass::Component)),
                deepest
            );
        }
    }
    /// A world whose one method declares `spread` before a point clause
    /// and binds its ABI handle to the point.
    fn spreading_world(
        spread: Vec<Value>,
        abi: Vec<AbiParam>,
    ) -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                abi,
                effects: vec![
                    Clause::ForEach {
                        list: Expr::Config(0),
                        body: vec![Clause::Effect {
                            target: TargetExpr::Point(Expr::ChildKey {
                                owner: Box::new(Expr::SelfAddr),
                                role: RoleId(9),
                                material: vec![Expr::Binding(0)],
                            }),
                            mode: ModeExpr::Delta,
                        }],
                    },
                    self_point(RoleId(1), ModeExpr::Write),
                ],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("spread"), package);
        let mut instances = InstanceRegistry::new();
        let spreader = instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("spread"),
                config: vec![Value::List(spread)],
                salt: Hash32([15; 32]),
            },
        );
        (cache, instances, one_node(spreader))
    }

    fn one_node(target: impl Into<Address>) -> Manifest {
        Manifest {
            nodes: vec![Node {
                target: target.into(),
                method: "m".into(),
                inputs: vec![],
            }],
        }
    }

    #[test]
    fn a_handle_names_a_clause_rather_than_a_table_position() {
        // The `for-each` ahead of the point clause expands over the
        // instance's configuration, so the point's position in the table
        // moves with it while its clause index does not.
        for width in 1u64..4 {
            let spread: Vec<Value> = (0..width).map(Value::U64).collect();
            let (cache, instances, manifest) = spreading_world(spread, vec![AbiParam::Handle(1)]);
            let routing = route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver(),
            )
            .expect("routes");
            let CallArg::Handle(rep) = routing.calls[0].args[0] else {
                panic!("a handle argument");
            };
            let declaration = routing.declaration().expect("one frame folds");
            assert_eq!(u64::from(rep), width);
            assert_eq!(
                declaration.ordered[usize::try_from(rep).unwrap()].mode,
                Mode::Write,
                "the bound clause's own effect, whatever the spread's width"
            );
        }
    }

    #[test]
    fn a_handle_on_a_spreading_clause_is_refused() {
        // Two elements make clause 0 declare two accesses, and a handle
        // is one capability — so the binding cannot be honoured, and the
        // verdict is the same on every node because the configuration it
        // depends on is creation-fixed.
        let spread = vec![Value::U64(1), Value::U64(2)];
        let (cache, instances, manifest) = spreading_world(spread, vec![AbiParam::Handle(0)]);
        let error = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect_err("a spreading clause cannot back a handle");
        assert!(
            matches!(
                error,
                RouteError::AmbiguousClause {
                    clause: 0,
                    effects: 2,
                    ..
                }
            ),
            "unexpected refusal: {error:?}"
        );
    }

    #[test]
    fn a_bucket_binding_names_the_edge_its_parameter_carries() {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "take".into(),
            MethodSignature {
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                outputs: vec![Expr::Literal(Value::Address(addr(0xE1)))],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("edges"), package);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("edges"));
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("edges").into(),
                    method: "make".into(),
                    inputs: vec![],
                },
                Node {
                    target: instance_of("edges").into(),
                    method: "take".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 3,
                        resource: addr(0xE1),
                        bounds: Bounds {
                            min: Some(7),
                            max: None,
                        },
                    }],
                },
            ],
        };
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        assert_eq!(
            routing.calls[1].args[0],
            CallArg::Bucket {
                source: 0,
                output: 3
            },
            "a bucket argument carries the producer's output slot, not just the producer"
        );
        assert_eq!(
            routing.calls[1].edges,
            vec![EdgeBound {
                source: 0,
                output: 3,
                param: 0,
                bounds: Bounds {
                    min: Some(7),
                    max: None,
                },
            }],
            "the consumed edge carries its signed bound to the walk"
        );
    }
    /// A world whose `forward` hands its bucket to a callee rather than
    /// reading the amount itself, plus a producer to feed it.
    fn forwarding_world() -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut router = PackageMetadata::default();
        router.methods.insert(
            "forward".into(),
            MethodSignature {
                params: vec![ParamType::Bucket],
                // Nothing carries the bucket: the callee reads it.
                abi: vec![AbiParam::Handle(0)],
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
                calls: vec![CallSite {
                    target: Expr::Literal(Value::Address(instance_of("callee").into())),
                    method: "take".into(),
                    args: vec![Expr::Arg(0)],
                }],
                ..MethodSignature::default()
            },
        );
        router.methods.insert(
            "make".into(),
            MethodSignature {
                outputs: vec![Expr::Literal(Value::Address(addr(0xE1)))],
                ..MethodSignature::default()
            },
        );
        let mut callee = PackageMetadata::default();
        callee.methods.insert(
            "take".into(),
            MethodSignature {
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(RoleId(2), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("router"), router);
        cache.publish(pkg("callee"), callee);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("router"));
        instances.create(&TestHasher, meta_of("callee"));
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("router").into(),
                    method: "make".into(),
                    inputs: vec![],
                },
                Node {
                    target: instance_of("router").into(),
                    method: "forward".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: addr(0xE1),
                        bounds: Bounds {
                            min: Some(42),
                            max: None,
                        },
                    }],
                },
            ],
        };
        (cache, instances, manifest)
    }

    #[test]
    fn a_forwarded_bucket_still_carries_its_edge_bound() {
        // The bound belongs to the edge, not to the argument list. A
        // method that hands its funds to a callee reads no amount, so
        // nothing in its own ABI carries the edge — and the signer's
        // bound is owed a check all the same, at the node where the edge
        // resolves.
        let (cache, instances, manifest) = forwarding_world();
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        let call = &routing.calls[1];
        assert!(
            !call
                .args
                .iter()
                .any(|arg| matches!(arg, CallArg::Bucket { .. })),
            "the forwarding method's own ABI carries no bucket"
        );
        assert_eq!(
            call.edges,
            vec![EdgeBound {
                source: 0,
                output: 0,
                param: 0,
                bounds: Bounds {
                    min: Some(42),
                    max: None,
                },
            }]
        );
    }

    #[test]
    fn a_malformed_binding_refuses_at_routing() {
        // Publish is the gate that should have caught this. Routing
        // judges it again, so a package that reached the cache without
        // one — a genesis static, a hand-authored fixture — cannot be
        // called on a binding nothing can honour.
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                outputs: vec![Expr::Literal(Value::Address(addr(0xE1)))],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("bad"), package);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("bad"));
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("bad").into(),
                    method: "make".into(),
                    inputs: vec![],
                },
                Node {
                    target: instance_of("bad").into(),
                    method: "m".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: addr(0xE1),
                        bounds: Bounds::default(),
                    }],
                },
            ],
        };
        let error = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect_err("a malformed binding cannot be called");
        assert!(
            matches!(error, RouteError::MalformedAbi { node: 1, .. }),
            "unexpected refusal: {error:?}"
        );
    }
}

//! The routing fold: from a manifest to per-shard effect sets and proof
//! obligations.
//!
//! Routing is a pure function of the manifest and content-addressed
//! metadata, evaluable by any node — validator, RPC, wallet, relay — with
//! no state. Shard resolution comes through the [`ShardResolver`] seam; the
//! beacon fold's shard trie binds there at integration.

use std::collections::BTreeMap;

use hyperscale_vm_types::{Address, CallTarget, Effect, EffectConflict, EffectSet};

use crate::admission::Admitted;
use crate::dsl::{
    Declaration, DeclaredAccess, EvalError, EvalInputs, evaluate_declaration, evaluate_expr,
    materialized_kind,
};
use crate::hash::Hasher;
use crate::instance::{InstanceMeta, InstanceRegistry, ResolveError};
use crate::invoke::{CallArg, EdgeBound, EdgeKind, NodeCall};
use crate::manifest::{ManifestHash, Node, NodeInput};
use crate::metadata::{MetadataCache, PackageHash};
use crate::publish::{AbiError, check_abi};
use crate::resource::issued_resource;
use crate::signature::{AbiParam, MethodSignature};
use crate::types::{MAX_IDS_PER_EDGE, ShardId, Value};

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
    /// The transaction's whole declaration, built as the fold runs;
    /// reached through [`Routing::declaration`].
    declaration: Declaration,
}

/// One frame's contribution to the transaction's declaration.
///
/// A frame is one manifest node's signature evaluation. Frames appear in
/// [`Routing::frames`] in node order, which is the order the kernel
/// materializes capabilities in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameDeclaration {
    /// The invoking manifest node.
    pub node: u32,
    /// This frame's accesses in clause order — one entry per clause the
    /// evaluation reached, `for-each` bodies expanded in place, each
    /// carrying what its cell holds.
    ///
    /// A frame's handles occupy a contiguous run of the capability table,
    /// so a generated guest's positional parameters are this slice.
    pub ordered: Vec<DeclaredAccess>,
}

impl Routing {
    /// The participating shards, ascending.
    pub fn shards(&self) -> impl Iterator<Item = ShardId> + '_ {
        self.per_shard.keys().copied()
    }

    /// The transaction's whole declaration, both views, straight from
    /// the fold.
    ///
    /// `ordered` is every frame's clauses concatenated in preorder — the
    /// order capability materialization builds its table in, and therefore
    /// the order a guest's handle parameters are in. It is deliberately not
    /// filtered by shard: the table is shard-invariant so that every
    /// participant of a cross-shard transaction agrees on which rep is
    /// which, and locality scopes what is *applied* rather than what is
    /// materialized. A fold whose reservations overflow the set is a
    /// [`RouteError::Conflict`] at `route()`, so a routing that exists
    /// has a declaration.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    /// Append an effect no signature declared: the kernel synthesizes it
    /// from the envelope rather than from a method body — today, the
    /// nullifier write of every subintent the transaction commits.
    ///
    /// Lands after every frame's clauses, so a frame's handle slice
    /// keeps the position its signature gives it however many subintents
    /// the envelope carries. Carries no resource of its own: nothing
    /// about it is a package's declaration.
    pub(crate) fn push_kernel_effect(&mut self, shard: ShardId, effect: Effect) {
        self.per_shard
            .entry(shard)
            .or_default()
            .insert(effect)
            .expect("only reserve amounts fold, and this is a write");
        self.declaration
            .set
            .insert(effect)
            .expect("only reserve amounts fold, and this is a write");
        self.declaration.ordered.push(DeclaredAccess {
            effect,
            holds: None,
        });
    }
}

/// The bound on manifest nodes admission or routing will address.
pub const MAX_MANIFEST_NODES: usize = 4096;

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
    /// A call target that does not resolve to a method.
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    /// The capability table outgrew the index a handle is named by.
    #[error("the capability table exceeds the addressable handle space")]
    TableOverflow,
    /// A conflict met while folding declared effects into the set —
    /// refused where the set is built rather than at the shard that
    /// would have to judge it.
    #[error(transparent)]
    Conflict(#[from] EffectConflict),
    /// A frame declaring an effect on somebody else's prefix.
    ///
    /// An object's cells are reachable by calling it, never by naming
    /// them: a package that could declare against another owner would
    /// reach that owner's state with no method of theirs in the path.
    #[error(
        "node {node}: `{method}` declares effect {clause} on {owner:?}, which is not its own \
         prefix"
    )]
    ForeignDeclaration {
        /// The manifest node whose fold reached it.
        node: u32,
        /// The method whose signature declared it.
        method: String,
        /// Which of the frame's evaluated effects it is, in clause order.
        clause: u32,
        /// The prefix it reached for.
        owner: Address,
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

/// Route an admitted transaction: evaluate every node's effect signature
/// and fold the results into per-shard effect sets and the obligations.
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
        declaration: Declaration::default(),
        table_len: 0,
    };
    for (index, node) in manifest.nodes.iter().enumerate() {
        let node_index = u32::try_from(index).map_err(|_| RouteError::TooManyNodes)?;
        let mut args = Vec::with_capacity(node.inputs.len());
        for input in &node.inputs {
            match input {
                NodeInput::Literal(value) => args.push(value.clone()),
                NodeInput::Edge {
                    source,
                    resource,
                    content,
                    ..
                } => {
                    if *source >= node_index {
                        return Err(RouteError::EdgeOrder {
                            node: node_index,
                            producer: *source,
                        });
                    }
                    args.push(Value::Bucket {
                        resource: *resource,
                        content: content.clone(),
                    });
                }
            }
        }
        fold.frame(node_index, node, &args)?;
    }

    Ok(Routing {
        per_shard: fold.per_shard,
        frames: fold.frames_log,
        calls: fold.calls,
        declaration: fold.declaration,
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
    node: &'a Node,
    inputs: &'a EvalInputs<'a>,
    hasher: &'a dyn Hasher,
}

/// Refuse a frame declaring an effect on a prefix that is not its own.
///
/// A declaration bounds what execution may touch; this bounds what a
/// declaration may claim. Without it the two are the same sentence read
/// twice, and a package reaches any cell it can name — a stranger's
/// balance among them — with no method's accessibility in the path,
/// because reaching for a cell is not calling the object that owns it.
///
/// Judged on the evaluated effect rather than on the expression that
/// produced it. The publish gate refuses the expression, so an author
/// hears about it first; this cannot be outgrown by an expression shape
/// nobody anticipated, because an effect either carries the frame's own
/// owner or it does not.
///
/// The nullifier a bound subintent spends is not judged here: it sits
/// under its signer's prefix, no signature declared it, and it reaches
/// the routing view as a kernel effect rather than through any frame.
fn own_prefix_only(
    declaration: &Declaration,
    instance: Address,
    node_index: u32,
    method: &str,
) -> Result<(), RouteError> {
    for (position, access) in declaration.ordered.iter().enumerate() {
        let owner = access.effect.target.owner();
        if owner != instance {
            return Err(RouteError::ForeignDeclaration {
                node: node_index,
                method: method.to_owned(),
                clause: u32::try_from(position).unwrap_or(u32::MAX),
                owner,
            });
        }
    }
    Ok(())
}

/// The argument a handle binding lowers to: the capability at the
/// clause's position, or the absence the guest is told about.
///
/// A span of one is the ordinary case. Zero is a clause that was guarded
/// out, and the kind travels with the argument because nothing
/// downstream can recover it — an engine reads a handle's type off the
/// capability at its rep, and there is none. More than one is a
/// `for-each`, whose width is the instance's rather than the signature's,
/// so no fixed export parameter can name it.
///
/// A span is one or zero and never more: `check_abi` has already
/// refused a handle naming anything but a single access, and an access
/// contributes one entry when it is declared and none when it is not.
fn bind_handle(
    signature: &MethodSignature,
    declaration: &Declaration,
    clause: u32,
    offset: u32,
) -> Option<CallArg> {
    let index = usize::try_from(clause).ok()?;
    let (start, len) = declaration.clause_spans.get(index).copied()?;
    match len {
        1 => start.checked_add(offset).map(CallArg::Handle),
        0 => signature
            .effects
            .get(index)
            .and_then(materialized_kind)
            .map(CallArg::AbsentHandle),
        _ => None,
    }
}

fn lower_call(
    node_index: u32,
    signature: &MethodSignature,
    lowering: &Lowering<'_>,
) -> Result<NodeCall, RouteError> {
    let Lowering {
        package,
        declaration,
        offset,
        node,
        inputs,
        hasher,
    } = *lowering;
    let instance = node.target;
    let method = node.method.as_str();
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
            AbiParam::Handle(clause) => bind_handle(signature, declaration, *clause, offset)
                .ok_or_else(|| unbindable(format!("clause {clause} binds no handle")))?,
            AbiParam::Guard(clause) => {
                let taken = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| declaration.clause_taken.get(index))
                    .copied()
                    .ok_or_else(|| {
                        unbindable(format!("no effect clause {clause} in the signature"))
                    })?;
                CallArg::Bool(taken)
            }
            AbiParam::Bucket(declared) => {
                let input = usize::try_from(*declared)
                    .ok()
                    .and_then(|index| node.inputs.get(index))
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
            AbiParam::Issuer => CallArg::Issuer,
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
        edges: edge_bounds(&node.inputs),
        outputs: output_kinds(signature, lowering, node_index, method)?,
        issues: signature
            .issues
            .as_deref()
            .map(|mark| issued_resource(lowering.hasher, instance, mark).address()),
        evidence: node.evidence.clone(),
        authority: node.authority.clone(),
    })
}

/// The declared cell shape of each edge a node produces, from the same
/// output projections admission evaluated — the two agree by
/// construction, both evaluating at the manifest's root.
fn output_kinds(
    signature: &MethodSignature,
    lowering: &Lowering<'_>,
    node_index: u32,
    method: &str,
) -> Result<Vec<EdgeKind>, RouteError> {
    let eval_context = |source| RouteError::Eval {
        node: node_index,
        method: method.to_owned(),
        source,
    };
    let mut outputs = Vec::with_capacity(signature.outputs.len());
    for expr in &signature.outputs {
        let value = evaluate_expr(expr, lowering.inputs, lowering.hasher).map_err(eval_context)?;
        outputs.push(match value {
            Value::Address(_) => EdgeKind::Fungible,
            Value::Bucket { content, .. } => EdgeKind::of(&content),
            other => {
                return Err(eval_context(EvalError::TypeMismatch {
                    expected: "resource or bucket",
                    found: other.kind(),
                }));
            }
        });
    }
    Ok(outputs)
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
                content,
                bounds,
                ..
            } => Some(EdgeBound {
                source: *source,
                output: *output,
                kind: EdgeKind::of(content),
                param: u32::try_from(position).unwrap_or(u32::MAX),
                bounds: *bounds,
            }),
            NodeInput::Literal(_) => None,
        })
        .collect()
}

/// A derived value's guest form. Amounts and addresses cross as their
/// canonical fixed-width bytes, and an id set crosses as the same
/// count-prefixed cell an edge carries — one framing wherever ids move.
/// The remaining compound kinds have no ABI shape and refuse rather than
/// picking an encoding the two runtimes would have to agree on
/// separately.
fn guest_arg(value: &Value) -> Option<CallArg> {
    match value {
        Value::U64(scalar) => Some(CallArg::U64(*scalar)),
        Value::U128(amount) => Some(CallArg::Bytes(amount.to_le_bytes().to_vec())),
        Value::Address(address) => Some(CallArg::Address(*address)),
        Value::Bytes(bytes) => Some(CallArg::Bytes(bytes.clone())),
        Value::List(elements) => {
            if elements.len() > MAX_IDS_PER_EDGE {
                return None;
            }
            let ids = elements
                .iter()
                .map(|element| match element {
                    Value::U64(id) => Some(*id),
                    _ => None,
                })
                .collect::<Option<Vec<u64>>>()?;
            Some(CallArg::Ids(ids))
        }
        // A judgment has no guest representation and no export takes
        // one: a selection hands over the value it chose, and a body
        // needing the comparison rebuilds it from operands that do
        // cross. A derived parameter evaluating to a judgment is refused
        // here like every other unrepresentable kind.
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) | Value::Bool(_) => None,
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
    declaration: Declaration,
    // Effects logged so far across every frame: the offset the next
    // frame's clause spans are relative to, and therefore the base of
    // every handle position that frame's binding resolves to.
    table_len: u32,
}

impl Fold<'_> {
    /// The record serving `instance`, whose class the fold has to check
    /// itself.
    ///
    /// An address that answers no calls is an address no record serves,
    /// which is the refusal it already had.
    fn record_of(
        instances: &InstanceRegistry,
        instance: Address,
    ) -> Result<&InstanceMeta, RouteError> {
        let target =
            CallTarget::try_from(instance).map_err(|_| ResolveError::UnknownInstance(instance))?;
        instances
            .get(target)
            .ok_or(ResolveError::UnknownInstance(instance))
            .map_err(RouteError::from)
    }

    fn frame(&mut self, node_index: u32, node: &Node, args: &[Value]) -> Result<(), RouteError> {
        let instance = node.target;
        let method = node.method.as_str();
        let meta = Self::record_of(self.instances, instance)?;
        let package = self
            .cache
            .get(meta.package)
            .ok_or(ResolveError::UnknownPackage(meta.package))?;
        let signature = package
            .methods
            .get(method)
            .ok_or_else(|| ResolveError::UnknownMethod {
                package: meta.package,
                method: method.to_owned(),
            })?;
        let inputs = EvalInputs {
            self_addr: instance,
            args,
            config: &meta.config,
            node_index,
            // A node evaluates one frame, which is the zeroth under it.
            frame: 0,
            identity: self.identity,
        };
        let eval_context = |source| RouteError::Eval {
            node: node_index,
            method: method.to_owned(),
            source,
        };
        let declaration =
            evaluate_declaration(&signature.effects, &inputs, self.hasher).map_err(eval_context)?;
        own_prefix_only(&declaration, instance, node_index, method)?;
        // The frame's handles occupy the run of the table starting here,
        // so the offset has to be taken before the frame is logged.
        let offset = self.table_len;
        let lowering = Lowering {
            package: meta.package,
            declaration: &declaration,
            offset,
            node,
            inputs: &inputs,
            hasher: self.hasher,
        };
        self.calls
            .push(lower_call(node_index, signature, &lowering)?);
        self.table_len = offset
            .checked_add(u32::try_from(declaration.ordered.len()).unwrap_or(u32::MAX))
            .ok_or(RouteError::TableOverflow)?;
        // The union is folded access by access, so reserve amounts two
        // clauses declared on one target sum here exactly as the set
        // semantics say — and an overflow is this fold's refusal.
        for access in &declaration.ordered {
            self.declaration
                .set
                .insert(access.effect)
                .map_err(RouteError::from)?;
            self.declaration.ordered.push(*access);
        }
        self.frames_log.push(FrameDeclaration {
            node: node_index,
            ordered: declaration.ordered,
        });
        for effect in declaration.set.iter() {
            let shard = self.shards.shard_of(effect.target.owner());
            self.per_shard
                .entry(shard)
                .or_default()
                .insert(effect)
                .map_err(RouteError::from)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use hyperscale_vm_types::{
        Address, AddressClass, CellKind, Effect, EffectConflict, EffectSet, EffectTarget, Mode,
        Presence,
    };

    use super::{
        AbiParam, Admitted, CallArg, EdgeBound, EdgeKind, MAX_MANIFEST_NODES, PrefixShardResolver,
        RouteError, ShardResolver, route,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::hash::{Hash32, TestHasher};
    use crate::instance::{InstanceMeta, InstanceRegistry, ResolveError};
    use crate::manifest::{Bounds, Manifest, ManifestHash, Node, NodeInput};
    use crate::metadata::{MetadataCache, PackageMetadata};
    use crate::publish::AbiError;
    use crate::signature::{MethodSignature, ParamType, Totality};
    use crate::test_worlds::{
        addr, instance_of, meta_of, method, payer_payee_world, pkg, resolver, self_point,
    };
    use crate::types::{EdgeContent, MAX_IDS_PER_EDGE, ShardId, SlotId, Value, child_key};

    fn identity() -> ManifestHash {
        ManifestHash(Hash32([0x1D; 32]))
    }

    /// Routing's own defences have to hold for manifests admission would
    /// never produce — a forward edge, a metadata cycle — so these tests
    /// build the admitted form directly rather than through `admit`.
    fn admitted(manifest: &Manifest) -> Admitted {
        Admitted::new(manifest.clone(), identity())
    }

    fn point(owner: impl Into<Address>, slot: SlotId) -> EffectTarget {
        EffectTarget::Point(child_key(&TestHasher, owner, slot, &[]))
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

        // Node order: one frame each, which is the order
        // `KernelSession::materialize` builds its capability table in, so
        // it is the order a generated guest's handle parameters are in.
        assert_eq!(
            routing
                .frames
                .iter()
                .map(|frame| frame.node)
                .collect::<Vec<_>>(),
            vec![0, 1],
        );

        // The transaction-wide declaration reaches every effect routing
        // placed on a shard and folds back to exactly that union — the
        // property a consumer building a kernel batch depends on, and the
        // one `execute_batch` rechecks before running anything.
        let declaration = routing.declaration().clone();
        let mut union = EffectSet::new();
        for set in routing.per_shard.values() {
            for effect in set.iter() {
                union.insert(effect).unwrap();
            }
        }
        assert_eq!(declaration.set, union);
        assert_eq!(
            declaration
                .ordered
                .iter()
                .map(|access| access.effect)
                .collect::<Vec<_>>(),
            vec![
                Effect {
                    target: point(instance_of("payer"), SlotId(1)),
                    mode: Mode::Delta,
                },
                Effect {
                    target: point(instance_of("payee"), SlotId(2)),
                    mode: Mode::Delta,
                },
            ],
            "each node's clauses in node order"
        );
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
                    content: EdgeContent::Fungible,
                    bounds: Bounds::default(),
                }],
                evidence: Vec::new(),
                authority: None,
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
                evidence: Vec::new(),
                authority: None,
            }],
        };
        let empty = route(
            &admitted(&manifest),
            &MetadataCache::new(),
            &InstanceRegistry::new(),
            &TestHasher,
            &resolver(),
        );
        assert_eq!(
            empty,
            Err(RouteError::Resolve(ResolveError::UnknownInstance(
                a_1_4.into()
            )))
        );

        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, ghost_meta);
        let missing_pkg = route(
            &admitted(&manifest),
            &MetadataCache::new(),
            &instances,
            &TestHasher,
            &resolver(),
        );
        assert_eq!(
            missing_pkg,
            Err(RouteError::Resolve(ResolveError::UnknownPackage(pkg(
                "ghost"
            ))))
        );

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
            Err(RouteError::Resolve(ResolveError::UnknownMethod {
                package: pkg("ghost"),
                method: "m".into(),
            }))
        );
    }

    #[test]
    fn a_locked_read_declares_its_target() {
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert(
            "peek".into(),
            method(vec![
                self_point(SlotId(1), ModeExpr::Locked),
                self_point(SlotId(2), ModeExpr::Locked),
            ]),
        );
        cache.publish(pkg("oracle"), meta);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("oracle"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("oracle").into(),
                method: "peek".into(),
                inputs: vec![],
                evidence: Vec::new(),
                authority: None,
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
        for slot in [SlotId(1), SlotId(2)] {
            assert!(declared.contains(&Effect {
                target: point(instance_of("oracle"), slot),
                mode: Mode::Locked,
            }));
        }
    }

    #[test]
    fn a_manifest_at_the_node_cap_routes_within_the_budget() {
        // Every node costs one evaluation, so a call-free manifest at the
        // node cap must route: the budget is sized from the cap, and a
        // manifest one node past it is rejected for its size, never for
        // arithmetic.
        let mut cache = MetadataCache::new();
        let mut meta = PackageMetadata::default();
        meta.methods.insert("m".into(), method(vec![]));
        cache.publish(pkg("wide"), meta);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("wide"));
        let nodes = |count: usize| Manifest {
            nodes: (0..count)
                .map(|_| Node {
                    target: instance_of("wide").into(),
                    method: "m".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
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
            method(vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot: SlotId(1),
                    material: vec![],
                }),
                mode: ModeExpr::Reserve(Expr::Arg(0)),
                denomination: None,
            }]),
        );
        cache.publish(pkg("vault"), meta);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("vault"));
        let node = || Node {
            target: instance_of("vault").into(),
            method: "take".into(),
            inputs: vec![NodeInput::Literal(Value::U128(u128::MAX))],
            evidence: Vec::new(),
            authority: None,
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
            Err(RouteError::Conflict(EffectConflict::ReserveOverflow))
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
                totality: Totality::Fallible,
                abi,
                effects: vec![
                    Clause::ForEach {
                        guard: None,
                        list: Expr::Config(0),
                        body: vec![Clause::Effect {
                            guard: None,
                            target: TargetExpr::Point(Expr::ChildKey {
                                owner: Box::new(Expr::SelfAddr),
                                slot: SlotId(9),
                                material: vec![Expr::Binding(0)],
                            }),
                            mode: ModeExpr::Delta,
                            denomination: None,
                        }],
                    },
                    self_point(
                        SlotId(1),
                        ModeExpr::Write {
                            requires: Presence::Either,
                        },
                    ),
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
                evidence: Vec::new(),
                authority: None,
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
            let declaration = routing.declaration().clone();
            assert_eq!(u64::from(rep), width);
            assert_eq!(
                declaration.ordered[usize::try_from(rep).unwrap()]
                    .effect
                    .mode,
                Mode::Write {
                    requires: Presence::Either
                },
                "the bound clause's own effect, whatever the spread's width"
            );
        }
    }

    /// A world whose one method guards its point clause on whether the
    /// instance's first configuration slot equals its second, with the
    /// clause's own verdict bound beside the handle it backs.
    fn guarded_world(
        left: Value,
        right: Value,
        abi: Vec<AbiParam>,
    ) -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                abi,
                effects: vec![Clause::Effect {
                    guard: Some(Box::new(Expr::Eq(
                        Box::new(Expr::Config(0)),
                        Box::new(Expr::Config(1)),
                    ))),
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        slot: SlotId(1),
                        material: vec![],
                    }),
                    mode: ModeExpr::Write {
                        requires: Presence::Either,
                    },
                    denomination: None,
                }],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("guarded"), package);
        let mut instances = InstanceRegistry::new();
        let target = instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("guarded"),
                config: vec![left, right],
                salt: Hash32([21; 32]),
            },
        );
        (cache, instances, one_node(target))
    }

    #[test]
    fn a_guarded_out_clause_declares_nothing_and_locks_nothing() {
        // The precision half: a method that writes one of two cells
        // declares, locks and routes to exactly the one it will write.
        let (cache, instances, manifest) = guarded_world(Value::U64(1), Value::U64(2), Vec::new());
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        assert_eq!(
            routing.declaration().clone().set.len(),
            0,
            "a guarded-out clause is out of the declared set"
        );
        assert_eq!(
            routing.shards().count(),
            0,
            "and out of the routed shard set, so its owner is no participant"
        );

        // The same signature over a configuration its guard holds for.
        let (cache, instances, manifest) = guarded_world(Value::U64(1), Value::U64(1), Vec::new());
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        assert_eq!(routing.declaration().clone().set.len(), 1);
    }

    #[test]
    fn a_guarded_out_handle_is_absent_rather_than_unbindable() {
        // An export's parameter list is a function of its signature and
        // cannot lose a parameter to a branch, so the guest is handed a
        // handle that answers nothing — carrying the type routing is the
        // last thing to know, beside the verdict that says so.
        let abi = vec![AbiParam::Handle(0), AbiParam::Guard(0)];
        let (cache, instances, manifest) = guarded_world(Value::U64(1), Value::U64(2), abi.clone());
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        assert_eq!(
            routing.calls[0].args,
            vec![CallArg::AbsentHandle(CellKind::Write), CallArg::Bool(false)]
        );

        let (cache, instances, manifest) = guarded_world(Value::U64(1), Value::U64(1), abi);
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        assert!(matches!(routing.calls[0].args[0], CallArg::Handle(_)));
        assert_eq!(routing.calls[0].args[1], CallArg::Bool(true));
    }

    #[test]
    fn a_guard_inside_a_loop_body_declares_per_element() {
        // Clauses land in whatever scope encloses them, so a guard
        // written inside a `for-each` is judged once per element against
        // that element's own binding — and the loop's own verdict is the
        // top-level one, which is the only one an ABI binding can name.
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::ForEach {
                    guard: None,
                    list: Expr::Config(0),
                    body: vec![Clause::Effect {
                        guard: Some(Box::new(Expr::Eq(
                            Box::new(Expr::Binding(0)),
                            Box::new(Expr::Literal(Value::U64(2))),
                        ))),
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: SlotId(9),
                            material: vec![Expr::Binding(0)],
                        }),
                        mode: ModeExpr::Delta,
                        denomination: None,
                    }],
                }],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("looped"), package);
        let mut instances = InstanceRegistry::new();
        let target = instances.create(
            &TestHasher,
            InstanceMeta {
                package: pkg("looped"),
                config: vec![Value::List(vec![
                    Value::U64(1),
                    Value::U64(2),
                    Value::U64(3),
                ])],
                salt: Hash32([22; 32]),
            },
        );
        let manifest = one_node(target);
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect("routes");
        let declaration = routing.declaration().clone();
        assert_eq!(
            declaration.set.len(),
            1,
            "one of three elements satisfies the guard"
        );
    }

    #[test]
    fn a_guard_binding_on_an_unguarded_clause_is_refused() {
        // Its verdict is the constant true, which no export needs told.
        let (cache, instances, manifest) =
            spreading_world(vec![Value::U64(1)], vec![AbiParam::Guard(1)]);
        let error = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect_err("an unguarded clause has no verdict to bind");
        assert!(
            matches!(
                error,
                RouteError::MalformedAbi {
                    source: AbiError::UnguardedClause { clause: 1, .. },
                    ..
                }
            ),
            "unexpected refusal: {error:?}"
        );
    }

    #[test]
    fn a_handle_on_a_spreading_clause_is_refused() {
        // A `for-each` expands over the target's creation-fixed
        // configuration, so a handle on one asks for a capability whose
        // count is the instance's rather than the signature's. Judged on
        // the signature, before any evaluation reaches the spread: the
        // clause is not a single access whatever the configuration says.
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
                RouteError::MalformedAbi {
                    source: AbiError::NotAnAccess { clause: 0, .. },
                    ..
                }
            ),
            "unexpected refusal: {error:?}"
        );
    }

    #[test]
    fn a_derived_judgment_has_no_guest_representation() {
        // A predicate is evaluated once, by routing, and the guest is told
        // the answer through a clause's verdict — never by being handed
        // the judgment as an argument, which would leave two copies of one
        // condition agreeing by convention.
        let spread = vec![Value::U64(1)];
        let judgment = AbiParam::Derived(Expr::Eq(
            Box::new(Expr::Config(0)),
            Box::new(Expr::Config(0)),
        ));
        let (cache, instances, manifest) = spreading_world(spread, vec![judgment]);
        let error = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .expect_err("a boolean cannot cross the ABI");
        assert!(
            matches!(
                &error,
                RouteError::UnbindableAbiParam { param: 0, reason, .. }
                    if reason == "a bool has no guest representation"
            ),
            "unexpected refusal: {error:?}"
        );
    }

    #[test]
    fn an_id_list_crosses_the_abi_as_the_ids_it_is() {
        use super::guest_arg;

        assert_eq!(
            guest_arg(&Value::List(vec![Value::U64(3), Value::U64(9)])),
            Some(CallArg::Ids(vec![3, 9])),
        );
        // A list of anything else has no guest representation, and
        // neither has a judgment.
        assert_eq!(guest_arg(&Value::List(vec![Value::U128(3)])), None);
        assert_eq!(guest_arg(&Value::Bool(true)), None);
        let over_cap: Vec<Value> = (0..=u64::try_from(MAX_IDS_PER_EDGE).unwrap())
            .map(Value::U64)
            .collect();
        assert_eq!(guest_arg(&Value::List(over_cap)), None);
    }

    #[test]
    fn a_bucket_projection_types_its_edge_and_cell_shape() {
        // A producer whose output projection is a non-fungible bucket:
        // the lowered call frames its cell as an id list, and the
        // consumer's bound is judged over the same shape.
        let ids = vec![3, 9];
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "take".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::Literal(Value::Bucket {
                    resource: addr(0xE1),
                    content: EdgeContent::NonFungible { ids: ids.clone() },
                })],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("nf"), package);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("nf"));
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("nf").into(),
                    method: "make".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("nf").into(),
                    method: "take".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: addr(0xE1),
                        content: EdgeContent::NonFungible { ids },
                        bounds: Bounds::default(),
                    }],
                    evidence: Vec::new(),
                    authority: None,
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
        assert_eq!(routing.calls[0].outputs, vec![EdgeKind::NonFungible]);
        assert_eq!(routing.calls[1].edges[0].kind, EdgeKind::NonFungible);
    }

    #[test]
    fn a_bucket_binding_names_the_edge_its_parameter_carries() {
        let mut package = PackageMetadata::default();
        package.methods.insert(
            "take".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
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
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("edges").into(),
                    method: "take".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 3,
                        resource: addr(0xE1),
                        content: EdgeContent::Fungible,
                        bounds: Bounds {
                            min: Some(7),
                            max: None,
                        },
                    }],
                    evidence: Vec::new(),
                    authority: None,
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
                kind: EdgeKind::Fungible,
                param: 0,
                bounds: Bounds {
                    min: Some(7),
                    max: None,
                },
            }],
            "the consumed edge carries its signed bound to the walk"
        );
    }
    /// A world whose `forward` consumes a bucket without reading its
    /// amount, plus a producer to feed it.
    fn forwarding_world() -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut router = PackageMetadata::default();
        router.methods.insert(
            "forward".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                // Nothing in the ABI carries the bucket: the method
                // consumes the edge without reading what crossed.
                abi: vec![AbiParam::Handle(0)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        router.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::Literal(Value::Address(addr(0xE1)))],
                ..MethodSignature::default()
            },
        );
        let mut cache = MetadataCache::new();
        cache.publish(pkg("router"), router);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("router"));
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("router").into(),
                    method: "make".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("router").into(),
                    method: "forward".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: addr(0xE1),
                        content: EdgeContent::Fungible,
                        bounds: Bounds {
                            min: Some(42),
                            max: None,
                        },
                    }],
                    evidence: Vec::new(),
                    authority: None,
                },
            ],
        };
        (cache, instances, manifest)
    }

    #[test]
    fn a_forwarded_bucket_still_carries_its_edge_bound() {
        // The bound belongs to the edge, not to the argument list. A
        // method that consumes its funds without reading them carries no
        // bucket in its own ABI — and the signer's bound is owed a check
        // all the same, at the node where the edge resolves.
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
            "the consuming method's own ABI carries no bucket"
        );
        assert_eq!(
            call.edges,
            vec![EdgeBound {
                source: 0,
                output: 0,
                kind: EdgeKind::Fungible,
                param: 0,
                bounds: Bounds {
                    min: Some(42),
                    max: None,
                },
            }]
        );
    }

    /// A declaration bounds what execution may touch; nothing about that
    /// bounds what a declaration may claim, unless this does.
    #[test]
    fn a_frame_cannot_declare_against_another_prefix() {
        let victim = addr(0x99);
        let foreign = |owner: Expr| {
            let mut package = PackageMetadata::default();
            package.methods.insert(
                "reach".into(),
                MethodSignature {
                    totality: Totality::Fallible,
                    params: vec![ParamType::Address],
                    effects: vec![Clause::Effect {
                        guard: None,
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(owner),
                            slot: SlotId(1),
                            material: vec![],
                        }),
                        mode: ModeExpr::Delta,
                        denomination: None,
                    }],
                    ..MethodSignature::default()
                },
            );
            let mut cache = MetadataCache::new();
            cache.publish(pkg("reacher"), package);
            let mut instances = InstanceRegistry::new();
            instances.create(&TestHasher, meta_of("reacher"));
            let manifest = Manifest {
                nodes: vec![Node {
                    target: instance_of("reacher").into(),
                    method: "reach".into(),
                    inputs: vec![NodeInput::Literal(Value::Address(victim))],
                    evidence: Vec::new(),
                    authority: None,
                }],
            };
            route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver(),
            )
        };

        // Every way a frame can name somebody else: what its caller
        // passed, and what it holds as a literal.
        for owner in [Expr::Arg(0), Expr::Literal(Value::Address(victim))] {
            let error = foreign(owner).expect_err("a foreign prefix is not a frame's to declare");
            assert!(
                matches!(
                    error,
                    RouteError::ForeignDeclaration { node: 0, ref owner, .. } if *owner == victim
                ),
                "unexpected refusal: {error:?}"
            );
        }

        // Its own prefix is the admitted case, so what bites is whose
        // cells the clause names and not the shape of the declaration.
        assert!(foreign(Expr::SelfAddr).is_ok());
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
                totality: Totality::Fallible,
                params: vec![ParamType::Bucket],
                abi: vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
                effects: vec![self_point(SlotId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        package.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
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
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("bad").into(),
                    method: "m".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: addr(0xE1),
                        content: EdgeContent::Fungible,
                        bounds: Bounds::default(),
                    }],
                    evidence: Vec::new(),
                    authority: None,
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

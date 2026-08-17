//! The routing fold: from a manifest to per-shard effect sets and proof
//! obligations.
//!
//! Routing is a pure function of the manifest and content-addressed
//! metadata, evaluable by any node — validator, RPC, wallet, relay — with
//! no state. Shard resolution comes through the [`ShardResolver`] seam; the
//! beacon fold's shard trie binds there at integration.

use std::collections::{BTreeMap, BTreeSet};

use crate::admission::Admitted;
use crate::dsl::{
    Clause, Declaration, EvalError, EvalInputs, ModeExpr, evaluate_declaration, evaluate_expr,
};
use crate::hash::Hasher;
use crate::invoke::{CallArg, EdgeBound, EdgeKind, NodeCall, ids_cell};
use crate::manifest::{Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{
    AbiError, AbiParam, InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature,
    PackageHash, Totality, check_abi,
};
use crate::types::{
    Address, CallTarget, EdgeContent, Effect, EffectSet, MAX_IDS_PER_EDGE, ShardId, Value,
    resource_address,
};

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

/// A method on an instance: what a frame evaluated.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MethodRef {
    /// The instance the method runs on.
    pub instance: Address,
    /// The method name.
    pub method: String,
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
    /// How many times the longest dependency chain changes shard. Zero
    /// exactly when the whole structure sits on one shard, which is what
    /// says there is nothing to decompose.
    pub alternation_depth: u32,
    /// How many of those crossings something waits on — the settlement
    /// latency staging would add, and what [`MAX_STAGED_DEPTH`] budgets.
    /// Lower than [`Self::alternation_depth`] by the crossings into
    /// outbound legs, which the core commits without hearing back from.
    pub staged_depth: u32,
    /// Where each manifest node sits in the star, in node order.
    pub roles: Vec<Role>,
    /// How this transaction's participants divide its execution.
    pub strategy: Strategy,
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
    /// The method this frame evaluated.
    pub method: MethodRef,
    /// This frame's effects in clause order — one entry per clause the
    /// evaluation reached, `for-each` bodies expanded in place.
    ///
    /// A frame's handles occupy a contiguous run of the capability table,
    /// so a generated guest's positional parameters are this slice.
    pub ordered: Vec<Effect>,
    /// What each of those entries holds, where it holds value, aligned
    /// index for index with `ordered`.
    pub denominations: Vec<Option<Address>>,
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
        let mut denominations = Vec::new();
        // The kernel's own effects are the fee reservation and its
        // settlement, which move value the payer's account already
        // denominates; nothing about them is a package's declaration, so
        // they carry no resource of their own.
        let frame_effects = self.frames.iter().flat_map(|frame| {
            frame
                .ordered
                .iter()
                .zip(frame.denominations.iter().copied())
        });
        let kernel_effects = self.kernel_effects.iter().map(|effect| (effect, None));
        for (effect, held) in frame_effects.chain(kernel_effects) {
            set.insert(*effect)
                .map_err(|_| RouteError::ReserveOverflow)?;
            ordered.push(*effect);
            denominations.push(held);
        }
        Ok(Declaration {
            set,
            ordered,
            denominations,
            // A clause index is a method's; this is every frame's clauses
            // concatenated, so there is no clause to index.
            clause_spans: Vec::new(),
        })
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
    /// The capability table outgrew the index a handle is named by.
    #[error("the capability table exceeds the addressable handle space")]
    TableOverflow,
    /// Folding reserve amounts across shards overflowed.
    #[error("declared reserve amounts overflow")]
    ReserveOverflow,
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

    let roles = classify_roles(manifest, cache, instances);
    let (alternation_depth, staged_depth) = chain_depths(manifest, shards, &roles);
    let strategy = classify_strategy(manifest, &roles, alternation_depth, staged_depth);

    Ok(Routing {
        per_shard: fold.per_shard,
        frames: fold.frames_log,
        calls: fold.calls,
        kernel_effects: Vec::new(),
        alternation_depth,
        staged_depth,
        roles,
        strategy,
    })
}

/// The deepest route staging is admissible for.
///
/// A budget rather than a capability. Staging never wins on latency —
/// every stage past the first adds an inclusion-to-certification gap and
/// a composition wait, where replication fetches every counterpart's
/// committed reads in one round whatever the shape — so what it buys is
/// the deleted replicated executions and the hot shard's decongestion,
/// and what it costs is settlement latency. Measured against a gap of one
/// block, a staged route runs about 1.6 times the replicated equivalent's
/// settlement at depth two and about 2.1 at depth three; the budget is
/// twice, so two is admitted and three is refused.
pub const MAX_STAGED_DEPTH: u32 = 2;

/// How a transaction's participants divide its execution.
///
/// Both are always correct and the choice is a cost decision, which is
/// why it can be derived rather than declared: replication is never
/// unavailable, and it is the fallback for every shape where staging
/// costs more than it saves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strategy {
    /// Every participant executes the whole manifest and computes the
    /// same result from the same committed inputs.
    #[default]
    Replicated,
    /// Each participant executes only the legs whose cells it owns and
    /// takes every other leg's result as an attested value.
    LegLocal,
}

/// Where a manifest node sits in the star a decomposable transaction
/// takes the shape of.
///
/// The topology is one core with legs on either side of it, and the two
/// leg kinds differ by which side: an inbound leg runs before the core and
/// hands it attested value, an outbound leg runs after and cannot refuse
/// what it is handed. Everything else is core, which is what the
/// transaction's atomicity has to cover.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Runs before the core, on arguments the core did not produce, and
    /// commits locally: its refusal is the escrow release path rather
    /// than the core's problem.
    Inbound,
    /// Neither leg. The default in both senses — what a node is when
    /// nothing lets it decompose, and what the star is organised around.
    #[default]
    Core,
    /// Runs after the core and offers it no veto: nothing it does can
    /// come back as a refusal the core would have to answer.
    Outbound,
}

/// Classify every manifest node into the star.
///
/// The two leg tests are structural, and both are read off the manifest's
/// own edges rather than off what a method is named:
///
/// - An **inbound** leg takes no value edge, so nothing the core produces
///   can be among its arguments — L3's core-independence, falling out of
///   the shape instead of needing its own analysis — and it is
///   reservation-shaped: one reserve declared, one value out.
/// - An **outbound** leg's output feeds nothing, and its method carries
///   the verified [`Totality::Total`] mark, so the core cannot be made to
///   wait on a verdict it might refuse.
///
/// Every other node is core, and so is every node either test is unsure
/// about. That direction is the safe one: a node wrongly called core
/// costs the transaction a decomposition it could have had, while a leg
/// wrongly peeled off the core costs the atomicity the core exists for.
fn classify_roles(
    manifest: &Manifest,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
) -> Vec<Role> {
    let consumed: BTreeSet<u32> = manifest
        .nodes
        .iter()
        .flat_map(|node| &node.inputs)
        .filter_map(|input| match input {
            NodeInput::Edge { source, .. } => Some(*source),
            NodeInput::Literal(_) => None,
        })
        .collect();

    manifest
        .nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let signature = CallTarget::try_from(node.target)
                .ok()
                .and_then(|target| instances.get(target))
                .and_then(|meta| cache.get(meta.package))
                .and_then(|pkg| pkg.methods.get(&node.method));
            let Some(signature) = signature else {
                return Role::Core;
            };
            let takes_no_edge = node
                .inputs
                .iter()
                .all(|input| matches!(input, NodeInput::Literal(_)));
            let index = u32::try_from(index).unwrap_or(u32::MAX);

            if takes_no_edge && is_reservation_shaped(signature) {
                Role::Inbound
            } else if !consumed.contains(&index) && signature.totality == Totality::Total {
                Role::Outbound
            } else {
                Role::Core
            }
        })
        .collect()
}

/// Whether a signature is the shape an inbound leg has to be: it declares
/// a conditional decrement, and it yields exactly one value out.
///
/// The reserve is what makes the leg's refusal local — the amount is
/// judged where the funds live, and a refusal there releases rather than
/// aborting the core — and the single output is what makes the value it
/// yields nameable as one escrow certificate.
fn is_reservation_shaped(signature: &MethodSignature) -> bool {
    fn declares_reserve(clauses: &[Clause]) -> bool {
        clauses.iter().any(|clause| match clause {
            Clause::Effect { mode, .. } => matches!(mode, ModeExpr::Reserve(_)),
            Clause::ForEach { body, .. } => declares_reserve(body),
        })
    }
    signature.outputs.len() == 1 && declares_reserve(&signature.effects)
}

/// Decide how this transaction's participants divide its execution.
///
/// Three things refuse staging, and each for its own reason:
///
/// - **Nothing crosses.** A transaction whose dependency structure sits
///   on one shard has one participant, so the two strategies name the
///   same execution and the honest verdict is the one that claims less.
/// - **It crosses too often.** Past [`MAX_STAGED_DEPTH`] the settlement
///   latency staging adds outruns the replicated work it deletes.
/// - **A leg moves a named instance.** The supply-delta attestation an
///   escrow certificate carries is linear over amounts and blind to
///   identity, so a fabricated non-fungible credit would arrive with a
///   delta its producer's history supports. Fungible legs are bounded by
///   that attestation; non-fungible ones are not, so they wait for one
///   that knows about ids. The test is over legs alone: a core's
///   participants reach agreement by unanimity rather than by attested
///   value, so nothing inside one is exposed to it.
fn classify_strategy(
    manifest: &Manifest,
    roles: &[Role],
    alternation_depth: u32,
    staged_depth: u32,
) -> Strategy {
    if alternation_depth == 0 || staged_depth > MAX_STAGED_DEPTH {
        return Strategy::Replicated;
    }
    let is_leg = |index: usize| matches!(roles.get(index), Some(Role::Inbound | Role::Outbound));
    for (index, node) in manifest.nodes.iter().enumerate() {
        for input in &node.inputs {
            let NodeInput::Edge {
                source, content, ..
            } = input
            else {
                continue;
            };
            if matches!(content, EdgeContent::NonFungible { .. })
                && (is_leg(index) || is_leg(*source as usize))
            {
                return Strategy::Replicated;
            }
        }
    }
    Strategy::LegLocal
}

/// How far the longest dependency chain reaches, counted two ways.
///
/// Returns `(crossings, stages)`. Both walk the same graph and differ
/// only in what a step costs, because the two questions they answer are
/// different: whether a transaction reaches beyond one shard at all, and
/// how much settlement latency staging it would add.
///
/// **Crossings** counts every shard change along the chain. It is the
/// structural fact — a chain returning to a shard it already visited has
/// crossed twice — and what says whether there is anything to decompose.
///
/// **Stages** counts only the crossings something waits on. A crossing
/// into an outbound leg costs nothing: the leg cannot refuse, so the core
/// commits without hearing back and no latency accrues on the far side of
/// it. This is the quantity [`MAX_STAGED_DEPTH`] budgets, and the two
/// diverge by exactly the outbound crossings — a single-venue swap
/// crosses twice to reach the venue and return, and stages once.
///
/// Two kinds of dependency contribute, and both are structural. A value
/// edge binds one manifest node's output to a later node's input. A call
/// edge runs a callee inside its caller, which crosses a boundary exactly
/// when the two sit on different shards. The union is acyclic — value
/// edges run from lower node indices to higher, and the call graph is a
/// DAG by construction — so the longest path settles rather than
/// searches.
fn chain_depths(manifest: &Manifest, shards: &dyn ShardResolver, roles: &[Role]) -> (u32, u32) {
    let shard_of = |node: u32| -> ShardId { shards.shard_of(manifest.nodes[node as usize].target) };

    // Successors, built once: a node's consumers.
    let mut successors: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (index, node) in manifest.nodes.iter().enumerate() {
        let consumer = u32::try_from(index).unwrap_or(u32::MAX);
        for input in &node.inputs {
            if let NodeInput::Edge { source, .. } = *input {
                successors.entry(source).or_default().insert(consumer);
            }
        }
    }

    // A crossing whose destination is an outbound leg costs no stage:
    // the leg cannot refuse, so nothing on the far side of it is waited
    // on and the chain ends there as far as latency is concerned. Every
    // other crossing is a stage, including one into a call the roles do
    // not describe, which is the conservative reading.
    let waited_on =
        |node: u32| -> bool { !matches!(roles.get(node as usize), Some(Role::Outbound)) };

    // Longest path, relaxed until it settles. Every node starts a chain
    // so each is seeded at zero; the manifest's producer-before-consumer
    // rule bounds the settling at one round per node.
    let mut crossings: BTreeMap<u32, u32> = BTreeMap::new();
    let mut stages: BTreeMap<u32, u32> = BTreeMap::new();
    for node in successors
        .keys()
        .copied()
        .chain(successors.values().flatten().copied())
    {
        crossings.entry(node).or_insert(0);
        stages.entry(node).or_insert(0);
    }
    let mut settled = false;
    let mut rounds = 0;
    while !settled && rounds <= crossings.len() {
        settled = true;
        rounds += 1;
        for (node, successor_set) in &successors {
            let (crossed_here, staged_here) = (
                crossings.get(node).copied().unwrap_or(0),
                stages.get(node).copied().unwrap_or(0),
            );
            let from = shard_of(*node);
            for successor in successor_set {
                let crossed = shard_of(*successor) != from;
                for (map, here, step) in [
                    (&mut crossings, crossed_here, u32::from(crossed)),
                    (
                        &mut stages,
                        staged_here,
                        u32::from(crossed && waited_on(*successor)),
                    ),
                ] {
                    let candidate = here.saturating_add(step);
                    let slot = map.entry(*successor).or_insert(0);
                    if candidate > *slot {
                        *slot = candidate;
                        settled = false;
                    }
                }
            }
        }
    }
    (
        crossings.values().copied().max().unwrap_or(0),
        stages.values().copied().max().unwrap_or(0),
    )
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
    for (position, effect) in declaration.ordered.iter().enumerate() {
        let owner = effect.target.owner();
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
        // The same derivation the declaration's own `SelfResource` runs,
        // over the same material: an empty mark separates nothing and
        // names the instance's primary issue.
        issues: signature.issues.as_ref().map(|mark| {
            let material = if mark.is_empty() {
                Vec::new()
            } else {
                vec![Value::Bytes(mark.clone()).canonical_bytes()]
            };
            resource_address(lowering.hasher, instance, &material).address()
        }),
        evidence: node.evidence.clone(),
        authority: node.authority,
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
            Some(CallArg::Bytes(ids_cell(&ids)))
        }
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) => None,
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
            CallTarget::try_from(instance).map_err(|_| RouteError::UnknownInstance(instance))?;
        instances
            .get(target)
            .ok_or(RouteError::UnknownInstance(instance))
    }

    fn frame(&mut self, node_index: u32, node: &Node, args: &[Value]) -> Result<(), RouteError> {
        let instance = node.target;
        let method = node.method.as_str();
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
        self.frames_log.push(FrameDeclaration {
            node: node_index,
            method: MethodRef {
                instance,
                method: method.to_owned(),
            },
            ordered: declaration.ordered,
            denominations: declaration.denominations,
        });
        for effect in declaration.set.iter() {
            let shard = self.shards.shard_of(effect.target.owner());
            self.per_shard
                .entry(shard)
                .or_default()
                .insert(effect)
                .map_err(|_| RouteError::ReserveOverflow)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        AbiParam, Admitted, CallArg, EdgeBound, EdgeKind, MAX_MANIFEST_NODES, MAX_STAGED_DEPTH,
        PrefixShardResolver, Role, RouteError, ShardResolver, Strategy, classify_strategy, route,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::hash::{Hash32, Hasher, TestHasher};
    use crate::manifest::{Bounds, Manifest, ManifestHash, Node, NodeInput};
    use crate::metadata::{
        InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature, PackageHash,
        PackageMetadata, ParamType, Totality,
    };
    use crate::types::{
        Address, AddressClass, ComponentAddr, EdgeContent, Effect, EffectSet, EffectTarget,
        MAX_IDS_PER_EDGE, Mode, RoleId, ShardId, Value, child_key,
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
            denomination: None,
        }
    }

    fn method(effects: Vec<Clause>) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects,
            ..MethodSignature::default()
        }
    }

    fn resolver() -> PrefixShardResolver {
        PrefixShardResolver { bits: 8 }
    }

    /// The star in its canonical shape: a reservation-shaped source, a
    /// venue in the middle whose output the source's value feeds, and a
    /// sink whose totality the caller chooses.
    ///
    /// Three nodes rather than two because the sink has to be a node the
    /// core does not consume from, which is exactly what makes it a leg.
    fn star_world(sink: Totality) -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut cache = MetadataCache::new();
        let mut vault_pkg = PackageMetadata::default();
        vault_pkg.methods.insert(
            "withdraw".into(),
            MethodSignature {
                outputs: vec![Expr::SelfAddr],
                effects: vec![self_point(RoleId(1), ModeExpr::Reserve(Expr::Arg(0)))],
                ..MethodSignature::default()
            },
        );
        let mut venue_pkg = PackageMetadata::default();
        venue_pkg.methods.insert(
            "swap".into(),
            MethodSignature {
                outputs: vec![Expr::SelfAddr],
                effects: vec![self_point(RoleId(2), ModeExpr::Write)],
                ..MethodSignature::default()
            },
        );
        let mut sink_pkg = PackageMetadata::default();
        sink_pkg.methods.insert(
            "deposit".into(),
            MethodSignature {
                totality: sink,
                effects: vec![self_point(RoleId(3), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        cache.publish(pkg("vault"), vault_pkg);
        cache.publish(pkg("venue"), venue_pkg);
        cache.publish(pkg("sink"), sink_pkg);
        let mut instances = InstanceRegistry::new();
        for name in ["vault", "venue", "sink"] {
            instances.create(&TestHasher, meta_of(name));
        }

        let edge = |source: u32, resource: ComponentAddr| NodeInput::Edge {
            source,
            output: 0,
            resource: resource.into(),
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
                    authority: None,
                },
                Node {
                    target: instance_of("venue").into(),
                    method: "swap".into(),
                    inputs: vec![edge(0, instance_of("vault"))],
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("sink").into(),
                    method: "deposit".into(),
                    inputs: vec![edge(1, instance_of("venue"))],
                    evidence: Vec::new(),
                    authority: None,
                },
            ],
        };
        (cache, instances, manifest)
    }

    /// A payer and a payee on different shards, joined by a value edge:
    /// two manifest nodes, one crossing between them.
    fn payer_payee_world() -> (MetadataCache, InstanceRegistry, Manifest) {
        let mut cache = MetadataCache::new();
        let mut sender_pkg = PackageMetadata::default();
        sender_pkg.methods.insert(
            "pay".into(),
            MethodSignature {
                totality: Totality::Fallible,
                params: vec![ParamType::Address, ParamType::U128],
                outputs: vec![Expr::Literal(Value::Address(addr(0xE1)))],
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
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
                    target: TargetExpr::Point(Expr::ChildKey {
                        owner: Box::new(Expr::SelfAddr),
                        role: RoleId(2),
                        material: vec![],
                    }),
                    mode: ModeExpr::Delta,
                    denomination: None,
                }],
                ..MethodSignature::default()
            },
        );
        cache.publish(pkg("payer"), sender_pkg);
        cache.publish(pkg("payee"), receiver_pkg);
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
                    authority: None,
                },
                Node {
                    target: instance_of("payee").into(),
                    method: "recv".into(),
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
        (cache, instances, manifest)
    }

    /// A call that stays on one shard crosses nothing, so a staged
    /// execution of it would pay for no boundary at all.
    #[test]
    fn a_single_shard_transaction_alternates_zero_times() {
        let mut cache = MetadataCache::new();
        let mut solo = PackageMetadata::default();
        solo.methods.insert(
            "act".into(),
            method(vec![self_point(RoleId(1), ModeExpr::Delta)]),
        );
        cache.publish(pkg("solo"), solo);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("solo"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("solo").into(),
                method: "act".into(),
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
        assert_eq!(routing.alternation_depth, 0);
    }

    /// A call reaching one instance on another shard crosses once. The
    /// depth counts the crossing rather than the shards, which is the
    /// distinction the whole quantity turns on — a chain returning to a
    /// shard it already visited has crossed twice, not once.
    #[test]
    fn a_call_to_another_shard_alternates_once() {
        let (cache, instances, manifest) = payer_payee_world();
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();

        assert_ne!(
            resolver().shard_of(instance_of("payer").into()),
            resolver().shard_of(instance_of("payee").into()),
            "the fixture has to straddle, or the depth below proves nothing",
        );
        assert_eq!(routing.alternation_depth, 1);
    }

    /// A value edge is a dependency like a call is: the consumer cannot
    /// run until the producer's output exists, so a consumer on another
    /// shard is a boundary even though neither node calls the other.
    #[test]
    fn a_value_edge_across_shards_alternates_once() {
        let mut cache = MetadataCache::new();
        let mut producing = PackageMetadata::default();
        producing.methods.insert(
            "make".into(),
            MethodSignature {
                totality: Totality::Fallible,
                outputs: vec![Expr::SelfAddr],
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
                ..MethodSignature::default()
            },
        );
        let mut consuming = PackageMetadata::default();
        consuming.methods.insert(
            "take".into(),
            method(vec![self_point(RoleId(2), ModeExpr::Delta)]),
        );
        cache.publish(pkg("producer"), producing);
        cache.publish(pkg("consumer"), consuming);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("producer"));
        instances.create(&TestHasher, meta_of("consumer"));
        assert_ne!(
            resolver().shard_of(instance_of("producer").into()),
            resolver().shard_of(instance_of("consumer").into()),
            "the fixture has to straddle, or the depth below proves nothing",
        );

        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("producer").into(),
                    method: "make".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("consumer").into(),
                    method: "take".into(),
                    inputs: vec![NodeInput::Edge {
                        source: 0,
                        output: 0,
                        resource: instance_of("producer").into(),
                        content: EdgeContent::Fungible,
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
        .unwrap();
        assert_eq!(routing.alternation_depth, 1);
    }

    /// The reservation-shaped source is the inbound leg: nothing the core
    /// produces reaches its arguments, so it can run first, and the
    /// reserve is what lets its refusal release rather than abort.
    #[test]
    fn a_reservation_shaped_source_is_an_inbound_leg() {
        let (cache, instances, manifest) = star_world(Totality::Fallible);
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert_eq!(routing.roles[0], Role::Inbound);
        assert_eq!(routing.roles[1], Role::Core, "the venue is the core");
    }

    /// A sink whose method carries the verified mark is the outbound leg.
    /// Without the mark the same node is core — the shape alone never
    /// earns it, because what the core needs is the guarantee that
    /// nothing comes back, and only the checker can give that.
    #[test]
    fn only_a_marked_sink_is_an_outbound_leg() {
        for (totality, expected) in [
            (Totality::Fallible, Role::Core),
            (Totality::Infallible, Role::Core),
            (Totality::Total, Role::Outbound),
        ] {
            let (cache, instances, manifest) = star_world(totality);
            let routing = route(
                &admitted(&manifest),
                &cache,
                &instances,
                &TestHasher,
                &resolver(),
            )
            .unwrap();
            assert_eq!(
                routing.roles[2], expected,
                "a {totality:?} sink should be {expected:?}",
            );
        }
    }

    /// Taking a value edge is what disqualifies an inbound leg, whatever
    /// its shape: an argument the core produced cannot be available
    /// before the core runs, which is the whole of L3's test.
    #[test]
    fn a_reservation_fed_by_the_core_joins_it() {
        let (cache, instances, _) = star_world(Totality::Fallible);
        // The venue first, and the same reservation-shaped method after
        // it — its amount now the venue's output rather than a literal.
        let manifest = Manifest {
            nodes: vec![
                Node {
                    target: instance_of("venue").into(),
                    method: "swap".into(),
                    inputs: vec![],
                    evidence: Vec::new(),
                    authority: None,
                },
                Node {
                    target: instance_of("vault").into(),
                    method: "withdraw".into(),
                    // The amount stays a literal so the reserve still
                    // evaluates — what disqualifies the leg is the edge
                    // beside it, not what the reserve reads.
                    inputs: vec![
                        NodeInput::Literal(Value::U128(5)),
                        NodeInput::Edge {
                            source: 0,
                            output: 0,
                            resource: instance_of("venue").into(),
                            content: EdgeContent::Fungible,
                            bounds: Bounds::default(),
                        },
                    ],
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
        .unwrap();
        assert_eq!(
            routing.roles[1],
            Role::Core,
            "a reserve fed by an edge is not core-independent",
        );
    }

    /// Nothing crossing means one participant, so the two strategies name
    /// the same execution and the verdict is the one claiming less.
    #[test]
    fn a_single_shard_transaction_does_not_decompose() {
        let mut cache = MetadataCache::new();
        let mut solo = PackageMetadata::default();
        solo.methods.insert(
            "act".into(),
            method(vec![self_point(RoleId(1), ModeExpr::Delta)]),
        );
        cache.publish(pkg("solo"), solo);
        let mut instances = InstanceRegistry::new();
        instances.create(&TestHasher, meta_of("solo"));
        let manifest = Manifest {
            nodes: vec![Node {
                target: instance_of("solo").into(),
                method: "act".into(),
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
        assert_eq!(routing.alternation_depth, 0);
        assert_eq!(routing.strategy, Strategy::Replicated);
    }

    /// A crossing inside the budget stages. The fixture's own depth is
    /// asserted beside the verdict, so a placement change that moved it
    /// past the budget would show up as the depth changing rather than as
    /// a verdict quietly meaning something else.
    #[test]
    fn a_crossing_within_the_budget_decomposes() {
        let (cache, instances, manifest) = payer_payee_world();
        let routing = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert!(routing.alternation_depth <= MAX_STAGED_DEPTH);
        assert_eq!(routing.strategy, Strategy::LegLocal);
    }

    /// The budget is a refusal, not a preference: past it the settlement
    /// latency staging adds outruns the replicated work it deletes, so
    /// the deeper route runs replicated however well shaped it is.
    #[test]
    fn a_route_past_the_budget_replicates() {
        let empty = Manifest { nodes: vec![] };
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH + 1, MAX_STAGED_DEPTH + 1),
            Strategy::Replicated,
        );
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH, MAX_STAGED_DEPTH),
            Strategy::LegLocal,
            "the budget's own depth is admitted, not refused",
        );
        // The budget reads stages, not crossings: a chain that crosses
        // past the budget but only stages within it still decomposes,
        // which is exactly the single-venue swap's shape.
        assert_eq!(
            classify_strategy(&empty, &[], MAX_STAGED_DEPTH + 4, MAX_STAGED_DEPTH),
            Strategy::LegLocal,
        );
    }

    /// A leg carrying named instances replicates: the supply delta an
    /// escrow certificate attests counts amounts and cannot see which id
    /// moved, so nothing bounds a fabricated one.
    #[test]
    fn a_leg_moving_named_instances_replicates() {
        let (cache, instances, manifest) = star_world(Totality::Total);
        let fungible = route(
            &admitted(&manifest),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert_eq!(fungible.roles[0], Role::Inbound);
        assert_eq!(fungible.strategy, Strategy::LegLocal);

        // The identical shape, with the inbound leg's value now named.
        let mut named = manifest;
        named.nodes[1].inputs = vec![NodeInput::Edge {
            source: 0,
            output: 0,
            resource: instance_of("vault").into(),
            content: EdgeContent::NonFungible { ids: vec![7] },
            bounds: Bounds::default(),
        }];
        let routing = route(
            &admitted(&named),
            &cache,
            &instances,
            &TestHasher,
            &resolver(),
        )
        .unwrap();
        assert_eq!(routing.strategy, Strategy::Replicated);
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
                .map(|frame| (frame.node, frame.method.method.clone()))
                .collect::<Vec<_>>(),
            vec![(0, "pay".to_owned()), (1, "recv".to_owned())],
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
            method(vec![
                self_point(RoleId(1), ModeExpr::Locked),
                self_point(RoleId(2), ModeExpr::Locked),
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
        for role in [RoleId(1), RoleId(2)] {
            assert!(declared.contains(&Effect {
                target: point(instance_of("oracle"), role),
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
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    role: RoleId(1),
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
                totality: Totality::Fallible,
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
                            denomination: None,
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
    fn an_id_list_crosses_the_abi_as_the_edge_cell_framing() {
        use super::guest_arg;
        use crate::invoke::ids_cell;

        assert_eq!(
            guest_arg(&Value::List(vec![Value::U64(3), Value::U64(9)])),
            Some(CallArg::Bytes(ids_cell(&[3, 9]))),
        );
        // A list of anything else has no guest representation.
        assert_eq!(guest_arg(&Value::List(vec![Value::U128(3)])), None);
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
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
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
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
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
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
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
                        target: TargetExpr::Point(Expr::ChildKey {
                            owner: Box::new(owner),
                            role: RoleId(1),
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
                effects: vec![self_point(RoleId(1), ModeExpr::Delta)],
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

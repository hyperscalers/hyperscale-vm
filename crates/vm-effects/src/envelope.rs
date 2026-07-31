//! The bound envelope tree: a root intent composed with separately
//! signed subintents over typed yield edges, and the nullifier
//! vocabulary that makes a committed subintent once-only.
//!
//! A subintent's signer signs an [`IntentDecl`] — a graph over declared
//! yield parameters, each a typed hole for a value edge the composition
//! supplies. The composer binds every hole to another intent's output
//! edge and signs the whole envelope; nothing about the tree is
//! renegotiated at admission. [`admit_tree`] flattens the tree into one
//! routing manifest: intents keep their author order, yield edges
//! interleave them deterministically, and a composition whose yields
//! admit no execution order is rejected — acyclicity is judged at yield
//! granularity.
//!
//! Committing a subintent writes a kernel nullifier substate at the
//! canonical address `signer_prefix | H(nullifier_role, subintent_hash)`
//! — computable, hence declarable, hence a creation conflict: two
//! compositions racing one subintent contend on the nullifier key and
//! exactly one commits. Cancellation is the signer spending the
//! nullifier under their own prefix.

use std::collections::BTreeSet;

use crate::dsl::{EvalInputs, evaluate_expr};
use crate::graph::{
    AdmissionError, Admitted, Constraint, EdgeRef, GraphArg, ManifestGraph, check_constraints,
    encode_constraints,
};
use crate::hash::{Hash32, Hasher};
use crate::manifest::{Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::{InstanceRegistry, MetadataCache, ParamType};
use crate::route::{MAX_MANIFEST_NODES, RouteError, Routing, ShardResolver, route};
use crate::types::{Address, Effect, EffectTarget, Mode, RoleId, SubstateKey, Value, child_key};

/// The bound on subintents one envelope may compose.
pub const MAX_SUBINTENTS: usize = 32;

/// The kernel-reserved role of subintent nullifier substates under a
/// signer's prefix. Stdlib roles count up from one; the top of the role
/// space is the kernel's.
pub const NULLIFIER_ROLE: RoleId = RoleId(0xFFFF);

/// A typed inbound yield edge an intent declares: the composition must
/// bind an edge carrying exactly this resource, under the declaring
/// intent's own constraints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YieldParam {
    /// The resource the yielded edge must carry.
    pub resource: Address,
    /// The declaring intent's constraints on the yielded edge — the same
    /// language that constrains ordinary graph edges.
    pub constraints: Vec<Constraint>,
}

/// One intent's declared form: a graph over typed yield parameters.
///
/// The root intent and every subintent share this shape; a subintent's
/// signer signs exactly this, so [`IntentDecl::hash`] is the subintent's
/// identity whatever composition later carries it. Outputs the graph
/// does not consume internally are the intent's yields — the composition
/// must consume every one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IntentDecl {
    /// The intent's invocation graph; arguments may reference the
    /// declared parameters via [`GraphArg::Param`].
    pub graph: ManifestGraph,
    /// The declared yield parameters, each consumed by exactly one node
    /// argument.
    pub params: Vec<YieldParam>,
}

/// A signed subintent's identity: the hash of its declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SubintentHash(pub Hash32);

const DOMAIN_SUBINTENT: &[u8] = b"hyperscale-vm/subintent";
const DOMAIN_ENVELOPE_TREE: &[u8] = b"hyperscale-vm/envelope-tree";

impl IntentDecl {
    /// The declaration's identity through the hasher seam: the graph
    /// hash plus every declared parameter with its constraints.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> SubintentHash {
        let graph = self.graph.hash(hasher);
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(1 + self.params.len());
        parts.push(graph.0.0.to_vec());
        for param in &self.params {
            let mut bytes = param.resource.0.to_vec();
            encode_constraints(&mut bytes, &param.constraints);
            parts.push(bytes);
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        SubintentHash(hasher.hash(DOMAIN_SUBINTENT, &refs))
    }
}

/// One typed yield edge: the `output`-th edge of node `producer` inside
/// intent `intent`, bound to a declared parameter of the consuming
/// intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct YieldBinding {
    /// The producing intent: `0` names the root, `i + 1` names
    /// subintent `i`.
    pub intent: u32,
    /// The produced edge within that intent's graph.
    pub edge: EdgeRef,
}

/// A subintent bound into an envelope.
///
/// Carries the signed declaration, the signer's account prefix, and one
/// yield binding per declared parameter. The bindings are the
/// composer's choice and are covered by the envelope identity, never by
/// the subintent's own hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subintent {
    /// What the subintent's signer signed.
    pub decl: IntentDecl,
    /// The signer's account prefix — the owner of the nullifier.
    pub signer: Address,
    /// The composition's binding for each declared parameter.
    pub bindings: Vec<YieldBinding>,
}

/// The bound envelope tree admission runs over: the composer's root
/// intent plus every bound subintent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EnvelopeTree {
    /// The composer's own intent.
    pub root: IntentDecl,
    /// The composition's binding for each root parameter.
    pub root_bindings: Vec<YieldBinding>,
    /// The bound subintents, in envelope order.
    pub subintents: Vec<Subintent>,
}

fn encode_bindings(bindings: &[YieldBinding]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bindings.len() * 12);
    for binding in bindings {
        out.extend(binding.intent.to_le_bytes());
        out.extend(binding.edge.producer.to_le_bytes());
        out.extend(binding.edge.output.to_le_bytes());
    }
    out
}

impl EnvelopeTree {
    /// The tree's own identity — the fallback for callers that sign
    /// nothing beyond the tree. A protocol envelope signing more (fee
    /// terms, validity windows, snapshot pins) derives its identity from
    /// the full signed form and passes that to [`admit_tree`] instead.
    #[must_use]
    pub fn hash(&self, hasher: &dyn Hasher) -> ManifestHash {
        let mut parts: Vec<Vec<u8>> = Vec::with_capacity(2 + 3 * self.subintents.len());
        parts.push(self.root.hash(hasher).0.0.to_vec());
        parts.push(encode_bindings(&self.root_bindings));
        for subintent in &self.subintents {
            parts.push(subintent.decl.hash(hasher).0.0.to_vec());
            parts.push(subintent.signer.0.to_vec());
            parts.push(encode_bindings(&subintent.bindings));
        }
        let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        ManifestHash(hasher.hash(DOMAIN_ENVELOPE_TREE, &refs))
    }
}

/// The canonical nullifier key for a signed subintent under its signer:
/// `signer_prefix | H(nullifier_role, subintent_hash)`.
#[must_use]
pub fn nullifier_key(
    hasher: &dyn Hasher,
    signer: Address,
    subintent: SubintentHash,
) -> SubstateKey {
    child_key(hasher, signer, NULLIFIER_ROLE, &[subintent.0.0.to_vec()])
}

/// One admitted subintent: its signed identity, its signer, and the
/// nullifier key whose creation write makes it once-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubintentRecord {
    /// The signed declaration's hash.
    pub subintent: SubintentHash,
    /// The signer's account prefix.
    pub signer: Address,
    /// The canonical nullifier key under the signer.
    pub nullifier: SubstateKey,
}

/// An admitted envelope tree: the flattened routing manifest with its
/// identity, plus the nullifier record of every bound subintent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedTree {
    /// The lowered manifest and the identity rooting fresh derivations.
    pub admitted: Admitted,
    /// One record per bound subintent, in envelope order.
    pub subintents: Vec<SubintentRecord>,
}

/// One intent as the shared admission checker consumes it.
pub(crate) struct IntentView<'a> {
    pub graph: &'a ManifestGraph,
    pub params: &'a [YieldParam],
    pub bindings: &'a [YieldBinding],
}

/// Admit a bound envelope tree: validate every intent, interleave the
/// tree into one flattened manifest along its yield edges, and derive
/// the subintent nullifier records.
///
/// `identity` is the signed envelope's hash — the root of every fresh
/// derivation. Distinct signed envelopes never mint the same fresh key,
/// even when they carry the same tree.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
pub fn admit_tree(
    tree: &EnvelopeTree,
    identity: ManifestHash,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<AdmittedTree, AdmissionError> {
    if tree.subintents.len() > MAX_SUBINTENTS {
        return Err(AdmissionError::TooManySubintents);
    }
    let mut records = Vec::with_capacity(tree.subintents.len());
    let mut seen = BTreeSet::new();
    for (index, subintent) in tree.subintents.iter().enumerate() {
        let hash = subintent.decl.hash(hasher);
        if !seen.insert((subintent.signer, hash)) {
            return Err(AdmissionError::DuplicateSubintent {
                index: u32::try_from(index).map_err(|_| AdmissionError::TooManySubintents)?,
            });
        }
        records.push(SubintentRecord {
            subintent: hash,
            signer: subintent.signer,
            nullifier: nullifier_key(hasher, subintent.signer, hash),
        });
    }

    let mut views = Vec::with_capacity(1 + tree.subintents.len());
    views.push(IntentView {
        graph: &tree.root.graph,
        params: &tree.root.params,
        bindings: &tree.root_bindings,
    });
    for subintent in &tree.subintents {
        views.push(IntentView {
            graph: &subintent.decl.graph,
            params: &subintent.decl.params,
            bindings: &subintent.bindings,
        });
    }
    let manifest = admit_intents(&views, identity, cache, instances, hasher)?;
    Ok(AdmittedTree {
        admitted: Admitted { manifest, identity },
        subintents: records,
    })
}

/// Route an admitted tree.
///
/// The flattened manifest's routing plus one exclusive nullifier
/// creation write per subintent at its signer's shard — the same union
/// effect set admission, scheduling, and execution all derive.
///
/// # Errors
///
/// Any [`RouteError`]; verdicts are deterministic and identical on every
/// node.
pub fn route_tree(
    tree: &AdmittedTree,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
    shards: &dyn ShardResolver,
) -> Result<Routing, RouteError> {
    let mut routing = route(
        &tree.admitted.manifest,
        tree.admitted.identity,
        cache,
        instances,
        hasher,
        shards,
    )?;
    for record in &tree.subintents {
        let shard = shards.shard_of(record.signer);
        routing
            .per_shard
            .entry(shard)
            .or_default()
            .insert(Effect {
                target: EffectTarget::Point(record.nullifier),
                mode: Mode::Write,
            })
            .map_err(|_| RouteError::ReserveOverflow)?;
    }
    Ok(routing)
}

/// Check every intent's bindings and parameter consumption, interleave
/// the intents into one flattened node order along the yield edges, and
/// run the node-by-node admission check over that order.
#[allow(clippy::too_many_lines)] // one pass over nodes, one check per rule
pub(crate) fn admit_intents(
    intents: &[IntentView<'_>],
    identity: ManifestHash,
    cache: &MetadataCache,
    instances: &InstanceRegistry,
    hasher: &dyn Hasher,
) -> Result<Manifest, AdmissionError> {
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();
    if total > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }

    // Bindings and parameter consumption, intent by intent: one binding
    // per declared parameter, every binding naming a real source, every
    // parameter consumed by exactly one node argument.
    for (index, intent) in intents.iter().enumerate() {
        let intent_index = u32::try_from(index).map_err(|_| AdmissionError::TooManySubintents)?;
        if intent.bindings.len() != intent.params.len() {
            return Err(AdmissionError::BindingArity {
                intent: intent_index,
                expected: intent.params.len(),
                found: intent.bindings.len(),
            });
        }
        for (position, binding) in intent.bindings.iter().enumerate() {
            let param = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            let source = usize::try_from(binding.intent)
                .ok()
                .and_then(|source| intents.get(source));
            let producer = usize::try_from(binding.edge.producer).unwrap_or(usize::MAX);
            if source.is_none_or(|source| producer >= source.graph.nodes.len()) {
                return Err(AdmissionError::UnknownYieldSource {
                    intent: intent_index,
                    param,
                });
            }
        }
        let mut uses = vec![0u32; intent.params.len()];
        for node in &intent.graph.nodes {
            for arg in &node.args {
                if let GraphArg::Param(param) = arg
                    && let Some(count) = usize::try_from(*param)
                        .ok()
                        .and_then(|position| uses.get_mut(position))
                {
                    *count += 1;
                }
            }
        }
        for (position, count) in uses.iter().enumerate() {
            let param = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            match count {
                0 => {
                    return Err(AdmissionError::UnusedYieldParam {
                        intent: intent_index,
                        param,
                    });
                }
                1 => {}
                _ => {
                    return Err(AdmissionError::YieldParamReused {
                        intent: intent_index,
                        param,
                    });
                }
            }
        }
    }

    // Deterministic interleave: repeatedly emit the lowest-indexed
    // intent whose next node has every yield dependency satisfied.
    // Intents keep their author order, so acyclicity is judged at yield
    // granularity; a stall is a cycle.
    let mut cursor = vec![0usize; intents.len()];
    let mut flat_of: Vec<Vec<u32>> = intents
        .iter()
        .map(|view| vec![0u32; view.graph.nodes.len()])
        .collect();
    let mut order: Vec<(usize, usize)> = Vec::with_capacity(total);
    while order.len() < total {
        let mut progressed = false;
        'candidates: for (index, intent) in intents.iter().enumerate() {
            let next = cursor[index];
            let Some(node) = intent.graph.nodes.get(next) else {
                continue;
            };
            for arg in &node.args {
                let GraphArg::Param(param) = arg else {
                    continue;
                };
                // An out-of-range parameter carries no dependency; the
                // node check below rejects it.
                let Some(binding) = usize::try_from(*param)
                    .ok()
                    .and_then(|position| intent.bindings.get(position))
                else {
                    continue;
                };
                let source = usize::try_from(binding.intent).unwrap_or(usize::MAX);
                let producer = usize::try_from(binding.edge.producer).unwrap_or(usize::MAX);
                if cursor
                    .get(source)
                    .is_none_or(|&emitted| producer >= emitted)
                {
                    continue 'candidates;
                }
            }
            flat_of[index][next] =
                u32::try_from(order.len()).map_err(|_| AdmissionError::TooManyNodes)?;
            order.push((index, next));
            cursor[index] += 1;
            progressed = true;
            break;
        }
        if !progressed {
            return Err(AdmissionError::CyclicYields);
        }
    }

    // Per emitted node: evaluated output resource types and a
    // consumption count per output slot, indexed by flattened position.
    let mut outputs: Vec<Vec<Address>> = Vec::with_capacity(total);
    let mut consumed: Vec<Vec<u32>> = Vec::with_capacity(total);
    let mut lowered: Vec<Node> = Vec::with_capacity(total);

    for &(intent_index, local_index) in &order {
        let intent = &intents[intent_index];
        let node = &intent.graph.nodes[local_index];
        let node_index = u32::try_from(lowered.len()).map_err(|_| AdmissionError::TooManyNodes)?;
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
        let meta = instances
            .get(node.target)
            .ok_or(AdmissionError::UnknownInstance(node.target))?;
        let package = cache
            .get(meta.package)
            .ok_or(AdmissionError::UnknownPackage(meta.package))?;
        let signature =
            package
                .methods
                .get(&node.method)
                .ok_or_else(|| AdmissionError::UnknownMethod {
                    package: meta.package,
                    method: node.method.clone(),
                })?;
        if signature.params.len() != node.args.len() {
            return Err(AdmissionError::ArityMismatch {
                node: node_index,
                expected: signature.params.len(),
                found: node.args.len(),
            });
        }

        let mut bound = Vec::with_capacity(node.args.len());
        let mut inputs = Vec::with_capacity(node.args.len());
        for (position, (arg, param)) in node.args.iter().zip(&signature.params).enumerate() {
            let param_index = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            match arg {
                GraphArg::Literal(value) => {
                    if *param == ParamType::Bucket {
                        return Err(AdmissionError::LiteralForBucketParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if !param.admits(value) {
                        return Err(AdmissionError::ParamKind {
                            node: node_index,
                            param: param_index,
                            expected: param.name(),
                            found: value.kind(),
                        });
                    }
                    bound.push(value.clone());
                    inputs.push(NodeInput::Literal(value.clone()));
                }
                GraphArg::Edge { edge, constraints } => {
                    if *param != ParamType::Bucket {
                        return Err(AdmissionError::EdgeForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if edge.producer >= local {
                        return Err(AdmissionError::ForwardEdge {
                            node: node_index,
                            producer: edge.producer,
                        });
                    }
                    let producer =
                        usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = flat_of[intent_index][producer];
                    let flat = usize::try_from(source).map_err(|_| AdmissionError::TooManyNodes)?;
                    let output =
                        usize::try_from(edge.output).map_err(|_| AdmissionError::TooManyNodes)?;
                    let resource =
                        *outputs[flat]
                            .get(output)
                            .ok_or(AdmissionError::NoSuchOutput {
                                producer: source,
                                output: edge.output,
                            })?;
                    consumed[flat][output] += 1;
                    if consumed[flat][output] > 1 {
                        return Err(AdmissionError::DoubleConsumption {
                            producer: source,
                            output: edge.output,
                        });
                    }
                    check_constraints(constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket { resource });
                    inputs.push(NodeInput::Edge { source, resource });
                }
                GraphArg::Param(reference) => {
                    let Some((decl, binding)) =
                        usize::try_from(*reference).ok().and_then(|position| {
                            Some((intent.params.get(position)?, intent.bindings.get(position)?))
                        })
                    else {
                        return Err(AdmissionError::UnboundParam {
                            node: node_index,
                            param: *reference,
                        });
                    };
                    if *param != ParamType::Bucket {
                        return Err(AdmissionError::EdgeForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    let source_intent = usize::try_from(binding.intent)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let producer = usize::try_from(binding.edge.producer)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = flat_of[source_intent][producer];
                    let flat = usize::try_from(source).map_err(|_| AdmissionError::TooManyNodes)?;
                    let output = usize::try_from(binding.edge.output)
                        .map_err(|_| AdmissionError::TooManyNodes)?;
                    let resource =
                        *outputs[flat]
                            .get(output)
                            .ok_or(AdmissionError::NoSuchOutput {
                                producer: source,
                                output: binding.edge.output,
                            })?;
                    if resource != decl.resource {
                        return Err(AdmissionError::YieldResourceMismatch {
                            intent: u32::try_from(intent_index)
                                .map_err(|_| AdmissionError::TooManySubintents)?,
                            param: *reference,
                        });
                    }
                    consumed[flat][output] += 1;
                    if consumed[flat][output] > 1 {
                        return Err(AdmissionError::DoubleConsumption {
                            producer: source,
                            output: binding.edge.output,
                        });
                    }
                    check_constraints(&decl.constraints, resource, node_index, param_index)?;
                    bound.push(Value::Bucket { resource });
                    inputs.push(NodeInput::Edge { source, resource });
                }
            }
        }

        // Evaluate this node's output resource types over its bound
        // inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target,
            args: &bound,
            config: &meta.config,
            node_index,
            frame: 0,
            identity,
        };
        let mut node_outputs = Vec::with_capacity(signature.outputs.len());
        for (slot, expr) in signature.outputs.iter().enumerate() {
            let slot_index = u32::try_from(slot).map_err(|_| AdmissionError::TooManyNodes)?;
            let value = evaluate_expr(expr, &eval_inputs, hasher).map_err(|source| {
                AdmissionError::Eval {
                    node: node_index,
                    source,
                }
            })?;
            let Value::Address(resource) = value else {
                return Err(AdmissionError::OutputType {
                    node: node_index,
                    output: slot_index,
                });
            };
            node_outputs.push(resource);
        }
        consumed.push(vec![0; node_outputs.len()]);
        outputs.push(node_outputs);
        lowered.push(Node {
            target: node.target,
            method: node.method.clone(),
            inputs,
        });
    }

    // Linearity: nothing dangles, yields included.
    for (producer, counts) in consumed.iter().enumerate() {
        for (output, count) in counts.iter().enumerate() {
            if *count == 0 {
                return Err(AdmissionError::UnconsumedOutput {
                    producer: u32::try_from(producer).unwrap_or(u32::MAX),
                    output: u32::try_from(output).unwrap_or(u32::MAX),
                });
            }
        }
    }

    Ok(Manifest { nodes: lowered })
}

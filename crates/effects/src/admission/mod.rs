//! Admission: the judgement that turns a signed form into a routing
//! manifest.
//!
//! One checker serves both signed forms. A bare graph is the degenerate
//! envelope — a single intent with no sockets and no subintents — and a
//! composed tree is several intents joined through the sockets they
//! declare, each carrying a value edge or a proof. So [`admit_intents`]
//! takes a slice of [`IntentView`] and everything below it is
//! shape-agnostic: bindings and socket consumption per intent, a
//! deterministic interleave over the sockets each node names, then one
//! pass over the flattened node order checking arity, kinds, linearity,
//! and constraints.
//!
//! Nothing here reads state. Verdicts are a pure function of the signed
//! form and content-addressed metadata, which is what lets every node
//! reach the identical one.
//!
//! What stays here is the walk: one pass over the flattened node order,
//! and the lowered form it produces. The four subjects beside it are
//! [`error`] (the verdict vocabulary and where each refusal points),
//! [`compose`] (what a signed form is, before any signature is read),
//! [`inject`] (the entries a resource's own rules put on a frame), and
//! [`abi`] (what a judged frame lowers to for the engine).

mod abi;
mod compose;
mod error;
mod inject;

use std::collections::BTreeSet;
use std::sync::Arc;

use abi::{CallBinding, lower_call};
pub(crate) use compose::{IntentView, check_instance_value_depth, check_value_depth, interleave};
use compose::{bind_edge, check_bindings};
pub use error::{AdmissionError, Placed};
use hyperscale_vm_types::{
    Address, CallTarget, Effect, EffectTarget, MAX_MANIFEST_NODES, Mode, Presence, PrincipalAddr,
    ResourceAddr,
};
pub use inject::{Asks, Injected};
use inject::{
    inject_destruction_rules, inject_issuance_rules, inject_movement_rules, inject_reach_rules,
};

use crate::claim::Claim;
use crate::dsl::{
    Condition, Declaration, DeclaredAccess, EvalBudget, EvalInputs, PresentedGrants,
    evaluate_declaration, evaluate_expr,
};
use crate::envelope::{Binding, Socket, SubintentHash};
use crate::graph::{EvidenceRef, GraphArg, GraphNode, ManifestGraph};
use crate::hash::Hasher;
use crate::instance::{InstanceMeta, ResolveError};
use crate::invoke::{IssuanceGrant, NodeCall};
use crate::manifest::{JudgedLeaf, Manifest, ManifestHash, Node, NodeInput};
use crate::metadata::PackageMetadata;
use crate::publish::{CheckedSignature, seals};
use crate::records::ChainRecords;
use crate::route::FrameDeclaration;
use crate::rule::{Judged, Rule};
use crate::signature::{MethodSignature, ParamType};
use crate::types::{EdgeContent, Value, child_key};
use crate::vocabulary::CONFIG;

/// The bound on sockets one intent may declare. A wire bound.
///
/// An intent binds one edge per socket, so this bounds the binding
/// vector too — which is what makes every socket position expressible
/// as a `u32` index by construction rather than by hope.
pub const MAX_SOCKETS: usize = 32;

/// An admitted transaction: the routing manifest plus the identity that
/// roots fresh-ID derivation — the signed graph's hash, so distinct
/// signed transactions never mint the same fresh key.
///
/// Only admission constructs one, and [`crate::route()`] takes nothing else,
/// so "routing consumes admitted manifests" is a fact about the types
/// rather than a convention callers are asked to keep.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    manifest: Manifest,
    identity: ManifestHash,
    frames: Vec<FrameDeclaration>,
    injected: Vec<Vec<Injected>>,
    calls: Vec<NodeCall>,
    declaration: Declaration,
    origins: Vec<NodeOrigin>,
}

/// Which signed intent a manifest node came from, and where in it.
///
/// The manifest's node order is the interleave the composition chose, so
/// a node's index in it is a fact about the whole tree rather than about
/// the party whose cells the node moves. This pair is the other reading:
/// content one signer signed, and a position inside it that only that
/// signer can move.
///
/// What consumes it is escrow-cell derivation. A cell keyed by the
/// manifest index under a transaction hash would take both halves of its
/// material from the composer, who need not be the cell's owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeOrigin {
    /// The signed intent this node belongs to.
    pub intent: SubintentHash,
    /// Its index within that intent's own graph.
    pub local: u32,
    /// When the cells this node's crossings write stop being owed: its
    /// intent's own window end plus the retention grace.
    ///
    /// The intent's window and never the transaction's. A transaction's
    /// window is the intersection of every intent's, so this is never
    /// the earlier of the two — and it is signed by the party whose
    /// cells it keys, where the transaction's is the composer's.
    pub expiry_ms: u64,
}

impl Admitted {
    /// The lowered routing manifest.
    #[must_use]
    pub const fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// The signed form's hash: the transaction identity every fresh
    /// derivation binds to, at admission and at routing alike.
    #[must_use]
    pub const fn identity(&self) -> ManifestHash {
        self.identity
    }

    /// Every evaluated frame's declaration, in node order.
    #[must_use]
    pub fn frames(&self) -> &[FrameDeclaration] {
        &self.frames
    }

    /// One lowered invocation per manifest node, in node order.
    #[must_use]
    pub fn calls(&self) -> &[NodeCall] {
        &self.calls
    }

    /// What the protocol put on each frame, in node order beside
    /// [`frames`](Self::frames).
    ///
    /// Kept rather than dropped because the rule alone cannot say who
    /// asked: it names a key, and a key is a hash that inverts to
    /// nothing. Local to whoever admitted, never signed and never
    /// routed — the shards judge the rules, and only a reader needs the
    /// entry behind one.
    #[must_use]
    pub fn injected(&self) -> &[Vec<Injected>] {
        &self.injected
    }

    /// The transaction's whole declaration, both views: the folded set,
    /// and every frame's clauses concatenated in preorder — the order
    /// capability materialization builds its table in.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.declaration
    }

    /// Which signed intent each node came from, in node order.
    #[must_use]
    pub fn origins(&self) -> &[NodeOrigin] {
        &self.origins
    }

    /// Whether each node's frame is answered by admission alone, in node
    /// order.
    ///
    /// The lowering already split every condition by where it is judged:
    /// one answerable from committed state joined the union declaration
    /// under this node's number, and every other rides the call. So the
    /// question is a read over the two halves rather than a second walk
    /// over the injection — which has five refusal paths and a hasher,
    /// and would have to be kept in step with admission by hand.
    ///
    /// What consumes it is the star classifier: an outbound leg
    /// materializes after the core committed, so a verdict its frame
    /// reaches at materialization lands on a caller that already
    /// committed.
    #[must_use]
    pub fn answered_at_admission(&self) -> Vec<bool> {
        let mut answered: Vec<bool> = self
            .calls
            .iter()
            .map(|call| {
                call.requires
                    .iter()
                    .all(|rule| rule.judged() == Judged::AtAdmission)
            })
            .collect();
        for condition in &self.declaration.conditions {
            if let Some(node) = condition.node
                && let Some(slot) = answered.get_mut(node as usize)
            {
                *slot = false;
            }
        }
        answered
    }
}

/// Admit a graph: check well-formedness, linearity, and type agreement
/// against package metadata, and lower it to the routing manifest.
///
/// A bare graph is the degenerate envelope: one intent signed by
/// `composer`, no parameters, no subintents, its own hash as the
/// identity. Envelope trees go
/// through [`crate::envelope::admit_tree`], which supplies the identity
/// from the signed envelope.
///
/// # Errors
///
/// Any [`AdmissionError`]; verdicts are deterministic and identical on
/// every node.
pub fn admit(
    graph: &ManifestGraph,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    admit_presenting(graph, composer, chain, PresentedGrants::none(), hasher)
}

/// The same, over resource records the composer presents.
///
/// A bare graph presents nothing, which is what every ungranted flow
/// needs; a graph reaching a resource whose rules govern needs the
/// record those rules derive, because the address is the hash of them
/// and re-derivation is what makes a presented record trustworthy.
///
/// # Errors
///
/// [`AdmissionError`] on the same terms as [`admit`].
pub fn admit_presenting(
    graph: &ManifestGraph,
    composer: PrincipalAddr,
    chain: &dyn ChainRecords,
    grants: &PresentedGrants,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    check_value_depth(graph)?;
    let identity = graph.hash(hasher);
    admit_intents(
        &[IntentView {
            graph,
            sockets: &[],
            bindings: &[],
            signer: Some(composer),
            // A bare graph is signed whole by its composer, so what its
            // signer signed is the graph itself.
            identity: SubintentHash(identity.0),
            // And it names no window, which is the offer that stands
            // forever — the same figure a header with no end derives.
            expiry_ms: u64::MAX,
        }],
        identity,
        chain,
        &BTreeSet::new(),
        grants,
        hasher,
    )
}

/// Check every intent's bindings and socket consumption, interleave the
/// intents into one flattened node order over the sockets they declare,
/// and run the node-by-node admission check over that order.
pub(crate) fn admit_intents(
    intents: &[IntentView<'_>],
    identity: ManifestHash,
    chain: &dyn ChainRecords,
    presented: &BTreeSet<Address>,
    grants: &PresentedGrants,
    hasher: &dyn Hasher,
) -> Result<Admitted, AdmissionError> {
    let total: usize = intents.iter().map(|view| view.graph.nodes.len()).sum();
    if total > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }

    check_bindings(intents)?;

    let (flat_of, order) = interleave(intents, total)?;
    let origins: Vec<NodeOrigin> = order
        .iter()
        .map(|&(intent_index, local_index)| NodeOrigin {
            intent: intents[intent_index].identity,
            local: u32::try_from(local_index).unwrap_or(u32::MAX),
            expiry_ms: intents[intent_index].expiry_ms,
        })
        .collect();

    let budget = EvalBudget::default();
    let mut admission = Admission {
        intents,
        identity,
        chain,
        presented,
        grants,
        hasher,
        flat_of: &flat_of,
        budget: &budget,
        outputs: Vec::with_capacity(total),
        consumed: Vec::with_capacity(total),
        proven: Vec::with_capacity(total),
        lowered: Vec::with_capacity(total),
        frames: Vec::with_capacity(total),
        injected: Vec::with_capacity(total),
        calls: Vec::with_capacity(total),
        declaration: Declaration::default(),
        table_len: 0,
    };
    for &(intent_index, local_index) in &order {
        admission.lower_node(intent_index, local_index)?;
    }
    let Admission {
        consumed,
        lowered,
        frames,
        injected,
        calls,
        declaration,
        ..
    } = admission;

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

    Ok(Admitted {
        manifest: Manifest { nodes: lowered },
        identity,
        frames,
        injected,
        calls,
        declaration,
        origins,
    })
}

/// The two records one call resolves through, held as long as the
/// signature read out of them is.
struct Resolved {
    instance: Arc<InstanceMeta>,
    package: Arc<PackageMetadata>,
}

impl Resolved {
    /// The checked signature of `method` on the resolved package.
    ///
    /// The witness is the cache's invariant: everything behind the
    /// publish door passed the composed signature check when it entered,
    /// so a record reached through here needs no second judgment.
    fn method(&self, method: &str) -> Option<CheckedSignature<'_>> {
        self.package
            .methods
            .get(method)
            .map(CheckedSignature::trusted)
    }
}

/// The admission accumulator: everything one interleaved walk threads
/// through [`admit_intents`] — the tree's one budget, the outputs and
/// consumption each node's edges resolve against, the proven claims,
/// the lowered nodes, and the union declaration.
struct Admission<'a> {
    intents: &'a [IntentView<'a>],
    identity: ManifestHash,
    chain: &'a dyn ChainRecords,
    /// The component addresses the envelope's own records resolve, and
    /// nothing committed does.
    ///
    /// A record may stand for exactly one call: the seal that makes its
    /// component actual. Every other target resolves from state, so a
    /// record presented beside one is a claim about a component the
    /// chain can already answer for — and admitting it would let a
    /// caller name the configuration of a component somebody else
    /// created.
    presented: &'a BTreeSet<Address>,
    grants: &'a PresentedGrants,
    hasher: &'a dyn Hasher,
    /// What admitting this envelope has spent, across every node the
    /// interleaved order holds. One meter for the tree, because a caller
    /// composes the tree and admission runs before any fee is assured.
    budget: &'a EvalBudget,
    /// Flattened position per (intent, local node).
    flat_of: &'a [Vec<u32>],
    /// Evaluated output projections per flattened node.
    outputs: Vec<Vec<(ResourceAddr, EdgeContent)>>,
    /// Consumption count per output slot, per flattened node.
    consumed: Vec<Vec<u32>>,
    /// What each flattened node proves: an authorizing method's own
    /// identity, a custodial method's badge, and an empty set from
    /// anything else. A proof drawn from a node draws the whole set, so
    /// a gate that verifies more than one thing about its caller
    /// presents all of it.
    proven: Vec<Vec<Claim>>,
    lowered: Vec<Node>,
    frames: Vec<FrameDeclaration>,
    /// What the protocol put on each frame, beside it.
    injected: Vec<Vec<Injected>>,
    calls: Vec<NodeCall>,
    /// The transaction's whole declaration, folded frame by frame.
    declaration: Declaration,
    /// Effects logged so far across every frame: the offset the next
    /// frame's clause spans are relative to, and therefore the base of
    /// every handle position that frame's binding resolves to.
    table_len: u32,
}

/// Every authority condition an evaluated frame carries that a proof
/// presented at this node could satisfy — an authored gate, or a
/// requirement admission injected onto the frame.
///
/// A condition materialization answers is not one evidence reaches: it
/// reads committed state rather than what the caller handed over.
fn judged_here(frame: &Declaration) -> Vec<&Rule<JudgedLeaf>> {
    frame
        .required()
        .filter(|rule| rule.judged() != Judged::AtMaterialization)
        .collect()
}

/// Whether this node presents evidence where its call requires some.
///
/// A property of what the call requires and nothing else: a guarded or
/// authorizing call presents something, a public one presents nothing.
/// Whether what it presents *satisfies* the target's rule is the
/// target's own business, answered where the target's state is.
fn check_evidence_presence(
    required: &[&Rule<JudgedLeaf>],
    node: &GraphNode,
    node_index: u32,
) -> Result<(), AdmissionError> {
    match (required.is_empty(), node.evidence.is_empty()) {
        (false, true) => Err(AdmissionError::MissingEvidence { node: node_index }),
        (true, false) => Err(AdmissionError::UnexpectedEvidence { node: node_index }),
        _ => Ok(()),
    }
}

impl Admission<'_> {
    fn lower_node(
        &mut self,
        intent_index: usize,
        local_index: usize,
    ) -> Result<(), AdmissionError> {
        // Both index unchecked: the pair comes off the interleave's own
        // emission order, which never names an intent or a node it was
        // not built over.
        let intent = &self.intents[intent_index];
        let node = &intent.graph.nodes[local_index];
        let node_index =
            u32::try_from(self.lowered.len()).map_err(|_| AdmissionError::TooManyNodes)?;
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
        let resolved = self.resolve_records(node)?;
        let signature = self.resolve_signature(&resolved, node, node_index)?;
        let meta = resolved.instance.as_ref();

        let (bound, inputs) = self.bind_args(intent_index, local, node, signature, node_index)?;

        // Evaluate this node's projections over its bound inputs.
        let eval_inputs = EvalInputs {
            self_addr: node.target.address(),
            args: &bound,
            record: meta,
            node_index,
            identity: self.identity,
            grants: self.grants,
            budget: self.budget,
        };
        check_denominations(signature, &bound, &eval_inputs, self.hasher, node_index)?;
        let node_outputs = project_outputs(signature, &eval_inputs, self.hasher, node_index)?;

        // The frame: this node's effect signature, evaluated over the
        // same inputs everything above evaluated over. The one place the
        // declaration comes into being.
        let mut frame = evaluate_declaration(&signature.effects, &eval_inputs, self.hasher)
            .map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        judge_prefixes(&frame, node.target.address(), node_index)?;
        let fence = self.fence(node.target, &mut frame)?;
        let (issues, injected) = self.inject(
            signature,
            node.target.address(),
            &meta.config,
            &inputs,
            &mut frame,
            node_index,
        )?;
        // Evidence last, because what a call must present is a property
        // of the declaration this node actually evaluated rather than of
        // the clause list its signature was written with: a guard that
        // did not fire states no requirement, and neither does a granted
        // entry open to everyone. Both are conditions the frame simply
        // does not carry, and demanding a proof for one nothing will
        // consume is the refusal a caller could never satisfy.
        let evidence =
            self.resolve_evidence(intent_index, local_index, node, &frame, node_index)?;
        // The frame's handles occupy the run of the capability table
        // starting here, so the offset is taken before the frame is
        // logged.
        let offset = self.table_len;
        // A frame's conditions split by where each is judged, and nothing
        // declares which: a rule answerable from committed state joins
        // the union declaration and is judged at materialization, beside
        // the presence a write requires; one whose leaves reach the
        // call's evidence rides the node's call.
        let mut requires = Vec::new();
        self.split_conditions(&frame, node_index, &mut requires);
        if let Some(rule) = fence {
            self.declaration.conditions.push(Condition {
                rule,
                node: Some(node_index),
            });
        }
        self.calls.push(lower_call(
            node_index,
            signature,
            CallBinding {
                package: meta.package,
                declaration: &frame,
                offset,
                target: node.target.address(),
                method: &node.method,
                node_inputs: &inputs,
                node_outputs: &node_outputs,
                evidence: &evidence,
                requires,
                issues,
                inputs: &eval_inputs,
                hasher: self.hasher,
            },
        )?);
        self.table_len = offset
            .checked_add(u32::try_from(frame.ordered.len()).unwrap_or(u32::MAX))
            .ok_or(AdmissionError::TableOverflow)?;
        // The union is folded access by access, so reserve amounts two
        // clauses declared on one target sum exactly as the set
        // semantics say — and an overflow is this fold's refusal.
        for access in &frame.ordered {
            self.declaration.set.insert(access.effect)?;
            self.declaration.ordered.push(*access);
        }
        // What this node proves is read off its declared clauses, the
        // widening already applied where the evaluation resolved them.
        self.proven.push(frame.proves);
        self.frames.push(FrameDeclaration {
            node: node_index,
            ordered: frame.ordered,
        });
        self.injected.push(injected);
        self.consumed.push(vec![0; node_outputs.len()]);
        self.outputs.push(node_outputs);
        self.lowered.push(Node {
            target: node.target.address(),
            method: node.method.clone(),
            inputs,
            evidence,
        });
        Ok(())
    }

    /// The two records a node's call resolves through: the instance its
    /// target names, and the package that instance runs.
    ///
    /// Held as shared handles rather than borrowed out of a collection,
    /// because the chain's records need not be a map this can point
    /// into. The caller keeps the pair alive for as long as it reads the
    /// signature out of it.
    fn resolve_records(&self, node: &GraphNode) -> Result<Resolved, AdmissionError> {
        let instance = self
            .chain
            .instance(node.target)
            .ok_or_else(|| ResolveError::UnknownInstance(node.target.address()))?;
        let package = self
            .chain
            .package(instance.package)
            .ok_or(ResolveError::UnknownPackage(instance.package))?;
        Ok(Resolved { instance, package })
    }

    /// The signature a node's call names, held to what this envelope may
    /// say about it.
    ///
    /// The last link of the chain from an address through its record and
    /// package — and then two judgments the signature makes possible:
    /// whether a record the envelope carried may stand for this call at
    /// all, and whether the arguments match what the method declares.
    fn resolve_signature<'r>(
        &self,
        resolved: &'r Resolved,
        node: &GraphNode,
        node_index: u32,
    ) -> Result<&'r MethodSignature, AdmissionError> {
        // The witness, not the record: everything behind the cache door
        // passed the composed signature check, so nothing below re-asks.
        let checked = resolved
            .method(&node.method)
            .ok_or_else(|| ResolveError::UnknownMethod {
                package: resolved.instance.package,
                method: node.method.clone(),
            })?;
        let signature = checked.signature();
        // A record the envelope carried stands for the seal of the
        // component it derives and nothing else. Every other target
        // answers from committed state, so a record beside one would be
        // a caller stating the configuration of a component the chain
        // holds its own answer for — and the two need never agree.
        if self.presented.contains(&node.target.address()) && !seals(signature) {
            return Err(AdmissionError::PresentedForCall {
                node: node_index,
                method: node.method.clone(),
            });
        }
        if signature.params.len() != node.args.len() {
            return Err(AdmissionError::ArityMismatch {
                node: node_index,
                expected: signature.params.len(),
                found: node.args.len(),
            });
        }
        Ok(signature)
    }

    /// The instantiation fence for a node's target: the read of its
    /// configuration leaf, appended to `frame`, and the presence the
    /// judging shard holds it to.
    ///
    /// The protocol's own term rather than the package's. Whether a
    /// creation finished is a question about the target's address class
    /// — a component derives from a record and has one to finish, a
    /// principal derives from a key and has none — so it is answered
    /// where the class is known and not by every method of every
    /// package restating it. A package cannot omit what it does not
    /// write, which is what makes the fence universal over hand-written
    /// declarations and derived ones alike.
    ///
    /// The read is appended, so every clause span the signature's own
    /// ABI bindings name keeps the position it had.
    ///
    /// A node that writes the leaf is the seal itself, and takes no
    /// presence: its own `Absent` door is what it declares, and the
    /// publish gate admits no other write at the slot.
    fn fence(
        &self,
        target: CallTarget,
        frame: &mut Declaration,
    ) -> Result<Option<Rule<JudgedLeaf>>, AdmissionError> {
        let CallTarget::Component(address) = target else {
            return Ok(None);
        };
        let leaf = EffectTarget::Point(child_key(self.hasher, address, CONFIG, &[]));
        let grants = frame.ordered.iter().any(|access| {
            access.effect.target == leaf && matches!(access.effect.mode, Mode::Write { .. })
        });
        if grants {
            return Ok(None);
        }
        let effect = Effect {
            target: leaf,
            mode: Mode::Read,
        };
        if frame.set.insert(effect)? {
            frame.ordered.push(DeclaredAccess {
                effect,
                holds: None,
                reach: None,
                clause: None,
            });
        }
        Ok(Some(Rule::Require(JudgedLeaf::Presence {
            target: leaf,
            expect: Presence::Present,
        })))
    }

    /// Bind the node's arguments against the signature's parameters: a
    /// literal for a value parameter, and for a bucket one either an
    /// edge of this graph or the socket some other intent fills.
    fn bind_args(
        &mut self,
        intent_index: usize,
        local: u32,
        node: &GraphNode,
        signature: &MethodSignature,
        node_index: u32,
    ) -> Result<(Vec<Value>, Vec<NodeInput>), AdmissionError> {
        let mut bound = Vec::with_capacity(node.args.len());
        let mut inputs = Vec::with_capacity(node.args.len());
        for (position, (arg, param)) in node.args.iter().zip(&signature.params).enumerate() {
            let param_index = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
            match arg {
                GraphArg::Literal(value) => {
                    if param.is_edge() {
                        return Err(AdmissionError::LiteralForBucketParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if !param.admits(value) {
                        // The one same-kind refusal is width, and it
                        // names the width the signature fixed.
                        return Err(match (param, value) {
                            (ParamType::BytesExact(expected), Value::Bytes(bytes)) => {
                                AdmissionError::ParamWidth {
                                    node: node_index,
                                    param: param_index,
                                    expected: *expected,
                                    found: bytes.len(),
                                }
                            }
                            _ => AdmissionError::ParamKind {
                                node: node_index,
                                param: param_index,
                                expected: param.name(),
                                found: value.kind(),
                            },
                        });
                    }
                    bound.push(value.clone());
                    inputs.push(NodeInput::Literal(value.clone()));
                }
                GraphArg::Edge { edge, constraints } => {
                    if !param.is_edge() {
                        return Err(AdmissionError::EdgeForValueParam {
                            node: node_index,
                            param: param_index,
                        });
                    }
                    if edge.producer >= local {
                        return Err(AdmissionError::ForwardEdge {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            producer: edge.producer,
                        });
                    }
                    let producer =
                        usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
                    let source = self.flat_of[intent_index][producer];
                    let (value, input) = bind_edge(
                        &self.outputs,
                        &mut self.consumed,
                        (source, edge.output),
                        constraints,
                        *param,
                        (node_index, param_index),
                        |_| Ok(()),
                    )?;
                    bound.push(value);
                    inputs.push(input);
                }
                GraphArg::Socket(reference) => {
                    let (value, input) = self.bind_socket(
                        intent_index,
                        local,
                        *reference,
                        *param,
                        (node_index, param_index),
                    )?;
                    bound.push(value);
                    inputs.push(input);
                }
            }
        }
        Ok((bound, inputs))
    }

    /// Every requirement the protocol puts on `frame`, appended to its
    /// own conditions and answered whole beside them.
    ///
    /// None of it is declared. A package will not write a rule it does
    /// not want, so each of these comes from the resource rather than
    /// from the signature — which is what makes omission inexpressible —
    /// and each is returned carrying the entry that demanded it, because
    /// the rule alone says what must hold and cannot say who asked.
    ///
    /// A rule asked twice is one question wherever the duplicate came
    /// from: a resource putting both directions of a movement on one
    /// register asks it twice, and the frame carries it once.
    fn inject(
        &self,
        signature: &MethodSignature,
        target: Address,
        config: &[Value],
        inputs: &[NodeInput],
        frame: &mut Declaration,
        node_index: u32,
    ) -> Result<(Vec<IssuanceGrant>, Vec<Injected>), AdmissionError> {
        // The reach's own entry before the movement entries, because a
        // reaching access earns none of the latter and a reader should
        // meet the authority that admitted it first.
        let mut injected = inject_reach_rules(self.grants, frame, target, node_index)?;
        injected.extend(inject_movement_rules(
            self.hasher,
            self.grants,
            frame,
            signature.totality.is_total(),
            node_index,
        )?);
        // Issuance is an actor question like any other, so its entry
        // joins the frame's conditions and computed placement routes it
        // to the call. Before evidence, because what a caller must
        // present is a property of the conditions the frame carries.
        let (mut issues, issuance) =
            inject_issuance_rules(self.hasher, signature, target, config, node_index)?;
        injected.extend(issuance);
        // Appended after them, so the index a body passes to a mint is
        // the position its own declaration fixed: a destruction names no
        // index, since the bucket carries the resource it holds.
        let (destroyed, destruction) =
            inject_destruction_rules(self.grants, signature, inputs, target, node_index)?;
        issues.extend(destroyed);
        injected.extend(destruction);
        for requirement in &injected {
            // The dedup scan compares rule trees, per injected entry over
            // every condition the frame holds — ingress work over
            // unverified bytes, charged like the claim copies are: per
            // rule compared, before anyone has paid for it.
            self.budget
                .spend(frame.required().count())
                .map_err(|source| AdmissionError::Eval {
                    node: node_index,
                    source,
                })?;
            if !frame.required().any(|rule| *rule == requirement.rule) {
                frame
                    .conditions
                    .push(Condition::declared(requirement.rule.clone()));
            }
        }
        Ok((issues, injected))
    }

    /// Split a frame's conditions by where each is judged.
    ///
    /// One answerable from committed state alone joins the union
    /// declaration and is judged at materialization, beside the presence
    /// a write requires; every other rides the node's call, where the
    /// evidence is. Nothing declares which.
    fn split_conditions(
        &mut self,
        frame: &Declaration,
        node_index: u32,
        requires: &mut Vec<Rule<JudgedLeaf>>,
    ) {
        for condition in &frame.conditions {
            if condition.rule.judged() == Judged::AtMaterialization {
                // Stamped here rather than at the frame, because this is
                // where the number starts meaning something: a frame's
                // own conditions are one node's, and the union's are
                // every node's in one list.
                self.declaration.conditions.push(Condition {
                    rule: condition.rule.clone(),
                    node: Some(node_index),
                });
            } else {
                requires.push(condition.rule.clone());
            }
        }
    }

    /// An intent's own position, as these payloads carry it.
    ///
    /// Bounded by `MAX_SUBINTENTS`, which the envelope gate enforces
    /// before anything here runs — the same expectation the interleave
    /// already makes of it.
    fn intent_of(intent_index: usize) -> u32 {
        u32::try_from(intent_index).expect("intents are bounded by MAX_SUBINTENTS")
    }

    /// Bind the edge a socket was filled with.
    ///
    /// The socket types what may arrive and the composition names what
    /// did, so both are checked here: the socket's declared resource
    /// against the edge's, and the declaring intent's own constraints
    /// against it as if it were an ordinary argument.
    fn bind_socket(
        &mut self,
        intent_index: usize,
        local: u32,
        reference: u32,
        param: ParamType,
        at: (u32, u32),
    ) -> Result<(Value, NodeInput), AdmissionError> {
        let intent = &self.intents[intent_index];
        let (node_index, param_index) = at;

        let Some((decl, binding)) = usize::try_from(reference).ok().and_then(|position| {
            Some((
                intent.sockets.get(position)?,
                intent.bindings.get(position)?,
            ))
        }) else {
            return Err(AdmissionError::UnknownSocket {
                intent: Self::intent_of(intent_index),
                node: local,
                socket: reference,
            });
        };
        if !param.is_edge() {
            return Err(AdmissionError::SocketForValueParam {
                node: node_index,
                param: param_index,
            });
        }
        let intent_at = u32::try_from(intent_index).expect("intents are bounded by MAX_SUBINTENTS");
        let (
            Socket::Value {
                resource: declared,
                constraints,
            },
            Binding::Value {
                intent: source_intent,
                edge,
            },
        ) = (decl, *binding)
        else {
            // A socket shaped for authority fills no argument: an
            // argument takes value, and a proof is not value.
            return Err(AdmissionError::AuthoritySocketAsArgument {
                node: node_index,
                param: param_index,
                socket: reference,
            });
        };
        let source_intent =
            usize::try_from(source_intent).map_err(|_| AdmissionError::TooManyNodes)?;
        let producer = usize::try_from(edge.producer).map_err(|_| AdmissionError::TooManyNodes)?;
        let source = self.flat_of[source_intent][producer];
        let declared = *declared;
        let (value, input) = bind_edge(
            &self.outputs,
            &mut self.consumed,
            (source, edge.output),
            constraints,
            param,
            (node_index, param_index),
            |resource| {
                if resource == declared {
                    Ok(())
                } else {
                    Err(AdmissionError::SocketResourceMismatch {
                        intent: intent_at,
                        socket: reference,
                    })
                }
            },
        )?;
        Ok((value, input))
    }

    /// Resolve the node's presented evidence against its own intent.
    ///
    /// A proof is scoped to the intent that produced it — a signature
    /// proof to the intent whose signature, a node proof to the intent
    /// whose node — so the identities resolve against this node's own
    /// intent and no other.
    fn resolve_evidence(
        &self,
        intent_index: usize,
        local_index: usize,
        node: &GraphNode,
        frame: &Declaration,
        node_index: u32,
    ) -> Result<Vec<Claim>, AdmissionError> {
        let intent = &self.intents[intent_index];
        let local = u32::try_from(local_index).map_err(|_| AdmissionError::TooManyNodes)?;
        let required = judged_here(frame);
        check_evidence_presence(&required, node, node_index)?;
        let mut evidence = Vec::with_capacity(node.evidence.len());
        for reference in &node.evidence {
            match reference {
                EvidenceRef::IntentSignature => {
                    // A signature signs in; a proof acts. Whether the
                    // key behind this proof still holds its account's
                    // authority is the account's rule, so the only
                    // gates it may reach are the ones that read a rule
                    // — the sign-in, and the recovery surface.
                    let reads_a_rule = required.iter().any(|rule| {
                        rule.leaves()
                            .any(|leaf| matches!(leaf, JudgedLeaf::Stored { .. }))
                    });
                    if !reads_a_rule {
                        return Err(AdmissionError::SignatureForGuarded { node: node_index });
                    }
                    let signer = intent
                        .signer
                        .ok_or(AdmissionError::UnsignedEvidence { node: node_index })?;
                    evidence.push(Claim::of_subject(signer));
                }
                EvidenceRef::Node(producer) => {
                    // An earlier node of the same intent, whose proven
                    // claims — the target's own statement, resolved when
                    // that node was judged — are what this proof
                    // presents. A node that proved nothing proves an
                    // empty set, which is nothing to present.
                    let flat = usize::try_from(*producer)
                        .ok()
                        .filter(|&earlier| earlier < local_index)
                        .map(|earlier| self.flat_of[intent_index][earlier])
                        .and_then(|flat| usize::try_from(flat).ok())
                        .ok_or_else(|| AdmissionError::ForwardProof {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            producer: *producer,
                        })?;
                    let claims = self
                        .proven
                        .get(flat)
                        .filter(|claims| !claims.is_empty())
                        .ok_or_else(|| AdmissionError::ProvesNothing {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            producer: *producer,
                        })?;
                    // Charged, because the copy is the cost. A claim is
                    // evaluated once by the node that proves it and then
                    // carried by every later node presenting that node's
                    // proof, so the work an envelope does here is the
                    // product of two caps rather than either of them —
                    // and it is work done at ingress, before a signature
                    // is checked and before anyone has paid for it.
                    self.budget
                        .spend(claims.len())
                        .map_err(|source| AdmissionError::Eval {
                            node: node_index,
                            source,
                        })?;
                    evidence.extend_from_slice(claims);
                }
                EvidenceRef::Socket(reference) => {
                    // A socket the declaration typed and the composition
                    // filled. What is presented is the claim the
                    // *declaration* named — never whatever else the
                    // proving node happened to prove — so a composition
                    // cannot hand an intent authority its signer never
                    // asked for.
                    let Some((
                        Socket::Authority(wanted),
                        Binding::Authority {
                            intent: filled_from,
                            producer,
                        },
                    )) = usize::try_from(*reference).ok().and_then(|position| {
                        Some((
                            intent.sockets.get(position)?,
                            *intent.bindings.get(position)?,
                        ))
                    })
                    else {
                        return Err(AdmissionError::UnknownSocket {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            socket: *reference,
                        });
                    };
                    let source = usize::try_from(filled_from)
                        .ok()
                        .and_then(|source| self.flat_of.get(source))
                        .and_then(|flat| usize::try_from(producer).ok().and_then(|at| flat.get(at)))
                        .and_then(|flat| usize::try_from(*flat).ok())
                        .ok_or_else(|| AdmissionError::UnknownSocket {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            socket: *reference,
                        })?;
                    // The interleave orders a node after every socket it
                    // reaches, so the proving node has been judged and
                    // its claims are in hand.
                    let proven = self
                        .proven
                        .get(source)
                        .expect("the interleave orders the proving node earlier");
                    if !proven.contains(wanted) {
                        return Err(AdmissionError::SocketClaimMismatch {
                            intent: Self::intent_of(intent_index),
                            node: local,
                            socket: *reference,
                        });
                    }
                    evidence.push(*wanted);
                }
            }
        }
        judge_presented(&required, &evidence, node_index)?;
        Ok(evidence)
    }
}

/// Judge every rule this stage can decide, against what the node
/// presented.
///
/// What a node presented is signed content and a claim leaf reads
/// nothing else, so a rule made of them alone is decided here — before
/// anything routes, and before any leg could have committed on the
/// strength of it. The walk judges it again over the same set, where it
/// cannot fail: that redundancy is what lets a frame whose caller
/// commits without waiting carry one at all.
fn judge_presented(
    required: &[&Rule<JudgedLeaf>],
    evidence: &[Claim],
    node_index: u32,
) -> Result<(), AdmissionError> {
    for rule in required
        .iter()
        .filter(|rule| rule.judged() == Judged::AtAdmission)
    {
        let judged = rule.map_leaves(&mut |leaf| match leaf {
            JudgedLeaf::Claim(claim) => Ok(*claim),
            // A rule this stage judges reads claims alone, which is what
            // put it here.
            JudgedLeaf::Presence { .. } | JudgedLeaf::Stored { .. } => {
                Err(AdmissionError::EvidenceUnsatisfied {
                    node: node_index,
                    rule: None,
                    presented: evidence.to_vec(),
                })
            }
        })?;
        if !judged.satisfied_by(evidence) {
            return Err(AdmissionError::EvidenceUnsatisfied {
                node: node_index,
                rule: Some(Box::new(judged)),
                presented: evidence.to_vec(),
            });
        }
    }
    Ok(())
}

/// Judge the denominations against the bound arguments.
///
/// Judged here rather than inside the binding loop, because a
/// denomination is an expression over the *bound* arguments: one naming
/// a later position would evaluate against a parameter that loop has not
/// reached.
fn check_denominations(
    signature: &MethodSignature,
    bound: &[Value],
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<(), AdmissionError> {
    for (position, denomination) in signature.denominations.iter().enumerate() {
        let Some(expr) = denomination else { continue };
        let param = u32::try_from(position).map_err(|_| AdmissionError::TooManyNodes)?;
        let value =
            evaluate_expr(expr, eval_inputs, hasher).map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        let Value::Address(expected) = value else {
            return Err(AdmissionError::DenominationType {
                node: node_index,
                param,
            });
        };
        let expected = ResourceAddr::try_from(expected).map_err(|source| AdmissionError::Eval {
            node: node_index,
            source: source.into(),
        })?;
        // A position the signature denominates and the call filled
        // with something other than an edge is already refused by the
        // kind check above, so what is left here is an edge.
        if let Some(Value::Bucket { resource, .. }) = bound.get(position)
            && *resource != expected
        {
            return Err(AdmissionError::WrongDenomination {
                node: node_index,
                param,
                expected,
                found: *resource,
            });
        }
    }
    Ok(())
}

/// Evaluate the node's declared output projections: the resource and
/// content of each edge it produces.
fn project_outputs(
    signature: &MethodSignature,
    eval_inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    node_index: u32,
) -> Result<Vec<(ResourceAddr, EdgeContent)>, AdmissionError> {
    let mut node_outputs = Vec::with_capacity(signature.outputs.len());
    for (slot, expr) in signature.outputs.iter().enumerate() {
        let slot_index = u32::try_from(slot).map_err(|_| AdmissionError::TooManyNodes)?;
        let value =
            evaluate_expr(expr, eval_inputs, hasher).map_err(|source| AdmissionError::Eval {
                node: node_index,
                source,
            })?;
        // A bare resource address is the fungible projection; a
        // bucket states its content. Nothing else names an edge.
        node_outputs.push(match value {
            Value::Address(resource) => (
                ResourceAddr::try_from(resource).map_err(|source| AdmissionError::Eval {
                    node: node_index,
                    source: source.into(),
                })?,
                EdgeContent::Fungible,
            ),
            Value::Bucket { resource, content } => (resource, content),
            _ => {
                return Err(AdmissionError::OutputType {
                    node: node_index,
                    output: slot_index,
                });
            }
        });
    }
    Ok(node_outputs)
}

/// Refuse a frame whose declared prefix does not answer to the
/// authority it claimed.
///
/// One rule with two halves, and they are the same sentence read in
/// both directions: **an access reaching under no authority names its
/// own prefix, and an access reaching under one names another's.**
///
/// The first half is what bounds a declaration. Without it a package
/// reaches any cell it can name — a stranger's balance among them —
/// with no method's accessibility in the path, because reaching for a
/// cell is not calling the object that owns it.
///
/// The second is what keeps the reach from being a way out of the
/// injections. A reaching access earns no movement requirement of any
/// kind, which is right where the party reached is the one every
/// requirement would fire against and wrong where that party is the
/// frame itself: a component naming its own prefix under an authority
/// would be exempt from its own resources' entries while doing nothing
/// a plain access could not do.
///
/// Both halves are judged on the evaluated effect rather than on the
/// expression that produced it, and the second is the reason that
/// matters. The publish gate refuses an owner spelled `SelfAddr`, so an
/// author hears about it first — but every reach names its owner by
/// argument, so publish sees an expression rather than an address and
/// only the evaluated effect can answer.
///
/// The nullifier a bound subintent spends is not judged here: it sits
/// under its signer's prefix, no signature declared it, and it reaches
/// the routing view as a kernel effect rather than through any frame.
fn judge_prefixes(
    declaration: &Declaration,
    instance: Address,
    node_index: u32,
) -> Result<(), AdmissionError> {
    for (position, access) in declaration.ordered.iter().enumerate() {
        // The clause the access evaluated from, in the numbering the
        // rendered listing uses. Every access here is clause-born — this
        // judgment runs on the frame as evaluated, before anything is
        // injected beside it — and the evaluated position stands in for
        // the impossible remainder rather than panicking over it.
        let clause = access
            .clause
            .unwrap_or_else(|| u32::try_from(position).unwrap_or(u32::MAX));
        let owner = access.effect.target.owner();
        match (access.reach.is_some(), owner == instance) {
            (false, false) => {
                return Err(AdmissionError::ForeignDeclaration {
                    node: node_index,
                    clause,
                    owner,
                });
            }
            (true, true) => {
                return Err(AdmissionError::ReachesItself {
                    node: node_index,
                    clause,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

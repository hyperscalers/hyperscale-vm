//! The manifest walk: one transaction's lowered invocations performed in
//! order, each one's arguments assembled from the capability table and
//! the cells its producers returned.
//!
//! This is the whole of what "running a transaction" means, and it lives
//! here rather than in an embedder because it is manifest semantics: what
//! a handle argument is, what a returned blob means, when an emitter is
//! entered and left. What an embedder still owns is the engine —
//! [`GuestBackend`] takes a call and a session and gives back a session
//! with how the export ended — the edges it produced, a declined code,
//! or an abort. An embedder can get engine embedding wrong; it cannot
//! get manifest semantics wrong.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_hbor::Bytes;
use hyperscale_vm_effects::{
    CallArg, EdgeContent, JudgedLeaf, NodeCall, PackageHash, Rule, RuleBytes,
};
use hyperscale_vm_embed::{GuestArg, Invoked};
use hyperscale_vm_types::{
    AbortReason, Address, Answer, MAX_ANSWER_BYTES, MAX_ERROR_CODES, Outcome, Presence,
    SubstateKey, UnmetCondition,
};

use crate::escrow::LegPlan;
use crate::executor::{BatchTx, GuestRunner, Job, RunResult, Unavailable};
use crate::session::{Held, KernelSession, SessionTrap};

/// One export invocation, fully assembled.
pub struct GuestCall<'a> {
    /// The package whose code runs; content-addressed, so a backend
    /// resolves the artifact by this and never by the instance address.
    pub package: PackageHash,
    /// The instance invoked — diagnostics only; the emitter the session
    /// stamps is already entered.
    pub target: Address,
    /// The export name.
    pub export: &'a str,
    /// The arguments, in the export's own order.
    pub args: &'a [GuestArg<'a>],
    /// The node's own signed ceiling. The backend meters this invocation
    /// against it and nothing else: a manifest's nodes each carry their
    /// own, so one node's slack is never another's to spend.
    pub fuel_budget: u64,
}

/// What one invocation produced: the session back from the engine, the
/// fuel consumed, and how it ended.
pub struct InvokeResult {
    /// The session, which always survives for the kernel's rollback.
    pub session: KernelSession,
    /// Fuel consumed by this invocation.
    pub fuel: u64,
    /// How the invocation ended.
    pub result: Invoked,
}

/// The engine embedding: instantiate the named package and invoke one of
/// its exports.
pub trait GuestBackend: Sync {
    /// Invoke `call` with `session` threaded through the engine's host
    /// state.
    fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult;
}

/// The kernel's [`GuestRunner`]: walk a transaction's lowered
/// invocations, node by node, over any backend.
pub struct ManifestWalk<'a, B: ?Sized> {
    /// The engine behind every invocation.
    pub backend: &'a B,
}

/// A node's invocation did not produce edges.
enum NodeFailure {
    /// The transaction failed, deterministically: its outcome and what it
    /// spent. The session comes back for the executor's rollback; boxed
    /// because it is large and this path is cold.
    Abort(Box<(KernelSession, Outcome, u64)>),
    /// The environment could not run the node — no verdict exists, and
    /// the walk refuses the batch rather than pricing the transaction.
    /// Names the package whose code the environment wanted, which is the
    /// one thing an embedder can act on.
    Unavailable(PackageHash, AbortReason),
}

/// A node's invocation succeeded: the session, the edges it produced,
/// whatever it answered with, and the fuel it consumed.
type NodeSuccess = (
    KernelSession,
    Vec<u32>,
    Option<Bytes<MAX_ANSWER_BYTES>>,
    u64,
);

impl NodeFailure {
    /// The walk's own answer to this failure, appended to what the
    /// nodes before it spent.
    fn into_result(self, mut spent: Vec<u64>) -> Result<RunResult, Unavailable> {
        match self {
            Self::Abort(failure) => {
                let (session, outcome, consumed) = *failure;
                spent.push(consumed);
                Ok(RunResult::Aborted {
                    session,
                    outcome,
                    spent,
                })
            }
            Self::Unavailable(package, reason) => Err(Unavailable(package, reason)),
        }
    }
}

fn fail(session: KernelSession, outcome: Outcome, fuel: u64) -> NodeFailure {
    NodeFailure::Abort(Box::new((session, outcome, fuel)))
}

/// A defect in whoever composed the batch: a lowered call that does not
/// fit the declaration materialized beside it. Priced to nobody — the
/// sender did not cause it.
fn composition_defect(session: KernelSession, reason: AbortReason) -> NodeFailure {
    fail(session, Outcome::ProtocolError { reason }, 0)
}

impl<B: GuestBackend + ?Sized> ManifestWalk<'_, B> {
    fn invoke_node(
        &self,
        node: u32,
        call: &NodeCall,
        outputs: &[Vec<Option<u32>>],
        fuel_budget: u64,
        event_bytes: usize,
        session: KernelSession,
    ) -> Result<NodeSuccess, NodeFailure> {
        // The gate and the signed bounds are the walk's own judgment
        // over the transaction's tables, made before the frame opens.
        let session = gated(call, node, session)?;
        let mut session = edge_bounds_hold(call, node, outputs, session)?;

        // The node names its target, and every emission of this frame is
        // attributed to it — the session holds one capability table for
        // the whole transaction, and what tells it whose call is running
        // is what the frame is lent from here on: the sites bound and the
        // edges lent below are the whole of what the body can name.
        session.enter_invocation(call.target, event_bytes);

        let mut args = Vec::with_capacity(call.args.len());
        for arg in &call.args {
            match arg {
                // One site per handle parameter, whatever its width: the
                // entries were resolved where the declaration was
                // evaluated, so the session is handed what the site
                // covers rather than a rule for finding it.
                CallArg::Site { entries } => {
                    // A rep names a position the whole transaction's
                    // declaration fixed, so one past the table is a
                    // composition defect rather than a guest's.
                    if entries.iter().flatten().any(|rep| {
                        usize::try_from(*rep)
                            .ok()
                            .and_then(|index| session.capabilities().get(index))
                            .is_none()
                    }) {
                        return Err(composition_defect(
                            session,
                            AbortReason::CapabilityOutOfRange,
                        ));
                    }
                    let site = session.bind_site(entries.clone());
                    args.push(GuestArg::Site { site });
                }
                CallArg::Bucket { source, output } => {
                    let Some(produced) = edge_at(outputs, *source, *output) else {
                        return Err(composition_defect(
                            session,
                            AbortReason::MissingProducerEdge,
                        ));
                    };
                    session.lend_bucket(produced);
                    args.push(GuestArg::Bucket(produced));
                }
                CallArg::Bool(taken) => args.push(GuestArg::Bool(*taken)),
                CallArg::U64(scalar) => args.push(GuestArg::U64(*scalar)),
                CallArg::Address(address) => args.push(GuestArg::Address(*address)),
                CallArg::Bytes(bytes) => args.push(GuestArg::Bytes(bytes)),
                CallArg::Ids(ids) => args.push(GuestArg::Ids(ids)),
            }
        }

        // Issuance is one node's, read off the issuances its signature
        // declares — in that order, which is the index its body names.
        // Who may is already settled: each resource's own entry was
        // injected onto this frame and judged with the rest of its gate,
        // so a body that reaches here reaches rights somebody granted.
        session.grant_issuance(call.issues.clone());

        let invoked = self.backend.invoke(
            session,
            &GuestCall {
                package: call.package,
                target: call.target,
                export: &call.export,
                args: &args,
                fuel_budget,
            },
        );
        settled(node, call, invoked)
    }
}

/// What one invocation left behind: the edges it produced, or the
/// outcome it failed with.
///
/// Separate from assembling the call because the two read different
/// halves of the node — what goes in comes from the declaration, and
/// what comes back is the artifact's own answer.
fn settled(node: u32, call: &NodeCall, invoked: InvokeResult) -> Result<NodeSuccess, NodeFailure> {
    let session = invoked.session;
    match invoked.result {
        // Edges come back as the buckets the kernel holds again, one per
        // declared output. A count that disagrees with the declaration is
        // a package whose code and signature part company — and so is a
        // non-fungible edge carrying ids other than the declaration's,
        // which are what admission keyed the instance cells by and what
        // a consumer routed on.
        Invoked::Produced {
            edges: reps,
            answer,
        } if reps.len() == call.outputs.len() => {
            for (rep, expected) in reps.iter().zip(&call.outputs) {
                let carried = session.bucket(*rep);
                let (declared_ids, carried_ids) = match (expected, carried) {
                    // A fungible edge's quantity is dynamic, so the
                    // declaration says only that one crosses; what it
                    // carries is the consumer's signed bound to judge.
                    (EdgeContent::Fungible, Ok(Held::Amount(_))) => continue,
                    (EdgeContent::NonFungible { ids }, Ok(Held::Instances(carried))) => {
                        (ids, carried)
                    }
                    // A bucket of the other shape than the output
                    // projected is a package whose code and signature
                    // part company, on the terms a wrong arity has.
                    _ => {
                        return Err(fail(
                            session,
                            Outcome::UserError {
                                reason: AbortReason::BadReturnShape,
                            },
                            invoked.fuel,
                        ));
                    }
                };
                let declared: BTreeSet<u128> =
                    declared_ids.iter().copied().map(u128::from).collect();
                if carried_ids != declared {
                    return Err(fail(
                        session,
                        Outcome::UserError {
                            reason: AbortReason::WrongMintedIds,
                        },
                        invoked.fuel,
                    ));
                }
            }
            // An answer is the declaration's to promise: a method that
            // says it answers and hands nothing back, or hands something
            // back it never declared, is a package whose code and
            // signature part company, on the terms a wrong arity has.
            if answer.is_some() != call.answers {
                return Err(fail(
                    session,
                    Outcome::UserError {
                        reason: AbortReason::BadReturnShape,
                    },
                    invoked.fuel,
                ));
            }
            // What a method answered with rides the receipt, so the
            // width one may carry is the vocabulary's rather than the
            // guest's: the answer's type holds the cap, and a value past
            // it is refused here, where it comes back, so an oversized
            // answer is a deterministic verdict every node reaches alike
            // instead of an encoding nothing downstream could hold.
            let answer = match answer.map(Bytes::new) {
                None => None,
                Some(Ok(value)) => Some(value),
                Some(Err(_)) => {
                    return Err(fail(
                        session,
                        Outcome::UserError {
                            reason: AbortReason::AnswerTooLarge,
                        },
                        invoked.fuel,
                    ));
                }
            };
            Ok((session, reps, answer, invoked.fuel))
        }
        Invoked::Produced { .. } => Err(fail(
            session,
            Outcome::UserError {
                reason: AbortReason::BadReturnShape,
            },
            invoked.fuel,
        )),
        // A decline is charged its own fuel, not the ceiling: the export
        // returned, so the figure is an ordinary completed-invocation one
        // and both engines reach it by construction. A code no package
        // could have declared is a defect in the guest rather than a
        // refusal, bounded here without the table the kernel does not
        // hold.
        Invoked::Declined(code) if code < MAX_ERROR_CODES => Err(fail(
            session,
            Outcome::Declined { node, code },
            invoked.fuel,
        )),
        Invoked::Declined(_) => Err(fail(
            session,
            Outcome::UserError {
                reason: AbortReason::ErrorCodeOutOfRange,
            },
            invoked.fuel,
        )),
        // A body reaching a cell outside its member's scope is not the
        // guest's defect but the classification's, which let a divided
        // member hold a handle on another member's cell: the protocol's
        // to answer for, like a record it cannot read.
        Invoked::Aborted(AbortReason::OutsideScope) => Err(fail(
            session,
            Outcome::ProtocolError {
                reason: AbortReason::OutsideScope,
            },
            invoked.fuel,
        )),
        // A credit the cell's width could not hold is the same lost
        // race the fold refuses a queued one as — the floor is the
        // state's, not the body's — so it is priced as one, naming the
        // cell and the amount the session recorded when it refused.
        Invoked::Aborted(AbortReason::CellOverflow) => {
            let mut session = session;
            let outcome = session.take_lost_floor().map_or(
                Outcome::UserError {
                    reason: AbortReason::CellOverflow,
                },
                |(key, amount)| Outcome::Infeasible { key, amount },
            );
            Err(fail(session, outcome, invoked.fuel))
        }
        // What a trapped invocation spent is what the meter's counter
        // gave up, exact at every ending: a block is paid for whole
        // before it runs, and exhaustion spends the counter whole, so a
        // node that ran out reports its allowance on either engine.
        Invoked::Aborted(reason) => Err(fail(session, Outcome::UserError { reason }, invoked.fuel)),
        Invoked::Unavailable(reason) => Err(NodeFailure::Unavailable(call.package, reason)),
    }
}

/// Check every signed edge bound a node consumes, before anything runs.
///
/// The check is the node's, not the callee's: a producer returning less
/// than the consumer declared fails the transaction whatever the
/// producer's own code checked, and a node that forwards its funds
/// onward never sees the amount its signer bounded. A non-fungible edge
/// is judged over its id count, the quantity its cell carries in place
/// of an amount.
fn edge_bounds_hold(
    call: &NodeCall,
    node: u32,
    outputs: &[Vec<Option<u32>>],
    session: KernelSession,
) -> Result<KernelSession, NodeFailure> {
    for edge in &call.edges {
        let Some(carried) = edge_at(outputs, edge.source, edge.output) else {
            return Err(composition_defect(
                session,
                AbortReason::MissingProducerEdge,
            ));
        };
        let Some(amount) = session.bucket(carried).ok().map(|held| held.quantity()) else {
            return Err(composition_defect(
                session,
                AbortReason::MissingProducerEdge,
            ));
        };
        if !edge.bounds.admits(amount) {
            return Err(fail(
                session,
                Outcome::ConstraintUnmet {
                    node,
                    param: edge.param,
                    amount,
                },
                0,
            ));
        }
    }
    Ok(session)
}

/// Stand in for a producer this shard does not run.
///
/// The output table is sized from the node's **own** declared outputs and
/// never from the plan: a plan naming an out-of-range output is a
/// composition defect, where sizing to the plan would let the plan pick
/// the width and so let a smaller one pass as a correct answer. Slots
/// nothing crossed on stay unset and meet the ordinary missing-edge
/// refusal at whoever reaches for them.
///
/// Nothing else of the node happens here. The gate, the signed edge
/// bounds, the issuance grants and the fuel all belong to the shard that
/// ran it, and every downstream reader asks the output table rather than
/// asking about locality.
fn claimed_outputs(
    node: u32,
    call: &NodeCall,
    legs: &LegPlan,
    mut session: KernelSession,
) -> Result<(KernelSession, Vec<Option<u32>>), NodeFailure> {
    let mut produced = vec![None; call.outputs.len()];
    for (slot, taken) in produced.iter_mut().enumerate() {
        let output = u32::try_from(slot).unwrap_or(u32::MAX);
        let Some(arrival) = legs.arrival(node, output) else {
            continue;
        };
        match session.escrow_in(arrival.crossed, arrival.claim, arrival.record) {
            Ok(rep) => *taken = Some(rep),
            Err(trap) => {
                return Err(fail(
                    session,
                    Outcome::UserError {
                        reason: trap.into(),
                    },
                    0,
                ));
            }
        }
    }
    Ok((session, produced))
}

/// Issue what leaves this execution, after the node that produced it
/// returned.
///
/// The bucket is consumed here, so an edge that departs is not also an
/// edge a local consumer could take — which is what keeps one output
/// from being both crossed and spent.
fn departing(
    node: u32,
    legs: &LegPlan,
    produced: Vec<u32>,
    mut session: KernelSession,
    consumed: u64,
) -> Result<(KernelSession, Vec<Option<u32>>), NodeFailure> {
    let mut kept = Vec::with_capacity(produced.len());
    for (slot, rep) in produced.into_iter().enumerate() {
        let output = u32::try_from(slot).unwrap_or(u32::MAX);
        let Some(departure) = legs.departure(node, output) else {
            kept.push(Some(rep));
            continue;
        };
        match session.escrow_out(node, output, rep, departure) {
            Ok(_) => kept.push(None),
            Err(trap) => {
                // A departure refused for the plan's shape is the batch's
                // defect wherever it is raised, which is the class the
                // settlement path already gives these two. What the guest
                // did with its bucket is its own.
                let outcome = match trap {
                    SessionTrap::EscrowCreditUndeclared(_)
                    | SessionTrap::CrossingKeyRepeated(_) => Outcome::ProtocolError {
                        reason: trap.into(),
                    },
                    other => Outcome::UserError {
                        reason: other.into(),
                    },
                };
                return Err(fail(session, outcome, consumed));
            }
        }
    }
    Ok((session, kept))
}

/// The edge a producer left on one of its outputs.
///
/// Absent two ways and one of them is new: a slot the producer never
/// declared, and a slot a producer another shard ran left empty because
/// nothing crossed on it. Both are a consumer reaching for value nobody
/// produced, so both meet the same refusal.
fn edge_at(outputs: &[Vec<Option<u32>>], source: u32, output: u32) -> Option<u32> {
    let produced = usize::try_from(source).ok().and_then(|i| outputs.get(i))?;
    usize::try_from(output)
        .ok()
        .and_then(|slot| produced.get(slot))
        .copied()
        .flatten()
}

/// Judge a call's gate, returning the session to whichever path owns it
/// next.
fn gated(
    call: &NodeCall,
    node: u32,
    mut session: KernelSession,
) -> Result<KernelSession, NodeFailure> {
    // One decode per (cell, role) across the node's whole judgment: a
    // rule may name the same cell at every one of its leaves, and the
    // cells a gate reads are committed state no body has run against
    // yet, so the verdict cannot move between two leaves asking for it.
    let mut judged: BTreeMap<SubstateKey, bool> = BTreeMap::new();
    for rule in &call.requires {
        match satisfies(rule, call, &mut session, &mut judged) {
            Ok(true) => {}
            Ok(false) => {
                return Err(fail(
                    session,
                    Outcome::ConditionUnmet {
                        condition: UnmetCondition::Satisfies { node },
                    },
                    0,
                ));
            }
            Err(_) => {
                return Err(composition_defect(
                    session,
                    AbortReason::AuthorityCellUnreadable,
                ));
            }
        }
    }
    Ok(session)
}

/// Whether the call's presented claims satisfy a required rule.
///
/// A claim leaf is a pure match against the proven claims. A stored
/// leaf reads the cell the declaration provisioned and judges the rule
/// stored there against the same presented claims — so a declared rule
/// reaches stored rules exactly one level deep, which is what
/// `Rule<Claim>` guarantees by construction. Recursion is bounded by the rule caps
/// the publish check held the tree to.
///
/// `judged` carries the verdicts already reached in this node's
/// judgment. A rule the caps admit has far more leaves than the cells
/// they can name, and each leaf's cost is a decode of the whole stored
/// table, which is what the footprint charges for once as a single
/// read.
fn satisfies(
    rule: &Rule<JudgedLeaf>,
    call: &NodeCall,
    session: &mut KernelSession,
    judged: &mut BTreeMap<SubstateKey, bool>,
) -> Result<bool, SessionTrap> {
    match rule {
        Rule::Require(JudgedLeaf::Claim(claim)) => Ok(call.evidence.contains(claim)),
        // A sign-in is the account's shard's to judge, from the cell as
        // read at materialization, and admission never routes one here.
        // Fails closed with the other leaves this judge cannot read.
        Rule::Require(JudgedLeaf::Signed { .. }) => Ok(false),
        Rule::Require(JudgedLeaf::Presence { target, expect }) => Ok(match expect {
            Presence::Either => true,
            Presence::Absent => !session.declared_present(*target)?,
            Presence::Present => session.declared_present(*target)?,
        }),
        Rule::Require(JudgedLeaf::Stored { cell }) => {
            if let Some(verdict) = judged.get(cell) {
                return Ok(*verdict);
            }
            let bytes = session.declared_cell(*cell)?;
            // An unwritten cell holds no rule, and no rule admits
            // nobody: what governs a cell before anything is written
            // there is the package's own business, stated as a rule
            // beside this one — so the kernel reads what is there and
            // nothing else. Bytes that do not decode are not a rule
            // either, so a cell that cannot be read fails closed.
            // A rule asking about a holding is the third way to be
            // unreadable here: this judge holds the call's evidence and
            // nothing about who holds what, so it fails closed with the
            // other two rather than answering the part it can see.
            let verdict = !bytes.is_empty()
                && RuleBytes::rule_in_cell(&bytes)
                    .ok()
                    .and_then(|rule| rule.claims_only())
                    .is_some_and(|claims| claims.satisfied_by(&call.evidence));
            judged.insert(*cell, verdict);
            Ok(verdict)
        }
        Rule::CountOf { count, rules } => {
            let mut met = 0usize;
            for rule in rules {
                if satisfies(rule, call, session, judged)? {
                    met += 1;
                }
            }
            Ok(met >= usize::from(*count))
        }
    }
}

/// Run a job that invokes no node: what it writes, in order, or the
/// first trap that stops it.
///
/// A settlement, a refusal and a deletion are the three of them. None
/// costs fuel, none reaches a guest, and so none can refuse for a
/// guest's reason — what each can refuse for is its own cells, which is
/// the batch's defect and not the transaction's.
fn walk_cells(
    mut session: KernelSession,
    mut each: impl FnMut(&mut KernelSession) -> Result<(), SessionTrap>,
) -> RunResult {
    if let Err(trap) = each(&mut session) {
        let outcome = match trap {
            SessionTrap::EscrowRecordUnreadable(_)
            | SessionTrap::EscrowCreditUndeclared(_)
            | SessionTrap::CrossingAnswerUnreadable(_) => Outcome::ProtocolError {
                reason: trap.into(),
            },
            other => Outcome::UserError {
                reason: other.into(),
            },
        };
        return RunResult::Aborted {
            session,
            outcome,
            spent: Vec::new(),
        };
    }
    RunResult::Completed {
        session,
        answers: Vec::new(),
        spent: Vec::new(),
    }
}

impl<B: GuestBackend + ?Sized> GuestRunner for ManifestWalk<'_, B> {
    fn run(&self, entry: &BatchTx, mut session: KernelSession) -> Result<RunResult, Unavailable> {
        let (calls, legs) = match &entry.job {
            // The records this member disposes of: read, credited back
            // or retired, deleted.
            Job::Records(disposals) => {
                return Ok(walk_cells(session, |session| {
                    disposals
                        .iter()
                        .try_for_each(|disposal| session.escrow_settle(disposal))
                }));
            }
            // The crossings it refuses: one cell each, saying a value
            // handed here will never be taken.
            Job::Refusals(refusals) => {
                return Ok(walk_cells(session, |session| {
                    refusals
                        .iter()
                        .try_for_each(|refusal| session.escrow_refuse(refusal))
                }));
            }
            // The answer cells it deletes: crossings this shard answered
            // whose records their producers have since disposed of.
            Job::Deletions(deletions) => {
                return Ok(walk_cells(session, |session| {
                    deletions
                        .iter()
                        .try_for_each(|deletion| session.escrow_delete(deletion))
                }));
            }
            // The tombstones its grace has run out on, removed.
            Job::Tombstones(keys) => {
                return Ok(walk_cells(session, |session| {
                    keys.iter().try_for_each(|key| session.escrow_sweep(*key))
                }));
            }
            // This shard's obligation ledger brought in line: notes
            // written for crossings it was handed, notes removed where
            // the answer they were waiting for stands.
            Job::Obligations(work) => {
                return Ok(walk_cells(session, |session| {
                    work.owe
                        .iter()
                        .try_for_each(|refusal| session.escrow_owe(refusal))?;
                    work.disown
                        .iter()
                        .try_for_each(|key| session.escrow_disown(*key))
                }));
            }
            Job::Manifest { calls, legs } => (calls, legs),
        };
        let mut outputs: Vec<Vec<Option<u32>>> = Vec::with_capacity(calls.len());
        let mut answers: Vec<Answer> = Vec::new();
        // What each node consumed, in node order: the receipt's report,
        // not a budget. Each node is metered against its own signed
        // ceiling, so what a composer needs back is where the fuel went
        // rather than the total, which is the fold. A node this member
        // does not run spends nothing and still takes its place, so the
        // vector is read by node index — one figure per node attempted,
        // whichever arm ends it, since a composer maps ceilings onto it
        // one for one.
        let mut spent: Vec<u64> = Vec::with_capacity(calls.len());
        for (index, call) in calls.iter().enumerate() {
            let node = u32::try_from(index).unwrap_or(u32::MAX);
            // A node another shard runs is not invoked here. What stands
            // in for it is the value that arrived, which costs no fuel,
            // reaches no gate, judges no signed bound and takes no
            // issuance grant — every one of those belongs to the shard
            // that ran it.
            if !legs.runs(node) {
                match claimed_outputs(node, call, legs, session) {
                    Ok((returned, produced)) => {
                        session = returned;
                        outputs.push(produced);
                        spent.push(0);
                        continue;
                    }
                    Err(failure) => return failure.into_result(spent),
                }
            }
            // A node without a ceiling or an event bound is a batch
            // composed against some other call list: the derivation holds
            // every envelope to one of each per node, so this is the
            // composer's defect.
            let (Some(ceiling), Some(emits)) = (entry.ceiling(index), entry.event_bound(index))
            else {
                return composition_defect(session, AbortReason::MissingCeiling).into_result(spent);
            };
            match self.invoke_node(node, call, &outputs, ceiling, emits, session) {
                Ok((returned, produced, answered, consumed)) => {
                    session = returned;
                    session.leave_invocation();
                    match departing(node, legs, produced, session, consumed) {
                        Ok((returned, produced)) => {
                            session = returned;
                            spent.push(consumed);
                            outputs.push(produced);
                        }
                        // The node ran and then its departure refused, so
                        // what it spent is reported by the failure that
                        // ends it — once, as on every other arm.
                        Err(failure) => return failure.into_result(spent),
                    }
                    if let Some(value) = answered {
                        answers.push(Answer { node, value });
                    }
                }
                Err(NodeFailure::Abort(failure)) => {
                    let (returned, outcome, consumed) = *failure;
                    spent.push(consumed);
                    return Ok(RunResult::Aborted {
                        session: returned,
                        outcome,
                        spent,
                    });
                }
                Err(NodeFailure::Unavailable(package, reason)) => {
                    return Err(Unavailable(package, reason));
                }
            }
        }
        Ok(RunResult::Completed {
            session,
            answers,
            spent,
        })
    }
}

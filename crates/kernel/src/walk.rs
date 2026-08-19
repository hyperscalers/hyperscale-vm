//! The manifest walk: one transaction's lowered invocations performed in
//! order, each one's arguments assembled from the capability table and
//! the cells its producers returned.
//!
//! This is the whole of what "running a transaction" means, and it lives
//! here rather than in an embedder because it is manifest semantics: what
//! a handle argument is, what a returned blob means, when an emitter is
//! entered and left. What an embedder still owns is the engine —
//! [`GuestBackend`] takes a call and a session and gives back a session
//! with either the export's bytes or a trap. An embedder can get engine
//! embedding wrong; it cannot get manifest semantics wrong.

use hyperscale_vm_effects::{
    AuthCell, AuthRole, AuthorityGate, CallArg, NodeCall, PackageHash, Possession,
};
use hyperscale_vm_embed::{GuestArg, Invoked};
use hyperscale_vm_types::{ABSENT_REP, AbortReason, Address, MAX_ERROR_CODES, Outcome};

use crate::executor::{BatchTx, GuestRunner, RunResult, Unavailable};
use crate::modes::decode_amount;
use crate::session::{KernelSession, SessionTrap};

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
    /// What is left of the transaction's signed ceiling. The backend
    /// meters this invocation against it, so a manifest's nodes share one
    /// budget rather than each getting the whole of it.
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
    /// Whether the invocation ended by exhausting its fuel budget.
    ///
    /// Reported as a flag rather than read out of the reason text: each
    /// engine words its own trap, and the classification is consensus
    /// content that has to be identical on both.
    pub exhausted: bool,
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
pub struct ManifestWalk<'a, B> {
    /// The engine behind every invocation.
    pub backend: &'a B,
}

/// How a trapped invocation reads: its outcome and what it spent.
///
/// One figure for exhaustion, whichever engine reported it. The counter
/// standing at a trap is engine-defined — one flushes an in-register
/// total, the other charges every operator — so a node that spent its
/// allowance reports the allowance. It could not have consumed more, and
/// both engines agree on that by construction rather than by happening to
/// count the same.
///
/// The class comes from the backend, which already classified the failure
/// against its own engine; the exhaustion flag decides only what is
/// charged.
const fn trapped(exhausted: bool, reason: AbortReason, budget: u64, spent: u64) -> (Outcome, u64) {
    let charged = if exhausted { budget } else { spent };
    (Outcome::UserError { reason }, charged)
}

/// A node's invocation did not produce edges.
enum NodeFailure {
    /// The transaction failed, deterministically: its outcome and what it
    /// spent. The session comes back for the executor's rollback; boxed
    /// because it is large and this path is cold.
    Abort(Box<(KernelSession, Outcome, u64)>),
    /// The environment could not run the node — no verdict exists, and
    /// the walk refuses the batch rather than pricing the transaction.
    Unavailable(AbortReason),
}

/// A node's invocation succeeded: the session, the edges it produced, and
/// the fuel it consumed.
type NodeSuccess = (KernelSession, Vec<u32>, u64);

fn fail(session: KernelSession, outcome: Outcome, fuel: u64) -> NodeFailure {
    NodeFailure::Abort(Box::new((session, outcome, fuel)))
}

/// A defect in whoever composed the batch: a lowered call that does not
/// fit the declaration materialized beside it. Priced to nobody — the
/// sender did not cause it.
fn composition_defect(session: KernelSession, reason: AbortReason) -> NodeFailure {
    fail(session, Outcome::ProtocolError { reason }, 0)
}

impl<B: GuestBackend> ManifestWalk<'_, B> {
    fn invoke_node(
        &self,
        node: u32,
        call: &NodeCall,
        outputs: &[Vec<u32>],
        fuel_budget: u64,
        mut session: KernelSession,
    ) -> Result<NodeSuccess, NodeFailure> {
        // The node names its target, and every emission of this frame is
        // attributed to it — the session holds one capability table for
        // the whole transaction and cannot tell whose call is running.
        session.enter_invocation(call.target);

        let session = gated(call, node, session)?;
        let mut session = edge_bounds_hold(call, node, outputs, session)?;

        let mut args = Vec::with_capacity(call.args.len());
        for arg in &call.args {
            match arg {
                CallArg::Handle(rep) => {
                    let Some(capability) = usize::try_from(*rep)
                        .ok()
                        .and_then(|index| session.capabilities().get(index))
                    else {
                        return Err(composition_defect(
                            session,
                            AbortReason::CapabilityOutOfRange,
                        ));
                    };
                    args.push(GuestArg::Handle {
                        rep: *rep,
                        kind: capability.kind(),
                    });
                }
                CallArg::Bucket { source, output } => {
                    let Some(produced) = edge_at(outputs, *source, *output) else {
                        return Err(composition_defect(
                            session,
                            AbortReason::MissingProducerEdge,
                        ));
                    };
                    args.push(GuestArg::Bucket(*produced));
                }
                CallArg::AbsentHandle(kind) => args.push(GuestArg::Handle {
                    rep: ABSENT_REP,
                    kind: *kind,
                }),
                CallArg::Bool(taken) => args.push(GuestArg::Bool(*taken)),
                CallArg::Issuer => args.push(GuestArg::Issuer),
                CallArg::U64(scalar) => args.push(GuestArg::U64(*scalar)),
                CallArg::Address(address) => args.push(GuestArg::Address(*address)),
                CallArg::Bytes(bytes) => args.push(GuestArg::Bytes(bytes)),
                CallArg::Ids(ids) => args.push(GuestArg::Ids(ids)),
            }
        }

        // Issuance is one node's, read off the outputs it declared: a
        // method producing a resource derived from its own address is a
        // method saying it issues one.
        if let Some(resource) = call.issues {
            session.grant_issuance(resource);
        }

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
        settled(node, call, invoked, fuel_budget)
    }
}

/// What one invocation left behind: the edges it produced, or the
/// outcome it failed with.
///
/// Separate from assembling the call because the two read different
/// halves of the node — what goes in comes from the declaration, and
/// what comes back is the artifact's own answer.
fn settled(
    node: u32,
    call: &NodeCall,
    invoked: InvokeResult,
    fuel_budget: u64,
) -> Result<NodeSuccess, NodeFailure> {
    let session = invoked.session;
    match invoked.result {
        // Edges come back as the buckets the kernel holds again, one per
        // declared output. A count that disagrees with the declaration is
        // a package whose code and signature part company.
        Invoked::Produced(reps) if reps.len() == call.outputs.len() => {
            Ok((session, reps, invoked.fuel))
        }
        Invoked::Produced(_) => Err(fail(
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
        Invoked::Aborted(reason) => {
            let (outcome, spent) = trapped(invoked.exhausted, reason, fuel_budget, invoked.fuel);
            Err(fail(session, outcome, spent))
        }
        Invoked::Unavailable(reason) => Err(NodeFailure::Unavailable(reason)),
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
    outputs: &[Vec<u32>],
    session: KernelSession,
) -> Result<KernelSession, NodeFailure> {
    for edge in &call.edges {
        let Some(carried) = edge_at(outputs, edge.source, edge.output) else {
            return Err(composition_defect(
                session,
                AbortReason::MissingProducerEdge,
            ));
        };
        let Some(amount) = session.bucket(*carried).ok().map(|held| held.quantity()) else {
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

/// The edge a producer left on one of its outputs.
fn edge_at(outputs: &[Vec<u32>], source: u32, output: u32) -> Option<&u32> {
    let produced = usize::try_from(source).ok().and_then(|i| outputs.get(i))?;
    usize::try_from(output)
        .ok()
        .and_then(|slot| produced.get(slot))
}

/// Judge a call's gate, returning the session to whichever path owns it
/// next.
fn gated(
    call: &NodeCall,
    node: u32,
    mut session: KernelSession,
) -> Result<KernelSession, NodeFailure> {
    match authorized(call, &mut session) {
        Ok(true) => Ok(session),
        Ok(false) => Err(fail(session, Outcome::Unauthorized { node }, 0)),
        Err(_) => Err(composition_defect(
            session,
            AbortReason::AuthorityCellUnreadable,
        )),
    }
}

/// Whether a call's presented identities satisfy its gate.
///
/// Admission has already checked that a guarded call presents something;
/// what remains is whether it presents *enough*, which is the target's
/// own question and is asked where the target is. An identity gate is a
/// pure match. A stored-rule gate reads the target's cell — declared by
/// the method itself, so provisioned wherever this runs — and hands the
/// bytes to [`AuthCell::admits`], the verdict this gate shares with the
/// payer shard's binding check, judged at the transaction clock.
fn authorized(call: &NodeCall, session: &mut KernelSession) -> Result<bool, SessionTrap> {
    match &call.authority {
        None => Ok(true),
        Some(AuthorityGate::Presented(rule)) => Ok(rule.satisfied_by(&call.evidence)),
        &Some(AuthorityGate::StoredRule { cell, role }) => {
            let bytes = session.declared_cell(cell)?;
            let clock = session.clock_ms();
            Ok(AuthCell::admits(
                &bytes,
                call.target,
                role,
                &call.evidence,
                clock,
            ))
        }
        &Some(AuthorityGate::Custody { cell, possession }) => {
            // The holder acts — its stored primary judges the presented
            // set exactly as a sign-in would — and the holder holds what
            // the claim names: value in the badge-keyed vault, or the
            // instance at its own id. Anything but a well-formed
            // non-zero amount cell reads as not held; a corrupt vault
            // grants nothing.
            let bytes = session.declared_cell(cell)?;
            let clock = session.clock_ms();
            if !AuthCell::admits(
                &bytes,
                call.target,
                AuthRole::Primary,
                &call.evidence,
                clock,
            ) {
                return Ok(false);
            }
            match possession {
                Possession::Vault(vault) => {
                    let amount = session.declared_cell(vault)?;
                    Ok(decode_amount(&amount).is_ok_and(|held| held > 0))
                }
                Possession::Instance {
                    owner,
                    holdings,
                    id,
                } => session.declared_holds_instance(owner, holdings, u128::from(id)),
            }
        }
    }
}

impl<B: GuestBackend> GuestRunner for ManifestWalk<'_, B> {
    fn run(&self, entry: &BatchTx, mut session: KernelSession) -> Result<RunResult, Unavailable> {
        let mut outputs: Vec<Vec<u32>> = Vec::with_capacity(entry.calls.len());
        let mut fuel = 0u64;
        for (index, call) in entry.calls.iter().enumerate() {
            let node = u32::try_from(index).unwrap_or(u32::MAX);
            // One budget across the manifest: each node is metered
            // against what its predecessors left.
            let remaining = entry.gas_limit.saturating_sub(fuel);
            match self.invoke_node(node, call, &outputs, remaining, session) {
                Ok((returned, produced, consumed)) => {
                    session = returned;
                    session.leave_invocation();
                    fuel = fuel.saturating_add(consumed);
                    outputs.push(produced);
                }
                Err(NodeFailure::Abort(failure)) => {
                    let (returned, outcome, consumed) = *failure;
                    return Ok(RunResult::Aborted {
                        session: returned,
                        outcome,
                        fuel: fuel.saturating_add(consumed),
                    });
                }
                Err(NodeFailure::Unavailable(reason)) => return Err(Unavailable(reason)),
            }
        }
        Ok(RunResult::Completed {
            session,
            value: None,
            fuel,
        })
    }
}

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
    Address, AuthCell, AuthorityGate, CallArg, EDGE_CELL_BYTES, NodeCall, PackageHash,
};

use crate::executor::{BatchTx, GuestRunner, RunResult};
use crate::modes::decode_amount;
use crate::session::{Capability, KernelSession, Outcome, SessionTrap};

/// Which handle type a rep names — the kernel's mode lattice as the
/// runtimes' resource types.
///
/// Derived from the capability itself rather than declared beside it, so
/// a backend is told what to construct instead of inferring it from the
/// export it happens to be calling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellKind {
    /// `read-cell`.
    Read,
    /// `locked-cell`.
    Locked,
    /// `write-cell`.
    Write,
    /// `delta-cell`.
    Delta,
    /// `reserve-cell`.
    Reserve,
    /// `range-read`.
    RangeRead,
    /// `range-write`.
    RangeWrite,
}

impl CellKind {
    /// The handle type a materialized capability is passed as.
    #[must_use]
    pub const fn of(capability: &Capability) -> Self {
        match capability {
            Capability::Read(_) => Self::Read,
            Capability::Locked(_) => Self::Locked,
            Capability::Write(_) => Self::Write,
            Capability::Delta(_) => Self::Delta,
            Capability::Reserve { .. } => Self::Reserve,
            Capability::RangeRead { .. } => Self::RangeRead,
            Capability::RangeWrite { .. } => Self::RangeWrite,
        }
    }
}

/// One assembled ABI argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestArg<'a> {
    /// A borrowed capability handle: its rep in the session's table and
    /// the resource type to construct it as.
    Handle {
        /// The table position the session assigned.
        rep: u32,
        /// The handle type.
        kind: CellKind,
    },
    /// A 64-bit scalar.
    U64(u64),
    /// A `list<u8>` argument.
    Bytes(&'a [u8]),
}

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
    /// Whether the export returns bytes. True exactly when the node
    /// produces value edges.
    pub returns: bool,
    /// What is left of the transaction's signed ceiling. The backend
    /// meters this invocation against it, so a manifest's nodes share one
    /// budget rather than each getting the whole of it.
    pub fuel_budget: u64,
}

/// What one invocation produced: the session back from the engine, the
/// fuel consumed, and either the export's output bytes or a trap reason.
pub struct InvokeResult {
    /// The session, which always survives for the kernel's rollback.
    pub session: KernelSession,
    /// Fuel consumed by this invocation.
    pub fuel: u64,
    /// The export's returned bytes, or a deterministic trap reason.
    pub result: Result<Option<Vec<u8>>, String>,
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

/// The reason a transaction that spent its signed ceiling reports.
///
/// Consensus content: both engines classify exhaustion as this, and the
/// charge is the declared limit rather than the fuel standing at the trap
/// — that number is engine-defined and no consensus reader may see it.
pub const OUT_OF_GAS: &str = "out of gas";

/// How a trapped invocation reads: its outcome and what it spent.
///
/// One reason and one figure for exhaustion, whichever engine reported
/// it. The trap text is engine-defined and so is the counter standing at
/// a trap — one flushes an in-register total, the other charges every
/// operator — so a node that spent its allowance reports the allowance.
/// It could not have consumed more, and both engines agree on that by
/// construction rather than by happening to count the same.
fn trapped(exhausted: bool, reason: String, budget: u64, spent: u64) -> (Outcome, u64) {
    if exhausted {
        (
            Outcome::UserError {
                reason: OUT_OF_GAS.to_string(),
            },
            budget,
        )
    } else {
        (Outcome::UserError { reason }, spent)
    }
}

/// A node's invocation failed, deterministically. The session comes back
/// for the executor's rollback; boxed because it is large and this path
/// is cold.
type NodeFailure = Box<(KernelSession, Outcome, u64)>;

/// A node's invocation succeeded: the session, the cells it produced, and
/// the fuel it consumed.
type NodeSuccess = (KernelSession, Vec<Vec<u8>>, u64);

fn fail(session: KernelSession, outcome: Outcome, fuel: u64) -> NodeFailure {
    Box::new((session, outcome, fuel))
}

/// A defect in whoever composed the batch: a lowered call that does not
/// fit the declaration materialized beside it. Priced to nobody — the
/// sender did not cause it.
fn composition_defect(session: KernelSession, reason: String) -> NodeFailure {
    fail(session, Outcome::ProtocolError { reason }, 0)
}

impl<B: GuestBackend> ManifestWalk<'_, B> {
    fn invoke_node(
        &self,
        node: u32,
        call: &NodeCall,
        outputs: &[Vec<Vec<u8>>],
        fuel_budget: u64,
        mut session: KernelSession,
    ) -> Result<NodeSuccess, NodeFailure> {
        // The node names its target, and every emission of this frame is
        // attributed to it — the session holds one capability table for
        // the whole transaction and cannot tell whose call is running.
        session.enter_invocation(call.target);

        let session = gated(call, node, session)?;

        // Every signed edge bound this node consumes, before anything
        // runs. The check is the node's, not the callee's: a producer
        // returning less than the consumer declared fails the
        // transaction whatever the producer's own code checked, and a
        // node that forwards its funds onward never sees the amount its
        // signer bounded.
        for edge in &call.edges {
            let Some(carried) = edge_cell(outputs, edge.source, edge.output) else {
                return Err(composition_defect(
                    session,
                    format!(
                        "parameter {} consumes output {} of node {}, which produced no such edge",
                        edge.param, edge.output, edge.source
                    ),
                ));
            };
            let Ok(amount) = decode_amount(carried) else {
                return Err(composition_defect(
                    session,
                    format!("parameter {} carries a malformed amount cell", edge.param),
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

        let mut args = Vec::with_capacity(call.args.len());
        for (position, arg) in call.args.iter().enumerate() {
            match arg {
                CallArg::Handle(rep) => {
                    let Some(capability) = usize::try_from(*rep)
                        .ok()
                        .and_then(|index| session.capabilities().get(index))
                    else {
                        return Err(composition_defect(
                            session,
                            format!("argument {position} names capability {rep}, past the table"),
                        ));
                    };
                    args.push(GuestArg::Handle {
                        rep: *rep,
                        kind: CellKind::of(capability),
                    });
                }
                CallArg::Bucket { source, output } => {
                    let Some(produced) = edge_cell(outputs, *source, *output) else {
                        return Err(composition_defect(
                            session,
                            format!(
                                "argument {position} consumes output {output} of node {source}, \
                                 which produced no such edge"
                            ),
                        ));
                    };
                    args.push(GuestArg::Bytes(produced));
                }
                CallArg::U64(scalar) => args.push(GuestArg::U64(*scalar)),
                CallArg::Bytes(bytes) => args.push(GuestArg::Bytes(bytes)),
            }
        }

        let invoked = self.backend.invoke(
            session,
            &GuestCall {
                package: call.package,
                target: call.target,
                export: &call.export,
                args: &args,
                returns: call.outputs > 0,
                fuel_budget,
            },
        );
        let returned = match invoked.result {
            Ok(returned) => returned,
            Err(reason) => {
                let (outcome, spent) =
                    trapped(invoked.exhausted, reason, fuel_budget, invoked.fuel);
                return Err(fail(invoked.session, outcome, spent));
            }
        };
        match split_outputs(returned.as_deref(), call.outputs) {
            Some(cells) => Ok((invoked.session, cells, invoked.fuel)),
            None => Err(fail(
                invoked.session,
                Outcome::UserError {
                    reason: format!(
                        "`{}` returned {} bytes for {} output edges",
                        call.export,
                        returned.map_or(0, |bytes| bytes.len()),
                        call.outputs
                    ),
                },
                invoked.fuel,
            )),
        }
    }
}

/// The cell a producer left on one of its output edges.
fn edge_cell(outputs: &[Vec<Vec<u8>>], source: u32, output: u32) -> Option<&[u8]> {
    let produced = usize::try_from(source).ok().and_then(|i| outputs.get(i))?;
    usize::try_from(output)
        .ok()
        .and_then(|slot| produced.get(slot))
        .map(Vec::as_slice)
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
        Err(trap) => Err(composition_defect(
            session,
            format!("the authority gate's cell read failed: {trap}"),
        )),
    }
}

/// Whether a call's presented identities satisfy its gate.
///
/// Admission has already checked that a guarded call presents something;
/// what remains is whether it presents *enough*, which is the target's
/// own question and is asked where the target is. An identity gate is a
/// pure match. A stored-rule gate reads the target's cell — declared by
/// the method itself, so provisioned wherever this runs — and dispatches
/// on presence: absent is the virtual rule, the identity the target's
/// address derives, whichever role asks; present is the stored role the
/// gate names, picked from the role set that governs at the transaction
/// clock — so a matured proposal judges here with nothing applying it.
/// A stored cell that does not decode admits nobody: the write path
/// refuses such bytes, so one here is not a rule, and a gate that
/// cannot be read fails closed.
fn authorized(call: &NodeCall, session: &mut KernelSession) -> Result<bool, SessionTrap> {
    match call.authority {
        None => Ok(true),
        Some(AuthorityGate::Identity(required)) => Ok(call.evidence.contains(&required)),
        Some(AuthorityGate::StoredRule { cell, role }) => {
            let bytes = session.declared_cell(cell)?;
            if bytes.is_empty() {
                return Ok(call.evidence.contains(&call.target));
            }
            let clock = session.clock_ms();
            Ok(AuthCell::from_slice(&bytes).is_ok_and(|stored| {
                stored
                    .governing(clock)
                    .roles
                    .rule(role)
                    .satisfied_by(&call.evidence)
            }))
        }
    }
}

/// Split an export's returned blob into one cell per output edge.
///
/// A method producing `n` edges returns exactly `n` amount cells
/// concatenated, and one producing none returns nothing at all — so a
/// blob of any other length is a package whose code and signature
/// disagree, which is its author's defect and its caller's trap.
fn split_outputs(returned: Option<&[u8]>, outputs: u32) -> Option<Vec<Vec<u8>>> {
    let expected = usize::try_from(outputs)
        .ok()?
        .checked_mul(EDGE_CELL_BYTES)?;
    let bytes = match (returned, expected) {
        (None, 0) => return Some(Vec::new()),
        (None, _) | (Some(_), 0) => return None,
        (Some(bytes), _) => bytes,
    };
    if bytes.len() != expected {
        return None;
    }
    Some(
        bytes
            .as_chunks::<EDGE_CELL_BYTES>()
            .0
            .iter()
            .map(|cell| cell.to_vec())
            .collect(),
    )
}

impl<B: GuestBackend> GuestRunner for ManifestWalk<'_, B> {
    fn run(&self, entry: &BatchTx, mut session: KernelSession) -> RunResult {
        let mut outputs: Vec<Vec<Vec<u8>>> = Vec::with_capacity(entry.calls.len());
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
                Err(failure) => {
                    let (returned, outcome, consumed) = *failure;
                    return RunResult {
                        session: returned,
                        outcome,
                        fuel: fuel.saturating_add(consumed),
                    };
                }
            }
        }
        RunResult {
            session,
            outcome: Outcome::Completed { value: None },
            fuel,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::split_outputs;

    #[test]
    fn an_export_returns_one_cell_per_output_edge() {
        assert_eq!(split_outputs(None, 0), Some(Vec::new()));
        assert_eq!(split_outputs(Some(&[7; 16]), 1), Some(vec![vec![7; 16]]));
        assert_eq!(
            split_outputs(Some(&[9; 32]), 2),
            Some(vec![vec![9; 16], vec![9; 16]])
        );
    }

    #[test]
    fn any_other_return_shape_is_refused() {
        // A blob for a method that declared no edges, none for a method
        // that declared one, and a length between two whole cells.
        assert_eq!(split_outputs(Some(&[0; 16]), 0), None);
        assert_eq!(split_outputs(None, 1), None);
        assert_eq!(split_outputs(Some(&[0; 24]), 1), None);
        assert_eq!(split_outputs(Some(&[0; 16]), 2), None);
    }
}

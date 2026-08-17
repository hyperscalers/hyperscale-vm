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
    AbortReason, Address, AuthCell, AuthRole, AuthorityGate, CallArg, EdgeKind, MAX_ERROR_CODES,
    NodeCall, PackageHash, cell_ids, nf_cell_len,
};

use crate::executor::{BatchTx, GuestRunner, RunResult};
use crate::modes::decode_amount;
use crate::session::{Capability, KernelSession, Outcome, SessionTrap};

/// One value edge in flight between the node that produced it and the
/// node that consumes it.
///
/// A fungible edge is the kernel's own bucket from the moment it is
/// produced: the rep names value the kernel holds, and what the consumer
/// receives is that same bucket rather than a number re-read from bytes.
/// A cell is what an edge crosses on where its guest has not been ported —
/// every non-fungible one, and every fungible one whose package still
/// returns the byte convention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Edge {
    /// A bucket the kernel holds on the producing node's behalf.
    Bucket(u32),
    /// The cell an edge crosses on under the byte convention.
    Cell(Vec<u8>),
}

impl Edge {
    /// The quantity a signed bound is judged over: a fungible edge's
    /// amount, a non-fungible edge's id count.
    ///
    /// A bucket answers for itself; a cell is read as the kind its
    /// producer declared, never sniffed from the bytes.
    fn quantity(&self, kind: EdgeKind, session: &KernelSession) -> Option<u128> {
        match self {
            Self::Bucket(rep) => session.bucket(*rep).ok(),
            Self::Cell(cell) => match kind {
                EdgeKind::Fungible => decode_amount(cell).ok(),
                EdgeKind::NonFungible => {
                    cell_ids(cell).and_then(|ids| u128::try_from(ids.len()).ok())
                }
            },
        }
    }
}

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
    /// An address, as the world's own record.
    Address(Address),
    /// A `list<u8>` argument.
    Bytes(&'a [u8]),
    /// A value edge, transferred to the guest as the bucket the kernel
    /// holds for it.
    Bucket(u32),
    /// This invocation's authority to issue, granted from the method's
    /// own declared outputs.
    Issuer,
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
    /// What is left of the transaction's signed ceiling. The backend
    /// meters this invocation against it, so a manifest's nodes share one
    /// budget rather than each getting the whole of it.
    pub fuel_budget: u64,
}

/// How one invocation ended.
///
/// Three ways rather than two, because returning on an error arm is
/// neither of the other two: the guest ran to completion and said no.
/// That distinction is what separates a declared refusal from a defect
/// everywhere downstream — the outcome it records, and the fee it pays.
pub enum Invoked {
    /// The export returned the value edges it produced, as the buckets
    /// the kernel holds again.
    Produced(Vec<u32>),
    /// The export returned; its output bytes when its signature produces
    /// any.
    Returned(Option<Vec<u8>>),
    /// The export declined, with an index into its package's error table.
    Declined(u32),
    /// The invocation failed, in the class the backend classified it as.
    ///
    /// A class rather than a message, so a backend has no formatting
    /// decision to make and two backends cannot word one failure two ways.
    Aborted(AbortReason),
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

/// A node's invocation failed, deterministically. The session comes back
/// for the executor's rollback; boxed because it is large and this path
/// is cold.
type NodeFailure = Box<(KernelSession, Outcome, u64)>;

/// A node's invocation succeeded: the session, the edges it produced, and
/// the fuel it consumed.
type NodeSuccess = (KernelSession, Vec<Edge>, u64);

fn fail(session: KernelSession, outcome: Outcome, fuel: u64) -> NodeFailure {
    Box::new((session, outcome, fuel))
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
        outputs: &[Vec<Edge>],
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
                        kind: CellKind::of(capability),
                    });
                }
                CallArg::Bucket { source, output } => {
                    let Some(produced) = edge_at(outputs, *source, *output) else {
                        return Err(composition_defect(
                            session,
                            AbortReason::MissingProducerEdge,
                        ));
                    };
                    args.push(match produced {
                        Edge::Bucket(rep) => GuestArg::Bucket(*rep),
                        Edge::Cell(bytes) => GuestArg::Bytes(bytes),
                    });
                }
                CallArg::Issuer => args.push(GuestArg::Issuer),
                CallArg::U64(scalar) => args.push(GuestArg::U64(*scalar)),
                CallArg::Address(address) => args.push(GuestArg::Address(*address)),
                CallArg::Bytes(bytes) => args.push(GuestArg::Bytes(bytes)),
            }
        }

        // Issuance is one node's, read off the outputs it declared: a
        // method producing a resource derived from its own address is a
        // method saying it issues one.
        if call.issues {
            session.grant_issuance();
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
    let returned = match invoked.result {
        // Edges come back as the buckets the kernel holds again, one per
        // declared output. A count that disagrees with the declaration is
        // the same shape refusal a byte blob that did not split used to
        // be.
        Invoked::Produced(reps) => {
            return if reps.len() == call.outputs.len() {
                Ok((
                    session,
                    reps.into_iter().map(Edge::Bucket).collect(),
                    invoked.fuel,
                ))
            } else {
                Err(fail(
                    session,
                    Outcome::UserError {
                        reason: AbortReason::BadReturnShape,
                    },
                    invoked.fuel,
                ))
            };
        }
        Invoked::Returned(returned) => returned,
        // A decline is charged its own fuel, not the ceiling: the export
        // returned, so the figure is an ordinary completed-invocation one
        // and both engines reach it by construction. A code no package
        // could have declared is a defect in the guest rather than a
        // refusal, bounded here without the table the kernel does not
        // hold.
        Invoked::Declined(code) if code < MAX_ERROR_CODES => {
            return Err(fail(
                session,
                Outcome::Declined { node, code },
                invoked.fuel,
            ));
        }
        Invoked::Declined(_) => {
            return Err(fail(
                session,
                Outcome::UserError {
                    reason: AbortReason::ErrorCodeOutOfRange,
                },
                invoked.fuel,
            ));
        }
        Invoked::Aborted(reason) => {
            let (outcome, spent) = trapped(invoked.exhausted, reason, fuel_budget, invoked.fuel);
            return Err(fail(session, outcome, spent));
        }
    };
    // A byte blob is what an edge crosses on where its guest has not been
    // ported, so what it splits into is cells rather than buckets.
    let Some(cells) = split_outputs(returned.as_deref(), &call.outputs) else {
        return Err(fail(
            session,
            Outcome::UserError {
                reason: AbortReason::BadReturnShape,
            },
            invoked.fuel,
        ));
    };
    Ok((
        session,
        cells.into_iter().map(Edge::Cell).collect(),
        invoked.fuel,
    ))
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
    outputs: &[Vec<Edge>],
    session: KernelSession,
) -> Result<KernelSession, NodeFailure> {
    for edge in &call.edges {
        let Some(carried) = edge_at(outputs, edge.source, edge.output) else {
            return Err(composition_defect(
                session,
                AbortReason::MissingProducerEdge,
            ));
        };
        let Some(amount) = carried.quantity(edge.kind, &session) else {
            return Err(composition_defect(session, AbortReason::MalformedEdgeCell));
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
fn edge_at(outputs: &[Vec<Edge>], source: u32, output: u32) -> Option<&Edge> {
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
    match call.authority {
        None => Ok(true),
        Some(AuthorityGate::Identity(required)) => Ok(call.evidence.contains(&required)),
        Some(AuthorityGate::StoredRule { cell, role }) => {
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
        Some(AuthorityGate::Custody {
            cell,
            vault,
            owner,
            holdings,
        }) => {
            // The holder acts — its stored primary judges the presented
            // set exactly as a sign-in would — and the holder holds:
            // value in the badge-keyed vault, or any instance in the
            // badge-keyed holdings. Anything but a well-formed non-zero
            // amount cell reads as not held; a corrupt vault grants
            // nothing.
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
            let amount = session.declared_cell(vault)?;
            let funded = decode_amount(&amount).is_ok_and(|held| held > 0);
            Ok(funded || session.declared_holdings_non_empty(owner, holdings)?)
        }
    }
}

/// Split an export's returned blob into one cell per output edge, each
/// framed by its declared kind.
///
/// The byte convention, which a non-fungible edge still crosses on and a
/// fungible one crosses on until its guest is ported: a fungible cell is
/// exactly [`EDGE_CELL_BYTES`], a non-fungible cell the framed shape
/// [`cell_ids`] admits, its ids distinct. A blob of any other shape is a
/// package whose code and signature disagree, which is its author's
/// defect and its caller's trap.
fn split_outputs(returned: Option<&[u8]>, outputs: &[EdgeKind]) -> Option<Vec<Vec<u8>>> {
    let bytes = match (returned, outputs.is_empty()) {
        (None, true) => return Some(Vec::new()),
        (None, false) | (Some(_), true) => return None,
        (Some(bytes), false) => bytes,
    };
    let mut cells = Vec::with_capacity(outputs.len());
    let mut rest = bytes;
    for kind in outputs {
        let width = match kind {
            // A fungible edge has no blob to split: it is a bucket the
            // kernel took ownership of, so a blob offered for one is a
            // package whose code and signature disagree.
            EdgeKind::Fungible => return None,
            EdgeKind::NonFungible => nf_cell_len(rest)?,
        };
        if rest.len() < width {
            return None;
        }
        let (cell, remaining) = rest.split_at(width);
        if matches!(kind, EdgeKind::NonFungible) {
            cell_ids(cell)?;
        }
        cells.push(cell.to_vec());
        rest = remaining;
    }
    rest.is_empty().then_some(cells)
}

impl<B: GuestBackend> GuestRunner for ManifestWalk<'_, B> {
    fn run(&self, entry: &BatchTx, mut session: KernelSession) -> RunResult {
        let mut outputs: Vec<Vec<Edge>> = Vec::with_capacity(entry.calls.len());
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
    use hyperscale_vm_effects::{EdgeKind, MAX_IDS_PER_EDGE, ids_cell};

    use super::split_outputs;

    const FUNGIBLE: EdgeKind = EdgeKind::Fungible;
    const NON_FUNGIBLE: EdgeKind = EdgeKind::NonFungible;

    #[test]
    fn an_export_returns_one_cell_per_output_edge() {
        assert_eq!(split_outputs(None, &[]), Some(Vec::new()));
        assert_eq!(
            split_outputs(Some(&ids_cell(&[3])), &[NON_FUNGIBLE]),
            Some(vec![ids_cell(&[3])])
        );
        let two: Vec<u8> = ids_cell(&[3]).into_iter().chain(ids_cell(&[9])).collect();
        assert_eq!(
            split_outputs(Some(&two), &[NON_FUNGIBLE, NON_FUNGIBLE]),
            Some(vec![ids_cell(&[3]), ids_cell(&[9])])
        );
    }

    #[test]
    fn a_fungible_output_has_no_blob_to_split() {
        // It is a bucket the kernel took ownership of, so a package
        // offering bytes for one is a package whose code and signature
        // disagree.
        assert_eq!(split_outputs(Some(&[7; 16]), &[FUNGIBLE]), None);
        assert_eq!(split_outputs(Some(&[9; 32]), &[FUNGIBLE, FUNGIBLE]), None);
    }

    #[test]
    fn a_non_fungible_output_frames_as_a_counted_id_list() {
        let cell = ids_cell(&[3, 9]);
        assert_eq!(
            split_outputs(Some(&cell), &[NON_FUNGIBLE]),
            Some(vec![cell.clone()])
        );

        // Two id cells, in declared order.
        let blob: Vec<u8> = cell.iter().copied().chain(ids_cell(&[7])).collect();
        assert_eq!(
            split_outputs(Some(&blob), &[NON_FUNGIBLE, NON_FUNGIBLE]),
            Some(vec![cell, ids_cell(&[7])])
        );
    }

    #[test]
    fn any_other_return_shape_is_refused() {
        // A blob for a method that declared no edges, none for a method
        // that declared one, and a cell cut short.
        assert_eq!(split_outputs(Some(&[0; 16]), &[]), None);
        assert_eq!(split_outputs(None, &[NON_FUNGIBLE]), None);
        let short = &ids_cell(&[3, 9])[..12];
        assert_eq!(split_outputs(Some(short), &[NON_FUNGIBLE]), None);
    }

    #[test]
    fn a_malformed_id_cell_is_refused() {
        // An id cell whose width disagrees with its count, one cut short
        // of its declared ids, an empty blob with no count byte, a count
        // past the cap, and trailing bytes after the last declared cell.
        assert_eq!(split_outputs(Some(&[2, 0, 0, 0, 0]), &[NON_FUNGIBLE]), None);
        let short = &ids_cell(&[3, 9])[..12];
        assert_eq!(split_outputs(Some(short), &[NON_FUNGIBLE]), None);
        assert_eq!(split_outputs(Some(&[]), &[NON_FUNGIBLE]), None);

        let over_cap = u8::try_from(MAX_IDS_PER_EDGE + 1).unwrap();
        let mut blob = vec![over_cap];
        blob.extend(std::iter::repeat_n(0u8, (MAX_IDS_PER_EDGE + 1) * 8));
        assert_eq!(split_outputs(Some(&blob), &[NON_FUNGIBLE]), None);

        let mut trailing = ids_cell(&[3]);
        trailing.push(0);
        assert_eq!(split_outputs(Some(&trailing), &[NON_FUNGIBLE]), None);
    }

    #[test]
    fn a_produced_cell_with_a_repeated_id_is_refused() {
        // Duplicates would count twice toward a consumer's bound: a
        // producer returning [9, 9] must not satisfy "at least 2".
        assert_eq!(
            split_outputs(Some(&ids_cell(&[9, 9])), &[NON_FUNGIBLE]),
            None
        );
    }
}

//! The guest boundary: what a judged frame lowers to for the engine.
//!
//! Not a judgement. A site name resolves to positions in the capability
//! table the declaration already fixed, and a literal picks the wire
//! representation the canonical ABI carries it in. `publish/abi.rs` asks
//! the same question of a signature; this is its evaluated twin.

use hyperscale_vm_types::{Address, ResourceAddr};

use super::AdmissionError;
use crate::claim::Claim;
use crate::dsl::{Clause, Declaration, EvalInputs, evaluate_expr, supports};
use crate::hash::Hasher;
use crate::invoke::{CallArg, EdgeBound, IssuanceGrant, NodeCall};
use crate::manifest::{JudgedLeaf, NodeInput};
use crate::metadata::PackageHash;
use crate::rule::Rule;
use crate::signature::{AbiParam, MethodSignature};
use crate::types::{EdgeContent, MAX_IDS_PER_EDGE, Value};

/// What lowering one frame's binding needs beyond the frame itself.
pub(super) struct CallBinding<'a> {
    pub(super) package: PackageHash,
    pub(super) declaration: &'a Declaration,
    pub(super) offset: u32,
    pub(super) target: Address,
    pub(super) method: &'a str,
    pub(super) node_inputs: &'a [NodeInput],
    pub(super) node_outputs: &'a [(ResourceAddr, EdgeContent)],
    pub(super) evidence: &'a [Claim],
    pub(super) requires: Vec<Rule<JudgedLeaf>>,
    /// The resource this node issues, already derived where its entries
    /// were injected — so the address a rule was resolved against and
    /// the address the grant carries are one derivation.
    pub(super) issues: Vec<IssuanceGrant>,
    pub(super) inputs: &'a EvalInputs<'a>,
    pub(super) hasher: &'a dyn Hasher,
}

/// The argument one handle binding lowers to: the capability each of
/// the site's elements names, and an absence where its guard did not
/// fire.
///
/// One function for both shapes, because a site is one shape: a plain
/// clause is a site of one element, a `for-each` clause's body site is
/// as wide as the list its loop mapped over, and a clause guarded out
/// contributes an absence rather than shortening anything. The
/// declaration recorded both — the spans for the first, the expansions
/// for the second — so nothing here computes a position.
fn bind_site(
    signature: &MethodSignature,
    declaration: &Declaration,
    clause: u32,
    site: u32,
    offset: u32,
) -> Result<CallArg, String> {
    let index = usize::try_from(clause).map_err(|_| format!("clause {clause} is out of range"))?;
    let declared = signature
        .effects
        .get(index)
        .ok_or_else(|| format!("clause {clause} is not declared"))?;

    let entries: Vec<Option<u32>> = if let Clause::ForEach { body, .. } = declared {
        let backed = usize::try_from(site)
            .ok()
            .and_then(|at| body.get(at))
            .is_some_and(supports);
        if !backed {
            return Err(format!(
                "site {site} of clause {clause} materializes nothing"
            ));
        }
        declaration
            .elements(clause, site)
            .ok_or_else(|| format!("clause {clause} has no site {site} to run"))?
            .to_vec()
    } else {
        // A plain clause is one site of one element: the span the
        // evaluation recorded is one entry when the clause was declared
        // and none when its guard ruled it out.
        if !supports(declared) {
            return Err(format!("clause {clause} materializes nothing"));
        }
        let (start, len) = declaration
            .clause_spans
            .get(index)
            .copied()
            .ok_or_else(|| format!("clause {clause} has no span"))?;
        match len {
            1 => vec![Some(start)],
            0 => vec![None],
            _ => {
                return Err(format!(
                    "clause {clause} evaluated to {len} accesses, which no handle names"
                ));
            }
        }
    };

    let entries = entries
        .into_iter()
        .map(|entry| {
            entry.map_or(Ok(None), |position| {
                position
                    .checked_add(offset)
                    .map(Some)
                    .ok_or_else(|| "the capability table overflowed".to_owned())
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CallArg::Site { entries })
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
pub(super) fn lower_call(
    node_index: u32,
    signature: &MethodSignature,
    binding: CallBinding<'_>,
) -> Result<NodeCall, AdmissionError> {
    let CallBinding {
        package,
        declaration,
        offset,
        target,
        method,
        node_inputs,
        node_outputs,
        evidence,
        requires,
        issues,
        inputs,
        hasher,
    } = binding;
    let mut args = Vec::with_capacity(signature.abi.len());
    for (position, binding) in signature.abi.iter().enumerate() {
        let param = u32::try_from(position).unwrap_or(u32::MAX);
        let unbindable = |reason: String| AdmissionError::UnbindableAbiParam {
            node: node_index,
            param,
            reason,
        };
        args.push(match binding {
            AbiParam::Handle { clause, site } => {
                bind_site(signature, declaration, *clause, *site, offset).map_err(&unbindable)?
            }
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
                    evaluate_expr(expr, inputs, hasher).map_err(|source| AdmissionError::Eval {
                        node: node_index,
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
        target,
        export: method.to_owned(),
        args,
        edges: edge_bounds(node_inputs),
        // The declared content of each produced edge, from the same
        // output projections everything else evaluated against.
        outputs: node_outputs
            .iter()
            .map(|(_, content)| content.clone())
            .collect(),
        issues,
        evidence: evidence.to_vec(),
        requires,
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
/// canonical fixed-width bytes, and an id set crosses as the same
/// count-prefixed cell an edge carries — one framing wherever ids move.
/// The remaining compound kinds have no ABI shape and refuse rather than
/// picking an encoding the two runtimes would have to agree on
/// separately.
fn guest_arg(value: &Value) -> Option<CallArg> {
    match value {
        Value::U64(scalar) => Some(CallArg::U64(*scalar)),
        Value::U128(amount) => Some(CallArg::Bytes(amount.to_le_bytes().to_vec())),
        // The same framing an amount crosses in, at twice the width: a
        // stored rate is a number the guest decodes, not a shape the
        // boundary knows about.
        Value::U256(scaled) => Some(CallArg::Bytes(scaled.to_vec())),
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
        // A judgment crosses as the flag a guarded clause's verdict
        // already crosses as. Most comparisons never reach here — a body
        // needing one rebuilds it from operands that cross, and a
        // selection hands over the value it chose — but a question only
        // the evaluator can answer, such as whether a configured table
        // holds a key, has no operands the guest holds.
        Value::Bool(judgment) => Some(CallArg::Bool(*judgment)),
        Value::Key(_) | Value::Bucket { .. } | Value::Tuple(_) => None,
    }
}

//! Construction-time projections: what a graph's declarations determine
//! before anything is signed.
//!
//! The typed builder tags the handles it mints with what a method's
//! output expressions evaluate to, and the envelope tier finds the
//! granted-rule records a graph's calls resolve against. Both read the
//! same facts off declared signatures, evaluated over whatever the
//! construction knows. Everything here is best effort by design:
//! admission re-derives every answer over the signed form, so an
//! expression this cannot resolve costs an untagged handle or a missing
//! record — a refusal at admission, never a movement let through.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{
    ChainRecords, Claim, Clause, Constraint, EdgeContent, EvalBudget, EvalInputs, Expr,
    GrantedBehaviour, GraphArg, Hash32, Hasher, InstanceMeta, MAX_EXPR_DEPTH, ManifestGraph,
    ManifestHash, MethodSignature, ParamType, PresentedGrants, ResourceGrants, ResourceMeta,
    SealedLeaf, Value, evaluate_expr, founds_its_resource, keying_resource,
};
use hyperscale_vm_types::{Address, CallTarget, ResourceAddr};

use crate::typed::TypedError;

/// The identity a construction-time evaluation runs under.
///
/// A transaction's identity is the signed graph's hash, which does not
/// exist while the graph is being written. Nothing reads this: the only
/// expressions that derive from an identity are the fresh-id forms, and
/// [`resolvable`] refuses to evaluate an output expression containing one.
pub(crate) const UNBOUND: ManifestHash = ManifestHash(Hash32([0; 32]));

/// Type each bound argument against the parameter it fills, answering the
/// value an output expression would read at that position — `None` where
/// nothing at construction determines it.
///
/// This is admission's own per-argument check, run against the same
/// declared parameters, one graph earlier.
fn type_args(
    method: &str,
    args: &[GraphArg],
    params: &[ParamType],
) -> Result<Vec<Option<Value>>, TypedError> {
    if args.len() != params.len() {
        return Err(TypedError::ArityMismatch {
            method: method.to_owned(),
            expected: params.len(),
            found: args.len(),
        });
    }
    let mut inputs = Vec::with_capacity(args.len());
    for (position, (arg, param)) in args.iter().zip(params).enumerate() {
        let index = u32::try_from(position).expect("arguments are bounded by the signature");
        let method = || method.to_owned();
        inputs.push(match arg {
            GraphArg::Literal(value) => {
                if param.is_edge() {
                    return Err(TypedError::LiteralForBucketParam {
                        method: method(),
                        param: index,
                    });
                }
                if !param.admits(value) {
                    return Err(TypedError::ParamKind {
                        method: method(),
                        param: index,
                        expected: param.name(),
                        found: value.kind(),
                    });
                }
                Some(value.clone())
            }
            GraphArg::Edge { constraints, .. } => {
                if !param.is_edge() {
                    return Err(TypedError::EdgeForValueParam {
                        method: method(),
                        param: index,
                    });
                }
                edge_resource(constraints).map(|resource| Value::Bucket {
                    resource,
                    // The builder types what it can see: an edge's own
                    // ids are the producing node's, which this pass does
                    // not resolve. What it does know is which kind the
                    // callee declared, and that is what admission judges
                    // the routed edge against.
                    content: if *param == ParamType::NfBucket {
                        EdgeContent::NonFungible { ids: Vec::new() }
                    } else {
                        EdgeContent::Fungible
                    },
                })
            }
            GraphArg::Socket(_) => {
                if !param.is_edge() {
                    return Err(TypedError::SocketForValueParam {
                        method: method(),
                        param: index,
                    });
                }
                // What fills a socket takes its resource from the
                // socket's own declaration, a tier up from here.
                None
            }
        });
    }
    Ok(inputs)
}

/// [`type_args`] split as every consumer holds it: each position's value
/// with [`unknown`] standing in where nothing at construction determines
/// one, beside which of them are real.
pub(crate) fn typed_values(
    method: &str,
    args: &[GraphArg],
    params: &[ParamType],
) -> Result<(Vec<Value>, Vec<bool>), TypedError> {
    let inputs = type_args(method, args, params)?;
    let known = inputs.iter().map(Option::is_some).collect();
    let values = inputs
        .into_iter()
        .map(|value| value.unwrap_or_else(unknown))
        .collect();
    Ok((values, known))
}

/// The inputs a construction-time evaluation runs under: the caller's
/// own meter, an [`UNBOUND`] identity, nothing presented.
pub(crate) fn eval_inputs<'a>(
    self_addr: Address,
    values: &'a [Value],
    record: &'a InstanceMeta,
    node_index: u32,
    budget: &'a EvalBudget,
) -> EvalInputs<'a> {
    EvalInputs {
        self_addr,
        args: values,
        record,
        node_index,
        identity: UNBOUND,
        grants: PresentedGrants::none(),
        budget,
    }
}

/// What each of a method's declared outputs carries, where the inputs
/// feeding the declaration are known.
///
/// The one derivation both tiers of this crate want: the typed builder
/// tags the handles it mints with it, and the projection reads it back off
/// a graph it was handed. `known` says which of `values` is real; the rest
/// hold [`unknown`], which nothing reaches because [`resolvable`] refuses
/// every expression that would.
pub(crate) fn output_resources(
    signature: &MethodSignature,
    target: CallTarget,
    record: &InstanceMeta,
    values: &[Value],
    known: &[bool],
    node_index: u32,
    hasher: &dyn Hasher,
) -> Vec<Option<ResourceAddr>> {
    // A builder-side projection, not admission: the meter is this
    // call's own, and nothing here reaches a chain verdict.
    let budget = EvalBudget::default();
    let inputs = eval_inputs(target.address(), values, record, node_index, &budget);
    signature
        .outputs
        .iter()
        .map(|expr| {
            if !resolvable(expr, known, 0) {
                return None;
            }
            match evaluate_expr(expr, &inputs, hasher) {
                Ok(Value::Address(address)) => ResourceAddr::try_from(address).ok(),
                Ok(Value::Bucket { resource, .. }) => Some(resource),
                _ => None,
            }
        })
        .collect()
}

/// The claims a call's injected authority entries name, and which the
/// frame's own identity does not already satisfy.
///
/// All four injections can read a claim. Three are actor questions and
/// always do; a movement entry does where its subject is an identity,
/// because nothing holds one and asking whether this transaction carried
/// a claim on it is the only other question there is.
///
/// **What an entry demands is [`GrantedBehaviour::demanded`]'s answer,
/// not this function's** — the same door admission injects through, so a
/// composer cannot come to a different view of which entries fire. The
/// two used to decide it separately, and the drift was silent both ways:
/// present nothing for an entry that fires and the call is refused for
/// missing evidence, present something for one that does not and it is
/// refused for offering it.
///
/// **Founding is not minting** is the one subtraction that stays here,
/// because it is a property of the declaration rather than of the entry:
/// an issuance whose own frame writes the resource's record earns
/// nothing, and no entry is consulted to know it.
pub(crate) fn earned_claims(
    signature: &MethodSignature,
    args: &[GraphArg],
    inputs: &EvalInputs<'_>,
    known: &[bool],
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Vec<Claim> {
    let own = Claim::of_address(inputs.self_addr);
    let mut wanted = Vec::new();
    let mut ask = |rules: &ResourceGrants, behaviour: GrantedBehaviour| {
        let Some(sealed) = rules.get(behaviour) else {
            return;
        };
        let Ok(Some(rule)) = behaviour.demanded(sealed, own) else {
            return;
        };
        for leaf in rule.leaves() {
            if let SealedLeaf::Claim(claim) = leaf
                && !wanted.contains(claim)
            {
                wanted.push(*claim);
            }
        }
    };

    // An issuance derives its own resource, so its entries are read off
    // the declaration rather than off any presented record.
    for issuance in &signature.issues {
        if founds_its_resource(issuance, signature) {
            continue;
        }
        let Ok(rules) = issuance
            .grants
            .resolve(hasher, inputs.self_addr, &inputs.record.config)
        else {
            continue;
        };
        for behaviour in issuance.direction.behaviours() {
            ask(&rules, *behaviour);
        }
    }
    // A destruction and a reach both govern a resource somebody else
    // issued, so both read the record the envelope carries.
    for (resource, behaviour) in governing(signature, args, inputs, known, hasher) {
        let Some(behaviour) = behaviour else {
            continue;
        };
        let Some(record) = chain.resource(resource, hasher) else {
            continue;
        };
        ask(&record.rules, behaviour);
    }
    wanted
}

/// Every granted-rule record a graph's calls will be resolved against,
/// in address order.
///
/// What an envelope carries in its `resources` section, found rather
/// than asked for. Run over a declaration rather than over a builder,
/// because the composer assembling an envelope is not always the party
/// that wrote what it carries: a presented subintent arrives whole and
/// already signed, and the records it needs are readable off it. Records
/// ride the envelope rather than any intent, so attaching them forges
/// nothing that a signature covers.
///
/// Best effort by construction, and safely so. A resource named through
/// a `for-each` element, or through an argument nothing in the
/// declaration determines, is one this cannot resolve — and a record
/// missing from the envelope is a refusal at admission rather than a
/// movement let through, because withholding a restricted resource's
/// record withholds the movement.
#[must_use]
pub fn graph_records(
    graph: &ManifestGraph,
    chain: &dyn ChainRecords,
    hasher: &dyn Hasher,
) -> Vec<ResourceMeta> {
    let mut found: BTreeMap<ResourceAddr, ResourceMeta> = BTreeMap::new();
    for (index, node) in graph.nodes.iter().enumerate() {
        let Some(meta) = chain.instance(node.target) else {
            continue;
        };
        let Some(package) = chain.package(meta.package) else {
            continue;
        };
        let Some(signature) = package.methods.get(&node.method) else {
            continue;
        };
        let Ok((values, known)) = typed_values(&node.method, &node.args, &signature.params) else {
            continue;
        };
        let budget = EvalBudget::default();
        let inputs = eval_inputs(
            node.target.address(),
            &values,
            &meta,
            u32::try_from(index).unwrap_or(u32::MAX),
            &budget,
        );
        for (resource, _) in governing(signature, &node.args, &inputs, &known, hasher) {
            if let std::collections::btree_map::Entry::Vacant(slot) = found.entry(resource)
                && let Some(record) = chain.resource(resource, hasher)
            {
                slot.insert(record);
            }
        }
    }
    found.into_values().collect()
}

/// Every resource whose granted-rule record this call's injected entries
/// will be resolved against.
///
/// Three sources, one per injection that reads a *presented* record. A
/// **destruction** governs the resource of an edge the caller named, so
/// the edge's own type says which. A **reach** is keyed first by the
/// resource whose entry admits it. And a **movement** is judged against
/// the entries of what the cell holds, which the clause's denomination
/// names.
///
/// The fourth injection needs nothing here: an issuance governs a
/// resource the *declaration* derives, so re-derivation is the address
/// and there is no record to find.
fn governing(
    signature: &MethodSignature,
    args: &[GraphArg],
    inputs: &EvalInputs<'_>,
    known: &[bool],
    hasher: &dyn Hasher,
) -> Vec<(ResourceAddr, Option<GrantedBehaviour>)> {
    let resolve = |expr: &Expr| {
        if !resolvable(expr, known, 0) {
            return None;
        }
        match evaluate_expr(expr, inputs, hasher) {
            Ok(Value::Address(address)) => ResourceAddr::try_from(address).ok(),
            _ => None,
        }
    };
    let destroyed = signature.destroys.iter().filter_map(|param| {
        let arg = usize::try_from(*param).ok().and_then(|at| args.get(at))?;
        let resource = match arg {
            GraphArg::Edge { constraints, .. } => edge_resource(constraints),
            GraphArg::Literal(_) | GraphArg::Socket(_) => None,
        }?;
        Some((resource, Some(GrantedBehaviour::Burn)))
    });
    let declared = signature
        .effects
        .iter()
        .flat_map(Clause::effects)
        .filter_map(|clause| {
            let Clause::Effect {
                target,
                mode,
                denomination,
                reach,
                ..
            } = clause
            else {
                return None;
            };
            let resource = match reach {
                Some(behaviour) => {
                    let keyed = keying_resource(target).and_then(&resolve)?;
                    return Some(vec![(keyed, Some(*behaviour))]);
                }
                None => denomination.as_deref().and_then(&resolve)?,
            };
            // Which movement entries the access earns, off the table
            // admission injects them from. A read earns none and still
            // needs the record, because a restricted resource's is what
            // tells a withheld one from a bypass.
            let Some(moves) = mode.moves() else {
                return Some(vec![(resource, None)]);
            };
            let behaviours = GrantedBehaviour::earned_by(moves);
            Some(
                behaviours
                    .iter()
                    .map(|behaviour| (resource, Some(*behaviour)))
                    .collect(),
            )
        })
        .flatten();
    destroyed.chain(declared).collect()
}

/// The value standing in for an input nothing determined.
///
/// Never read: [`resolvable`] is what decides whether an expression may be
/// evaluated at all, and it answers no for every expression reaching an
/// unknown input.
pub(crate) const fn unknown() -> Value {
    Value::Tuple(Vec::new())
}

/// The resource a bound edge was typed with, read off the assertion it
/// carries — which is where a typed handle put it, and where an author
/// asserting one by hand puts it too.
fn edge_resource(constraints: &[Constraint]) -> Option<ResourceAddr> {
    constraints.iter().find_map(|constraint| match constraint {
        Constraint::ResourceIs(resource) => Some(*resource),
        Constraint::MinAmount(_) | Constraint::MaxAmount(_) => None,
    })
}

/// Whether an output expression can be evaluated against what is known at
/// construction.
///
/// Two things a signed graph has that a graph under construction does not:
/// the resource on an edge nothing typed, and the transaction identity the
/// fresh-id forms derive from. An expression reaching either is left to
/// admission, which has both. The depth bound mirrors the evaluator's own,
/// so metadata nested past what any evaluation would accept is refused
/// here rather than recursed into.
fn resolvable(expr: &Expr, known: &[bool], depth: usize) -> bool {
    if depth > MAX_EXPR_DEPTH {
        return false;
    }
    let deeper = |expr| resolvable(expr, known, depth + 1);
    match expr {
        Expr::Literal(_) | Expr::SelfAddr | Expr::SelfRecord | Expr::Config(_) => true,
        Expr::Arg(index) => usize::try_from(*index)
            .ok()
            .and_then(|index| known.get(index).copied())
            .unwrap_or(false),
        // No `for-each` encloses an output expression, and no identity
        // exists to derive from yet.
        Expr::Binding(_) | Expr::FreshId { .. } | Expr::FreshKey { .. } => false,
        Expr::Field(inner, _)
        | Expr::ResourceOf(inner)
        | Expr::IdsOf(inner)
        | Expr::Len(inner)
        | Expr::Only(inner)
        | Expr::Not(inner) => deeper(inner),
        Expr::Lookup { map, key } | Expr::Contains { map, key } => deeper(map) && deeper(key),
        Expr::Pack { hi, lo } => deeper(hi) && deeper(lo),
        Expr::Add(left, right)
        | Expr::And(left, right)
        | Expr::Or(left, right)
        | Expr::Eq(left, right)
        | Expr::Lt(left, right) => deeper(left) && deeper(right),
        // Which arm a conditional takes is a fact about arguments a graph
        // under construction may not have yet, so both arms must resolve
        // before the selection does.
        Expr::If {
            cond,
            then,
            otherwise,
        } => deeper(cond) && deeper(then) && deeper(otherwise),
        Expr::NfBucket { resource, ids } => deeper(resource) && deeper(ids),
        Expr::List(elements) | Expr::Tuple(elements) => elements.iter().all(deeper),
        Expr::SelfResource { material, .. } => material.iter().all(deeper),
        Expr::ChildKey {
            owner, material, ..
        }
        | Expr::OrderKey {
            owner, material, ..
        } => deeper(owner) && material.iter().all(deeper),
    }
}

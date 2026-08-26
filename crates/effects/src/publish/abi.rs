//! The ABI gate: whether a signature's export binding can be honoured.
//!
//! What a guest's exported function takes, against what the signature
//! says each parameter is. Every verdict is a pure function of the
//! metadata, so it is the same wherever it is reached — at publish,
//! where it refuses the artifact, and at routing, where it refuses a
//! call to a package that reached the cache without one.

use std::collections::BTreeSet;

use crate::dsl::Clause;
use crate::signature::{AbiParam, MethodSignature};

/// Why a signature's ABI binding cannot be honoured.
///
/// Every clause is a pure function of the metadata, so the verdict is the
/// same wherever it is reached: at publish, where it refuses the artifact,
/// and at routing, where it refuses a call to a package that reached the
/// cache without one.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// A handle binding naming an effect clause the signature does not
    /// declare.
    #[error("ABI parameter {position} names effect clause {clause}, past the {declared} declared")]
    NoSuchClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
        /// How many clauses the signature declares.
        declared: u32,
    },
    /// A guard binding naming a clause that carries no guard. Its
    /// verdict is the constant true, which no export needs told.
    #[error("ABI parameter {position} takes the verdict of clause {clause}, which has no guard")]
    UnguardedClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A handle binding naming a site an access does not have.
    ///
    /// One access is one site, numbered zero. Sites past it belong to a
    /// `for-each`, which expands over configuration and has one per
    /// element — so a site on a plain access is a position nothing
    /// occupies rather than a clause of the wrong shape.
    #[error(
        "ABI parameter {position} borrows site {site} of clause {clause}, which is one access \
         and has only site 0"
    )]
    NoSuchSite {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
        /// The site it named within that clause.
        site: u32,
    },
    /// A handle binding naming a clause that declares no capability.
    ///
    /// A handle is borrowed from an access, and a condition or a mint is
    /// neither an access nor a loop over them — so there is nothing for
    /// the parameter to be handed, at any site.
    #[error("ABI parameter {position} borrows clause {clause}, which declares no capability")]
    NotACapability {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A handle binding naming a body position that declares no access.
    ///
    /// A condition declares no capability, and a nested loop's own
    /// expansions are not addressable by an index over the outer one's
    /// elements — so neither backs a site.
    #[error(
        "ABI parameter {position} borrows site {site} of clause {clause}, which is not an access"
    )]
    NotALoopedAccess {
        /// The ABI parameter position.
        position: u32,
        /// The `for-each` clause it names.
        clause: u32,
        /// The body position it names.
        site: u32,
    },
    /// One declared site borrowed by two handle parameters.
    ///
    /// The mirror of [`AbiError::BucketCarriedTwice`], and refused for a
    /// stronger reason than redundancy: what a declaration bought is one
    /// capability, and the budgets the kernel keeps against it — a write
    /// interval's cap, a reservation's single take — are the
    /// capability's. A body holding one twice would be asking for them
    /// twice.
    #[error("ABI parameter {position} borrows site {site} of clause {clause}, already borrowed")]
    SiteBorrowedTwice {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
        /// The site within that clause.
        site: u32,
    },
    /// A bucket binding naming a parameter the signature does not declare.
    #[error("ABI parameter {position} names parameter {param}, past the {declared} declared")]
    NoSuchParam {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// How many parameters the signature declares.
        declared: u32,
    },
    /// A bucket binding naming a parameter that is not a bucket.
    ///
    /// A bucket's amount is the one value a signature cannot derive,
    /// which is the whole reason the variant exists; naming any other
    /// parameter through it asks for bytes that are already static.
    #[error("ABI parameter {position} takes the amount of parameter {param}, which is {kind}")]
    NotABucket {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// What that parameter actually is.
        kind: &'static str,
    },
    /// One bucket parameter carried by more than one ABI parameter.
    ///
    /// A bucket carried by *none* is well-formed: a method that forwards
    /// its funds to a callee never reads the amount itself, so nothing in
    /// its own ABI carries it. Carrying it twice has no such reading —
    /// the guest would receive one edge's bytes under two names.
    #[error("parameter {param} is a bucket carried by {carried} ABI parameters")]
    BucketCarriedTwice {
        /// The socket.
        param: u32,
        /// How many ABI parameters name it.
        carried: u32,
    },
}

/// Judge that a handle binding names a site something declares.
///
/// A plain clause is one site of its own, named at site zero; anything
/// past that names a site of a `for-each` body. Each way of getting it
/// wrong earns its own refusal, because they send an author to different
/// places: a site an access does not have, a body position declaring no
/// access, and a clause that declares no capability at any site.
fn declares_a_site(
    signature: &MethodSignature,
    position: u32,
    clause: u32,
    site: u32,
) -> Result<(), AbiError> {
    let declared = usize::try_from(clause)
        .ok()
        .and_then(|index| signature.effects.get(index));
    let Some(declared) = declared else {
        return Err(AbiError::NoSuchClause {
            position,
            clause,
            declared: u32::try_from(signature.effects.len()).unwrap_or(u32::MAX),
        });
    };
    match declared {
        Clause::Effect { .. } if site == 0 => Ok(()),
        Clause::Effect { .. } => Err(AbiError::NoSuchSite {
            position,
            clause,
            site,
        }),
        // A loop's sites are its body's positions, and only the ones
        // declaring an access back a handle.
        Clause::ForEach { body, .. } => {
            let inside = usize::try_from(site).ok().and_then(|at| body.get(at));
            if matches!(inside, Some(Clause::Effect { .. })) {
                Ok(())
            } else {
                Err(AbiError::NotALoopedAccess {
                    position,
                    clause,
                    site,
                })
            }
        }
        _ => Err(AbiError::NotACapability { position, clause }),
    }
}

/// Judge a signature's ABI binding against the declaration it is a
/// binding for.
///
/// A binding says where each of the guest's arguments comes from, and a
/// caller that cannot resolve one cannot invoke the method at all — so an
/// unresolvable binding is a package that publishes and then traps for
/// everyone.
///
/// What this cannot judge is the binding against the component's real
/// ABI: that needs the artifact, and it belongs with whoever holds one.
///
/// # Errors
///
/// Any [`AbiError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_abi(signature: &MethodSignature) -> Result<(), AbiError> {
    let bound = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
    let mut carried = vec![0u32; signature.params.len()];
    let mut borrowed = BTreeSet::new();
    for (index, binding) in signature.abi.iter().enumerate() {
        let position = bound(index);
        match binding {
            AbiParam::Handle { clause, site } => {
                declares_a_site(signature, position, *clause, *site)?;
                if !borrowed.insert((*clause, *site)) {
                    return Err(AbiError::SiteBorrowedTwice {
                        position,
                        clause: *clause,
                        site: *site,
                    });
                }
            }
            AbiParam::Guard(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let Some(declared) = declared else {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                };
                if declared.guard().is_none() {
                    return Err(AbiError::UnguardedClause {
                        position,
                        clause: *clause,
                    });
                }
            }
            AbiParam::Bucket(param) => {
                let slot = usize::try_from(*param).map_err(|_| AbiError::NoSuchParam {
                    position,
                    param: *param,
                    declared: bound(signature.params.len()),
                })?;
                match signature.params.get(slot) {
                    Some(kind) if kind.is_edge() => carried[slot] += 1,
                    Some(other) => {
                        return Err(AbiError::NotABucket {
                            position,
                            param: *param,
                            kind: other.name(),
                        });
                    }
                    None => {
                        return Err(AbiError::NoSuchParam {
                            position,
                            param: *param,
                            declared: bound(signature.params.len()),
                        });
                    }
                }
            }
            // A derived binding is an expression over the same inputs the
            // effect clauses read, so its argument and configuration
            // references are bounded by the same evaluation every node
            // runs at routing. Repeating that walk here would be a second
            // opinion on it.
            AbiParam::Derived(_) => {}
        }
    }
    for (param, count) in carried.iter().enumerate() {
        if *count > 1 {
            return Err(AbiError::BucketCarriedTwice {
                param: bound(param),
                carried: *count,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    use hyperscale_vm_types::Presence;

    use super::*;
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::rule::{Rule, RuleLeaf};
    use crate::signature::{AbiParam, MethodSignature, ParamType, Totality};

    /// One ordinary effect clause, for the bindings that are about the
    /// parameter rather than about what it points at.
    fn clause() -> Clause {
        Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Delta,
            denomination: None,
        }
    }

    fn signature(params: Vec<ParamType>, abi: Vec<AbiParam>) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            params,
            abi,
            effects: vec![clause()],
            ..MethodSignature::default()
        }
    }

    #[test]
    fn a_binding_resolves_against_its_own_signature() {
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle { clause: 0, site: 0 }, AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        assert!(matches!(
            check_abi(&signature(
                vec![],
                vec![AbiParam::Handle { clause: 1, site: 0 }]
            )),
            Err(AbiError::NoSuchClause { clause: 1, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![ParamType::U64], vec![AbiParam::Bucket(0)])),
            Err(AbiError::NotABucket { param: 0, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![], vec![AbiParam::Bucket(3)])),
            Err(AbiError::NoSuchParam { param: 3, .. })
        ));
    }

    /// Each shape a handle binding can name wrongly earns its own
    /// refusal, saying what the author actually wrote.
    ///
    /// One access is one site. Naming a second used to read "clause 0,
    /// which is not a single access" — of a clause that is exactly a
    /// single access, and has no site 1. Naming a condition used to fall
    /// through to the loop check and read "which is not a `for-each`",
    /// sending an author to look for a loop they never wrote.
    #[test]
    fn a_binding_names_the_shape_it_got_wrong() {
        // A site past the one an access has.
        assert!(matches!(
            check_abi(&signature(
                vec![],
                vec![AbiParam::Handle { clause: 0, site: 1 }]
            )),
            Err(AbiError::NoSuchSite {
                clause: 0,
                site: 1,
                ..
            })
        ));

        // A clause that declares no capability at all, at any site.
        let conditional = MethodSignature {
            totality: Totality::Fallible,
            abi: vec![AbiParam::Handle { clause: 0, site: 0 }],
            effects: vec![Clause::Requires {
                guard: None,
                rule: Rule::Require(RuleLeaf::Presence {
                    target: Box::new(TargetExpr::Point(Expr::SelfAddr)),
                    expect: Presence::Present,
                }),
            }],
            ..MethodSignature::default()
        };
        assert!(matches!(
            check_abi(&conditional),
            Err(AbiError::NotACapability { clause: 0, .. })
        ));
    }

    #[test]
    fn a_declared_site_is_borrowed_at_most_once() {
        // Two parameters onto one clause hand a body the same capability
        // twice, and the budgets the kernel keeps against it — a write
        // interval's cap, a reservation's single take — are the
        // capability's, not the parameter's.
        assert_eq!(
            check_abi(&signature(
                vec![],
                vec![
                    AbiParam::Handle { clause: 0, site: 0 },
                    AbiParam::Handle { clause: 0, site: 0 },
                ],
            )),
            Err(AbiError::SiteBorrowedTwice {
                position: 1,
                clause: 0,
                site: 0,
            })
        );
        // And one borrow of it admits, so the refusal is the repetition.
        assert_eq!(
            check_abi(&signature(
                vec![],
                vec![AbiParam::Handle { clause: 0, site: 0 }],
            )),
            Ok(())
        );
    }

    #[test]
    fn a_bucket_is_carried_at_most_once() {
        // A guest receiving one edge's bytes under two names.
        assert!(matches!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
            )),
            Err(AbiError::BucketCarriedTwice {
                param: 0,
                carried: 2
            })
        ));
        // Two buckets, each carried once, in either order.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket, ParamType::U128, ParamType::Bucket],
                vec![AbiParam::Bucket(2), AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        // A bucket the declaring method forwards to a callee: its own
        // guest never reads the amount, so its own ABI carries nothing.
        // The edge's signed bound is still checked where the edge
        // resolves, which is a property of the node and not of the ABI.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle { clause: 0, site: 0 }]
            )),
            Ok(())
        );
    }
}

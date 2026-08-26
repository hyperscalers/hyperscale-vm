//! Caps: what one signature may hold at all.
//!
//! Every walk here mirrors the evaluator's own recursion — same starting
//! depth, same comparison — so a signature this accepts is one
//! evaluation will not refuse on structure alone. Nothing here reads the
//! package around it; what the whole metadata has to answer is
//! [`package`](super::package)'s question.

use crate::dsl::{
    Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, ModeExpr, TargetExpr,
};
use crate::resource::GrantsExpr;
use crate::rule::{
    GrantClaim, MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_LEAVES, RuleExpr, RuleLeaf, always,
    never,
};
use crate::signature::{
    AbiParam, MAX_ISSUANCES_PER_SIGNATURE, MAX_MINTS_PER_SIGNATURE, MethodSignature,
};
use crate::types::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_ITEMS, value_within_width};

/// Why one signature is past a bound the vocabulary fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureBoundsError {
    /// A granted entry spelled a way its behaviour does not admit.
    #[error("a granted behaviour does not admit the spelling its entry was written with")]
    UnadmittedGrant,
    /// More issuances than one signature may carry.
    #[error("a method issues more than {MAX_ISSUANCES_PER_SIGNATURE} resources")]
    TooManyIssuances,
    /// More minting clauses than one signature may carry.
    #[error("a method mints more than {MAX_MINTS_PER_SIGNATURE} claims")]
    TooManyMints,
    /// A granted rule naming a badge whose own rules name a badge.
    #[error("a granted rule names a badge whose own rules name a badge")]
    BadgeChainTooDeep,
    /// A declared rule past the caps a stored one is decoded under.
    #[error(
        "a declared rule nests past {MAX_RULE_DEPTH}, branches past {MAX_RULE_BRANCHES}, or \
         holds a threshold nobody meant"
    )]
    RuleCaps,
    /// An expression nested past the evaluator's own recursion bound.
    #[error("expression nests deeper than {MAX_EXPR_DEPTH}")]
    ExprDepth,
    /// A literal nested past the value depth admission bounds.
    #[error("literal nests deeper than {MAX_VALUE_DEPTH}")]
    LiteralDepth,
    /// `for-each` clauses nested past the evaluator's bound.
    #[error("for-each clauses nest deeper than {MAX_CLAUSE_DEPTH}")]
    ClauseDepth,
    /// More effect clauses than one signature may declare.
    #[error("signature declares more than {MAX_EFFECTS_PER_SIGNATURE} effects")]
    TooManyEffects,
    /// A value wider than the bound every walk over one is charged
    /// against — a literal past it, or a list the evaluator would build
    /// past it.
    #[error("a value is wider than {MAX_VALUE_ITEMS} items or {MAX_VALUE_BYTES} bytes")]
    ValueWidth,
}

/// A declared rule under the caps a stored one is decoded under, and
/// every leaf under the expression caps.
fn check_rule_bounds(rule: &RuleExpr) -> Result<(), SignatureBoundsError> {
    if !rule.within_caps(0) {
        return Err(SignatureBoundsError::RuleCaps);
    }
    match rule {
        RuleExpr::Require(RuleLeaf::Claim(claim)) => check_expr_bounds(claim, 0),
        RuleExpr::Require(RuleLeaf::Stored { cell, .. }) => check_expr_bounds(cell, 0),
        RuleExpr::Require(RuleLeaf::Presence { target, .. }) => check_target_bounds(target),
        RuleExpr::CountOf { rules, .. } => rules.iter().try_for_each(check_rule_bounds),
    }
}

pub(super) fn check_signature_bounds(
    signature: &MethodSignature,
) -> Result<(), SignatureBoundsError> {
    for output in &signature.outputs {
        check_expr_bounds(output, 0)?;
    }
    for denomination in signature.denominations.iter().flatten() {
        check_expr_bounds(denomination, 0)?;
    }
    for param in &signature.abi {
        if let AbiParam::Derived(expr) = param {
            check_expr_bounds(expr, 0)?;
        }
    }
    if signature.issues.len() > MAX_ISSUANCES_PER_SIGNATURE {
        return Err(SignatureBoundsError::TooManyIssuances);
    }
    for issuance in &signature.issues {
        check_grants_bounds(&issuance.grants)?;
    }
    let mut declared = 0usize;
    let mut minted = 0usize;
    check_clause_bounds(&signature.effects, 0, &mut declared, &mut minted)
}

fn check_clause_bounds(
    clauses: &[Clause],
    depth: usize,
    declared: &mut usize,
    minted: &mut usize,
) -> Result<(), SignatureBoundsError> {
    if depth > MAX_CLAUSE_DEPTH {
        return Err(SignatureBoundsError::ClauseDepth);
    }
    for clause in clauses {
        match clause {
            Clause::Effect {
                guard,
                target,
                mode,
                denomination,
                reach: _,
            } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                check_target_bounds(target)?;
                check_mode_bounds(mode)?;
                if let Some(denomination) = denomination {
                    check_expr_bounds(denomination, 0)?;
                }
            }
            Clause::ForEach { guard, list, body } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                check_expr_bounds(list, 0)?;
                check_clause_bounds(body, depth + 1, declared, minted)?;
            }
            Clause::Requires { guard, rule } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                check_rule_bounds(rule)?;
            }
            Clause::Mints { guard, claim } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyEffects);
                }
                // Minting carries its own ceiling as well as the shared
                // one: what a mint costs is not the clause but the copy
                // every later node presenting it makes, so the shared
                // budget is the wrong size to bound it by.
                *minted += 1;
                if *minted > MAX_MINTS_PER_SIGNATURE {
                    return Err(SignatureBoundsError::TooManyMints);
                }
                check_expr_bounds(claim, 0)?;
            }
        }
    }
    Ok(())
}

fn check_target_bounds(target: &TargetExpr) -> Result<(), SignatureBoundsError> {
    match target {
        TargetExpr::Point(key) => check_expr_bounds(key, 0),
        TargetExpr::Entry {
            owner,
            material,
            order,
            ..
        } => {
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(order, 0)
        }
        TargetExpr::Range {
            owner,
            material,
            lo,
            hi,
            cap,
            ..
        } => {
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(lo, 0)?;
            check_expr_bounds(hi, 0)?;
            check_expr_bounds(cap, 0)
        }
    }
}

fn check_mode_bounds(mode: &ModeExpr) -> Result<(), SignatureBoundsError> {
    match mode {
        ModeExpr::Read | ModeExpr::Delta | ModeExpr::Credit | ModeExpr::Write { .. } => Ok(()),
        ModeExpr::Reserve(amount) => check_expr_bounds(amount, 0),
    }
}

fn check_expr_bounds(expr: &Expr, depth: usize) -> Result<(), SignatureBoundsError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(SignatureBoundsError::ExprDepth);
    }
    if let Expr::Literal(literal) = expr {
        if literal.depth() > MAX_VALUE_DEPTH {
            return Err(SignatureBoundsError::LiteralDepth);
        }
        value_within_width(literal).map_err(|_| SignatureBoundsError::ValueWidth)?;
    }
    // A list or tuple the evaluator *builds* rather than decodes: its
    // arity is the expression's own, so the codec's width bound has
    // nothing to say about it, and what it produces is a value every
    // walk downstream pays for by the element.
    if let Expr::List(elements) | Expr::Tuple(elements) = expr
        && elements.len() > MAX_VALUE_ITEMS
    {
        return Err(SignatureBoundsError::ValueWidth);
    }
    // The granted set is not a child — its leaves hold no expression at
    // all — so it is walked here rather than reached by the recursion.
    if let Expr::SelfResource { grants, .. } = expr {
        check_grants_bounds(grants)?;
    }
    expr.children()
        .try_for_each(|child| check_expr_bounds(child, depth + 1))
}

/// Every rule a declaration grants, under the caps a stored rule is
/// decoded under.
///
/// Held here as well as at resolution because a resolved rule is what a
/// holder judges: a set past the caps would derive an address whose
/// rules nothing could decode, and refusing at publish is the verdict a
/// package author can read.
fn check_grants_bounds(grants: &GrantsExpr) -> Result<(), SignatureBoundsError> {
    grants.iter().try_for_each(|(behaviour, rule)| {
        // The constant a behaviour's own absence already says is a second
        // spelling of nothing, and saying so at publish is what keeps the
        // sealed table to one spelling per state. Which side a rule's
        // leaves read is the resolver's, because the sealed leaf a
        // declared one becomes is chosen there.
        if *rule
            == if behaviour.asks_about_the_actor() {
                never()
            } else {
                always()
            }
        {
            return Err(SignatureBoundsError::UnadmittedGrant);
        }
        // A movement entry naming a badge through configuration seals as
        // both shapes a holding takes, because a configuration field
        // carries no kind — so the rule the address folds sits one level
        // below the rule the author wrote, and is held to the caps there.
        let widening: usize = if behaviour.asks_about_the_actor() {
            0
        } else {
            rule.leaves()
                .filter(|leaf| matches!(leaf, GrantClaim::Config(_)))
                .count()
        };
        if !rule.within_caps(usize::from(widening > 0)) {
            return Err(SignatureBoundsError::RuleCaps);
        }
        // And the leaves it seals as, not only the ones it was written
        // with: each widened leaf becomes two, so a set inside the
        // budget as declared can be past it as sealed — which derives an
        // address whose rules nothing can decode. Whether a given field
        // actually widens is the instance's answer, so what is decidable
        // here is the ceiling: refusing on it refuses a package that
        // could only ever have resolved for some configurations.
        if rule.leaves().count() + widening > MAX_RULE_LEAVES {
            return Err(SignatureBoundsError::RuleCaps);
        }
        rule.leaves().try_for_each(check_grant_leaf)
    })
}

/// One grant leaf, held to the one link a badge chain may be.
///
/// A badge carries the rules its own address grants, and those rules name
/// no badge: the chain a resource's address folds is one link long, so
/// the depth of a derivation is a property of the resource rather than of
/// how deeply its author nested. The verdict is here as well as at
/// resolution because publish is where a package author can read it.
fn check_grant_leaf(claim: &GrantClaim) -> Result<(), SignatureBoundsError> {
    let rules = match claim {
        GrantClaim::SelfAddr | GrantClaim::Config(_) => return Ok(()),
        GrantClaim::SelfBadge { rules, .. } | GrantClaim::SelfInstance { rules, .. } => rules,
    };
    rules.iter().try_for_each(|(_, rule)| {
        if !rule.within_caps(0) {
            return Err(SignatureBoundsError::RuleCaps);
        }
        rule.leaves().try_for_each(|leaf| match leaf {
            GrantClaim::SelfAddr | GrantClaim::Config(_) => Ok(()),
            GrantClaim::SelfBadge { .. } | GrantClaim::SelfInstance { .. } => {
                Err(SignatureBoundsError::BadgeChainTooDeep)
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyperscale_vm_types::Moves;

    use super::*;
    use crate::PACKAGE_SLOT_BASE;
    use crate::dsl::{
        Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, ModeExpr,
        SlotRef, TargetExpr,
    };
    use crate::metadata::PackageMetadata;
    use crate::publish::package::check_metadata;
    use crate::resource::{GrantedBehaviour, GrantsExpr};
    use crate::rule::{GrantRuleExpr, MAX_RULE_BRANCHES, MAX_RULE_DEPTH, RuleExpr};
    use crate::signature::{AbiParam, MethodSignature, Totality};
    use crate::types::{MAX_VALUE_BYTES, MAX_VALUE_DEPTH, MAX_VALUE_ITEMS, SlotId, Value};

    /// A signature whose only effect points at `expr`.
    fn signature_over(expr: Expr) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Point(expr),
                mode: ModeExpr::Write { moves: Moves::Both },
                denomination: None,
            }],
            ..MethodSignature::default()
        }
    }

    fn one_method(signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert("m".into(), signature);
        metadata
    }

    /// Both sides of a bound: the structure at it is admitted, the one
    /// past it refused.
    fn assert_bounded(admitted: &PackageMetadata, refused: &PackageMetadata) {
        assert_eq!(check_metadata(admitted), Ok(()));
        assert!(
            check_metadata(refused).is_err(),
            "the checker admitted a structure past the bound"
        );
    }

    /// A left-nested projection chain, the shape the evaluator's own
    /// depth test uses.
    fn nested_projection(depth: usize) -> Expr {
        let mut expr = Expr::Arg(0);
        for _ in 0..depth {
            expr = Expr::Field(Box::new(expr), 0);
        }
        expr
    }

    fn nested_foreach(depth: usize) -> Clause {
        let mut clause = Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        for _ in 0..depth {
            clause = Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        clause
    }

    #[test]
    fn expression_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH))),
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH + 1))),
        );
    }

    #[test]
    fn abi_expressions_are_bounded_like_every_other_walk() {
        let derived = |depth: usize| MethodSignature {
            totality: Totality::Fallible,
            abi: vec![AbiParam::Derived(nested_projection(depth))],
            ..MethodSignature::default()
        };
        assert_bounded(
            &one_method(derived(MAX_EXPR_DEPTH)),
            &one_method(derived(MAX_EXPR_DEPTH + 1)),
        );
    }

    #[test]
    fn clause_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH)],
                ..MethodSignature::default()
            }),
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH + 1)],
                ..MethodSignature::default()
            }),
        );
    }

    #[test]
    fn a_range_cap_is_an_expression_under_the_expression_bounds() {
        // No magnitude bound stands here: what bounds an evaluated cap
        // is the depth `footprint` charges for it. The expression itself
        // walks the same structural bounds as the bounds beside it.
        let capped = |cap: Expr| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: SlotRef::Fixed(SlotId(PACKAGE_SLOT_BASE)),
                        material: vec![],
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(u128::MAX)),
                        cap,
                    },
                    mode: ModeExpr::Read,
                    denomination: None,
                }],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &capped(nested_projection(MAX_EXPR_DEPTH)),
            &capped(nested_projection(MAX_EXPR_DEPTH + 1)),
        );
    }

    #[test]
    fn a_clause_tree_wider_than_a_signature_can_declare_is_refused() {
        let effect = Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let with = |count: usize| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![effect.clone(); count],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &with(MAX_EFFECTS_PER_SIGNATURE),
            &with(MAX_EFFECTS_PER_SIGNATURE + 1),
        );
    }

    /// A gate mints one claim, or two where an instance widens to its
    /// resource, so the cap is headroom — and it is a cap of its own
    /// because the shared effect budget is four thousand, which is the
    /// wrong size for a set every later node presenting this one copies.
    #[test]
    fn a_signature_minting_more_than_a_gate_needs_is_refused() {
        let mints = Clause::Mints {
            guard: None,
            claim: Expr::SelfAddr,
        };
        let with = |count: usize| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![mints.clone(); count],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &with(MAX_MINTS_PER_SIGNATURE),
            &with(MAX_MINTS_PER_SIGNATURE + 1),
        );
    }

    #[test]
    fn literal_nesting_is_bounded_where_admission_bounds_it() {
        let literal = |depth: usize| {
            let mut value = Value::U64(0);
            for _ in 1..depth {
                value = Value::Tuple(vec![value]);
            }
            Expr::Literal(value)
        };
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_DEPTH))),
            &one_method(signature_over(literal(MAX_VALUE_DEPTH + 1))),
        );
    }

    /// A value's width is bounded wherever one comes from.
    ///
    /// The codec refuses an over-wide value on the way in, so a literal
    /// that arrived is already inside the bound; this holds the two
    /// cases no decoder saw — a declaration assembled in memory, and a
    /// list the evaluator would build from the expression's own arity.
    /// What the bound buys is that a walk over a value costs something
    /// the per-clause charge can pay for.
    #[test]
    fn a_value_wider_than_a_walk_is_charged_for_is_refused() {
        let literal = |items: usize| Expr::Literal(Value::List(vec![Value::U64(0); items]));
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_ITEMS))),
            &one_method(signature_over(literal(MAX_VALUE_ITEMS + 1))),
        );

        let built = |items: usize| Expr::List(vec![Expr::Literal(Value::U64(0)); items]);
        assert_bounded(
            &one_method(signature_over(built(MAX_VALUE_ITEMS))),
            &one_method(signature_over(built(MAX_VALUE_ITEMS + 1))),
        );

        let bytes = |len: usize| Expr::Literal(Value::Bytes(vec![0; len]));
        assert_bounded(
            &one_method(signature_over(bytes(MAX_VALUE_BYTES))),
            &one_method(signature_over(bytes(MAX_VALUE_BYTES + 1))),
        );
    }

    /// A declared threshold sits under the caps a stored one is decoded
    /// under, so a signature that publishes cannot evaluate into a rule
    /// the decode gate would refuse.
    #[test]
    fn a_declared_rule_is_held_to_the_stored_rules_caps() {
        let guarded = |rule: RuleExpr| PackageMetadata {
            methods: BTreeMap::from([(
                "m".to_owned(),
                MethodSignature {
                    effects: vec![Clause::Requires { guard: None, rule }],
                    ..MethodSignature::default()
                },
            )]),
            ..PackageMetadata::default()
        };
        let leaf = || RuleExpr::claim(Expr::Config(0));
        let nest = |levels: usize| {
            let mut rule = leaf();
            for _ in 0..levels {
                rule = RuleExpr::CountOf {
                    count: 1,
                    rules: vec![rule],
                };
            }
            rule
        };

        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH - 1))).is_ok());
        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH))).is_err());
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES],
            }))
            .is_ok()
        );
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES + 1],
            }))
            .is_err()
        );

        // The degenerate thresholds a stored rule is refused for: one
        // that admits anyone, and one that admits no one.
        for count in [0, 3] {
            assert!(
                check_metadata(&guarded(RuleExpr::CountOf {
                    count,
                    rules: vec![leaf(), leaf()],
                }))
                .is_err()
            );
        }
    }

    /// A granted rule is held to the leaves it *seals* as.
    ///
    /// A configuration leaf on a holder behaviour carries an address and
    /// no kind, so what it seals as is a threshold over both shapes a
    /// holding takes — two leaves where the author wrote one. A set
    /// inside the budget as declared can therefore be past it as sealed,
    /// and the address it would derive is one whose rules no decoder
    /// admits: a resource nobody may ever move.
    ///
    /// Whether a given field widens is the instance's answer, so what is
    /// decidable here is the ceiling. An actor question reads the claim
    /// as it stands and widens nothing, which is what the second half
    /// pins.
    #[test]
    fn a_granted_rule_is_held_to_the_leaves_it_seals_as() {
        // Leaves in groups the branch cap admits, so what this varies is
        // the leaf count and nothing else.
        let leaves_of = |count: usize| {
            let leaf = || GrantRuleExpr::Require(GrantClaim::Config(0));
            let mut branches: Vec<GrantRuleExpr> = Vec::new();
            let mut left = count;
            while left > 0 {
                let group = left.min(MAX_RULE_BRANCHES);
                branches.push(GrantRuleExpr::CountOf {
                    count: 1,
                    rules: (0..group).map(|_| leaf()).collect(),
                });
                left -= group;
            }
            GrantRuleExpr::CountOf {
                count: 1,
                rules: branches,
            }
        };
        let granting = |behaviour, count: usize| {
            let mut grants = GrantsExpr::new();
            grants.set(behaviour, leaves_of(count));
            check_grants_bounds(&grants)
        };

        // A holder question doubles: half the budget is the ceiling.
        let half = MAX_RULE_LEAVES / 2;
        assert!(granting(GrantedBehaviour::Withdraw, half).is_ok());
        assert!(
            granting(GrantedBehaviour::Withdraw, half + 1).is_err(),
            "a set that seals past the caps is refused where it was written"
        );

        // An actor question reads the claim it was given, so its whole
        // budget is its own.
        assert!(granting(GrantedBehaviour::Mint, MAX_RULE_LEAVES).is_ok());
        assert!(granting(GrantedBehaviour::Mint, MAX_RULE_LEAVES + 1).is_err());
    }
}

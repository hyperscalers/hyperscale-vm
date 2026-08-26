//! The leaf grammar every authored rule is written in.
//!
//! One parser for both spellings a package can reach: a gate's
//! `#[requires(…)]` and a resource's `grants(…)`. What differs between
//! them is what a leaf means, which arrives as a closure — so the shape
//! of a rule, its thresholds and its branch caps are stated once and
//! neither spelling can drift from the other.

use hyperscale_vm_effects::{MAX_RULE_DEPTH, Rule, well_formed};
use proc_macro2::Span;
use syn::spanned::Spanned as _;

/// One rule as written, before either position turns it into tokens.
///
/// A method's gate and a resource's granted entry take the same grammar
/// over different leaves and emit different types. Parsed once, so the
/// two cannot drift in the ways they already had: two spellings of one
/// depth refusal, two count parsers, and one `n_of` predicate applied
/// from two places.
pub enum RuleAst<L> {
    /// A claim, in whatever shape the position admits.
    Leaf(L),
    /// A threshold over branches, its count already held to the
    /// vocabulary's predicate.
    CountOf { count: u8, branches: Vec<Self> },
}

/// The rule grammar, over whatever leaf the position admits.
///
/// Rust's own operators carry the algebra: `||` is a count of one, `&&`
/// a count of every branch, and `n_of(k, …)` the threshold no operator
/// expresses. Precedence and grouping are the language's, so an author
/// reads a rule the way they read any other condition — and a chain of
/// one operator flattens into one threshold rather than nesting, because
/// depth is the cap that binds first.
///
/// `noun` is what a refusal calls the thing being written, and it is the
/// only difference between the two positions a reader should see.
pub fn parse_rule<L>(
    expr: &syn::Expr,
    noun: &str,
    depth: usize,
    leaf: &mut impl FnMut(&syn::Expr) -> syn::Result<L>,
) -> syn::Result<RuleAst<L>> {
    match expr {
        syn::Expr::Paren(inner) => parse_rule(&inner.expr, noun, depth, leaf),
        syn::Expr::Binary(binary) => {
            let all = match binary.op {
                syn::BinOp::Or(_) => false,
                syn::BinOp::And(_) => true,
                _ => {
                    return Err(syn::Error::new(
                        binary.op.span(),
                        format!("{noun} combines claims with `||`, `&&`, or `n_of(k, …)`"),
                    ));
                }
            };
            let branches =
                parse_branches(expr.span(), &flatten(expr, &binary.op), noun, depth, leaf)?;
            // `||` is a count of one and `&&` a count of every branch, so
            // neither can be a threshold nobody meant: a chain has at
            // least two branches, and both counts sit inside them.
            let count = if all {
                u8::try_from(branches.len()).unwrap_or(u8::MAX)
            } else {
                1
            };
            check_threshold_node(expr.span(), count, branches.len())?;
            Ok(RuleAst::CountOf { count, branches })
        }
        // A threshold no operator expresses: `n_of(2, a, b, c)`.
        syn::Expr::Call(call) if calls(&call.func, "n_of") => {
            let mut args = call.args.iter();
            let count = args.next().and_then(count_literal).ok_or_else(|| {
                syn::Error::new(
                    call.span(),
                    "a threshold states its count first: `n_of(2, a, b, c)`",
                )
            })?;
            let rest: Vec<_> = args.collect();
            let branches = parse_branches(call.span(), &rest, noun, depth, leaf)?;
            check_threshold_node(call.span(), count, branches.len())?;
            Ok(RuleAst::CountOf { count, branches })
        }
        other => Ok(RuleAst::Leaf(leaf(other)?)),
    }
}

/// The branches of one threshold, held to the depth the vocabulary
/// admits.
///
/// The cap is read from the vocabulary rather than restated, and it is
/// checked here rather than at the tracer's own assertion: both refuse
/// the same trees — a threshold at the deepest level would put its
/// branches past the cap, which is what `within_caps` walks into — but
/// only this one can point at the line that wrote it. Depth is a
/// property of the shape alone, so a rule whose leaves nobody has
/// evaluated is still answerable for it.
pub fn parse_branches<L>(
    span: Span,
    branches: &[&syn::Expr],
    noun: &str,
    depth: usize,
    leaf: &mut impl FnMut(&syn::Expr) -> syn::Result<L>,
) -> syn::Result<Vec<RuleAst<L>>> {
    if depth + 1 >= MAX_RULE_DEPTH {
        return Err(syn::Error::new(
            span,
            format!("{noun} nests past the {MAX_RULE_DEPTH} levels the vocabulary admits"),
        ));
    }
    branches
        .iter()
        .map(|branch| parse_rule(branch, noun, depth + 1, leaf))
        .collect()
}

/// One threshold node's shape, judged by the vocabulary's own predicate
/// — the same one the tracer's `n_of` and the stored rule's decode gate
/// apply — so what the macro refuses cannot fork from what they refuse.
/// The span is the one thing this side adds: the line that wrote the
/// gate, rather than the tracer's panic inside a generated `blueprint()`.
pub fn check_threshold_node(span: Span, count: u8, width: usize) -> syn::Result<()> {
    let node = Rule::CountOf {
        count,
        rules: vec![Rule::Require(()); width],
    };
    well_formed(&node).map_err(|reason| syn::Error::new(span, reason))
}

/// One operator's whole chain as a flat branch list.
///
/// `a || b || c` parses left-nested, and nesting is what the depth cap
/// binds first — so a chain of one operator is one threshold over three
/// branches rather than two over two.
pub fn flatten<'a>(expr: &'a syn::Expr, op: &syn::BinOp) -> Vec<&'a syn::Expr> {
    let same = |other: &syn::BinOp| {
        matches!(
            (op, other),
            (syn::BinOp::Or(_), syn::BinOp::Or(_)) | (syn::BinOp::And(_), syn::BinOp::And(_))
        )
    };
    match expr {
        syn::Expr::Binary(binary) if same(&binary.op) => {
            let mut out = flatten(&binary.left, op);
            out.extend(flatten(&binary.right, op));
            out
        }
        other => vec![other],
    }
}

/// A `u8` count written as a literal.
pub fn count_literal(expr: &syn::Expr) -> Option<u8> {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(int) => int.base10_parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// Whether a call's callee is the free function `name`.
pub fn calls(func: &syn::Expr, name: &str) -> bool {
    matches!(func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|last| last.ident == name))
}

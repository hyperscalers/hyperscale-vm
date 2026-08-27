//! Lowering a method body to its access declaration and its guest code.
//!
//! A syntactic dataflow pass, not an interpreter. It walks statements in
//! order, tracks what each local holds as a [`Slot`], and records every
//! site where the body opens a handle on component state. A *value* it
//! cannot express becomes [`Slot::Opaque`] and is carried along harmlessly
//! until something tries to use it as a key — which is where the macro
//! stops and points at the line. An *expression form* it does not model is
//! refused outright: walking past one would drop whatever accesses it
//! contains, and a silently smaller declaration is the one failure mode
//! the derivation must not have.
//!
//! Two properties make this sound rather than a heuristic:
//!
//! - **The access vocabulary is closed.** State is reachable only through
//!   the handle types in `hyperscale_vm_sdk::state`, and every method on
//!   them names exactly one point of the mode lattice. So the *mode* is
//!   read off the body rather than declared, and a method that both reads
//!   and writes one cell folds to `Write` because the lattice says so.
//! - **Over-declaration is legal.** A conditional access is declared on
//!   both arms, so the declaration is a superset of what any one execution
//!   touches. The VM already supports this — it prices the superset through
//!   `footprint` rather than rejecting it — which is what lets ordinary
//!   control flow survive the pass.
//!
//! # One walk, two outputs
//!
//! The same walk produces the executing body. Every expression evaluates
//! to a [`Val`] — what the declaration learns — beside a [`Code`] — what
//! the guest runs. The two cannot be derived from one another and they
//! cannot be walked apart: which handle `self.vaults.at(k)` resolves to is
//! the declaration's answer, and rewriting the call to that handle is the
//! guest's, so a second pass would be a second opinion on the same
//! question.
//!
//! What the guest reaches through an export parameter rather than
//! computes is what [`Need`] enumerates, and it is why the binding is not
//! a function of the declaration: an argument consumed as key material
//! never reaches the guest, and a fresh id the guest never draws does.

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::vocabulary::RESOURCE;
use hyperscale_vm_effects::{GrantedBehaviour, Issued, ResourceKind};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;

mod resource_ops;

use crate::resource::Resource;
use crate::state::holds_rule;
use crate::term::{Op, Slot, SlotRef, Term};
use crate::{Declared, is_named};

/// What kind of state a component field holds, and under which slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// The instance's creation-fixed configuration; its fields are the
    /// record's config slots.
    Config,
    /// A single substate leaf.
    Cell,
    /// A family of leaves keyed by an address.
    Keyed,
    /// An ordered collection.
    Ordered,
    /// An unordered collection: entries keyed by hash.
    Unordered,
}

/// One declared field of the component's state.
#[derive(Clone, Debug)]
pub struct Field {
    /// The slot the field's children sit under.
    pub slot: u16,
    /// What shape of state it is.
    pub kind: FieldKind,
    /// The value each leaf holds, which is what a guest accessor decodes
    /// into.
    pub element: Option<syn::Type>,
    /// The resource this field's leaves hold, where the field states one.
    ///
    /// A `Keyed<Vault>` is denominated by whatever key a body names, so
    /// it carries none; a `Cell<Vault>` has no key to be denominated by
    /// and states it here.
    pub denomination: Option<syn::Expr>,
}

/// One target a body opened a handle on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    /// A single substate leaf under a slot.
    Point {
        /// The slot.
        slot: SlotRef,
        /// The child-key material.
        material: Vec<Term>,
        /// Whose prefix the leaf sits under, where it is not the
        /// declaring instance's own.
        ///
        /// A reaching access says so here and says which authority it
        /// acts under beside it; every ordinary one leaves both absent
        /// and lands under `self`.
        owner: Option<Term>,
    },
    /// One ordered-collection entry.
    Entry {
        /// The collection's slot.
        slot: u16,
        /// The sub-collection under that slot, empty where the slot holds
        /// one collection outright.
        material: Vec<Term>,
        /// The entry's order key.
        order: Term,
    },
    /// An interval of a collection's order-key space.
    Range {
        /// The collection's slot.
        slot: SlotRef,
        /// Whose prefix the collection sits under, on [`Target::Point`]'s
        /// terms.
        owner: Option<Term>,
        /// The sub-collection under that slot, empty where the slot holds
        /// one collection outright.
        material: Vec<Term>,
        /// Inclusive lower bound.
        lo: Term,
        /// Inclusive upper bound.
        hi: Term,
        /// The entry cap, derivable like the bounds beside it — or
        /// absent, for an interval whose cap is the count of the one
        /// move performed through it ([`Site::moved`]).
        cap: Option<Term>,
    },
    /// One unordered-collection entry, at the hash of a logical key.
    KeyedEntry {
        /// The collection's slot.
        slot: u16,
        /// The logical key, hashed into the entry's order.
        key: Term,
    },
    /// An unordered collection's tail from a cursor.
    Sweep {
        /// The collection's slot.
        slot: u16,
        /// The inclusive lower bound.
        cursor: Term,
        /// The entry cap, derivable like the cursor.
        cap: Term,
    },
}

/// A handle the body opened, with every operation performed through it.
#[derive(Clone, Debug)]
pub struct Site {
    /// What the handle is on.
    pub target: Target,
    /// The operations, in order; the mode is their fold.
    pub ops: Vec<(Op, Option<Term>)>,
    /// The value each leaf under this handle holds.
    pub element: Option<syn::Type>,
    /// The resource the leaves under this handle hold, where they hold
    /// value at all.
    ///
    /// What a credit through this handle has to carry and what a debit
    /// through it produces — one fact, read from the declaration rather
    /// than guessed from the shape of a key.
    pub denomination: Option<Term>,
    /// How many `for-each` binders enclosed the access that opened this
    /// site; zero for a clause the method declares directly.
    ///
    /// What decides whether the site the export takes is one element
    /// wide or as wide as the loop's expansion — and, where it is a
    /// loop's, which loop's index its elements are named by.
    pub binder: usize,
    /// The behaviour this site's access reaches a foreign prefix under,
    /// where it reaches one.
    pub reach: Option<GrantedBehaviour>,
    /// The condition this site's clause is declared under, or `None` for
    /// a clause declared always.
    ///
    /// A property of the cell rather than of where the access was
    /// written: a body touches one cell from wherever it likes, and what
    /// the declaration owes is the condition that holds at every one of
    /// those places. Where they do not agree there is no such condition
    /// but the trivial one, which is what `None` says.
    pub guard: Option<Term>,
    /// The cap derived from the moves performed through a capless
    /// interval: the counts of the ids each take names and the
    /// instances each filed edge carries, summed. Guarded moves sum
    /// like the rest — the sum is an upper bound on the walk, and an
    /// untaken branch over-declares only depth.
    ///
    /// Held beside the target rather than written into it, because the
    /// target is the site's identity — two opens of one capless interval
    /// must stay one site whether or not a move has landed yet.
    pub moved: Option<Term>,
}

impl Site {
    /// Whether this site declares a clause at all.
    ///
    /// A body that opens a handle and never uses it names no mode, so
    /// there is nothing for the declaration to say. Asked of the
    /// emission itself rather than of a second fold over the same
    /// operations: what a site declares is one lattice, and a copy of it
    /// here would be a copy to keep in step.
    pub fn declares(&self) -> bool {
        crate::emit::mode(self).is_some()
    }
}

/// The declaration's clause structure: sites in declaration order, with
/// `for` loops preserved as the `for-each` clauses they become.
#[derive(Clone, Debug)]
pub enum Node {
    /// One declared access, by index into [`Lowered::sites`].
    Site(usize),
    /// Bind the verdict of the clause just declared to the `bool` the
    /// export takes.
    ///
    /// A node rather than a flag on the site, because what the tracer
    /// answers with is *the clause just declared* — a fact about where
    /// emission has got to, and the emission order is what a node
    /// carries.
    BindGuard,
    /// One access set per element of a configured collection.
    ForEach {
        /// The collection mapped over.
        list: Term,
        /// The nesting depth this binder introduces.
        depth: usize,
        /// The clauses inside.
        body: Vec<Self>,
    },
}

/// Which way a branch's flag reads.
///
/// A flag names a clause, and the clause it can name is one the arm
/// declared — so where only the `else` arm touches state, the verdict
/// bound is that arm's and the `if` reads its negation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Polarity {
    /// The flag names a clause of the `if` arm.
    Taken,
    /// The flag names a clause of the `else` arm.
    Untaken,
}

/// The first clause under these nodes that `cond` guards.
///
/// The arm's own clauses and no others: a cell the arm shares with the
/// code around it is declared always, so its verdict is the constant
/// true and no export needs told.
fn declares_under(nodes: &[Node], sites: &[Site], cond: &Term) -> Option<usize> {
    nodes.iter().find_map(|node| match node {
        Node::Site(index) => sites
            .get(*index)
            .filter(|site| site.declares() && site.guard.as_ref() == Some(cond))
            .map(|_| *index),
        Node::ForEach { body, .. } => declares_under(body, sites, cond),
        Node::BindGuard => None,
    })
}

/// A runtime value the guest reaches through an export parameter because
/// it cannot compute it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Need {
    /// A value the kernel evaluates over the call's bound inputs.
    Derived(Term),
    /// The runtime amount of a bucket parameter — the one value the
    /// declaration cannot name.
    Amount(u32),
}

/// The shape of accessor a site's handle is reached through.
#[derive(Clone, Debug)]
pub enum Form {
    /// One substate leaf.
    Slot,
    /// One entry of a collection, picked out by its order key.
    ///
    /// The order is resolved where the entry is opened rather than where
    /// the handle is: it is a value the guest is handed, and a body that
    /// names an entry has needed it from that point on however it goes on
    /// to use the handle.
    Entry(TokenStream),
    /// A whole declared interval.
    Interval,
}

/// What a subexpression evaluated to, on the guest's side.
#[derive(Clone, Debug)]
pub enum Code {
    /// Code the guest runs as it stands.
    Rust(TokenStream),
    /// An open handle on a declared site. Deferred like a term: a clause
    /// a body states without operating through it — a movement it may
    /// make on one path and not another — has nothing for the guest to
    /// call, so it costs no export parameter.
    Handle {
        /// The site the handle is opened on.
        site: usize,
        /// How the accessor reaches it.
        form: Form,
        /// Where the body opened it, for the `for-each` refusal.
        span: Span,
    },
    /// A declared term. The guest reaches it only through an export
    /// parameter, so one is bound where a value is actually wanted and
    /// nowhere else — which is what keeps key material out of the ABI.
    ///
    /// Carries where the body read it. A term is a shape rather than
    /// syntax — the same `Arg(0)` is derived at every use — so nothing
    /// about it names a line, and the expression it was read from is the
    /// line a refusal about it belongs on.
    Term(Span, Term),
    /// A bucket parameter, which the guest holds under the name the
    /// author gave it. Deferred like a term: an edge a method only
    /// forwards is one whose amount its own guest never reads, and
    /// nothing in its ABI carries it.
    Bucket(Span, u32),
    /// The instance's configuration record, whole. Deferred like a
    /// term: the record is fields the kernel evaluates one at a time, so
    /// a body that only projects it binds nothing and one that passes it
    /// on binds a parameter per field.
    Record(Span),
    /// Nothing the guest can produce: a resource address, a table lookup,
    /// a handle in value position. Carries where the body named it, so a
    /// refusal can point at the line.
    Absent(Span, &'static str),
}

/// What one lowered method declares, and what its guest export runs.
#[derive(Clone, Debug, Default)]
pub struct Lowered {
    /// Every handle site, in the order the body opened them.
    pub sites: Vec<Site>,
    /// The clause tree over those sites.
    pub nodes: Vec<Node>,
    /// The resources of the value edges the method produces.
    pub outputs: Vec<Term>,
    /// The resource each consumed edge is fixed to, by parameter.
    ///
    /// Sparse, because a position is fixed only where the body credits it
    /// to a cell keyed by something other than the edge's own resource.
    pub denominations: BTreeMap<u32, Term>,
    /// The sites whose handles the export takes.
    ///
    /// Ordered by site, which is declaration order: the ABI binding rides
    /// beside the clause it names, so the export's parameter order has to
    /// be the clauses' rather than the order the body first reached for
    /// one — a nested access would otherwise number them apart.
    pub handles: BTreeSet<usize>,
    /// The sites a `for-each` body declared, whose width is the
    /// instance's rather than the signature's.
    ///
    /// A subset of [`Lowered::handles`], because a looped site is a
    /// handle parameter like any other — what differs is how many
    /// elements it covers and how the binding names it.
    pub looped: BTreeSet<usize>,
    /// The values the export takes, in the order the body needs them.
    pub values: Vec<Need>,
    /// How many fresh ids the body draws.
    pub fresh: usize,
    /// The branches whose verdict the export takes, in the order they
    /// were declared, each saying which arm's clause its flag names.
    pub flags: Vec<Polarity>,
    /// The bucket parameters the body destroys, in the order it reaches
    /// them.
    ///
    /// Separate from `issues` because the resource is separate: an
    /// issuance derives one this instance owns, and this names one a
    /// caller chose.
    pub destroys: Vec<u32>,
    /// Every resource the body issues — its kind, its mark and which way
    /// the body moves it — in the order the walk first reached each.
    ///
    /// The order is the index: the trace binds them in this order and
    /// each call site passes its own position, so a component founding
    /// three resources says which of them each call means and the two
    /// halves cannot disagree.
    ///
    /// The direction is the body's own fact: a burn has no output
    /// projection to read one from, and a frame asked the entry it never
    /// uses would be held to an authority it does not exercise.
    pub issues: Vec<(ResourceKind, Vec<u8>, Issued)>,
    /// The rewritten statements, executing against materialized handles.
    pub body: TokenStream,
    /// The value edges the body ends with, each as the expression that
    /// produced it.
    ///
    /// Composed into a return by whichever target is emitting: a guest
    /// hands the kernel back the handle it owns, a host the table
    /// position it holds — which is the one place the two tails differ,
    /// and the reason this is the edges rather than the tail.
    pub edges: Vec<TokenStream>,
    /// The value the body ends with beside its edges, as the expression
    /// that computed it.
    ///
    /// Encoded into the receipt rather than routed: a manifest consumes
    /// edges, and a value has no shape a later node could take. Both
    /// halves compose it the same way, so unlike the edges this is the
    /// expression itself.
    pub answer: Option<TokenStream>,
    /// Which element of the tail the answer came from.
    ///
    /// The signature's own tuple position, so a caller's wrapper can
    /// name the answer's Rust type without classifying the tail a second
    /// time — the walk already decided which element was an edge and
    /// which was the value, and re-deciding it syntactically is the
    /// classification that drifts.
    pub answer_at: usize,
    /// Whether the method yields a value at all.
    pub returns: bool,
}

/// What a method's tail hands back.
///
/// The edges are two lists rather than one because the halves compose
/// them differently — a guest hands the kernel the handle it owns, a
/// host the table position it holds — where the answer is one
/// expression both halves encode the same way.
#[derive(Default)]
struct Returned {
    /// The resource of each value edge, in output order.
    outputs: Vec<Term>,
    /// The guest code for each edge, in the same order.
    edges: Vec<TokenStream>,
    /// The value beside them, where the method answers with one.
    answer: Option<TokenStream>,
    /// Which element of the tail that value was.
    answer_at: usize,
}

impl Lowered {
    /// The site reaching the component's own unkeyed cell at `slot`,
    /// which is where a package's stored role table lives.
    ///
    /// Both halves of a table gate ask this one question: the shape
    /// check holds a rewrite to reading what it rewrites, and the
    /// emission rides the body's clause rather than declaring the read
    /// beside it.
    pub fn point_site(&self, slot: u16) -> Option<&Site> {
        self.sites.iter().find(|site| {
            matches!(
                &site.target,
                Target::Point { slot: at, material, owner: None }
                    if at.fixed() == Some(slot) && material.is_empty()
            )
        })
    }
}

/// What a subexpression evaluated to.
#[derive(Clone, Debug)]
enum Val {
    /// A DSL-expressible value.
    Term(Term),
    /// `self.<field>`, and the material naming the sub-collection under
    /// it — empty until a body says otherwise. Not yet an access.
    Field {
        /// The state field's name.
        name: String,
        /// The sub-collection under the field's slot.
        material: Vec<Term>,
    },
    /// The instance's configuration record; its fields are config slots.
    Config,
    /// An open handle, by site index.
    Handle(usize),
    /// A value edge this call produces, carrying the named resource.
    ///
    /// Kept apart from [`Val::Term`] because a produced bucket is the one
    /// thing a return position treats specially: `outputs` records the
    /// resource, and `-> Bucket` on its own never could.
    Produced(Term),
    /// Several value edges at once, in the order the tuple holds them.
    ///
    /// A division of one edge yields parts that all carry what the whole
    /// carried, and a `let` over a tuple pattern is where they take their
    /// names. Without this the parts bind opaquely and everything
    /// downstream stops knowing what they hold.
    Edges(Vec<Term>),
    /// Anything the grammar does not cover.
    Opaque,
}

impl Val {
    /// The DSL term this reading is, where it is one.
    fn term(self) -> Option<Term> {
        match self {
            Self::Term(term) => Some(term),
            _ => None,
        }
    }
}

impl From<Slot> for Val {
    fn from(slot: Slot) -> Self {
        match slot {
            Slot::Value(term) | Slot::Deferred(term) => Self::Term(term),
            Slot::Handle(index) => Self::Handle(index),
            Slot::Produced(term) => Self::Produced(term),
            Slot::Config => Self::Config,
            Slot::Opaque => Self::Opaque,
        }
    }
}

/// One expression's two readings: what the declaration learns, and what
/// the guest runs.
#[derive(Clone, Debug)]
struct Eval {
    val: Val,
    code: Code,
}

impl Eval {
    /// An expression the declaration reads nothing from, rewritten
    /// verbatim.
    const fn plain(code: TokenStream) -> Self {
        Self {
            val: Val::Opaque,
            code: Code::Rust(code),
        }
    }

    /// An expression neither reading names anything.
    const fn absent(span: Span, why: &'static str) -> Self {
        Self {
            val: Val::Opaque,
            code: Code::Absent(span, why),
        }
    }
}

/// Split a block into its statements and its tail expression, if it has
/// one. The tail is where a method's produced value edges are named.
fn split_tail(block: &syn::Block) -> (&[syn::Stmt], Option<&syn::Expr>) {
    match block.stmts.split_last() {
        Some((syn::Stmt::Expr(expr, None), rest)) => (rest, Some(expr)),
        _ => (&block.stmts, None),
    }
}

/// Strip a type ascription off a pattern: `let x: u64 = …` binds `x`.
fn unwrap_pat(pat: &syn::Pat) -> &syn::Pat {
    match pat {
        syn::Pat::Type(typed) => unwrap_pat(&typed.pat),
        // `&name` and `name` bind the same thing: what a pattern takes a
        // reference apart from is still the value the walk is tracking.
        syn::Pat::Reference(reference) => unwrap_pat(&reference.pat),
        other => other,
    }
}

/// Reach the expression a borrow names: `&edge` and `edge` name the
/// same edge, and a call reading one for its declaration wants what it
/// names rather than the reference.
fn borrowed(expr: &syn::Expr) -> &syn::Expr {
    match expr {
        syn::Expr::Reference(reference) => borrowed(&reference.expr),
        syn::Expr::Paren(paren) => borrowed(&paren.expr),
        syn::Expr::Group(group) => borrowed(&group.expr),
        other => other,
    }
}

/// A verb at the start of a sentence.
fn capitalized(verb: &str) -> String {
    let mut chars = verb.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + chars.as_str()
    })
}

/// Whether a binary operator writes its left operand (`+=` and family).
const fn binary_op_assigns(op: syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::AddAssign(_)
            | syn::BinOp::SubAssign(_)
            | syn::BinOp::MulAssign(_)
            | syn::BinOp::DivAssign(_)
            | syn::BinOp::RemAssign(_)
            | syn::BinOp::BitXorAssign(_)
            | syn::BinOp::BitAndAssign(_)
            | syn::BinOp::BitOrAssign(_)
            | syn::BinOp::ShlAssign(_)
            | syn::BinOp::ShrAssign(_)
    )
}

/// The judgment a comparison spells, where both operands are terms.
///
/// Six operators over two DSL variants: `!=`, `>`, `<=` and `>=` are the
/// two the vocabulary has, rearranged. Deriving them rather than refusing
/// them is what keeps an author from writing `>=` and getting the
/// superset silently — the cost of an unread branch is contention, which
/// is not a thing a compiler complains about.
const fn judges(op: syn::BinOp) -> bool {
    matches!(
        op,
        syn::BinOp::Eq(_)
            | syn::BinOp::Ne(_)
            | syn::BinOp::Lt(_)
            | syn::BinOp::Gt(_)
            | syn::BinOp::Le(_)
            | syn::BinOp::Ge(_)
            | syn::BinOp::And(_)
            | syn::BinOp::Or(_)
    )
}

fn judgment(op: syn::BinOp, left: &Val, right: &Val) -> Option<Term> {
    let (Val::Term(left), Val::Term(right)) = (left, right) else {
        return None;
    };
    let (left, right) = (Box::new(left.clone()), Box::new(right.clone()));
    let ordered = |lo: Box<Term>, hi: Box<Term>| Term::Lt(lo, hi);
    Some(match op {
        syn::BinOp::Eq(_) => Term::Eq(left, right),
        syn::BinOp::Ne(_) => Term::Not(Box::new(Term::Eq(left, right))),
        syn::BinOp::Lt(_) => ordered(left, right),
        syn::BinOp::Gt(_) => ordered(right, left),
        syn::BinOp::Le(_) => Term::Not(Box::new(ordered(right, left))),
        syn::BinOp::Ge(_) => Term::Not(Box::new(ordered(left, right))),
        syn::BinOp::And(_) | syn::BinOp::Or(_) => {
            if !left.is_judgment() || !right.is_judgment() {
                return None;
            }
            if matches!(op, syn::BinOp::And(_)) {
                Term::And(left, right)
            } else {
                Term::Or(left, right)
            }
        }
        _ => return None,
    })
}

/// The two arms of an `if` that could be a selection: each a block whose
/// only statement is its tail, and an `else` that is one of those or a
/// further `if`. An `if let` is excluded by its condition binding names,
/// which a value position has nowhere to put.
fn selectable(branch: &syn::ExprIf) -> Option<(&syn::Expr, &syn::Expr)> {
    if matches!(&*branch.cond, syn::Expr::Let(_)) {
        return None;
    }
    let [syn::Stmt::Expr(then, None)] = branch.then_branch.stmts.as_slice() else {
        return None;
    };
    let (_, otherwise) = branch.else_branch.as_ref()?;
    let otherwise = match &**otherwise {
        syn::Expr::Block(block) => match block.block.stmts.as_slice() {
            [syn::Stmt::Expr(expr, None)] => expr,
            _ => return None,
        },
        // `else if` chains, so a package's own multi-way table reads the
        // way the same table written in Rust would.
        chained @ syn::Expr::If(_) => chained,
        _ => return None,
    };
    Some((then, otherwise))
}

/// Whether an expression is the bare `self` path.
pub fn is_self(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Path(path) if path.path.is_ident("self"))
}

/// Whether an expression is written block-first, which a statement would
/// parse as a statement of its own — a consumer rendering tokens after
/// one wraps it in parentheses so the whole stays one expression.
const fn block_form(expr: &syn::Expr) -> bool {
    matches!(
        expr,
        syn::Expr::Block(_)
            | syn::Expr::If(_)
            | syn::Expr::Match(_)
            | syn::Expr::ForLoop(_)
            | syn::Expr::While(_)
            | syn::Expr::Loop(_)
            | syn::Expr::Unsafe(_)
            | syn::Expr::TryBlock(_)
            | syn::Expr::Const(_)
    )
}

/// The generated name of the `index`-th bound export value.
pub fn value_ident(index: usize) -> syn::Ident {
    syn::Ident::new(&format!("__value_{index}"), Span::call_site())
}

/// The generated name of the `index`-th branch's verdict.
pub fn flag_ident(index: usize) -> syn::Ident {
    syn::Ident::new(&format!("__flag_{index}"), Span::call_site())
}

/// The generated name of the handle materialized for `site`.
pub fn handle_ident(site: usize) -> syn::Ident {
    syn::Ident::new(&format!("__capability_{site}"), Span::call_site())
}

/// The generated name of the element index a site at binder depth
/// `depth` is walked by.
pub fn element_index_ident(depth: usize) -> syn::Ident {
    syn::Ident::new(&format!("__element_{depth}"), Span::call_site())
}

/// The lowering pass over one method body.
pub struct Lowerer<'a> {
    /// Everything the package declares by name — the same set the gate
    /// parser reads, so a body and its gate resolve one name one way.
    declared: &'a Declared<'a>,
    /// Whether the method claims totality, which is what turns a branch
    /// back into the superset it used to declare: a total leg runs with
    /// every declared handle materialized, and a guarded-out clause
    /// materializes none.
    total: bool,
    params: &'a [(String, syn::Type)],
    /// Whether the method yields anything at all, read off its return
    /// type. A body ending in a loop or a conditional has a tail
    /// expression of unit type, which is a statement rather than a value
    /// however it is spelled.
    returns: bool,
    locals: Vec<BTreeMap<String, Slot>>,
    out: Lowered,
    /// The clause scopes being built, innermost last.
    scopes: Vec<Vec<Node>>,
    /// The `for-each` binders enclosing the walk, innermost last: the
    /// site count when each opened, and the list it maps over.
    ///
    /// The floor separates two loops that sit side by side — their
    /// elements are both binding zero, so a body writing the same cell
    /// in each spells one target twice, and the floor tells the sites one
    /// loop opened from the sites around it. The list is what an element
    /// read as a value reads out of: the site is walked by the element's
    /// index, so the same index into the same list is the same element.
    binders: Vec<(usize, Term)>,
    /// The conditions the walk is under, innermost last, each already
    /// conjoined with the ones enclosing it.
    guards: Vec<Term>,
    /// The sites the survey found touched under more than one condition,
    /// whose clauses are therefore declared always.
    ///
    /// By site rather than by target, because the two walks number sites
    /// identically and a spelling is not an identity: two loops side by
    /// side name their elements the same way, so a guard one of them is
    /// under is no fact about the other's leaf.
    escaping: Vec<usize>,
    /// Every condition a site was reached under, in the order the walk
    /// reached them. Filled by the survey and read by nothing else.
    reached: Vec<(usize, Option<Term>)>,
    errors: Vec<syn::Error>,
}

impl<'a> Lowerer<'a> {
    /// Start a pass over a method with these positional parameters.
    pub fn new(
        declared: &'a Declared<'a>,
        params: &'a [(String, syn::Type)],
        returns: bool,
        total: bool,
    ) -> Self {
        Self {
            declared,
            total,
            params,
            returns,
            locals: vec![BTreeMap::new()],
            out: Lowered::default(),
            scopes: vec![Vec::new()],
            binders: Vec::new(),
            guards: Vec::new(),
            escaping: Vec::new(),
            reached: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// A second lowerer over the same inputs, for the survey walk.
    fn twin(&self) -> Self {
        Self::new(self.declared, self.params, self.returns, self.total)
    }

    /// The declaration an issuance is called on, kind and all.
    ///
    /// Answering the kind rather than checking it is what lets one word
    /// serve both: the derivation folds the kind, so an operation reading
    /// it off the declaration reaches the resource the author named
    /// instead of the vacant sibling the other kind would derive.
    fn issuing_mark(&mut self, call: &syn::ExprCall, op: &str) -> Option<Resource> {
        let named = free_call_mark(call);
        let at = named
            .as_ref()
            .map_or_else(|| call.func.span(), Spanned::span);
        let Some(declared) = named.and_then(|n| self.resource_named(&n)) else {
            self.error(at, &undeclared_mark(op));
            return None;
        };
        Some(declared)
    }

    /// A reach's arguments, and the resource its mark named where it was
    /// called on one.
    ///
    /// Two spellings for one operation, and the split is what the mark
    /// buys. `Resource::recall(..)` names a resource **this package
    /// issues**, so the declaration's own kind picks the cell shape and
    /// the edge type; the free `recall(.., resource, ..)` names one it
    /// does not, where there is no mark to ask and the spelling is the
    /// only signal there is.
    ///
    /// A mark that names no declaration is refused rather than read as
    /// the free form: `Whatever::halt(..)` is an author reaching for a
    /// resource they did not declare, and answering that with an arity
    /// complaint would be answering the wrong question.
    fn reached_resource<'c>(
        &mut self,
        call: &'c syn::ExprCall,
        op: &str,
        behaviour: GrantedBehaviour,
    ) -> (Vec<&'c syn::Expr>, Option<Term>) {
        let named: Vec<&syn::Expr> = call.args.iter().collect();
        let Some(mark) = free_call_mark(call) else {
            return (named, None);
        };
        let Some(declared) = self.resource_named(&mark) else {
            self.error(mark.span(), &undeclared_mark(op));
            return (Vec::new(), None);
        };
        self.granted(&declared, behaviour, call.func.span());
        (
            named,
            Some(Term::SelfResource(declared.kind, declared.mark)),
        )
    }

    /// Refuse an operation on one of the package's own marks where that
    /// mark's declaration grants nobody the behaviour.
    ///
    /// The macro holds both halves at expansion — the `grants(…)` the
    /// attribute states and the call reaching for it — so the mistake is
    /// answerable on the token that made it. Left to the layers below,
    /// an issuance is refused at publish, which has only a package to
    /// point at, and a reach is refused at every admission, which has
    /// only a caller.
    fn granted(&mut self, issued: &Resource, behaviour: GrantedBehaviour, at: Span) {
        if issued.grants.behaviours.contains(&behaviour) {
            return;
        }
        let (name, word) = (&issued.name, behaviour.word());
        // A mint is the one behaviour with a second answer: an author
        // who wanted the supply the component comes up holding wanted an
        // attribute rather than a body.
        let remedy = if behaviour == GrantedBehaviour::Mint {
            format!(
                "state `grants(mint = self)` on `{name}`, or found the supply it comes up \
                 holding with `initial(<n>)`"
            )
        } else {
            format!(
                "state `grants({word} = self)` on `{name}`, where `self` is the issuing \
                 instance"
            )
        };
        self.error(
            at,
            &format!(
                "`{name}` grants no `{word}`, and an address admits only what its \
                 declaration grants — {remedy}"
            ),
        );
    }

    /// The declaration a name refers to, where it refers to one.
    fn resource_named(&self, name: &syn::Ident) -> Option<Resource> {
        let name = name.to_string();
        self.declared
            .resources
            .iter()
            .find(|r| r.name == name)
            .cloned()
    }

    /// The key of a record-cell site — the mark-derived resource — where
    /// `site` is one, which is what makes `create` on it the record's.
    fn record_cell(&self, site: usize) -> Option<Term> {
        match self.out.sites.get(site).map(|s| &s.target) {
            Some(Target::Point { slot, material, .. }) if slot.fixed() == Some(RESOURCE.0) => {
                material.first().cloned()
            }
            _ => None,
        }
    }

    /// The declared resource an `issued(Name)` call names, as a term
    /// carrying the declaration's own mark and kind.
    fn declared_resource(&self, call: &syn::ExprCall) -> Option<Term> {
        let name = call.args.first().and_then(|arg| match arg {
            syn::Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
            _ => None,
        })?;
        let declared = self.declared.resources.iter().find(|r| r.name == name)?;
        Some(Term::SelfResource(declared.kind, declared.mark.clone()))
    }

    /// The cells this body touches under more than one condition.
    ///
    /// A guard is a fact about the cell, and one walk cannot settle it:
    /// a body that writes a cell inside a branch and again after it has
    /// written it unconditionally, and the second write is not reached
    /// until the branch is long emitted. So the walk runs twice — once
    /// to see where every cell is touched, once to declare it — and what
    /// crosses between them is this.
    ///
    /// Errors and refusals are the emitting walk's to report: this one
    /// takes the same path and would only say the same things twice.
    fn survey(mut self, block: &syn::Block) -> Vec<usize> {
        let _ = self.walk(block);
        let mut escaping = Vec::new();
        for (index, cond) in &self.reached {
            let first = self
                .reached
                .iter()
                .find(|(seen, _)| seen == index)
                .map(|(_, cond)| cond);
            if first != Some(cond) && !escaping.contains(index) {
                escaping.push(*index);
            }
        }
        escaping
    }

    /// The state a name refers to: the package's own field, or the
    /// protocol cell an accessor named.
    ///
    /// One lookup because a body cannot tell the two apart once it holds
    /// a handle — what differs is only how the name was reached.
    fn state(&self, name: &str) -> Option<Field> {
        self.declared
            .fields
            .get(name)
            .or_else(|| self.declared.accessors.get(name))
            .cloned()
    }

    /// Lower a body, or report every reason it could not be.
    ///
    /// The tail expression is evaluated in return position, where a
    /// produced bucket — or a tuple of them — becomes the method's declared
    /// outputs.
    pub fn run(mut self, block: &syn::Block) -> Result<Lowered, Vec<syn::Error>> {
        // Which cells the body touches from more than one place is
        // settled before anything is declared, because a guard is a fact
        // about the cell and the walk that declares meets each cell's
        // first mention before its last.
        self.escaping = self.twin().survey(block);
        let (statements, returned) = self.walk(block);

        if self.errors.is_empty() {
            self.out.nodes = self.scopes.pop().unwrap_or_default();
            self.out.body = quote!(#(#statements)*);
            self.out.returns = !returned.edges.is_empty() || returned.answer.is_some();
            self.out.outputs = returned.outputs;
            self.out.edges = returned.edges;
            self.out.answer = returned.answer;
            self.out.answer_at = returned.answer_at;
            Ok(self.out)
        } else {
            Err(self.errors)
        }
    }

    /// The walk itself: the body's statements and what its tail hands
    /// back. Shared with [`Lowerer::survey`], so the two passes see the
    /// same body the same way.
    fn walk(&mut self, block: &syn::Block) -> (Vec<TokenStream>, Returned) {
        self.locals.push(BTreeMap::new());
        // A method yielding nothing has no tail expression worth the
        // name: whatever sits last is a statement, and reading it as a
        // return would try to hand back the unit a loop evaluates to.
        let (body, tail) = if self.returns {
            split_tail(block)
        } else {
            (&block.stmts[..], None)
        };
        let mut statements = Vec::new();
        for stmt in body {
            statements.push(self.stmt(stmt));
        }
        let returned = tail.map_or_else(Returned::default, |tail| self.returned(tail));
        self.locals.pop();
        (statements, returned)
    }

    /// Fold one thing a tail hands back into what the method returns: a
    /// value edge, or the value it answers with.
    ///
    /// An edge is value the kernel takes ownership of and a later node
    /// may consume. Anything else is an answer — it rides the receipt,
    /// where whoever sent the transaction reads it, and a manifest has
    /// nowhere else to put it. One answer per method, because one result
    /// is one value however many edges travel beside it.
    fn hands_back(
        &mut self,
        expr: &syn::Expr,
        eval: Eval,
        position: usize,
        returned: &mut Returned,
    ) {
        let produced = match &eval.val {
            Val::Produced(term) => Some(term.clone()),
            // An edge the method was handed and hands on: it carries the
            // resource the manifest routed it as, and forwarding one is
            // the case `check_abi` already admits.
            Val::Term(term) if matches!(eval.code, Code::Bucket(..)) => Some(self.forwarded(term)),
            _ => None,
        };
        let code = self.value(eval.code);
        if let Some(term) = produced {
            returned.outputs.push(term);
            returned.edges.push(code);
            return;
        }
        if returned.answer.is_some() {
            self.error(
                expr.span(),
                "a method answers with one value: several are a record with a field for \
                 each, which is one value and decodes as what it is",
            );
            return;
        }
        returned.answer_at = position;
        returned.answer = Some(quote!(
            ::hyperscale_vm_sdk::hbor::to_vec(&#code)
                .expect("a method's answer encodes within the vocabulary's caps")
        ));
    }

    /// The projection of a value edge the method was handed and hands
    /// on unchanged.
    ///
    /// A fungible edge is its resource: the amount is the kernel's, and
    /// a projection saying anything about it would be the declaration
    /// guessing. A non-fungible one is its resource and the instances it
    /// carries, because that is what an edge of one is — a resource
    /// alone names an edge carrying nothing.
    fn forwarded(&self, edge: &Term) -> Term {
        let resource = Term::ResourceOf(Box::new(edge.clone()));
        let instances = matches!(edge, Term::Arg(index)
            if self
                .params
                .get(*index as usize)
                .is_some_and(|(_, ty)| is_nf_bucket(ty)));
        if instances {
            Term::NfBucket {
                resource: Box::new(resource),
                ids: Box::new(Term::IdsOf(Box::new(edge.clone()))),
            }
        } else {
            resource
        }
    }

    /// Evaluate an expression in return position: the value edges it
    /// yields, the guest code for each, and the one value it answers
    /// with beside them.
    fn returned(&mut self, expr: &syn::Expr) -> Returned {
        let mut returned = Returned::default();
        match expr {
            syn::Expr::Tuple(tuple) => {
                for (position, element) in tuple.elems.iter().enumerate() {
                    let eval = self.expr(element);
                    self.hands_back(element, eval, position, &mut returned);
                }
                returned
            }
            syn::Expr::Paren(paren) => self.returned(&paren.expr),
            // An error arm's success side is where the edges are: the arm
            // itself is the declared refusal, and a refusal produces
            // nothing.
            syn::Expr::Call(call) if free_call_name(call).as_deref() == Some("Ok") => call
                .args
                .first()
                .map_or(returned, |inner| self.returned(inner)),
            // The refusal itself, which produces nothing. Reached from an
            // early `return Err(..)` as well as from a tail, and neither
            // carries an edge.
            syn::Expr::Call(call) if free_call_name(call).as_deref() == Some("Err") => returned,
            other => {
                let eval = self.expr(other);
                self.hands_back(other, eval, 0, &mut returned);
                returned
            }
        }
    }

    /// How many `for-each` binders enclose the walk.
    ///
    /// The binder count rather than the scope depth: a guard opens a
    /// scope to collect its arm's clauses and introduces no binder, so a
    /// clause inside one still names a fixed export parameter and still
    /// reads the enclosing loop's element.
    const fn depth(&self) -> usize {
        self.binders.len()
    }

    fn error(&mut self, span: Span, message: &str) {
        self.errors.push(syn::Error::new(span, message));
    }

    /// How much of a declaration the walk has built: the sites it
    /// opened, the operations it recorded against them, the clauses it
    /// pushed, the parameters it fixed a resource on, the grant it took
    /// and the fresh ids it drew.
    ///
    /// One number, because what reads it wants one question answered —
    /// did this stretch of body declare anything — and a stretch that
    /// declared nothing left every part of it alone.
    fn declared(&self) -> usize {
        self.out.sites.len()
            + self
                .out
                .sites
                .iter()
                .map(|site| site.ops.len())
                .sum::<usize>()
            + self.scopes.iter().map(Vec::len).sum::<usize>()
            + self.out.denominations.len()
            + self.out.fresh
            + self.out.issues.len()
    }

    fn bind(&mut self, name: String, slot: Slot) {
        if let Some(scope) = self.locals.last_mut() {
            scope.insert(name, slot);
        }
    }

    fn lookup(&self, name: &str) -> Option<Slot> {
        self.locals
            .iter()
            .rev()
            .find_map(|scope| scope.get(name).cloned())
    }

    fn push_node(&mut self, node: Node) {
        if let Some(scope) = self.scopes.last_mut() {
            scope.push(node);
        }
    }

    /// Open a handle on `target`, or answer the one already open on it.
    ///
    /// Two accesses to one target are one handle, because the evaluated
    /// effect set folds them anyway and the kernel materializes one
    /// capability per clause. Folding here is also what holds a cell a
    /// body reads and writes to a single `Write`, rather than declaring
    /// the leaf twice under modes that exclude each other.
    ///
    /// One handle is also one clause and therefore one guard, so every
    /// reach is recorded: a cell the survey saw reached under two
    /// conditions is declared always, because the only condition holding
    /// at both places is the trivial one.
    fn open(
        &mut self,
        target: Target,
        element: Option<syn::Type>,
        declared: Option<Term>,
    ) -> usize {
        self.open_reaching(target, element, declared, None)
    }

    /// The same, for a site reaching a prefix that is not this
    /// instance's own under `reach`.
    fn open_reaching(
        &mut self,
        target: Target,
        element: Option<syn::Type>,
        declared: Option<Term>,
        reach: Option<GrantedBehaviour>,
    ) -> usize {
        // Only among the sites this loop opened: a clause belongs to the
        // scope that declared it, and two loops side by side spell their
        // elements the same way while naming different leaves.
        let floor = self.binders.last().map_or(0, |(floor, _)| *floor);
        if let Some(index) = self.out.sites[floor..]
            .iter()
            .position(|s| s.target == target)
            .map(|index| index + floor)
        {
            self.reached.push((index, self.guards.last().cloned()));
            return index;
        }
        let index = self.out.sites.len();
        self.reached.push((index, self.guards.last().cloned()));
        // A cell reached from more than one place is reached
        // unconditionally by the weakest of them, and the survey has
        // already found which those are.
        let guard = if self.escaping.contains(&index) {
            None
        } else {
            self.guards.last().cloned()
        };
        // A field that states its resource answers for every leaf under
        // it; one that does not is keyed by the resource, and the key is
        // the material a body named it at.
        //
        // Only where the leaf holds value at all, which the element type
        // says. A cell holding anything else is keyed by whatever its
        // author found useful — a validator id, a name — which is a key
        // and not a resource however it is spelled. An instance
        // collection is narrowed by the resource whose holdings it is,
        // which is the same statement in collection form.
        let holds_value =
            matches!(&element, Some(ty) if is_named(ty, "Vault") || is_named(ty, "NfVault"));
        let denomination = declared.or_else(|| match &target {
            Target::Point { material, .. }
            | Target::Range { material, .. }
            | Target::Entry { material, .. }
                if holds_value =>
            {
                material.first().cloned()
            }
            // A hashed key, a cursor, and a valueless collection's
            // narrowing name an entry, never a resource.
            _ => None,
        });
        let binder = self.depth();
        self.out.sites.push(Site {
            reach,
            target,
            ops: Vec::new(),
            element,
            denomination,
            guard,
            binder,
            moved: None,
        });
        self.push_node(Node::Site(index));
        index
    }

    /// Record an operation against a site, holding the site to one mode.
    ///
    /// A read beside a write folds to `Write` because the lattice says so;
    /// nothing else folds. A read beside a movement, a movement beside a
    /// reservation, or a second reservation has no single point on the
    /// lattice, so recording one is refused where it happens rather than
    /// silently resolved by priority at emission.
    fn record(&mut self, site: usize, op: Op, param: Option<Term>, span: Span) {
        // A vault's balance is not writable: value moves, and the seam
        // judges movements. The type system refuses this too, but on the
        // trait bound's terms — this is the sentence.
        if matches!(op, Op::Set)
            && matches!(
                self.out.sites.get(site),
                Some(entry) if matches!(&entry.element, Some(ty) if is_named(ty, "Vault"))
            )
        {
            self.error(
                span,
                "a vault's balance is not written — value moves, and `put`, `take`, or \
                 `reserve` are what change it",
            );
            return;
        }
        // Whether this site is an issued instance's own cell, which is
        // what turns an opposite-presence pair into a mint beside a burn.
        let issued_instance = matches!(
            self.out.sites.get(site).map(|entry| &entry.target),
            Some(Target::Point { material, .. })
                if matches!(material.first(), Some(Term::SelfResource(ResourceKind::NonFungible, _)))
        );
        let Some(entry) = self.out.sites.get_mut(site) else {
            return;
        };
        let exclusive = |op: &Op| {
            matches!(
                op,
                Op::Get
                    | Op::Set
                    | Op::Move
                    | Op::Credit
                    | Op::Debit
                    | Op::Create
                    | Op::Existing
                    | Op::Vacant
            )
        };
        let compatible = match op {
            // A movement sits beside a read: together they are the
            // exclusive mode, which is what the site resolves to. A
            // presence requirement rides that same mode, so it sits
            // beside any of them — the one pair that does not is a
            // requirement against its own opposite, refused below.
            Op::Get
            | Op::Set
            | Op::Move
            | Op::Credit
            | Op::Debit
            | Op::Create
            | Op::Existing
            | Op::Vacant => entry.ops.iter().all(|(prior, _)| exclusive(prior)),
            // A reservation folds with nothing, itself included, so it
            // is the only op a handle may carry and it may carry it once.
            Op::Reserve => entry.ops.is_empty(),
        };
        // Two accesses on one leaf that cannot both stand, stated as
        // unordered pairs: what a body wrote first is not what decides
        // whether it makes sense, and a rule read one way is a rule with
        // a way around it.
        let refusal = |a: Op, b: Op| match (a, b) {
            // Opposite presences over one leaf: no committed state
            // satisfies both, so the clause could never be feasible. On
            // an issued instance's own cell the pair has a name — the
            // mint requires the cell absent and the burn requires it
            // there — and the sentence says so.
            (Op::Create, Op::Existing) | (Op::Existing, Op::Create) if issued_instance => Some(
                "this mints an instance and burns it in one body — the mint requires \
                 its cell absent and the burn requires it there, and no committed \
                 state satisfies both. Mint in one call, and burn what an edge \
                 carries in another",
            ),
            (Op::Create, Op::Existing) | (Op::Existing, Op::Create) => Some(
                "one access requires the leaf to be absent and to be there — no \
                 committed state satisfies both, so the call could never be \
                 feasible. Declare the one the body actually needs",
            ),
            // A fresh read requiring absence beside a write: the site
            // resolves to one mode, and a body that writes a leaf it also
            // declared read would publish a declaration its own code
            // contradicts. `create` is the write that requires absence.
            (Op::Vacant, Op::Set | Op::Create | Op::Existing)
            | (Op::Set | Op::Create | Op::Existing, Op::Vacant) => Some(
                "a fresh read requiring the leaf absent sits beside a write of the \
                 same leaf, so the site has two modes and no way to declare both. \
                 Use `create` for a write that requires absence",
            ),
            _ => None,
        };
        if let Some(message) = entry.ops.iter().find_map(|(prior, _)| refusal(*prior, op)) {
            self.error(span, message);
        } else if compatible {
            entry.ops.push((op, param));
        } else {
            self.error(
                span,
                "one handle declares one access mode — a reservation beside anything \
                 else, or a second reservation, folds to no single mode. Open a \
                 separate access for each mode instead",
            );
        }
    }

    /// Resolve a field's `#[denomination(..)]` to the term the router
    /// evaluates.
    ///
    /// Two forms, because two things can name a resource before any
    /// transaction exists: a slot of the instance's creation-fixed
    /// configuration, and a resource the instance derives from its own
    /// address. Anything else would be a resource nobody could resolve
    /// without reading state, which is the wall every declared key meets.
    fn field_denomination(&mut self, field: &Field) -> Option<Term> {
        let expr = field.denomination.as_ref()?;
        let refuse = |lowerer: &mut Self| {
            lowerer.error(
                expr.span(),
                "a denomination is `config.<field>` for a configured resource, or \
                 `issued(<Resource>)` for a declared one the instance derives from its \
                 own address",
            );
            None
        };
        match expr {
            // `config.x` — the record's slot, by name.
            syn::Expr::Field(access) => {
                let syn::Expr::Path(base) = &*access.base else {
                    return refuse(self);
                };
                let configured = base.path.get_ident().is_some_and(|ident| {
                    self.state(&ident.to_string())
                        .is_some_and(|f| f.kind == FieldKind::Config)
                });
                let syn::Member::Named(name) = &access.member else {
                    return refuse(self);
                };
                if !configured {
                    return refuse(self);
                }
                let name = name.to_string();
                let Some(index) = self
                    .declared
                    .config_fields
                    .iter()
                    .position(|(f, _)| *f == name)
                else {
                    self.error(
                        expr.span(),
                        "not a field of the component's configuration struct",
                    );
                    return None;
                };
                Some(Term::Config(
                    u32::try_from(index).expect("a configuration record is shorter than u32"),
                ))
            }
            // `issued(Name)` — the instance's own resource, by the
            // declared `#[resource]` struct whose mark and kind derive it.
            syn::Expr::Call(call) => {
                if free_call_name(call).as_deref() != Some("issued") {
                    return refuse(self);
                }
                self.declared_resource(call)
                    .map_or_else(|| refuse(self), Some)
            }
            _ => refuse(self),
        }
    }

    /// A resource term as the author wrote it.
    ///
    /// A diagnostic naming `Config(1)` sends a reader to count fields; one
    /// naming `config.y` sends them to the line they wrote. The terms that
    /// can denominate anything are few, so the rest fall back to a phrase
    /// rather than to a dump of the tracer's own model.
    fn describe(&self, term: &Term) -> String {
        match term {
            Term::Config(slot) => self.declared.config_fields.get(*slot as usize).map_or_else(
                || format!("configuration slot {slot}"),
                |(name, _)| format!("`config.{name}`"),
            ),
            // A mark is a declaration's own name, so the declaration is
            // what a reader goes back to — the mark itself is a spelling
            // no body writes.
            Term::SelfResource(_, mark) => self
                .declared
                .resources
                .iter()
                .find(|declared| declared.mark == *mark)
                .map_or_else(
                    || "a resource this instance issues".into(),
                    |declared| format!("`issued({})`", declared.name),
                ),
            Term::ResourceOf(inner) => match **inner {
                Term::Arg(index) => format!("argument {index}'s resource"),
                _ => "the resource of a value the body holds".into(),
            },
            Term::Arg(index) => format!("argument {index}"),
            _ => "a derived resource".into(),
        }
    }

    /// The resource an evaluated expression's value edge carries, where
    /// it is one and the lowering can see what it holds.
    ///
    /// An edge the method was handed carries whatever the manifest routed
    /// it as, which is that parameter's resource; one the body produced
    /// carries the resource its producer named.
    fn edge_resource(eval: &Eval) -> Option<Term> {
        match &eval.val {
            Val::Produced(term) => Some(term.clone()),
            Val::Term(term) if matches!(eval.code, Code::Bucket(..)) => {
                Some(Term::ResourceOf(Box::new(term.clone())))
            }
            _ => None,
        }
    }

    /// Fix what the edge at `param` carries.
    ///
    /// One parameter credited to two cells with different keys is a
    /// method no call satisfies — the edge would have to carry both
    /// resources at once — so the second one is refused where the body
    /// wrote it rather than left for a caller to discover.
    fn denominate(&mut self, param: u32, resource: Term, span: Span) {
        // What an edge carries is one resource, stated once on the
        // signature — so it cannot be an element of a list the
        // declaration maps over, which names a different one each time
        // round and none of them where the signature is read.
        if resource.reads_element() {
            self.error(
                span,
                "this credits a value edge to a cell a `for-each` element keys, so what \
                 the edge carries would be a different resource each time round — one \
                 edge carries one resource, and the signature states it once",
            );
            return;
        }
        // Under a guard the two are the arms of one selection rather
        // than a contradiction, so they fold into one expression — still
        // exactly one, so what a caller reads off the signature stays
        // exact rather than widening to a set.
        if let Some(held) = self.out.denominations.get(&param).cloned()
            && held != resource
            && let Some(cond) = self.guards.last().cloned()
        {
            self.out.denominations.insert(
                param,
                Term::If {
                    cond: Box::new(cond),
                    then: Box::new(resource),
                    otherwise: Box::new(held),
                },
            );
            return;
        }
        if let Some(held) = self.out.denominations.get(&param).cloned()
            && held != resource
        {
            let (held, resource) = (self.describe(&held), self.describe(&resource));
            self.error(
                span,
                &format!(
                    "this edge is credited to a cell holding {held} and to one holding \
                     {resource}, and no edge carries both. Key one of them by the edge's \
                     own resource, or take the second cell's value from a separate \
                     parameter"
                ),
            );
            return;
        }
        self.out.denominations.insert(param, resource);
    }

    /// Hold two edges being merged to one resource.
    ///
    /// A merge makes two edges one, so whatever the result carries both
    /// halves carried. Where one half is a parameter, that is where a
    /// caller supplies it and so where the constraint is stated — against
    /// the other half's resource, which may itself be a parameter's.
    /// Where neither is, both resources are already fixed and a merge
    /// across them is a body converting value by writing it down.
    fn unify(&mut self, into: &Term, from: &Term, span: Span) {
        if into == from {
            return;
        }
        match (into, from) {
            (_, Term::ResourceOf(inner)) if matches!(**inner, Term::Arg(_)) => {
                if let Term::Arg(param) = **inner {
                    self.denominate(param, into.clone(), span);
                }
            }
            (Term::ResourceOf(inner), _) if matches!(**inner, Term::Arg(_)) => {
                if let Term::Arg(param) = **inner {
                    self.denominate(param, from.clone(), span);
                }
            }
            _ => {
                let (into, from) = (self.describe(into), self.describe(from));
                self.error(
                    span,
                    &format!(
                        "this merges {from} into {into}, and one edge carries one resource. \
                         A merge moves value without converting it, so the two have to be \
                         the same resource"
                    ),
                );
            }
        }
    }

    // ---- guest values ---------------------------------------------------

    /// The guest code for a value, binding an export parameter where the
    /// guest cannot compute one.
    fn value(&mut self, code: Code) -> TokenStream {
        match code {
            Code::Rust(tokens) => tokens,
            Code::Handle { site, form, span } => {
                let handle = self.handle(site, span);
                let element = self.element(site);
                match form {
                    Form::Slot => {
                        quote!(::hyperscale_vm_sdk::state::Slot::<#element>::at(#handle))
                    }
                    Form::Interval => {
                        quote!(::hyperscale_vm_sdk::state::Interval::<#element>::at(#handle))
                    }
                    Form::Entry(order) => {
                        quote!(::hyperscale_vm_sdk::state::Entry::<#element>::at(#handle, #order))
                    }
                }
            }
            Code::Term(span, term) => self.term_value(span, &term),
            Code::Bucket(span, param) => self.need(span, &Need::Amount(param)),
            Code::Record(span) => self.config_record(span),
            Code::Absent(span, why) => {
                // Only where nothing else has been said. Most values
                // that have no guest form are already the subject of an
                // error — the walk carries an absence forward so it can
                // reach whatever else the body got wrong — and reporting
                // the absence too would name one mistake twice.
                if self.errors.is_empty() {
                    self.error(
                        span,
                        &format!("this value is not one a guest can reach: {why}"),
                    );
                }
                quote!(::core::unimplemented!())
            }
        }
    }

    /// The guest code for a declared term, refused on the line the body
    /// read it from where the guest has no reach to it.
    fn term_value(&mut self, span: Span, term: &Term) -> TokenStream {
        match term {
            Term::LitU64(value) => quote!(#value),
            Term::LitU128(value) => quote!(#value),
            Term::Pack { hi, lo } => {
                // `pack` is ordinary arithmetic, so the guest folds the
                // two halves itself rather than taking the packed key —
                // which is what makes a price and a sequence id two
                // parameters instead of one opaque cell.
                let hi = self.term_value(span, hi);
                let lo = self.term_value(span, lo);
                quote!(::hyperscale_vm_sdk::state::pack(#hi, #lo))
            }
            // Everything the evaluator can reach from the call's own
            // inputs is a value the kernel hands over: a resource is one
            // of those, evaluated from the declaration rather than taken
            // from the guest, so a body that reads one cannot disagree
            // with what its signature says the edge carries.
            // A selection is one of these rather than a rebuild of its
            // arms, and deliberately: handing over the value the
            // declaration chose is what leaves the guest nothing to
            // disagree with, where choosing again in wasm would rest on
            // two copies of one condition staying identical.
            // A lookup, the question a miss answers and a projection
            // are here for the same reason: the evaluator reaches each
            // from the call's own inputs, so the declared value is what
            // crosses rather than a second walk over a table the guest
            // does not hold.
            Term::Arg(_)
            | Term::Config(_)
            | Term::FreshId(_)
            | Term::ResourceOf(_)
            | Term::IdsOf(_)
            | Term::Len(_)
            | Term::Only(_)
            | Term::OrderKey { .. }
            | Term::SelfResource(..)
            | Term::SelfRecord
            | Term::Add(..)
            | Term::Lookup { .. }
            | Term::Contains { .. }
            | Term::Field(..)
            | Term::If { .. } => {
                // The binding a `for-each` element occupies exists only
                // while the loop is being evaluated, and an export's
                // arguments are evaluated outside every loop — so a
                // parameter that reads one is a parameter nothing could
                // ever bind.
                if term.reads_element() {
                    self.error(
                        span,
                        "this reads a `for-each` element, which exists only inside the \
                         evaluation of the loop that binds it — a body reaches an element \
                         as a key and never as a value. A package that needs the element \
                         itself is written the long way: its own component beside a \
                         declaration written out, which the publish gate judges the same",
                    );
                    return quote!(::core::unimplemented!());
                }
                self.need(span, &Need::Derived(term.clone()))
            }
            // A judgment has no guest representation, so what crosses is
            // its operands and the guest does the comparison — which is
            // what a body that branches on one was doing before the
            // declaration could read it.
            Term::Not(inner) => {
                let inner = self.term_value(span, inner);
                quote!(!#inner)
            }
            Term::And(left, right) => self.judgment(span, left, right, &quote!(&&)),
            Term::Or(left, right) => self.judgment(span, left, right, &quote!(||)),
            Term::Eq(left, right) => self.judgment(span, left, right, &quote!(==)),
            Term::Lt(left, right) => self.judgment(span, left, right, &quote!(<)),
            Term::List(elements) => {
                let elements: Vec<_> = elements.iter().map(|e| self.term_value(span, e)).collect();
                quote!([#(#elements),*])
            }
            Term::Tuple(fields) => {
                let fields: Vec<_> = fields.iter().map(|f| self.term_value(span, f)).collect();
                quote!((#(#fields),*))
            }
            // An element read as a value is read out of the list its loop
            // maps over, at the index the site is walked by: the two
            // indices are the same by construction, so the element the
            // body reads is the element the clause beside it declared.
            Term::Binding(depth) => {
                let depth = *depth;
                let Some(list) = self.binders.get(depth).map(|(_, list)| list.clone()) else {
                    self.error(
                        span,
                        "this reads a `for-each` element outside the loop that binds it \
                         — an element is a key inside its own loop and nothing outside it",
                    );
                    return quote!(::core::unimplemented!());
                };
                let held = self.need(span, &Need::Derived(list));
                let at = element_index_ident(depth);
                quote!(#held[#at as usize])
            }
            Term::NfBucket { .. } => {
                self.error(
                    span,
                    "an edge is a routable summary rather than a value: what it carries \
                     is the declaration's answer, and a body reaches it through the \
                     capability the edge justified",
                );
                quote!(::core::unimplemented!())
            }
        }
    }

    /// The configuration record rebuilt on the guest, field by field.
    ///
    /// Each field crosses as the value the kernel evaluated for its slot,
    /// which is what a projection of the record already does — so the
    /// record a body passes on and the field it reads are one evaluation,
    /// and the sealed leaf is never decoded.
    ///
    /// Owned, because that is what the accessor answers with: the
    /// configuration is creation-fixed and a handful of words, so a body
    /// holds the terms without borrowing the component.
    fn config_record(&mut self, span: Span) -> TokenStream {
        let declared = self.declared;
        let Some(name) = declared.config_record else {
            self.error(span, "this package declares no configuration");
            return quote!(::core::unimplemented!());
        };
        let fields: Vec<TokenStream> = declared
            .config_fields
            .iter()
            .enumerate()
            .map(|(index, (field, _))| {
                let slot =
                    u32::try_from(index).expect("a configuration record is shorter than u32");
                let value = self.need(span, &Need::Derived(Term::Config(slot)));
                let field = syn::Ident::new(field, span);
                quote!(#field: #value)
            })
            .collect();
        quote!(#name { #(#fields),* })
    }

    /// One binary judgment, rebuilt over its operands' guest values.
    fn judgment(&mut self, span: Span, left: &Term, right: &Term, op: &TokenStream) -> TokenStream {
        let left = self.term_value(span, left);
        let right = self.term_value(span, right);
        quote!((#left #op #right))
    }

    /// The export parameter carrying `need`, binding one if the body has
    /// not needed it before.
    fn need(&mut self, span: Span, need: &Need) -> TokenStream {
        // A value with no shape is one no export parameter can carry.
        // Refused here rather than at the emission, where it would land
        // on the macro as a missing trait impl instead of on the line
        // that read it. Only where nothing else has been said: a
        // selection whose arms disagree is already refused where it was
        // written, and naming it twice names one mistake twice.
        if let Need::Derived(term) = need
            && crate::bind::derived_shape(term, self.params, self.declared.config_fields).is_none()
            && self.errors.is_empty()
        {
            self.error(
                span,
                "this value crosses the call boundary as nothing an export parameter can \
                 carry — a sequence crosses as the numbers it holds, and only a byte \
                 string crosses as the bytes a guest decodes",
            );
        }
        let index = self
            .out
            .values
            .iter()
            .position(|held| held == need)
            .unwrap_or_else(|| {
                self.out.values.push(need.clone());
                self.out.values.len() - 1
            });
        match need {
            // A bucket parameter is bound under the author's own name, so
            // `funds.quantity()` in a body is `funds.quantity()` in the
            // guest rather than a decoded local wearing the same meaning.
            // A value edge is `Copy`: it is a resource and an amount,
            // and neither is owned by the body holding it.
            Need::Amount(param) => {
                let ident = self.param_ident(*param);
                quote!(#ident)
            }
            Need::Derived(_) => {
                let ident = value_ident(index);
                quote!(#ident.clone())
            }
        }
    }

    /// The author's own name for the `index`-th socket.
    fn param_ident(&self, index: u32) -> syn::Ident {
        crate::syntax::param_ident(index, self.params)
            .unwrap_or_else(|| value_ident(index as usize))
    }

    /// Record this method's issuance grant.
    ///
    /// No parameter follows it: the grant is the invocation's, read off
    /// the outputs the declaration names, so nothing crosses to say so.
    /// Record that this body issues `mark`, and answer the index the
    /// grant occupies.
    ///
    /// One entry per mark however many calls name it: a body reaching
    /// both ways through one grant takes both entries, folded call by
    /// call rather than decided by whichever one the walk saw last.
    fn issuer(&mut self, kind: ResourceKind, mark: &[u8], direction: Issued) -> u32 {
        let held = self
            .out
            .issues
            .iter()
            .position(|(k, m, _)| *k == kind && m == mark);
        let at = if let Some(at) = held {
            self.out.issues[at].2 = self.out.issues[at].2.with(direction);
            at
        } else {
            self.out.issues.push((kind, mark.to_vec(), direction));
            self.out.issues.len() - 1
        };
        u32::try_from(at).unwrap_or(u32::MAX)
    }

    /// Bind the handle for `site` as an export parameter, and answer the
    /// `Handle` the accessors take.
    fn handle(&mut self, site: usize, span: Span) -> TokenStream {
        self.out.handles.insert(site);
        let ident = handle_ident(site);
        let binder = self.out.sites[site].binder;
        // Every site has a width, so every access names an element. A
        // plain one is a site of one and names element zero; a site a
        // `for-each` body declared names the element it was declared
        // for, so it exists inside that loop and nowhere else.
        if binder == 0 {
            return quote!(#ident.handle(0));
        }
        if self.depth() < binder {
            self.error(
                span,
                "this handle was declared inside a `for-each`, so it names an entry of \
                 that loop's site — and outside the loop there is no element to name",
            );
        }
        self.out.looped.insert(site);
        let at = element_index_ident(binder - 1);
        quote!(#ident.handle(#at))
    }

    // ---- statements -----------------------------------------------------

    fn block(&mut self, block: &syn::Block) -> TokenStream {
        self.locals.push(BTreeMap::new());
        let statements: Vec<_> = block.stmts.iter().map(|stmt| self.stmt(stmt)).collect();
        self.locals.pop();
        quote!({ #(#statements)* })
    }

    /// A block in value position is its tail. Where every other
    /// statement binds a name without emitting guest code, the tail's
    /// evaluation — its term, where it has one — is the block's, so a
    /// helper's spliced body routes exactly as the same text written
    /// inline. A statement that renders real guest code keeps the block
    /// opaque: discarding rendered code at a consumer that reads only
    /// the value would drop its effects, so such a block stays what any
    /// composite the declaration cannot read has always been.
    fn block_expr(&mut self, block: &syn::ExprBlock) -> Eval {
        let label = &block.label;
        self.locals.push(BTreeMap::new());
        let mut rendered: Vec<TokenStream> = Vec::new();
        let mut tail: Option<Eval> = None;
        for (index, stmt) in block.block.stmts.iter().enumerate() {
            if index + 1 == block.block.stmts.len()
                && label.is_none()
                && let syn::Stmt::Expr(expr, None) = stmt
            {
                tail = Some(self.expr(expr));
            } else {
                rendered.push(self.stmt(stmt));
            }
        }
        self.locals.pop();
        match tail {
            Some(eval) if rendered.iter().all(TokenStream::is_empty) => eval,
            Some(eval) => {
                let code = self.value(eval.code);
                Eval::plain(quote!({ #(#rendered)* #code }))
            }
            None => Eval::plain(quote!(#label { #(#rendered)* })),
        }
    }

    fn stmt(&mut self, stmt: &syn::Stmt) -> TokenStream {
        match stmt {
            syn::Stmt::Local(local) => {
                let eval = local.init.as_ref().map_or_else(
                    || Eval::absent(local.span(), "an uninitialised binding"),
                    |init| self.expr(&init.expr),
                );
                let diverge = if let Some(init) = &local.init
                    && let Some((_, branch)) = &init.diverge
                {
                    let branch = self.expr(branch);
                    Some(self.value(branch.code))
                } else {
                    None
                };
                // A name for a declaration term is a name the
                // declaration uses. The guest gets the local only where
                // it could reassign it, because a rebound name is no
                // longer the term and the statement rebinding it needs
                // somewhere to write.
                let deferred = matches!(eval.code, Code::Term(..))
                    && diverge.is_none()
                    && matches!(
                        unwrap_pat(&local.pat),
                        syn::Pat::Ident(syn::PatIdent {
                            by_ref: None,
                            mutability: None,
                            subpat: None,
                            ..
                        })
                    );
                let slot = match &eval.val {
                    Val::Term(term) if deferred => Slot::Deferred(term.clone()),
                    Val::Term(term) => Slot::Value(term.clone()),
                    Val::Handle(index) => Slot::Handle(*index),
                    Val::Produced(term) => Slot::Produced(term.clone()),
                    // The configuration record binds a name whose
                    // *fields* are config slots; the binding itself is
                    // not a value.
                    Val::Config => Slot::Config,
                    // Several edges are not one value, so the binding as a
                    // whole holds nothing; the names come from the pattern
                    // below.
                    Val::Edges(_) | Val::Field { .. } | Val::Opaque => Slot::Opaque,
                };
                let parts = match &eval.val {
                    Val::Edges(terms) => terms.clone(),
                    _ => Vec::new(),
                };
                // A plain name takes the slot, and a tuple over edges takes
                // one per element — a division names its parts, and each
                // part carries what the whole did. Any other pattern binds
                // its names opaquely, so a destructured piece used as a key
                // is refused at the use site rather than resolved to
                // whatever an outer scope happened to call by the same
                // name.
                let names = Self::edge_names(&local.pat);
                match unwrap_pat(&local.pat) {
                    syn::Pat::Tuple(_) if !parts.is_empty() && names.len() == parts.len() => {
                        for (element, term) in names.into_iter().zip(parts) {
                            match unwrap_pat(&element) {
                                syn::Pat::Ident(ident) => {
                                    self.bind(ident.ident.to_string(), Slot::Produced(term));
                                }
                                other => self.bind_pattern(other),
                            }
                        }
                    }
                    syn::Pat::Ident(ident) => self.bind(ident.ident.to_string(), slot),
                    other => self.bind_pattern(other),
                }
                if matches!(eval.code, Code::Absent(..) | Code::Record(..)) {
                    // The declaration read something the guest holds no
                    // local for. Whatever the body does with the name is
                    // either evaluated elsewhere — a configuration field
                    // is a slot the kernel hands over, and the record is
                    // rebuilt from those wherever it is read whole — or
                    // refused at the line that reads it.
                    return quote!();
                }
                if deferred {
                    return quote!();
                }
                let init = self.value(eval.code);
                let pat = &local.pat;
                let attrs = &local.attrs;
                diverge.map_or_else(
                    || quote!(#(#attrs)* let #pat = #init;),
                    |branch| quote!(#(#attrs)* let #pat = #init else #branch;),
                )
            }
            syn::Stmt::Expr(expr, semi) => {
                let eval = self.expr(expr);
                let code = self.value(eval.code);
                semi.map_or_else(|| quote!(#code), |_| quote!(#code;))
            }
            syn::Stmt::Macro(mac) => {
                let code = self.macro_call(&mac.mac);
                let semi = mac.semi_token.map(|_| quote!(;));
                quote!(#code #semi)
            }
            // A nested item cannot capture the component, so it can hold no
            // state access.
            syn::Stmt::Item(item) => quote!(#item),
        }
    }

    /// Walk a macro invocation's arguments for accesses, or refuse it.
    ///
    /// The judgment is the parse rather than a list of names: a body that
    /// reads as a comma-separated expression list is one every argument
    /// can be walked and re-emitted through, so an access inside it
    /// declares like an access outside it. A body carrying its own syntax
    /// parses as nothing, and walking is the only thing keeping an access
    /// inside it out of nowhere — so that is where the refusal is.
    ///
    /// An argument holding no access is rewritten to itself, so admitting
    /// a macro costs nothing at the sites that were only ever passing
    /// values through.
    fn macro_call(&mut self, mac: &syn::Macro) -> TokenStream {
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        #[allow(clippy::single_match_else)] // two returns over one refusal
        match mac.parse_body_with(parser) {
            Ok(args) => {
                let rewritten: Vec<_> = args
                    .iter()
                    .map(|arg| {
                        let eval = self.expr(arg);
                        self.value(eval.code)
                    })
                    .collect();
                let path = &mac.path;
                quote!(#path!(#(#rewritten),*))
            }
            Err(_) => {
                self.error(
                    mac.span(),
                    "these macro arguments do not parse as expressions, so they cannot be \
                     checked for state accesses",
                );
                quote!()
            }
        }
    }

    /// Bind every name a pattern introduces as opaque, in the current scope.
    ///
    /// Sound both ways: a pattern-bound name used as a key is refused where
    /// it is used, and it can no longer shadow an outer binding into a
    /// declaration it has nothing to do with.
    fn bind_pattern(&mut self, pat: &syn::Pat) {
        match pat {
            syn::Pat::Ident(ident) => {
                self.bind(ident.ident.to_string(), Slot::Opaque);
                if let Some((_, sub)) = &ident.subpat {
                    self.bind_pattern(sub);
                }
            }
            syn::Pat::Tuple(tuple) => {
                for elem in &tuple.elems {
                    self.bind_pattern(elem);
                }
            }
            syn::Pat::TupleStruct(tuple) => {
                for elem in &tuple.elems {
                    self.bind_pattern(elem);
                }
            }
            syn::Pat::Struct(strct) => {
                for field in &strct.fields {
                    self.bind_pattern(&field.pat);
                }
            }
            syn::Pat::Slice(slice) => {
                for elem in &slice.elems {
                    self.bind_pattern(elem);
                }
            }
            syn::Pat::Or(or) => {
                for case in &or.cases {
                    self.bind_pattern(case);
                }
            }
            syn::Pat::Paren(paren) => self.bind_pattern(&paren.pat),
            syn::Pat::Reference(reference) => self.bind_pattern(&reference.pat),
            syn::Pat::Type(typed) => self.bind_pattern(&typed.pat),
            // A guard is an expression walked with the pattern's names
            // already bound; nesting puts it on match arms and anywhere
            // else a pattern sits.
            syn::Pat::Guard(guard) => {
                self.bind_pattern(&guard.pat);
                self.expr(&guard.guard);
            }
            // Wildcards, literals, paths, rests, and ranges bind nothing.
            _ => {}
        }
    }

    // ---- expressions ----------------------------------------------------

    /// Walk `expr` and take only its guest code.
    fn code(&mut self, expr: &syn::Expr) -> TokenStream {
        let eval = self.expr(expr);
        self.value(eval.code)
    }

    /// An `if`, read as a selection where it is one and as control flow
    /// otherwise.
    ///
    /// A selection is the shape whose arms are expressions: `if a == b {
    /// x } else { y }`, where the condition is a judgment the DSL can
    /// read and each arm is one term. That is the whole of it — an arm
    /// with a statement in it is a body, not a value, and stays the
    /// superset it has always been. Both readings walk the same pieces
    /// once, so nothing is declared twice on the way to the decision.
    fn branch(&mut self, branch: &syn::ExprIf) -> Eval {
        let arms = selectable(branch);
        let Some((then, otherwise)) = arms else {
            return self.control_flow(branch);
        };
        let cond = self.expr(&branch.cond);
        let then = self.expr(then);
        let otherwise = self.expr(otherwise);
        if let (Val::Term(judgment), Val::Term(taken), Val::Term(untaken)) =
            (&cond.val, &then.val, &otherwise.val)
            && judgment.is_judgment()
        {
            let term = Term::If {
                cond: Box::new(judgment.clone()),
                then: Box::new(taken.clone()),
                otherwise: Box::new(untaken.clone()),
            };
            // What a selection chooses crosses the boundary as one
            // value, so its arms must cross as one shape — an address
            // one way and a scalar the other is a parameter no export
            // can declare. Refused here, where the selection was
            // written, rather than shaped by fallback at emission.
            if crate::bind::derived_shape(&term, self.params, self.declared.config_fields).is_none()
            {
                self.error(
                    branch.if_token.span,
                    "the arms of this selection cross the call boundary as different \
                     shapes, so no one export parameter can carry what it chooses — \
                     give both arms the shape the value is used at",
                );
            }
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(branch.span(), term),
            };
        }
        let cond = self.value(cond.code);
        let then = self.value(then.code);
        let otherwise = self.value(otherwise.code);
        Eval::plain(quote!(if #cond { #then } else { #otherwise }))
    }

    /// An `if` whose arms are bodies: both are declared, so the result is
    /// a superset of any one execution. Legal, and priced as the superset
    /// it is. An `if let` scrutinee is walked and its pattern's names are
    /// bound opaquely for the taken branch.
    fn control_flow(&mut self, branch: &syn::ExprIf) -> Eval {
        if let Some(guarded) = self.guard_scope(branch) {
            return guarded;
        }
        self.locals.push(BTreeMap::new());
        let cond = self.condition(&branch.cond);
        let then = self.block(&branch.then_branch);
        self.locals.pop();
        let otherwise = branch
            .else_branch
            .as_ref()
            .map(|(_, otherwise)| self.code(otherwise))
            .map(|code| quote!(else #code));
        Eval::plain(quote!(if #cond #then #otherwise))
    }

    /// An `if` whose condition the declaration can read: each arm's
    /// accesses are declared under it, so a body that writes one of two
    /// cells declares, locks and routes to exactly the one it will
    /// write.
    ///
    /// `None` where the condition is not a judgment the DSL expresses,
    /// or where the method claims totality — both fall back to declaring
    /// the union, which is what keeps a body free to branch on things a
    /// declaration has no business seeing.
    fn guard_scope(&mut self, branch: &syn::ExprIf) -> Option<Eval> {
        if self.total || matches!(&*branch.cond, syn::Expr::Let(_)) {
            return None;
        }
        let cond = self.expr(&branch.cond);
        let Val::Term(judgment) = cond.val.clone() else {
            return None;
        };
        if !judgment.is_judgment() {
            return None;
        }

        let (then_path, then_nodes, then_code) =
            self.arm(judgment.clone(), |me| me.block(&branch.then_branch));
        let negated = Term::Not(Box::new(judgment));
        let otherwise = branch.else_branch.as_ref().map(|(_, otherwise)| {
            self.arm(negated, |me| {
                let code = me.code(otherwise);
                quote!(#code)
            })
        });

        // The guest branches on the declaration's own verdict, so the
        // flag names a clause the arm declared *and this arm guards*. An
        // arm whose cells are all shared with the code around it guards
        // nothing, so there is no verdict to hand over and the condition
        // stands as the author wrote it — as it does for an arm that
        // declares nothing at all.
        //
        // Nor inside a `for-each`, whose clause count is the instance's
        // rather than the signature's: a verdict per element of a
        // configuration occupies no fixed export parameter.
        let taken = declares_under(&then_nodes, &self.out.sites, &then_path);
        let untaken = otherwise
            .as_ref()
            .and_then(|(path, nodes, _)| declares_under(nodes, &self.out.sites, path));
        let (flag, guarded) = match (taken, untaken) {
            (Some(site), _) => (Some(Polarity::Taken), Some(site)),
            (None, Some(site)) => (Some(Polarity::Untaken), Some(site)),
            (None, None) => (None, None),
        };

        // The arms' clauses land where the branch does. Each carries its
        // own condition, so nothing about the order or the depth they sit
        // at is what makes them conditional.
        for node in then_nodes {
            self.push_node(node);
        }
        // A verdict crosses as a parameter only where the loop it sits in
        // is none: inside one it is the site's answer, which is already
        // beside the capability the arm declares.
        if flag == Some(Polarity::Taken) && self.binders.is_empty() {
            self.push_node(Node::BindGuard);
        }
        if let Some((_, else_nodes, _)) = &otherwise {
            for node in else_nodes.clone() {
                self.push_node(node);
            }
            if flag == Some(Polarity::Untaken) && self.binders.is_empty() {
                self.push_node(Node::BindGuard);
            }
        }

        let cond = match flag {
            // Inside a loop the verdict is the element's, so it is the
            // site that reports it: an element is declared exactly where
            // this arm's guard fired, which is the same question the flag
            // answers at top level.
            Some(polarity) if !self.binders.is_empty() => {
                let verdict = guarded
                    .filter(|site| self.out.looped.contains(site))
                    .map(|site| {
                        let held = handle_ident(site);
                        let at = element_index_ident(self.depth() - 1);
                        quote!(#held.declared(#at))
                    });
                match (verdict, polarity) {
                    (Some(verdict), Polarity::Taken) => verdict,
                    (Some(verdict), Polarity::Untaken) => quote!(!#verdict),
                    // The arm declares a clause the body never operates
                    // through, so there is no site to read the verdict off
                    // and the condition is the author's own — which reads
                    // the element, and is refused where it does.
                    (None, _) => self.value(cond.code),
                }
            }
            Some(polarity) => {
                let index = self.out.flags.len();
                self.out.flags.push(polarity);
                let ident = flag_ident(index);
                match polarity {
                    Polarity::Taken => quote!(#ident),
                    Polarity::Untaken => quote!(!#ident),
                }
            }
            None => self.value(cond.code),
        };
        let otherwise = otherwise.map(|(_, _, code)| quote!(else #code));
        Some(Eval::plain(quote!(if #cond #then_code #otherwise)))
    }

    /// One arm: the condition its clauses are declared under, the clauses
    /// themselves, and its code.
    ///
    /// The clauses are collected rather than pushed, so the branch can
    /// ask which of them it guards before deciding whether a verdict
    /// crosses. Where they land is the branch's to say, and it says the
    /// scope it sits in.
    fn arm<F>(&mut self, cond: Term, walk: F) -> (Term, Vec<Node>, TokenStream)
    where
        F: FnOnce(&mut Self) -> TokenStream,
    {
        let conjoined = match self.guards.last() {
            Some(outer) => Term::And(Box::new(outer.clone()), Box::new(cond)),
            None => cond,
        };
        self.guards.push(conjoined.clone());
        self.locals.push(BTreeMap::new());
        self.scopes.push(Vec::new());
        let code = walk(self);
        let nodes = self.scopes.pop().unwrap_or_default();
        self.locals.pop();
        self.guards.pop();
        (conjoined, nodes, code)
    }

    /// An array or a tuple, read as a term where every element is one.
    ///
    /// This is what lets a package spell its own lookup table: the rows
    /// are its text rather than a list a caller configures, so what the
    /// table says is held in the declaration a caller routes on.
    fn sequence<'e>(
        &mut self,
        span: Span,
        elements: impl Iterator<Item = &'e syn::Expr>,
        listed: bool,
    ) -> Eval {
        let evals: Vec<Eval> = elements.map(|element| self.expr(element)).collect();
        let terms: Option<Vec<Term>> = evals
            .iter()
            .map(|eval| match &eval.val {
                Val::Term(term) => Some(term.clone()),
                _ => None,
            })
            .collect();
        if let Some(terms) = terms {
            let term = if listed {
                Term::List(terms)
            } else {
                Term::Tuple(terms)
            };
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(span, term),
            };
        }
        let codes: Vec<_> = evals
            .into_iter()
            .map(|eval| self.value(eval.code))
            .collect();
        Eval::plain(if listed {
            quote!([#(#codes),*])
        } else {
            quote!((#(#codes),*))
        })
    }

    #[allow(clippy::too_many_lines)] // one arm per expression form the walk models
    fn expr(&mut self, expr: &syn::Expr) -> Eval {
        match expr {
            syn::Expr::Path(path) => self.path(path),
            syn::Expr::Lit(lit) => Self::literal(lit),
            syn::Expr::Field(field) => self.field(field),
            syn::Expr::MethodCall(call) => self.method_call(call),
            syn::Expr::Call(call) => self.free_call(call),
            syn::Expr::Reference(reference) => {
                let inner = self.expr(&reference.expr);
                let code = self.value(inner.code);
                let and = &reference.mutability;
                Eval {
                    val: inner.val,
                    code: Code::Rust(quote!(&#and #code)),
                }
            }
            syn::Expr::Paren(paren) => {
                let inner = self.expr(&paren.expr);
                let code = self.value(inner.code);
                Eval {
                    val: inner.val,
                    code: Code::Rust(quote!((#code))),
                }
            }
            syn::Expr::Group(group) => self.expr(&group.expr),

            // Control flow: both arms are declared, so the result is a
            // superset of any one execution. Legal, and priced as the
            // superset it is. An `if let` scrutinee is walked and its
            // pattern's names are bound opaquely for the taken branch.
            syn::Expr::If(branch) => self.branch(branch),
            syn::Expr::Match(match_) => {
                let scrutinee = self.code(&match_.expr);
                let arms: Vec<_> = match_
                    .arms
                    .iter()
                    .map(|arm| {
                        self.locals.push(BTreeMap::new());
                        // A guard is part of the pattern, and `bind_pattern`
                        // walks it there.
                        self.bind_pattern(&arm.pat);
                        let body = self.code(&arm.body);
                        self.locals.pop();
                        let pat = &arm.pat;
                        quote!(#pat => #body,)
                    })
                    .collect();
                Eval::plain(quote!(match #scrutinee { #(#arms)* }))
            }
            syn::Expr::Block(block) => self.block_expr(block),
            syn::Expr::ForLoop(loop_) => {
                let code = self.for_loop(loop_);
                Eval::plain(code)
            }
            syn::Expr::Return(ret) => {
                let value = ret.expr.as_ref().map(|value| {
                    let produced = self.returned(value);
                    if !produced.outputs.is_empty() || produced.answer.is_some() {
                        self.error(
                            ret.span(),
                            "what a method hands back must leave through its tail \
                             expression — the declared outputs are exact and the answer \
                             is one value, so an early return's cannot be reconciled with \
                             the tail's",
                        );
                    }
                    self.code(value)
                });
                Eval::plain(quote!(return #value))
            }

            // A `while` or `loop` introduces no binder, so it declares
            // nothing a straight-line body would not. Walking in is enough:
            // an access inside still has to name a key derivable from the
            // arguments, and that check is what actually guards the
            // declaration. Iterating the entries of an already-declared
            // range is the common case and is entirely legitimate — the
            // range clause covered them before the loop started.
            syn::Expr::While(loop_) => {
                self.locals.push(BTreeMap::new());
                let cond = self.condition(&loop_.cond);
                let body = self.block(&loop_.body);
                self.locals.pop();
                Eval::plain(quote!(while #cond #body))
            }
            syn::Expr::Loop(loop_) => {
                let body = self.block(&loop_.body);
                Eval::plain(quote!(loop #body))
            }
            syn::Expr::Let(let_) => {
                let value = self.code(&let_.expr);
                self.bind_pattern(&let_.pat);
                let pat = &let_.pat;
                Eval::plain(quote!(let #pat = #value))
            }

            // Assignment forgets the target's slot: after a conditional
            // reassignment the static value is not knowable, so a later
            // use as a key must be refused where it is used rather than
            // declare the stale key.
            syn::Expr::Assign(assign) => {
                let right = self.code(&assign.right);
                let left = self.assign_target(&assign.left);
                Eval::plain(quote!(#left = #right))
            }
            // A comparison is read before it is rewritten, because its two
            // readings differ: what the declaration learns is a judgment,
            // and what the guest runs is the comparison it was written as.
            syn::Expr::Binary(binary) if judges(binary.op) => {
                let left = self.expr(&binary.left);
                let right = self.expr(&binary.right);
                if let Some(term) = judgment(binary.op, &left.val, &right.val) {
                    return Eval {
                        val: Val::Term(term.clone()),
                        code: Code::Term(binary.span(), term),
                    };
                }
                let left = self.value(left.code);
                let right = self.value(right.code);
                let op = binary.op;
                Eval::plain(quote!(#left #op #right))
            }
            // A sum of two derivable values is derivable, and the guest
            // reads the declaration's own sum rather than re-adding: the
            // evaluator refuses overflow where Rust's `+` would panic or
            // wrap, and one addition cannot disagree with itself.
            syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Add(_)) => {
                let left = self.expr(&binary.left);
                let right = self.expr(&binary.right);
                if let (Val::Term(l), Val::Term(r)) = (&left.val, &right.val)
                    && !l.is_judgment()
                    && !r.is_judgment()
                {
                    let term = Term::Add(Box::new(l.clone()), Box::new(r.clone()));
                    return Eval {
                        val: Val::Term(term.clone()),
                        code: Code::Term(binary.span(), term),
                    };
                }
                let left = self.value(left.code);
                let right = self.value(right.code);
                Eval::plain(quote!(#left + #right))
            }
            syn::Expr::Binary(binary) => {
                let left = self.code(&binary.left);
                let right = self.code(&binary.right);
                let op = binary.op;
                if binary_op_assigns(binary.op) {
                    self.assign_target(&binary.left);
                }
                Eval::plain(quote!(#left #op #right))
            }

            // Forms that carry no access semantics of their own but can
            // contain accesses: walked exhaustively, evaluated to nothing.
            syn::Expr::Unary(unary) => {
                let inner = self.expr(&unary.expr);
                // `!` over a judgment is negation; over an integer it is
                // a bitwise complement, which the DSL has no word for.
                if let (syn::UnOp::Not(_), Val::Term(term)) = (&unary.op, &inner.val)
                    && term.is_judgment()
                {
                    let term = Term::Not(Box::new(term.clone()));
                    return Eval {
                        val: Val::Term(term.clone()),
                        code: Code::Term(unary.span(), term),
                    };
                }
                let inner = self.value(inner.code);
                let op = unary.op;
                Eval::plain(quote!(#op #inner))
            }
            syn::Expr::Tuple(tuple) => self.sequence(tuple.span(), tuple.elems.iter(), false),
            // A cast can truncate, so the result is not the term it was
            // cast from.
            syn::Expr::Cast(cast) => {
                let inner = self.code(&cast.expr);
                let ty = &cast.ty;
                Eval::plain(quote!(#inner as #ty))
            }
            syn::Expr::Try(try_) => {
                let inner = self.code(&try_.expr);
                let inner = if block_form(&try_.expr) {
                    quote!((#inner))
                } else {
                    inner
                };
                Eval::plain(quote!(#inner?))
            }
            syn::Expr::Index(index) => {
                let base = self.code(&index.expr);
                let subscript = self.code(&index.index);
                Eval::plain(quote!(#base[#subscript]))
            }
            syn::Expr::Array(array) => self.sequence(array.span(), array.elems.iter(), true),
            syn::Expr::Repeat(repeat) => {
                let element = self.code(&repeat.expr);
                let len = self.code(&repeat.len);
                Eval::plain(quote!([#element; #len]))
            }
            syn::Expr::Struct(strct) => {
                let path = &strct.path;
                let fields: Vec<_> = strct
                    .fields
                    .iter()
                    .map(|field| {
                        let member = &field.member;
                        let value = self.code(&field.expr);
                        quote!(#member: #value)
                    })
                    .collect();
                let rest = strct
                    .rest
                    .as_ref()
                    .map(|rest| self.code(rest))
                    .map(|rest| quote!(..#rest));
                Eval::plain(quote!(#path { #(#fields),* #rest }))
            }
            syn::Expr::Range(range) => {
                let start = range.start.as_ref().map(|start| self.code(start));
                let end = range.end.as_ref().map(|end| self.code(end));
                let limits = &range.limits;
                Eval::plain(quote!(#start #limits #end))
            }
            syn::Expr::Break(brk) => {
                let value = brk.expr.as_ref().map(|value| self.code(value));
                let label = &brk.label;
                Eval::plain(quote!(break #label #value))
            }
            syn::Expr::Continue(cont) => Eval::plain(quote!(#cont)),
            syn::Expr::Macro(mac) => {
                let code = self.macro_call(&mac.mac);
                Eval::plain(code)
            }

            // A closure whose body reaches nothing is arithmetic, and
            // arithmetic is ordinary code: `Option::map` over a value in
            // hand declares what the line before it declared. What the
            // rule is about is the access inside one, which no
            // declaration site could be attributed — so the walk asks
            // the body rather than the syntax.
            syn::Expr::Closure(closure) => {
                let before = self.declared();
                self.locals.push(BTreeMap::new());
                for input in &closure.inputs {
                    self.bind_pattern(input);
                }
                let body = self.expr(&closure.body);
                let produced = matches!(body.val, Val::Produced(_) | Val::Edges(_));
                let code = self.value(body.code);
                self.locals.pop();
                if self.declared() != before || produced {
                    self.error(
                        closure.span(),
                        "`#[blueprint]` does not model closures — an access inside one \
                         cannot be attributed to a declaration",
                    );
                    return Eval::absent(closure.span(), "a closure");
                }
                let capture = &closure.capture;
                let inputs = &closure.inputs;
                let output = &closure.output;
                // A closure with a declared return type has a block for
                // a body, which the rewritten expression is not — so the
                // type comes back over a block wrapping it.
                match output {
                    syn::ReturnType::Default => Eval::plain(quote!(#capture |#inputs| #code)),
                    ty @ syn::ReturnType::Type(..) => {
                        Eval::plain(quote!(#capture |#inputs| #ty { #code }))
                    }
                }
            }

            // Anything not modelled above would be walked past silently,
            // and a silent skip is a declaration missing whatever the body
            // did inside it. Refusing is what makes over-declaration the
            // only failure mode the derivation has.
            other => {
                self.error(
                    other.span(),
                    "`#[blueprint]` does not model this expression, so it cannot see \
                     the accesses inside it — rewrite the body with the forms the \
                     macro admits (see the crate docs)",
                );
                Eval::absent(other.span(), "an unmodelled expression")
            }
        }
    }

    /// Walk an `if`/`while` condition, binding an `if let` pattern's names
    /// opaquely into the scope the caller pushed.
    fn condition(&mut self, cond: &syn::Expr) -> TokenStream {
        if let syn::Expr::Let(let_) = cond {
            let value = self.code(&let_.expr);
            self.bind_pattern(&let_.pat);
            let pat = &let_.pat;
            quote!(let #pat = #value)
        } else {
            self.code(cond)
        }
    }

    /// Forget the slot an assignment target held, wherever it is bound.
    fn assign_target(&mut self, left: &syn::Expr) -> TokenStream {
        if let syn::Expr::Path(path) = left
            && let Some(ident) = path.path.get_ident()
        {
            let name = ident.to_string();
            for scope in self.locals.iter_mut().rev() {
                if let Some(slot) = scope.get_mut(&name) {
                    *slot = Slot::Opaque;
                    break;
                }
            }
            quote!(#ident)
        } else {
            self.code(left)
        }
    }

    fn path(&self, path: &syn::ExprPath) -> Eval {
        let Some(ident) = path.path.get_ident() else {
            // `u64::MAX` and friends are literals wearing a path. They show
            // up at range boundaries — "every sequence at this price" — so
            // refusing them would push authors to write the number out.
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let val = match segments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                ["u64", "MAX"] => Val::Term(Term::LitU64(u64::MAX)),
                ["u64", "MIN"] => Val::Term(Term::LitU64(0)),
                ["u128", "MAX"] => Val::Term(Term::LitU128(u128::MAX)),
                ["u128", "MIN"] => Val::Term(Term::LitU128(0)),
                _ => Val::Opaque,
            };
            return Eval {
                val,
                code: Code::Rust(quote!(#path)),
            };
        };
        let name = ident.to_string();
        if let Some(slot) = self.lookup(&name) {
            // A local's guest code is the local: whatever the binding was
            // rewritten to at its `let` is what the name now holds. Two
            // exceptions, both because the binding holds nothing the
            // guest has: the configuration record is fields that are
            // slots, and a declaration term is re-derived at each use, so
            // naming one costs an export parameter only where the guest
            // reads it and nothing where the declaration does.
            let code = match &slot {
                Slot::Config => Code::Record(path.span()),
                Slot::Deferred(term) => Code::Term(path.span(), term.clone()),
                _ => Code::Rust(quote!(#ident)),
            };
            return Eval {
                val: slot.into(),
                code,
            };
        }
        if let Some(index) = self.params.iter().position(|(p, _)| *p == name) {
            let slot = u32::try_from(index).expect("a parameter list is shorter than u32");
            let term = Term::Arg(slot);
            return Eval {
                val: Val::Term(term.clone()),
                // A parameter reaches the guest only if something actually
                // reads it: one consumed as key material is in the
                // declaration and nowhere else.
                code: if is_bucket(&self.params[index].1) {
                    Code::Bucket(path.span(), slot)
                } else {
                    Code::Term(path.span(), term)
                },
            };
        }
        Eval {
            val: Val::Opaque,
            code: Code::Rust(quote!(#path)),
        }
    }

    fn literal(lit: &syn::ExprLit) -> Eval {
        // The wide read is a fallback rather than the only parse, so a
        // key within `u64` keeps the term its consumers match on; what
        // the wide one buys is that an order-key literal is a literal
        // rather than "not derivable".
        let val = match &lit.lit {
            syn::Lit::Int(int) => int.base10_parse::<u64>().map_or_else(
                |_| {
                    int.base10_parse::<u128>()
                        .map_or(Val::Opaque, |value| Val::Term(Term::LitU128(value)))
                },
                |value| Val::Term(Term::LitU64(value)),
            ),
            _ => Val::Opaque,
        };
        Eval {
            val,
            code: Code::Rust(quote!(#lit)),
        }
    }

    fn field(&mut self, field: &syn::ExprField) -> Eval {
        // `self.<name>` names a state field rather than a value.
        if let syn::Expr::Path(path) = &*field.base
            && path.path.is_ident("self")
            && let syn::Member::Named(name) = &field.member
        {
            return Eval {
                val: Val::Field {
                    name: name.to_string(),
                    material: Vec::new(),
                },
                code: Code::Absent(field.span(), "a state field in value position"),
            };
        }
        let base = self.expr(&field.base);
        let member = &field.member;
        match (&base.val, member) {
            // `self.config.x` — a configuration field read directly.
            //
            // This declares nothing, and that is the point: the record is
            // what admission resolved the target with, so a declaration
            // may consult it without claiming anything.
            (
                Val::Field {
                    name: field_name, ..
                },
                syn::Member::Named(name),
            ) if self
                .state(field_name)
                .is_some_and(|f| f.kind == FieldKind::Config) =>
            {
                self.config_slot(&name.to_string(), field)
            }

            // A field of the record bound as a whole.
            (Val::Config, syn::Member::Named(name)) => self.config_slot(&name.to_string(), field),
            (Val::Term(term), syn::Member::Unnamed(index)) => {
                let term = Term::Field(Box::new(term.clone()), index.index);
                Eval {
                    val: Val::Term(term.clone()),
                    code: Code::Term(field.span(), term),
                }
            }
            _ => {
                let code = self.value(base.code);
                let code = if block_form(&field.base) {
                    quote!((#code))
                } else {
                    code
                };
                Eval::plain(quote!(#code.#member))
            }
        }
    }

    /// Resolve a configuration field name to its slot index.
    ///
    /// The guest reaches a configuration value the same way the
    /// declaration does — the kernel evaluates the slot — rather than by
    /// decoding the leaf, so a pinned read and a consulted one differ in
    /// what they exclude and in nothing else.
    fn config_slot(&mut self, name: &str, field: &syn::ExprField) -> Eval {
        let Some(index) = self
            .declared
            .config_fields
            .iter()
            .position(|(f, _)| f == name)
        else {
            self.error(
                field.span(),
                "not a field of the component's configuration struct",
            );
            return Eval::absent(field.span(), "an unknown configuration field");
        };
        let term =
            Term::Config(u32::try_from(index).expect("a configuration record is shorter than u32"));
        Eval {
            val: Val::Term(term.clone()),
            code: Code::Term(field.span(), term),
        }
    }

    #[allow(clippy::too_many_lines)] // one arm per free call the vocabulary names
    fn free_call(&mut self, call: &syn::ExprCall) -> Eval {
        for arg in &call.args {
            if is_self(arg) {
                self.error(
                    arg.span(),
                    "the component reference cannot be passed on — a callee's accesses \
                     would be invisible to this method's declaration",
                );
            }
        }
        let Some(name) = free_call_name(call) else {
            let func = self.code(&call.func);
            let args: Vec<_> = call.args.iter().map(|a| self.code(a)).collect();
            return Eval::plain(quote!(#func(#(#args),*)));
        };
        // A fresh id is drawn once per call site: the entry key derived
        // from it and the parameter carrying it are one draw, not two.
        if name == "fresh_id" && call.args.is_empty() {
            let site = self.out.fresh;
            self.out.fresh += 1;
            let term = Term::FreshId(site);
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(call.span(), term),
            };
        }
        // `Resource::mint(..)` — the one edge with no cell behind it. The
        // declaration names the resource exactly as `issued(Resource)`
        // derives an address from one, so the output projection and the
        // issuance grant come out of the same call, and the kind it
        // states is what picks between a quantity and a list of ids.
        // `Resource::__found(..)` — the same issuance under the one word
        // that is not minting. The generated `instantiate` writes it and
        // an authored body cannot: founding is the supply a component
        // comes up holding, so no `Mint` entry governs it and the mark's
        // own grants have no say.
        if name == "mint" || name == "__found" {
            let Some(issued) = self.issuing_mark(call, &name) else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            if name == "mint" {
                self.granted(&issued, GrantedBehaviour::Mint, call.func.span());
            }
            return match issued.kind {
                ResourceKind::NonFungible => self.lower_mint_nf(&issued, call),
                ResourceKind::Fungible => self.lower_mint(&issued, call),
            };
        }
        // `Resource::__record(..)` — the record cell, written where the
        // resource comes into existence. The generated `instantiate`'s
        // marker, unspellable from an authored body for the reason
        // `__seal` is: a record is written once, where the component
        // becomes actual, so a body that wrote one would be writing a
        // second.
        if name == "__record" {
            let Some(issued) = self.issuing_mark(call, "__record") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return self.lower_record_create(&issued, call);
        }
        // `Resource::at(id)` — the record one instance carries.
        if name == "at" {
            let Some(issued) = self.issuing_mark(call, "at") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return self.lower_at(&issued, call);
        }
        // `Resource::rewrite(id, record)` — the cell the mint filed,
        // written again under the presence the mint required absent.
        if name == "rewrite" {
            let Some(issued) = self.issuing_mark(call, "rewrite") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return self.lower_rewrite(&issued, call);
        }
        // `Resource::held(edge)` — the same record, at the id the edge
        // supplies rather than one the caller names.
        if name == "held" {
            let Some(issued) = self.issuing_mark(call, "held") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return self.lower_held(&issued, call);
        }
        // `Resource::each(edge)` — the same record, once per instance the
        // edge carries rather than once for the one it must carry.
        if name == "each" {
            let Some(issued) = self.issuing_mark(call, "each") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return self.lower_each(&issued, call);
        }
        // `Resource::burn(funds)` — the inverse, under the same grant.
        // The kind picks the shape the same way the mint's does: an
        // amount leaves a balance, and an instance leaves existence
        // along with the cell that described it.
        if name == "burn" {
            let Some(issued) = self.issuing_mark(call, "burn") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            self.granted(&issued, GrantedBehaviour::Burn, call.func.span());
            return match issued.kind {
                ResourceKind::NonFungible => self.lower_burn_nf(&issued, call),
                ResourceKind::Fungible => self.lower_burn(&issued.mark, call),
            };
        }
        // `halt(holder, resource)` — the one cell a package reaches under
        // somebody else's prefix. What admits it is the resource's own
        // `Halt` entry, injected where the declaration is evaluated,
        // so the package names the authority and the resource names who
        // holds it.
        if name == "halt" || name == "unhalt" {
            return self.lower_halt(name == "halt", call);
        }
        // `recall(holder, slot, resource, amount)` and its interval
        // form — value taken out of a prefix that is not this
        // instance's, admitted by the resource's own `Recall` entry.
        // The slot is the caller's because a holder keeps value
        // wherever they like.
        if name == "recall" || name == "recall_instances" {
            return self.lower_recall(name == "recall_instances", call);
        }
        // `destroy(funds)` / `destroy_nf(funds)` — the holder's side of
        // supply leaving. What it destroys is the edge's own resource,
        // so the declaration names the parameter and the rule that
        // admits it is that resource's, not this instance's.
        if name == "destroy" || name == "destroy_nf" {
            return self.lower_destroy(&name, call);
        }
        // `Name::address()` — the resource the mark derives, as a body
        // names it. The same derivation `issued(Name)` reaches from an
        // attribute, so a gate and a body cannot mean two addresses.
        if name == "address" {
            let Some(issued) = self.issuing_mark(call, "address") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            let term = Term::SelfResource(issued.kind, issued.mark);
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(call.span(), term),
            };
        }
        if name == "issued" {
            let Some(term) = self.declared_resource(call) else {
                self.error(
                    call.args.span(),
                    "`issued` names a declared `#[resource]` struct — the derivation \
                     folds the resource's kind, and the declaration is where a kind \
                     is stated",
                );
                return Eval::absent(call.args.span(), "an undeclared resource");
            };
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(call.span(), term),
            };
        }
        let evals: Vec<Eval> = call.args.iter().map(|a| self.expr(a)).collect();
        let vals: Vec<Val> = evals.iter().map(|e| e.val.clone()).collect();
        if let ("pack", [Val::Term(hi), Val::Term(lo)]) = (name.as_str(), vals.as_slice()) {
            let term = Term::Pack {
                hi: Box::new(hi.clone()),
                lo: Box::new(lo.clone()),
            };
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(call.span(), term),
            };
        }
        let func = self.code(&call.func);
        let args: Vec<_> = evals
            .into_iter()
            .map(|eval| self.value(eval.code))
            .collect();
        Eval::plain(quote!(#func(#(#args),*)))
    }

    #[allow(clippy::too_many_lines)] // one arm per receiver the vocabulary admits
    fn method_call(&mut self, call: &syn::ExprMethodCall) -> Eval {
        // `self.<accessor>(…)` names one of the protocol's own cells,
        // which exist under every owner and so are reached without being
        // declared. Anything else on `self` is another method of the
        // component, whose accesses cannot land in this declaration.
        if is_self(&call.receiver) {
            let name = call.method.to_string();
            // The generated seal's marker, which no authored body can
            // spell: `expand` never emits it into the module, so the one
            // caller is the synthesized `instantiate`.
            if name == "__seal" {
                return self.seal_record(call);
            }
            if self.declared.accessors.contains_key(&name) {
                return self.accessor(&name, call);
            }
            self.error(
                call.span(),
                "a contract method cannot call a published method of the component — \
                 each method declares only its own body's accesses. Factor the shared \
                 code into a private method, which inlines where it is called, or lift \
                 the shared value to a parameter",
            );
            for arg in &call.args {
                self.expr(arg);
            }
            return Eval::absent(call.span(), "a call to another method of the component");
        }
        for arg in &call.args {
            if is_self(arg) {
                self.error(
                    arg.span(),
                    "the component reference cannot be passed on — a callee's accesses \
                     would be invisible to this method's declaration",
                );
            }
        }
        let receiver = self.expr(&call.receiver);
        let method = call.method.to_string();
        let evals: Vec<Eval> = call.args.iter().map(|a| self.expr(a)).collect();
        let args: Vec<Val> = evals.iter().map(|e| e.val.clone()).collect();

        // A merge of one value edge into another. The receiver is an edge
        // the body holds rather than a cell, so this is the one `put` that
        // moves nothing into state — what it fixes is that the two halves
        // are the same resource.
        if method == "put"
            && let Some(into) = Self::edge_resource(&receiver)
            && let Some(from) = evals.first().and_then(Self::edge_resource)
        {
            self.unify(&into, &from, call.span());
        }

        // A division of a value edge yields parts that each carry what the
        // whole carried. The kernel performs the subtraction, so the parts
        // are the whole and nothing about them is the body's to choose —
        // which is why they stay traceable through the names a tuple
        // pattern gives them rather than becoming opaque there.
        if method == "split"
            && let Some(resource) = Self::edge_resource(&receiver)
        {
            let code = self.pass_through(&receiver, &method, evals, call);
            return Eval {
                val: Val::Edges(vec![resource.clone(), resource]),
                code: Code::Rust(code),
            };
        }

        // The same division against a stated weight table: as many parts
        // as the table has rows, and the remainder beside them. The count
        // is read off the table's own syntax because a declaration states
        // how many edges a method yields, so a slice whose length only
        // the runtime knows is a division this cannot lower.
        if method == "split_n"
            && let Some(resource) = Self::edge_resource(&receiver)
        {
            let Some(rows) = call.args.first().and_then(Self::literal_len) else {
                self.error(
                    call.args.span(),
                    "a division needs its weight table written out here, because the \
                     declaration states how many edges the method yields. Write the \
                     shares as an array literal",
                );
                return Eval::absent(call.args.span(), "a division of unknown width");
            };
            let code = self.pass_through(&receiver, &method, evals, call);
            return Eval {
                // One per row, and the remainder last, in the order the
                // parts come back.
                val: Val::Edges(vec![resource; rows + 1]),
                code: Code::Rust(code),
            };
        }

        match receiver.val.clone() {
            // ---- opening a handle on a state field ----------------------
            Val::Field { name, material } => {
                let Some(field) = self.state(&name) else {
                    self.error(
                        call.receiver.span(),
                        "not a declared field of the component's state struct",
                    );
                    return Eval::absent(call.receiver.span(), "an undeclared state field");
                };
                // Narrowing to a sub-collection is not an access: it names
                // which collection under the slot, and every accessor
                // below reads the same with the material as without it.
                if method == "of" && field.kind == FieldKind::Ordered {
                    let Some(Val::Term(key)) = args.first() else {
                        self.error(
                            call.args.span(),
                            "this collection key is not derivable from the method's \
                             arguments or the component's configuration. Routing \
                             evaluates a declaration before execution and never reads \
                             state, so a key computed from a substate value cannot be \
                             declared — pass it as a parameter instead",
                        );
                        return Eval::absent(call.args.span(), "an underivable collection key");
                    };
                    let mut material = material;
                    material.push(key.clone());
                    return Eval {
                        val: Val::Field { name, material },
                        code: Code::Absent(call.span(), "a collection in value position"),
                    };
                }
                self.on_field(&field, &material, &method, &evals, call)
            }

            // ---- operating through an open handle -----------------------
            Val::Handle(site) => {
                let Some(op) = Op::from_method(&method) else {
                    // A handle reaches the kernel, so every method on one
                    // is an operation the declaration has to name. Passing
                    // an unmodelled one through would emit a body that
                    // acts through a capability the declaration never
                    // bought — the one shape the walk exists to make
                    // impossible.
                    let vocabulary = Op::VOCABULARY.join(", ");
                    self.error(
                        call.method.span(),
                        &format!(
                            "`{method}` names no operation a declaration can carry, so what it reaches the kernel for is not what this method declares. One of: {vocabulary}"
                        ),
                    );
                    return Eval::absent(call.span(), "an operation the vocabulary does not hold");
                };
                let param = match args.first() {
                    Some(Val::Term(term)) => Some(term.clone()),
                    _ => None,
                };
                if op == Op::Reserve && param.is_none() {
                    self.error(
                        call.span(),
                        "the amount a `reserve` judges and the window a `pinned` read \
                         declares are part of the declaration, so both must be \
                         derivable from the arguments",
                    );
                }
                self.record(site, op, param, call.span());

                // A capless interval's cap is the count of what the
                // moves through it walk: the ids each take names, the
                // instances each filed edge carries, summed where a
                // body moves more than once. Deriving it here is what
                // makes the declaration correct by construction — a
                // body cannot under-declare the walk its own moves
                // perform. Anything else through such a handle has no
                // count to derive a cap from, so it names its page with
                // `range` instead.
                if matches!(
                    self.out.sites.get(site).map(|s| &s.target),
                    Some(Target::Range { cap: None, .. })
                ) {
                    let counted = if call.method == "take" {
                        // A take whose ids are underivable is reported
                        // once, where the produced edge is judged below.
                        match args.first() {
                            Some(Val::Term(ids)) => Some(Term::Len(Box::new(ids.clone()))),
                            _ => None,
                        }
                    } else if call.method == "file" {
                        if let Some(Val::Term(edge) | Val::Produced(edge)) = args.first() {
                            Some(Term::Len(Box::new(Term::IdsOf(Box::new(edge.clone())))))
                        } else {
                            self.error(
                                call.args.span(),
                                "the instances this edge carries are what the interval's \
                                 cap derives from, so the edge must be derivable from the \
                                 method's arguments — routing evaluates the declaration \
                                 before execution and never reads state",
                            );
                            None
                        }
                    } else {
                        self.error(
                            call.span(),
                            "a capless interval derives its cap from the moves through \
                             it, and this access moves nothing. An access that walks a \
                             chosen page names it with `range`",
                        );
                        None
                    };
                    if let Some(counted) = counted {
                        let moved = &mut self.out.sites[site].moved;
                        *moved = Some(match moved.take() {
                            None => counted,
                            Some(walked) => Term::Add(Box::new(walked), Box::new(counted)),
                        });
                    }
                }

                // A declared movement the body does not make binds no
                // handle: the clause is what the kernel provisions and
                // what a caller routes on, and there is nothing for the
                // guest to call.
                if call.method == "declared"
                    || call.method == "declared_credit"
                    || call.method == "exclusive"
                {
                    // The unit it evaluates to, not nothing: a declared
                    // access can stand in expression position, and a
                    // match arm needs something there. Neither binds a
                    // handle — the clause is what the kernel provisions
                    // and what a caller routes on, and there is nothing
                    // for the guest to call.
                    return Eval::plain(quote!(()));
                }
                let resource = self
                    .out
                    .sites
                    .get(site)
                    .and_then(|s| s.denomination.clone());
                let instances = matches!(
                    self.out.sites.get(site).map(|s| &s.target),
                    Some(Target::Range { .. })
                );
                // The grant needs no amount at the boundary: the kernel
                // judged and held it against this method's own
                // declaration before the body ran, so the amount is the
                // declaration's and reaches the guest through nothing.
                if op == Op::Reserve
                    && let Some(resource) = resource.clone()
                {
                    let capability = self.handle(site, call.span());
                    return Eval {
                        val: Val::Produced(resource),
                        code: Code::Rust(
                            quote!(::hyperscale_vm_sdk::state::take_reservation(#capability)),
                        ),
                    };
                }
                // What the credited edge carries, read before the arguments
                // are rewritten: a credit is where an edge meets a cell,
                // and the cell's key is what the edge has to be.
                let credited = evals.first().and_then(Self::edge_resource);
                let receiver_code = self.value(receiver.code);
                let rewritten: Vec<_> = evals
                    .into_iter()
                    .map(|eval| self.value(eval.code))
                    .collect();

                // A credit fixes what the edge carries: the vault's key
                // names one resource, and value going into it is that
                // resource or the balance stops being one. Where the edge
                // traces back to a parameter, that is where a caller
                // supplies it and so where the constraint is stated; a
                // vault keyed by the arriving edge's own resource names
                // whatever arrives, which fixes nothing and is what a
                // wallet is.
                //
                // An edge the lowering cannot see the resource of is
                // refused rather than passed over: a signature that
                // constrains nothing reads as a method taking any
                // resource, so a credit nobody can type would publish as
                // a promise the body never made.
                if op == Op::Credit
                    && call.method == "put"
                    && let Some(keyed) = resource.clone()
                {
                    match &credited {
                        // The cell is keyed by what arrived, so it names
                        // whatever comes and fixes nothing.
                        Some(term) if *term == keyed => {}
                        // An edge a caller supplies, credited to a cell
                        // keyed by something else: that key is what the
                        // caller has to send.
                        Some(Term::ResourceOf(inner)) if matches!(**inner, Term::Arg(_)) => {
                            if let Term::Arg(param) = **inner {
                                self.denominate(param, keyed, call.span());
                            }
                        }
                        // An edge the body produced — issued, or debited
                        // from another vault — carries a resource nothing
                        // about this call can change, and it is not the
                        // one this cell holds. No caller is involved, so
                        // there is no constraint to state: the body is
                        // simply wrong.
                        Some(held) => {
                            let (held, keyed) = (self.describe(held), self.describe(&keyed));
                            self.error(
                                call.args.span(),
                                &format!(
                                    "this cell holds {keyed} and the value going into it is \
                                     {held}. A credit does not convert what it moves — take \
                                     from the cell holding what you have, or mint the \
                                     resource this one is denominated in"
                                ),
                            );
                        }
                        None => self.error(
                            call.args.span(),
                            "this cell is keyed by one resource and the lowering cannot see \
                             what is going into it. Credit an edge the method was handed, \
                             one taken from a declared cell, or one it issued",
                        ),
                    }
                }

                // A debit yields the value it moved, carrying the vault's
                // own resource — which the site's key material already
                // names, so the produced edge needs no separate
                // declaration. Out of a collection it yields the
                // instances that actually left, which the ids it named
                // are: the removal and the edge are one operation, so the
                // set cannot be one the body chose.
                if op == Op::Debit
                    && call.method == "take"
                    && let Some(resource) = resource
                {
                    let produced = if instances {
                        let Some(Val::Term(ids)) = args.first() else {
                            self.error(
                                call.args.span(),
                                "the instances a take names are the edge it produces, so \
                                 they must be derivable from the method's arguments",
                            );
                            return Eval::absent(call.args.span(), "an underivable instance set");
                        };
                        Term::NfBucket {
                            resource: Box::new(resource),
                            ids: Box::new(ids.clone()),
                        }
                    } else {
                        resource
                    };
                    return Eval {
                        val: Val::Produced(produced),
                        code: Code::Rust(quote!(#receiver_code.take(#(#rewritten),*))),
                    };
                }
                // The record cell's create writes the canonical record.
                // The kind is the mark's — the site's key carries it — so
                // the body states only what the address cannot: a
                // fungible record's display quantization.
                if call.method == "create"
                    && let Some(Term::SelfResource(kind, _)) = self.record_cell(site)
                {
                    let record = match kind {
                        ResourceKind::Fungible => {
                            let Some(display_digits) = rewritten.first() else {
                                self.error(
                                    call.span(),
                                    "a fungible record states its display quantization: \
                                     `create(<display_digits>)`",
                                );
                                return Eval::absent(call.span(), "a record with no display width");
                            };
                            quote!(::hyperscale_vm_sdk::state::ResourceRecord::Fungible {
                                display_digits: #display_digits,
                            })
                        }
                        ResourceKind::NonFungible => {
                            if !rewritten.is_empty() {
                                self.error(
                                    call.span(),
                                    "a non-fungible record has nothing to state — the kind \
                                     is the mark's and instances are whole by construction",
                                );
                            }
                            quote!(::hyperscale_vm_sdk::state::ResourceRecord::NonFungible)
                        }
                    };
                    return Eval::plain(quote!(#receiver_code.create(#record)));
                }
                let name = &call.method;
                Eval::plain(quote!(#receiver_code.#name(#(#rewritten),*)))
            }

            // ---- projections over values --------------------------------
            // A produced edge's resource is the declaration's answer, so
            // reading one is a term the kernel evaluates rather than
            // anything the guest already holds.
            Val::Produced(resource) if method == "resource" => Eval {
                val: Val::Term(resource.clone()),
                code: Code::Term(call.span(), resource),
            },
            Val::Produced(resource) => {
                let code = self.pass_through(&receiver, &method, evals, call);
                Eval {
                    val: Val::Produced(resource),
                    code: Code::Rust(code),
                }
            }

            // A split of a value edge is a value edge, carrying the same
            // resource: the receiver is a bucket the body holds, and what
            // comes off it is the kernel's own subtraction.
            Val::Term(term) if method == "take" && matches!(receiver.code, Code::Bucket(..)) => {
                let code = self.pass_through(&receiver, &method, evals, call);
                Eval {
                    val: Val::Produced(Term::ResourceOf(Box::new(term))),
                    code: Code::Rust(code),
                }
            }
            Val::Term(term) => match method.as_str() {
                "resource" => Eval {
                    val: Val::Term(Term::ResourceOf(Box::new(term.clone()))),
                    code: Code::Term(call.span(), Term::ResourceOf(Box::new(term))),
                },
                // The count of what the receiver names: an edge's
                // instances, or a list argument's elements — which is
                // what derives a move's cap from the move itself.
                "count" => {
                    let inner = if matches!(receiver.code, Code::Bucket(..)) {
                        Term::IdsOf(Box::new(term))
                    } else {
                        term
                    };
                    let counted = Term::Len(Box::new(inner));
                    Eval {
                        val: Val::Term(counted.clone()),
                        code: Code::Term(call.span(), counted),
                    }
                }
                // A clone is the value it was taken from: what a term
                // names does not change by being copied, and value —
                // which could not be copied and still be value — is not
                // `Clone`, so nothing linear reaches here. The emission
                // writes this expression from the term either way, so
                // the copy the author needed to satisfy the borrow
                // checker is not one the guest half repeats.
                "clone" if evals.is_empty() => Eval {
                    val: Val::Term(term.clone()),
                    code: Code::Term(call.span(), term),
                },
                "lookup" | "get" | "contains" if matches!(args.first(), Some(Val::Term(_))) => {
                    let Some(Val::Term(key)) = args.first() else {
                        return Eval::absent(call.span(), "a lookup with no key");
                    };
                    let map = Box::new(term);
                    let key = Box::new(key.clone());
                    // The question a miss makes answerable: guarding the
                    // lookup on this is what turns a routing refusal into
                    // a default the package chose.
                    let term = if method == "contains" {
                        Term::Contains { map, key }
                    } else {
                        Term::Lookup { map, key }
                    };
                    Eval {
                        val: Val::Term(term.clone()),
                        code: Code::Term(call.span(), term),
                    }
                }
                _ => {
                    let code = self.pass_through(&receiver, &method, evals, call);
                    Eval::plain(code)
                }
            },

            // A tuple of edges answers no method of its own: the parts are
            // reached by the names a pattern gave them, and anything else
            // asked of it is ordinary code.
            Val::Config | Val::Edges(_) | Val::Opaque => {
                let code = self.pass_through(&receiver, &method, evals, call);
                Eval::plain(code)
            }
        }
    }

    /// How many elements a literal collection is written with.
    ///
    /// Syntactic on purpose: what this answers is how many edges the
    /// declaration names, so the only table it can read is one the
    /// source spells out.
    fn literal_len(arg: &syn::Expr) -> Option<usize> {
        let mut expr = arg;
        while let syn::Expr::Reference(reference) = expr {
            expr = &reference.expr;
        }
        match expr {
            syn::Expr::Array(array) => Some(array.elems.len()),
            _ => None,
        }
    }

    /// The names a division's pattern binds, in the order its parts come
    /// back.
    ///
    /// Tuples and arrays both flatten, because how a division groups its
    /// answer is a shape the Rust signature chose and not something the
    /// declaration means: `(a, b)` and `([a, b], rest)` are both a run of
    /// edges, and each name in either takes the part at its position.
    fn edge_names(pat: &syn::Pat) -> Vec<syn::Pat> {
        match unwrap_pat(pat) {
            syn::Pat::Tuple(tuple) => tuple.elems.iter().flat_map(Self::edge_names).collect(),
            syn::Pat::Slice(slice) => slice.elems.iter().flat_map(Self::edge_names).collect(),
            other => vec![other.clone()],
        }
    }

    /// Rebuild a method call the vocabulary does not model, over its
    /// rewritten receiver and arguments.
    fn pass_through(
        &mut self,
        receiver: &Eval,
        _method: &str,
        evals: Vec<Eval>,
        call: &syn::ExprMethodCall,
    ) -> TokenStream {
        let receiver_code = self.value(receiver.code.clone());
        let receiver_code = if block_form(&call.receiver) {
            quote!((#receiver_code))
        } else {
            receiver_code
        };
        let args: Vec<_> = evals
            .into_iter()
            .map(|eval| self.value(eval.code))
            .collect();
        let name = &call.method;
        let turbofish = &call.turbofish;
        quote!(#receiver_code.#name #turbofish(#(#args),*))
    }

    /// One of the protocol's own cells, reached by accessor.
    ///
    /// Every case lands on the same clause its field spelling lowered to,
    /// because it lands on the same call: a keyed accessor is that field
    /// at the key it was handed, and a collection accessor is that field
    /// narrowed to the sub-collection. What the accessor removes is the
    /// author's chance to declare the cell wrongly, not a step in the
    /// lowering.
    fn accessor(&mut self, name: &str, call: &syn::ExprMethodCall) -> Eval {
        let Some(field) = self.declared.accessors.get(name).cloned() else {
            return Eval::absent(call.span(), "an unknown protocol cell");
        };
        let evals: Vec<Eval> = call.args.iter().map(|arg| self.expr(arg)).collect();
        let arity = usize::from(!matches!(field.kind, FieldKind::Cell | FieldKind::Config));
        if evals.len() != arity {
            self.error(call.span(), &format!("`{name}` takes {arity} argument(s)"));
            return Eval::absent(call.span(), "a protocol cell named with the wrong arity");
        }
        match field.kind {
            // A leaf of the family, at the key the accessor was handed.
            // The family is the vault one, so that key is the resource
            // the leaf holds — read off the element type where the site
            // is opened rather than stated by the accessor.
            FieldKind::Keyed => self.on_field(&field, &[], "at", &evals, call),
            // The sub-collection under the cell, which the body then
            // opens an interval on.
            FieldKind::Ordered => {
                let Some(Val::Term(key)) = evals.first().map(|e| e.val.clone()) else {
                    self.error(
                        call.args.span(),
                        "this collection key is not derivable from the method's arguments \
                         or the component's configuration",
                    );
                    return Eval::absent(call.args.span(), "an underivable collection key");
                };
                Eval {
                    val: Val::Field {
                        name: name.to_owned(),
                        material: vec![key],
                    },
                    code: Code::Absent(call.span(), "a collection in value position"),
                }
            }
            // The cell itself, which the body then reads or writes.
            FieldKind::Cell => Eval {
                val: Val::Field {
                    name: name.to_owned(),
                    material: Vec::new(),
                },
                code: Code::Absent(call.span(), "a protocol cell in value position"),
            },
            // The configuration record itself. It declares nothing: every
            // method's fence already reads the leaf it was sealed into
            // and holds it present, and after the seal the leaf has no
            // writer. Its fields are slots the kernel evaluates, so a
            // body reading the record whole is handed those rather than
            // the leaf's bytes.
            FieldKind::Config => Eval {
                val: Val::Config,
                code: Code::Record(call.span()),
            },
            FieldKind::Unordered => Eval::absent(call.span(), "an unordered protocol cell"),
        }
    }

    #[allow(clippy::too_many_lines)] // single dispatch over (field kind, accessor) pairs
    fn on_field(
        &mut self,
        field: &Field,
        material: &[Term],
        method: &str,
        args: &[Eval],
        call: &syn::ExprMethodCall,
    ) -> Eval {
        let slot = field.slot;
        let declared = self.field_denomination(field);
        let vals: Vec<Val> = args.iter().map(|e| e.val.clone()).collect();
        match (field.kind, method) {
            // A family of leaves keyed by an address.
            (FieldKind::Keyed, "at") => {
                if let Some(Val::Term(key)) = vals.first() {
                    let site = self.open(
                        Target::Point {
                            owner: None,
                            slot: SlotRef::Fixed(slot),
                            material: vec![key.clone()],
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::slot(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "this key is not derivable from the method's arguments or the \
                     component's configuration. Routing evaluates a declaration before \
                     execution and never reads state, so a key computed from a substate \
                     value cannot be declared — pass it as a parameter instead",
                    );
                    Eval::absent(call.args.span(), "an underivable key")
                }
            }

            // One entry of an ordered collection.
            (FieldKind::Ordered, "at") => {
                if let Some(Val::Term(order)) = vals.first() {
                    let order = order.clone();
                    let site = self.open(
                        Target::Entry {
                            slot,
                            material: material.to_vec(),
                            order: order.clone(),
                        },
                        field.element.clone(),
                        declared,
                    );
                    self.entry(site, &order, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "this order key is not derivable from the method's arguments or the \
                     component's configuration",
                    );
                    Eval::absent(call.args.span(), "an underivable order key")
                }
            }

            // One unordered-collection entry, at the hash of its key.
            (FieldKind::Unordered, "at") => {
                if let Some(Val::Term(key)) = vals.first() {
                    let site = self.open(
                        Target::KeyedEntry {
                            slot,
                            key: key.clone(),
                        },
                        field.element.clone(),
                        declared,
                    );
                    // The order is the kernel's hash over owner, slot and
                    // key. A guest cannot rebuild it, so it is handed one:
                    // the same evaluation admission runs, bound as a value.
                    let order = Term::OrderKey {
                        slot,
                        key: Box::new(key.clone()),
                    };
                    self.entry(site, &order, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "this key is not derivable from the method's arguments or the \
                     component's configuration. Routing evaluates a declaration before \
                     execution and never reads state, so a key computed from a substate \
                     value cannot be declared — pass it as a parameter instead",
                    );
                    Eval::absent(call.args.span(), "an underivable key")
                }
            }

            // An unordered collection's tail from a cursor.
            (FieldKind::Unordered, "sweep") => {
                if let (Some(Val::Term(cursor)), Some(Val::Term(cap))) = (vals.first(), vals.get(1))
                {
                    let site = self.open(
                        Target::Sweep {
                            slot,
                            cursor: cursor.clone(),
                            cap: cap.clone(),
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "a sweep's cursor and entry cap must be derivable from the method's \
                     arguments or the component's configuration — routing evaluates the \
                     declaration before execution and never reads state",
                    );
                    Eval::absent(call.args.span(), "an underivable sweep")
                }
            }

            // A declared interval of an ordered collection.
            (FieldKind::Ordered, "range") => {
                if let (Some(Val::Term(lo)), Some(Val::Term(hi)), Some(Val::Term(cap))) =
                    (vals.first(), vals.get(1), vals.get(2))
                {
                    let site = self.open(
                        Target::Range {
                            slot: SlotRef::Fixed(slot),
                            owner: None,
                            material: material.to_vec(),
                            lo: lo.clone(),
                            hi: hi.clone(),
                            cap: Some(cap.clone()),
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "a range's bounds and entry cap must be derivable from the method's \
                     arguments or the component's configuration — routing evaluates the \
                     declaration before execution and never reads state",
                    );
                    Eval::absent(call.args.span(), "an underivable range")
                }
            }

            // The whole of a collection's order-key space, with no cap
            // of its own: the cap is the count of the one move performed
            // through the handle, derived where that move lands.
            (FieldKind::Ordered, "all") => {
                if vals.is_empty() {
                    let site = self.open(
                        Target::Range {
                            slot: SlotRef::Fixed(slot),
                            owner: None,
                            material: material.to_vec(),
                            lo: Term::LitU128(0),
                            hi: Term::LitU128(u128::MAX),
                            cap: None,
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "`all` takes no cap — the interval's cap is the count of the one \
                     move performed through it. An interval that walks a chosen page \
                     names it with `range`",
                    );
                    Eval::absent(call.args.span(), "an interval with a spurious cap")
                }
            }

            // A single leaf: the operation lands directly on it.
            // A vault is opened, not accessed in place: what a body does
            // through the handle is what fixes the mode, and the resource
            // rides the site rather than any argument.
            //
            // The declared resource is the leaf's key material, which is
            // what makes the two vault forms one addressing scheme: a
            // keyed family's leaf is at the resource a body named it at,
            // and a single vault's is at the resource its field declared.
            // A leaf's key names what the leaf holds, either way.
            (FieldKind::Cell, "vault") => {
                let site = self.open(
                    Target::Point {
                        owner: None,
                        slot: SlotRef::Fixed(slot),
                        material: declared.clone().into_iter().collect(),
                    },
                    field.element.clone(),
                    declared,
                );
                Self::slot(site, call.span())
            }

            (FieldKind::Cell, _) => {
                // A role table is read whole where it is judged, and an
                // absent one denies. A `get` would read the absence as an
                // empty table and carry on — on a component nobody
                // instantiated, silently — so the table is reached by
                // `existing()`, whose presence condition makes that the
                // routed refusal it should be.
                if method == "get" && holds_rule(field) {
                    self.error(
                        call.span(),
                        "a stored role table is read with `existing()` — a `get` reads an \
                         absent table as an empty one, and on a component nobody instantiated \
                         that silence is the defect. The presence condition `existing()` \
                         carries is what turns it into a routed refusal",
                    );
                    return Eval::absent(call.span(), "a table read without its presence");
                }
                if let Some(op) = Op::from_method(method) {
                    let site = self.open(
                        Target::Point {
                            owner: None,
                            slot: SlotRef::Fixed(slot),
                            material: vec![],
                        },
                        field.element.clone(),
                        declared,
                    );
                    let param = match vals.first() {
                        Some(Val::Term(term)) => Some(term.clone()),
                        _ => None,
                    };
                    self.record(site, op, param, call.span());
                    let slot = Self::slot(site, call.span());
                    let receiver = self.value(slot.code);
                    let rewritten: Vec<_> = args
                        .iter()
                        .map(|eval| self.value(eval.code.clone()))
                        .collect();
                    let name = &call.method;
                    return Eval::plain(quote!(#receiver.#name(#(#rewritten),*)));
                }
                Eval::absent(call.span(), "an accessor the vocabulary does not name")
            }

            _ => Eval::absent(call.span(), "an accessor this field shape does not have"),
        }
    }

    /// The guest-side value a point handle resolves to.
    const fn slot(site: usize, span: Span) -> Eval {
        Eval {
            val: Val::Handle(site),
            code: Code::Handle {
                site,
                form: Form::Slot,
                span,
            },
        }
    }

    /// The guest-side value one ordered-collection entry resolves to.
    fn entry(&mut self, site: usize, order: &Term, span: Span) -> Eval {
        let order = self.term_value(span, order);
        Eval {
            val: Val::Handle(site),
            code: Code::Handle {
                site,
                form: Form::Entry(order),
                span,
            },
        }
    }

    /// The guest-side value a declared interval resolves to.
    const fn interval(site: usize, span: Span) -> Eval {
        Eval {
            val: Val::Handle(site),
            code: Code::Handle {
                site,
                form: Form::Interval,
                span,
            },
        }
    }

    /// The value the leaves under a site hold.
    fn element(&self, site: usize) -> TokenStream {
        self.out
            .sites
            .get(site)
            .and_then(|s| s.element.as_ref())
            .map_or_else(|| quote!(_), |ty| quote!(#ty))
    }

    /// A `for` is one of two things, and which one is read off what it
    /// ranges over.
    ///
    /// Over a configured collection it is a `for-each`: one access set
    /// per element, with a binder the clause carries. Over anything else
    /// it is a `while` that happens to bind a name — walking the entries
    /// of an interval the body already declared is the common case, and
    /// the range clause covered them before the loop started. The two
    /// differ in whether a clause is pushed, not in whether the body is
    /// walked: an access inside still has to name a key derivable from
    /// the arguments, and that check is what guards the declaration
    /// either way.
    fn for_loop(&mut self, loop_: &syn::ExprForLoop) -> TokenStream {
        // Read through the borrow: `&list` and `list` name the same
        // sequence, and what the declaration maps over is what it names.
        let list = self.expr(borrowed(&loop_.expr));
        let pat = &loop_.pat;

        let Val::Term(list_term) = list.val.clone() else {
            // The element is not a value the DSL can express, so it binds
            // opaquely and a key derived from it is refused at the line
            // that uses it rather than at the loop.
            let list = self.value(list.code);
            self.locals.push(BTreeMap::new());
            self.bind_pattern(&loop_.pat);
            let statements: Vec<_> = loop_.body.stmts.iter().map(|s| self.stmt(s)).collect();
            self.locals.pop();
            return quote!(for #pat in #list { #(#statements)* });
        };

        // A handle parameter covers one site of one loop, walked by that
        // loop's element — so a loop inside another expands to a width
        // the outer element decides, and there is no parameter its sites
        // could occupy. Hard, because a declaration nothing can execute
        // is not one to publish.
        if self.depth() > 0 {
            self.error(
                loop_.for_token.span,
                "a `for-each` inside another expands to a width the outer element \
                 decides, and a handle parameter covers one site of one loop — so the \
                 clauses this declares are ones no export could reach",
            );
        }

        let depth = self.depth();
        let opened = self.out.sites.len();
        self.scopes.push(Vec::new());
        self.locals.push(BTreeMap::new());
        self.binders.push((opened, list_term.clone()));
        // Deferred, because the loop the guest runs is over the site's
        // indices and binds no element: the name is the declaration's,
        // and a body reading it as a value is refused where it does
        // rather than emitted against a local nothing declares.
        match unwrap_pat(&loop_.pat) {
            syn::Pat::Ident(ident) => {
                self.bind(
                    ident.ident.to_string(),
                    Slot::Deferred(Term::Binding(depth)),
                );
            }
            other => self.bind_pattern(other),
        }
        let statements: Vec<_> = loop_.body.stmts.iter().map(|s| self.stmt(s)).collect();
        self.binders.pop();
        self.locals.pop();
        let body = self.scopes.pop().unwrap_or_default();

        self.push_node(Node::ForEach {
            list: list_term,
            depth,
            body,
        });

        self.element_walk(
            opened,
            depth,
            loop_.for_token.span,
            &quote!(#(#statements)*),
        )
    }

    /// The loop the guest runs over a `for-each`'s expansions.
    ///
    /// The width is the site's, so the guest walks what the declaration
    /// produced rather than a list it does not hold — the element itself
    /// is evaluated where the declaration is, and the body reaches it
    /// only as a key. `opened` is the site count before the body was
    /// walked, which is what tells the loop's own sites from the ones
    /// around it.
    fn element_walk(
        &mut self,
        opened: usize,
        depth: usize,
        span: Span,
        body: &TokenStream,
    ) -> TokenStream {
        let Some(site) = (opened..self.out.sites.len())
            .find(|site| self.out.looped.contains(site))
            .map(handle_ident)
        else {
            self.error(
                span,
                "this loop's body declares no access, so there is no site for the guest \
                 to walk and no element for it to read — reach a declared cell inside \
                 it, or drop the loop, whose only effect on a declaration is the sites \
                 its body opens",
            );
            return quote!(::core::unimplemented!());
        };
        let at = element_index_ident(depth);
        quote!(for #at in 0..#site.len() { #body })
    }

    /// Declare one clause per instance an edge carries, and emit the
    /// loop the guest runs over the site those expansions lend.
    ///
    /// The `for-each` a general instance call is: the ids are a list the
    /// declaration evaluates off the edge, and the element is the id
    /// whose cell each clause names — so the body reaches the instance
    /// as a key, and the guest walks the width the edge turned out to
    /// have rather than one the signature fixed.
    fn over_instances<F>(&mut self, edge: Term, span: Span, body: F) -> TokenStream
    where
        F: FnOnce(&mut Self, Term) -> TokenStream,
    {
        // The loop this opens is a loop like any other, so it is one a
        // `for-each` cannot already be open around: a handle parameter
        // covers one site of one loop.
        if self.depth() > 0 {
            self.error(
                span,
                "this reaches every instance the edge carries, which is a `for-each` of \
                 its own — and a handle parameter covers one site of one loop, so it \
                 cannot sit inside another",
            );
        }

        let depth = self.depth();
        let opened = self.out.sites.len();
        self.scopes.push(Vec::new());
        self.binders
            .push((opened, Term::IdsOf(Box::new(edge.clone()))));
        let statements = body(self, Term::Binding(depth));
        self.binders.pop();
        let inner = self.scopes.pop().unwrap_or_default();
        self.push_node(Node::ForEach {
            list: Term::IdsOf(Box::new(edge)),
            depth,
            body: inner,
        });
        self.element_walk(opened, depth, span, &statements)
    }
}

/// Whether a socket is a non-fungible value edge, which
/// carries named instances where a fungible one carries an amount.
fn is_nf_bucket(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "NfBucket"))
}

/// Whether a socket is a value edge, which is the one kind
/// the guest holds as a type of its own rather than as a plain value.
fn is_bucket(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "Bucket"))
        || is_nf_bucket(ty)
}

/// The last segment of a free call's path, when it has one.
fn free_call_name(call: &syn::ExprCall) -> Option<String> {
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    path.path.segments.last().map(|s| s.ident.to_string())
}

/// What an operation says when the mark it was called on names no
/// declaration — including the spelling, because an author reaching for
/// the free-function form lands here.
fn undeclared_mark(op: &str) -> String {
    format!(
        "`{op}` is called on a declared `#[resource]` struct — `Name::{op}(..)`. The \
         derivation folds the resource's kind, and the declaration is where a kind is stated"
    )
}

/// The mark an issuance is called on: the `Name` of `Name::mint(..)`.
fn free_call_mark(call: &syn::ExprCall) -> Option<syn::Ident> {
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    let [mark, _] = path.path.segments.iter().collect::<Vec<_>>()[..] else {
        return None;
    };
    mark.arguments.is_none().then(|| mark.ident.clone())
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Field, FieldKind, Lowered, Lowerer};
    use crate::{Declared, accessors};

    /// The state a refusal fixture is written against: one byte cell,
    /// and two families of leaves keyed by whatever a body names.
    fn fields() -> BTreeMap<String, Field> {
        let cell = |slot, kind| Field {
            slot,
            kind,
            element: Some(syn::parse_quote!(u64)),
            denomination: None,
        };
        BTreeMap::from([
            ("noted".to_owned(), cell(10, FieldKind::Cell)),
            ("owed".to_owned(), cell(11, FieldKind::Keyed)),
            ("paid".to_owned(), cell(12, FieldKind::Keyed)),
        ])
    }

    /// One pass over `body`, against a package with two configured lists
    /// and a schedule.
    fn lower(body: &str) -> Result<Lowered, Vec<String>> {
        let block: syn::Block = syn::parse_str(body).expect("the fixture parses as a block");
        let fields = fields();
        let config = syn::Ident::new("Terms", proc_macro2::Span::call_site());
        let accessors = accessors(Some(&config));
        let config_fields = [
            ("sides".to_owned(), syn::parse_quote!(::std::vec::Vec<u64>)),
            ("others".to_owned(), syn::parse_quote!(::std::vec::Vec<u64>)),
            ("fallback".to_owned(), syn::parse_quote!(u64)),
        ];
        let declared = Declared {
            fields: &fields,
            accessors: &accessors,
            config_record: Some(&config),
            config_fields: &config_fields,
            resources: &[],
            declines: &BTreeSet::new(),
        };
        Lowerer::new(&declared, &[], false, false)
            .run(&block)
            .map_err(|errors| errors.iter().map(ToString::to_string).collect())
    }

    /// The lowering of `body`.
    ///
    /// # Panics
    ///
    /// If the body draws an error, which is what a fixture written to
    /// reach one asks for by name instead.
    fn lowered(body: &str) -> Lowered {
        lower(body)
            .unwrap_or_else(|errors| panic!("the fixture drew a hard error: {}", errors.join("; ")))
    }

    /// The errors `body` draws.
    ///
    /// # Panics
    ///
    /// If the body draws none, which a fixture meaning to reach one has
    /// not.
    fn errors(body: &str) -> Vec<String> {
        lower(body).expect_err("the fixture draws a hard error")
    }

    #[test]
    fn a_loop_over_a_configured_list_executes() {
        // The control the refusals in `tests/refusals` are read against:
        // a body whose every access under the loop sits on a looped site.
        let lowered =
            lowered("{ for &side in &self.config().sides { self.owed.at(side).set(1); } }");
        assert_eq!(lowered.looped.len(), 1);
        assert_eq!(lowered.sites.len(), 1);
    }

    #[test]
    fn two_loops_over_one_field_stay_apart() {
        // Their elements are both binding zero, so the two bodies spell
        // one target — and the leaves they name are the two lists', which
        // are not the same leaves. One site each.
        let lowered = lowered(
            "{ for &side in &self.config().sides { self.owed.at(side).set(1); } \
               for &other in &self.config().others { self.owed.at(other).set(2); } }",
        );
        assert_eq!(lowered.looped.len(), 2, "one looped site per loop");
        assert_eq!(lowered.sites.len(), 2, "and no site outside one");
    }

    #[test]
    fn one_leaf_reached_twice_in_a_loop_is_one_site() {
        // The dedup a loop keeps: two reaches of one leaf inside one body
        // are one clause, and therefore one element of one site.
        let lowered = lowered(
            "{ for &side in &self.config().sides { \
               self.owed.at(side).set(1); self.owed.at(side).set(2); } }",
        );
        assert_eq!(lowered.looped.len(), 1);
        assert_eq!(lowered.sites.len(), 1);
    }

    #[test]
    fn a_leaf_escaping_one_loop_leaves_its_sibling_guarded() {
        // A cell reached under two conditions is declared always, and
        // that is a fact about the leaf rather than about the way a body
        // spells it: the first loop reaches its element's leaf both under
        // a guard and outside one, so its clause is unconditional — and
        // the second loop, whose element is spelled the same and whose
        // leaf is not the same, keeps the guard it was written under.
        let lowered = lowered(
            "{ for &side in &self.config().sides { \
               if self.config().fallback == 1 { self.owed.at(side).set(1); } \
               self.owed.at(side).set(2); } \
               for &other in &self.config().others { \
               if self.config().fallback == 1 { self.owed.at(other).set(3); } } }",
        );
        assert_eq!(lowered.sites.len(), 2, "one site per loop");
        assert!(
            lowered.sites[0].guard.is_none(),
            "the leaf the first loop reaches twice is declared always",
        );
        assert!(
            lowered.sites[1].guard.is_some(),
            "and the second loop's is declared under its own condition",
        );
    }

    #[test]
    fn a_loop_inside_a_loop_is_refused() {
        // Hard rather than wasm-only: the inner site's width is the outer
        // element's, so there is no parameter it could occupy and no
        // declaration worth publishing.
        let errors = errors(
            "{ for &side in &self.config().sides { \
               for &other in &self.config().others { self.owed.at(other).set(1); } } }",
        );
        assert!(
            errors.iter().any(|why| why.contains("inside another")),
            "unexpected errors: {errors:?}",
        );
    }
}

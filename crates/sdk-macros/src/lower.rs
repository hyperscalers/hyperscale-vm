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

use hyperscale_vm_effects::ResourceKind;
use hyperscale_vm_effects::vocabulary::{CONFIG, INSTANCE, RESOURCE};
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;

use crate::mode::HandleMode;
use crate::term::{Op, Slot, Term};
use crate::{Declared, Resource, holds_role_table, is_named};

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
        slot: u16,
        /// The child-key material.
        material: Vec<Term>,
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
        slot: u16,
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
    /// What decides whether the export takes one capability or the whole
    /// expansion as a run — and, for a run, which loop's index its
    /// entries are named by.
    pub binder: usize,
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
    /// there is nothing for the declaration to say — the same predicate
    /// the emission uses to skip the clause, asked here so a guard's
    /// flag is bound exactly where a clause exists to answer for it.
    pub fn declares(&self) -> bool {
        self.resource().is_some()
    }

    /// The kernel resource this site's handle borrows, which is its
    /// mode, its target shape and what the cell holds together.
    ///
    /// The denomination is read for the same reason routing reads it: a
    /// cell that says what it holds gets the handle value moves through,
    /// and a cell that says nothing gets the one bytes are written to.
    /// The two share no operation, so a body reaching for the wrong one
    /// holds a type that does not have it.
    ///
    /// `None` for a site the body opened and never used: it declares
    /// nothing, so there is no handle for the export to take.
    pub fn resource(&self) -> Option<HandleMode> {
        let has = |op: Op| self.ops.iter().any(|(o, _)| *o == op);
        let holds_value = self.denomination.is_some();
        let interval = matches!(
            self.target,
            Target::Entry { .. }
                | Target::Range { .. }
                | Target::KeyedEntry { .. }
                | Target::Sweep { .. }
        );
        let (moves, writes, reads) = (
            has(Op::Move),
            has(Op::Set) || has(Op::Create) || has(Op::Existing),
            has(Op::Get),
        );
        Some(match (interval, writes || moves, reads) {
            (true, true, _) if holds_value => HandleMode::InstanceRange,
            (true, true, _) => HandleMode::RangeWrite,
            (true, false, true) => HandleMode::RangeRead,
            // A body that only moves value declares a commutative
            // movement; one that also reads the balance, or assigns it,
            // needs the exclusivity a read-modify-write has. The mode is
            // what the body needs rather than which word it typed.
            (false, true, _) if moves && !writes && !reads => HandleMode::DeltaCell,
            (false, true, _) if holds_value => HandleMode::AmountCell,
            (false, true, _) => HandleMode::WriteCell,
            (false, false, true) if holds_value => HandleMode::AmountRead,
            (false, false, true) => HandleMode::ReadCell,
            (_, false, false) => {
                if has(Op::Reserve) {
                    HandleMode::ReserveCell
                } else {
                    return None;
                }
            }
        })
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
    Term(Term),
    /// A bucket parameter, which the guest holds under the name the
    /// author gave it. Deferred like a term: an edge a method only
    /// forwards is one whose amount its own guest never reads, and
    /// nothing in its ABI carries it.
    Bucket(u32),
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
    /// The sites the export takes as runs rather than as single
    /// capabilities: those a `for-each` body declared, whose width is
    /// the instance's rather than the signature's.
    ///
    /// A subset of [`Lowered::handles`], because a run is a capability
    /// parameter like any other — what differs is what it covers.
    pub runs: BTreeSet<usize>,
    /// The values the export takes, in the order the body needs them.
    pub values: Vec<Need>,
    /// How many fresh ids the body draws.
    pub fresh: usize,
    /// The branches whose verdict the export takes, in the order they
    /// were declared, each saying which arm's clause its flag names.
    pub flags: Vec<Polarity>,
    /// The resource the body issues, where it issues one — its kind and
    /// its mark — and so whether the export takes the grant.
    pub issues: Option<(ResourceKind, Vec<u8>)>,
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
    /// Whether the method yields a value at all.
    pub returns: bool,
    /// Why the guest half cannot be emitted, if it cannot, and where the
    /// body wrote what it cannot. The declaration still stands: the
    /// publish gate judges artifacts, so a package the SDK cannot
    /// execute is one whose guest is written the long way.
    pub refusal: Option<(Span, String)>,
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
                Target::Point { slot: at, material } if *at == slot && material.is_empty()
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
fn is_self(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Path(path) if path.path.is_ident("self"))
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

/// The generated name of the element index a run at binder depth
/// `depth` is walked by.
pub fn run_index_ident(depth: usize) -> syn::Ident {
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
    /// How many `for-each` binders enclose the walk.
    binders: usize,
    /// The conditions the walk is under, innermost last, each already
    /// conjoined with the ones enclosing it.
    guards: Vec<Term>,
    /// The cells the survey found touched under more than one condition,
    /// whose clauses are therefore declared always.
    escaping: Vec<Target>,
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
            binders: 0,
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
            Some(Target::Point { slot, material }) if *slot == RESOURCE.0 => {
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
    fn survey(mut self, block: &syn::Block) -> Vec<Target> {
        let _ = self.walk(block);
        let mut escaping = Vec::new();
        for (index, cond) in &self.reached {
            let first = self
                .reached
                .iter()
                .find(|(seen, _)| seen == index)
                .map(|(_, cond)| cond);
            if first != Some(cond)
                && let Some(site) = self.out.sites.get(*index)
                && !escaping.contains(&site.target)
            {
                escaping.push(site.target.clone());
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
    fn hands_back(&mut self, expr: &syn::Expr, eval: Eval, returned: &mut Returned) {
        let produced = match &eval.val {
            Val::Produced(term) => Some(term.clone()),
            // An edge the method was handed and hands on: it carries the
            // resource the manifest routed it as, and forwarding one is
            // the case `check_abi` already admits.
            Val::Term(term) if matches!(eval.code, Code::Bucket(_)) => Some(self.forwarded(term)),
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
                for element in &tuple.elems {
                    let eval = self.expr(element);
                    self.hands_back(element, eval, &mut returned);
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
                self.hands_back(other, eval, &mut returned);
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
        self.binders
    }

    fn error(&mut self, span: Span, message: &str) {
        self.errors.push(syn::Error::new(span, message));
    }

    /// Record why the guest half cannot be emitted, keeping the first
    /// reason: the rest are usually consequences of it.
    fn refuse(&mut self, span: Span, why: &str) {
        if self.out.refusal.is_none() {
            self.out.refusal = Some((span, why.to_owned()));
        }
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
            + usize::from(self.out.issues.is_some())
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
        if let Some(index) = self.out.sites.iter().position(|s| s.target == target) {
            self.reached.push((index, self.guards.last().cloned()));
            return index;
        }
        let index = self.out.sites.len();
        self.reached.push((index, self.guards.last().cloned()));
        // A cell reached from more than one place is reached
        // unconditionally by the weakest of them, and the survey has
        // already found which those are.
        let guard = if self.escaping.contains(&target) {
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
        let Some(entry) = self.out.sites.get_mut(site) else {
            return;
        };
        let exclusive =
            |op: &Op| matches!(op, Op::Get | Op::Set | Op::Move | Op::Create | Op::Existing);
        let compatible = match op {
            // A movement sits beside a read: together they are the
            // exclusive mode, which is what the site resolves to. A
            // presence requirement rides that same mode, so it sits
            // beside any of them — the one pair that does not is a
            // requirement against its own opposite, refused below.
            Op::Get | Op::Set | Op::Move | Op::Create | Op::Existing => {
                entry.ops.iter().all(|(prior, _)| exclusive(prior))
            }
            // A reservation folds with nothing, itself included, so it
            // is the only op a handle may carry and it may carry it once.
            Op::Reserve => entry.ops.is_empty(),
        };
        let opposite = match op {
            Op::Create => Some(Op::Existing),
            Op::Existing => Some(Op::Create),
            _ => None,
        };
        if opposite.is_some_and(|other| entry.ops.iter().any(|(prior, _)| *prior == other)) {
            self.error(
                span,
                "one access requires the leaf to be absent and to be there — no \
                 committed state satisfies both, so the call could never be \
                 feasible. Declare the one the body actually needs",
            );
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
            Val::Term(term) if matches!(eval.code, Code::Bucket(_)) => {
                Some(Term::ResourceOf(Box::new(term.clone())))
            }
            _ => None,
        }
    }

    /// Lower `Name::mint(quantity)` — value with no cell debited behind
    /// it, against the grant this method's declared outputs earn.
    fn lower_mint(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let amount = call.args.first().map_or(
            Code::Absent(call.args.span(), "an issue with no amount"),
            |a| self.expr(a).code,
        );
        let amount = self.value(amount);
        let grant = self.issuer(ResourceKind::Fungible, &issued.mark);
        Eval {
            val: Val::Produced(Term::SelfResource(
                ResourceKind::Fungible,
                issued.mark.clone(),
            )),
            code: Code::Rust(quote!(::hyperscale_vm_sdk::state::mint_granted(#grant, #amount))),
        }
    }

    /// Lower `Name::__record(..)` — the record cell, under the one-way
    /// door its absence is.
    ///
    /// The record is the protocol's own encoding rather than anything a
    /// body assembles, so what the call carries is the single fact the
    /// address does not: a fungible resource's display quantization,
    /// which the mark's own attribute states.
    fn lower_record_create(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let stated: Vec<_> = call
            .args
            .iter()
            .map(|arg| {
                let eval = self.expr(arg);
                self.value(eval.code)
            })
            .collect();
        let record = match issued.kind {
            ResourceKind::Fungible => {
                let Some(display_digits) = stated.first() else {
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
                if !stated.is_empty() {
                    self.error(
                        call.span(),
                        "a non-fungible record has nothing to state — the kind is the \
                         mark's and instances are whole by construction",
                    );
                }
                quote!(::hyperscale_vm_sdk::state::ResourceRecord::NonFungible)
            }
        };
        let site = self.open(
            Target::Point {
                slot: RESOURCE.0,
                material: vec![Term::SelfResource(issued.kind, issued.mark.clone())],
            },
            Some(syn::parse_quote!(
                ::core::option::Option<::hyperscale_vm_sdk::state::ResourceRecord>
            )),
            None,
        );
        self.record(site, Op::Create, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.create(#record)))
    }

    /// Lower the generated `instantiate` body's one statement: the
    /// creation-fixed record sealed into the configuration leaf, under
    /// the one-way door its absence is.
    ///
    /// The bytes are the kernel's evaluation of the record admission
    /// resolved the target with, handed over as a value the body cannot
    /// choose — so what the leaf ends holding is what the address
    /// commits, or the transaction never admitted.
    fn seal_record(&mut self, call: &syn::ExprMethodCall) -> Eval {
        let site = self.open(
            Target::Point {
                slot: CONFIG.0,
                material: vec![],
            },
            Some(syn::parse_quote!(::std::vec::Vec<u8>)),
            None,
        );
        self.record(site, Op::Create, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        let record = self.need(&Need::Derived(Term::SelfRecord));
        Eval::plain(quote!(#leaf.set(#record)))
    }

    /// Lower `Name::at(id)` — the record one instance carries, read at
    /// the cell its mint filed it in.
    ///
    /// Issuer-side by construction rather than by rule: the mark is the
    /// package's own type, so there is no spelling for a foreign
    /// instance's data, and reaching one is a call to whoever issues it.
    fn lower_at(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "read", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is read at its id, and the id is part of the declaration",
            );
            return Eval::absent(call.args.span(), "an instance read with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Get, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.get()))
    }

    /// Whether the mark has an instance record at all, refusing on the
    /// mark's own terms where it has none.
    ///
    /// A fungible mark holds a balance and no instance; a non-fungible
    /// one declaring no fields holds the presence byte, which is nothing
    /// to hand back and nothing to change.
    fn instance_record(&mut self, issued: &Resource, what: &str, span: Span) -> Option<Eval> {
        if issued.kind != ResourceKind::NonFungible {
            self.error(
                span,
                &format!(
                    "`{}` is fungible, and value carries no record of its own — a \
                     balance is what it holds and an instance is what has data",
                    issued.name
                ),
            );
            return Some(Eval::absent(span, "a fungible instance record"));
        }
        if !issued.schema {
            self.error(
                span,
                &format!(
                    "`{}` declares no fields, so its instance holds the presence byte \
                     and there is nothing to {what} — a mark carrying a schema is a \
                     struct with fields",
                    issued.name
                ),
            );
            return Some(Eval::absent(span, "a bare instance record"));
        }
        None
    }

    /// Lower `Name::held(edge)` — the record of the one instance the
    /// edge carries, read without the caller naming an id.
    ///
    /// The edge already knows its instances, so the id comes off it
    /// rather than from an argument beside it. Where the edge carries
    /// the caller's instances that is a question the declaration asks at
    /// evaluation, and an edge carrying any other number than one is
    /// refused there, before the body runs.
    fn lower_held(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "read", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is read off the edge carrying it, and the edge is part \
                 of the declaration",
            );
            return Eval::absent(call.args.span(), "an instance read with no edge");
        };
        let Some((edge, _)) = self.instance_edge(issued, named, "reads", call.span()) else {
            return Eval::absent(named.span(), "an underivable edge");
        };
        let Some(id) = self.sole_id(edge, named) else {
            return Eval::absent(named.span(), "an edge naming no one instance");
        };
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Get, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.get()))
    }

    /// Lower `Name::rewrite(id, record)` — the cell the mint filed,
    /// written again.
    ///
    /// The mint's door read the other way: the leaf is required present
    /// rather than absent, so a rewrite of an id nothing minted, or of
    /// one a burn retired, is refused before the body runs. Issuer-side
    /// by construction, on the terms the read is: the mark is the
    /// package's own type, and the cell sits under the package's own
    /// prefix.
    fn lower_rewrite(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        if let Some(refused) = self.instance_record(issued, "change", call.func.span()) {
            return refused;
        }
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "an instance is rewritten at its id, and the id is part of the declaration",
            );
            return Eval::absent(call.args.span(), "a rewrite with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        let Some(filed) = call.args.iter().nth(1) else {
            self.error(
                call.args.span(),
                &format!(
                    "a rewrite files the whole record: `{}` is what one of its \
                     instances holds, and what replaces it is another",
                    issued.name
                ),
            );
            return Eval::absent(call.args.span(), "a rewrite with no record");
        };
        // The record is the cell's content and not its key, so it is
        // ordinary code the body computes — the declaration is keyed by
        // the id alone, exactly as the mint's is.
        let record = self.expr(filed);
        let record = self.value(record.code);
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Existing, None, call.span());
        let leaf = self.value(Code::Handle {
            site,
            form: Form::Slot,
            span: call.span(),
        });
        Eval::plain(quote!(#leaf.rewrite(#record)))
    }

    /// The edge an instance operation is called on, held to the mark's
    /// own resource.
    ///
    /// Walked for the term it names rather than for a value: an
    /// operation keyed by the edge's instances reads nothing off the
    /// handle, and binding one would hand the guest a parameter nothing
    /// touches. Where the edge is a parameter, which resource it carries
    /// is the caller's to supply and the mark's is stated on the
    /// parameter; where the body produced it, the resource is already
    /// fixed and a mismatch is the body naming a mark it did not.
    fn instance_edge(
        &mut self,
        issued: &Resource,
        named: &syn::Expr,
        verb: &str,
        span: Span,
    ) -> Option<(Term, Code)> {
        let eval = self.expr(borrowed(named));
        let carried = Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone());
        let amount = |lowering: &mut Self| {
            lowering.error(
                named.span(),
                &format!(
                    "this edge carries an amount, and an instance of `{}` is what the \
                     call is about — a non-fungible edge is an `NfBucket`, which names \
                     the instances it moves",
                    issued.name
                ),
            );
        };
        match (&eval.val, &eval.code) {
            (Val::Term(edge), Code::Bucket(param)) => {
                if !self
                    .params
                    .get(*param as usize)
                    .is_some_and(|(_, ty)| is_nf_bucket(ty))
                {
                    amount(self);
                    return None;
                }
                self.denominate(*param, carried, span);
                Some((edge.clone(), eval.code.clone()))
            }
            (Val::Produced(edge @ Term::NfBucket { resource, .. }), _) => {
                if **resource != carried {
                    let (found, wanted) = (self.describe(resource), self.describe(&carried));
                    self.error(
                        named.span(),
                        &format!(
                            "this {verb} an instance of {wanted} off an edge carrying \
                             {found}. An instance's record is filed under the resource it \
                             is an instance of"
                        ),
                    );
                }
                Some((edge.clone(), eval.code.clone()))
            }
            (Val::Produced(_), _) => {
                amount(self);
                None
            }
            _ => {
                self.error(
                    named.span(),
                    &format!(
                        "the lowering cannot see what this edge carries. {} an instance \
                         off an edge the method was handed or one it minted",
                        capitalized(verb),
                    ),
                );
                None
            }
        }
    }

    /// The id of the one instance an edge carries.
    ///
    /// An edge the body produced names its instances outright, so the id
    /// is the one it names and the cell is the same site the mint
    /// opened — which is what lets a mint and a retirement of the same
    /// instance meet on one leaf rather than on two spellings of it. An
    /// edge whose instances are the caller's names them only at
    /// evaluation, so the id is the sole element of its id list and an
    /// edge carrying any other number is refused there.
    fn sole_id(&mut self, edge: Term, named: &syn::Expr) -> Option<Term> {
        let Term::NfBucket { ids, .. } = &edge else {
            return Some(Term::Only(Box::new(Term::IdsOf(Box::new(edge)))));
        };
        let Term::List(named_ids) = ids.as_ref() else {
            return Some(Term::Only(Box::new(Term::IdsOf(Box::new(edge)))));
        };
        match named_ids.as_slice() {
            [one] => Some(one.clone()),
            several => {
                self.error(
                    named.span(),
                    &format!(
                        "this edge carries {} instances, and an instance is what the \
                         call is about — one edge, one instance, and a body holding \
                         several reaches each of them through an edge of its own",
                        several.len(),
                    ),
                );
                None
            }
        }
    }

    /// Lower `Name::burn(edge)` on a non-fungible mark — the instances
    /// the edge carries leave circulation, and the cell each of them
    /// filed ends with them.
    ///
    /// The one instance the edge carries, on the terms the read takes
    /// it: clearing the cells of several would need a run of handles no
    /// export parameter holds. The cell is required present, which is
    /// the mint's own door read the other way round — so a burn of an
    /// instance nothing minted is refused before the body runs, and a
    /// burn of one this body minted is refused where it is written.
    fn lower_burn_nf(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "a non-fungible burn retires the instances an edge carries, and the \
                 edge is what it takes",
            );
            return Eval::absent(call.args.span(), "a burn with no edge");
        };
        let Some((edge, destroyed)) = self.instance_edge(issued, named, "retires", call.span())
        else {
            return Eval::absent(named.span(), "an underivable edge");
        };
        let Some(id) = self.sole_id(edge, named) else {
            return Eval::absent(named.span(), "an edge naming no one instance");
        };
        let site = self.instance_site(issued, id, call.func.span());
        self.record(site, Op::Existing, None, call.span());
        let handle = self.handle(site, call.span());
        let funds = self.value(destroyed);
        let grant = self.issuer(ResourceKind::NonFungible, &issued.mark);
        Eval::plain(quote!({
            ::hyperscale_vm_sdk::state::clear_instance(#handle);
            ::hyperscale_vm_sdk::state::burn_nf_granted(#grant, #funds)
        }))
    }

    /// The data cell of one instance, as every call that reaches it
    /// opens it.
    ///
    /// A site is what its target names, and its element type is settled
    /// where it is first opened — so a mint and a read that opened the
    /// same cell separately would leave whichever came second reading
    /// the other's answer. One opener is what makes the element the
    /// mark's own statement: a fielded mark's cell holds the record it
    /// declares, a bare mark's holds the presence byte and no type.
    fn instance_site(&mut self, issued: &Resource, id: Term, span: Span) -> usize {
        let mark = syn::Ident::new(&issued.name, span);
        let element = issued
            .schema
            .then(|| syn::parse_quote!(::core::option::Option<#mark>));
        self.open(
            Target::Point {
                slot: INSTANCE.0,
                material: vec![
                    Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone()),
                    id,
                ],
            },
            element,
            None,
        )
    }

    /// Lower `Name::mint(id)` — the non-fungible mint, coupled to the
    /// instance-cell write it implies: the named id is one data cell
    /// created where absent, so a minted instance and its filed cell are
    /// one declaration.
    fn lower_mint_nf(&mut self, issued: &Resource, call: &syn::ExprCall) -> Eval {
        let Some(named) = call.args.first() else {
            self.error(
                call.args.span(),
                "a non-fungible mint names the instance it creates rather than an amount \
                 — one id, and the instance's data cell is keyed by it",
            );
            return Eval::absent(call.args.span(), "a mint with no id");
        };
        let eval = self.expr(named);
        let Val::Term(id) = eval.val else {
            self.error(
                named.span(),
                "this id is not derivable from the method's arguments — routing \
                 evaluates the declaration before execution and never reads state",
            );
            return Eval::absent(named.span(), "an underivable instance id");
        };
        // The data is the cell's content and not its key, so it is
        // ordinary code the body computes — nothing about it reaches the
        // declaration, which is keyed by the id alone.
        let data = match (issued.schema, call.args.iter().nth(1)) {
            (true, Some(arg)) => {
                let eval = self.expr(arg);
                Some(self.value(eval.code))
            }
            (true, None) => {
                self.error(
                    call.args.span(),
                    &format!(
                        "`{}` declares fields, so its instance carries them: a mint names \
                         the id and the record filed under it",
                        issued.name
                    ),
                );
                return Eval::absent(call.args.span(), "a fielded mint with no record");
            }
            (false, Some(arg)) => {
                self.error(
                    arg.span(),
                    &format!(
                        "`{}` declares no fields, so its instance holds the presence byte \
                         and nothing else — a mark carrying a schema is a struct with fields",
                        issued.name
                    ),
                );
                return Eval::absent(arg.span(), "a bare mint handed a record");
            }
            (false, None) => None,
        };
        let resource_term = Term::SelfResource(ResourceKind::NonFungible, issued.mark.clone());
        let site = self.instance_site(issued, id.clone(), call.func.span());
        self.record(site, Op::Create, None, call.span());
        // A fielded mark's cell is the mark's own record, so the mint
        // writes it as one — the same leaf, at the same absence
        // requirement, that a read of this instance reaches. A bare mark
        // has the presence byte and no element type to write it through.
        let file = if let Some(data) = data {
            let leaf = self.value(Code::Handle {
                site,
                form: Form::Slot,
                span: call.span(),
            });
            quote!(#leaf.create(#data);)
        } else {
            let handle = self.handle(site, call.span());
            quote!(::hyperscale_vm_sdk::state::file_instance(#handle);)
        };
        let id_value = self.value(eval.code);
        let grant = self.issuer(ResourceKind::NonFungible, &issued.mark);
        let produced = Term::NfBucket {
            resource: Box::new(resource_term),
            ids: Box::new(Term::List(vec![id])),
        };
        Eval {
            val: Val::Produced(produced),
            code: Code::Rust(quote!({
                #file
                ::hyperscale_vm_sdk::state::mint_nf_granted(#grant, #id_value)
            })),
        }
    }

    /// Lower `Name::burn(funds)`.
    ///
    /// What it destroys is the resource the mark derives, so an edge a
    /// caller supplied is held to that resource exactly as a credit to a
    /// cell holding it would be — and one the body produced is compared
    /// outright, because no caller is involved to be constrained.
    fn lower_burn(&mut self, mark: &[u8], call: &syn::ExprCall) -> Eval {
        let Some(destroyed) = call.args.first().map(|a| self.expr(a)) else {
            self.error(call.args.span(), "a burn with nothing to destroy");
            return Eval::absent(call.args.span(), "a burn with no value");
        };
        let held = Term::SelfResource(ResourceKind::Fungible, mark.to_vec());
        match Self::edge_resource(&destroyed) {
            Some(Term::ResourceOf(inner)) if matches!(*inner, Term::Arg(_)) => {
                if let Term::Arg(param) = *inner {
                    self.denominate(param, held, call.span());
                }
            }
            Some(carried) if carried != held => {
                let (carried, held) = (self.describe(&carried), self.describe(&held));
                self.error(
                    call.args.span(),
                    &format!(
                        "this destroys {carried} against a grant over {held}. A grant is \
                         authority over one resource, and burning is that authority in the \
                         other direction"
                    ),
                );
            }
            Some(_) => {}
            None => self.error(
                call.args.span(),
                "the lowering cannot see what this destroys. Burn an edge the method was \
                 handed, one taken from a declared cell, or one it minted",
            ),
        }
        let funds = self.value(destroyed.code);
        let grant = self.issuer(ResourceKind::Fungible, mark);
        Eval::plain(quote!(::hyperscale_vm_sdk::state::burn_granted(#grant, #funds)))
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
            Code::Term(term) => self.term_value(&term),
            Code::Bucket(param) => self.need(&Need::Amount(param)),
            Code::Record(span) => self.config_record(span),
            Code::Absent(span, why) => {
                self.refuse(
                    span,
                    &format!(
                        "this value is not one a guest can reach: {why}. The declaration \
                     stands; the executing body has to be written the long way"
                    ),
                );
                quote!(::core::unimplemented!())
            }
        }
    }

    /// The guest code for a declared term.
    fn term_value(&mut self, term: &Term) -> TokenStream {
        match term {
            Term::LitU64(value) => quote!(#value),
            Term::LitU128(value) => quote!(#value),
            Term::Pack { hi, lo } => {
                // `pack` is ordinary arithmetic, so the guest folds the
                // two halves itself rather than taking the packed key —
                // which is what makes a price and a sequence id two
                // parameters instead of one opaque cell.
                let hi = self.term_value(hi);
                let lo = self.term_value(lo);
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
                    self.refuse(
                        Span::call_site(),
                        "this reads a `for-each` element, which exists only inside the \
                         evaluation of the loop that binds it — a body reaches an element \
                         as a key and never as a value",
                    );
                    return quote!(::core::unimplemented!());
                }
                self.need(&Need::Derived(term.clone()))
            }
            // A judgment has no guest representation, so what crosses is
            // its operands and the guest does the comparison — which is
            // what a body that branches on one was doing before the
            // declaration could read it.
            Term::Not(inner) => {
                let inner = self.term_value(inner);
                quote!(!#inner)
            }
            Term::And(left, right) => self.judgment(left, right, &quote!(&&)),
            Term::Or(left, right) => self.judgment(left, right, &quote!(||)),
            Term::Eq(left, right) => self.judgment(left, right, &quote!(==)),
            Term::Lt(left, right) => self.judgment(left, right, &quote!(<)),
            Term::List(elements) => {
                let elements: Vec<_> = elements.iter().map(|e| self.term_value(e)).collect();
                quote!([#(#elements),*])
            }
            Term::Tuple(fields) => {
                let fields: Vec<_> = fields.iter().map(|f| self.term_value(f)).collect();
                quote!((#(#fields),*))
            }
            Term::Binding(_) | Term::NfBucket { .. } => {
                // A term names no line of its own; the whole invocation
                // is the nearest anchor.
                self.refuse(
                    Span::call_site(),
                    "this term is evaluated where the declaration is: a `for-each` \
                     element exists only inside an evaluation, and an edge is a \
                     routable summary rather than a value",
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
    /// A borrow, because that is what the accessor answers with: the
    /// record is the instance's and a body consults it.
    fn config_record(&mut self, span: Span) -> TokenStream {
        let declared = self.declared;
        let Some(name) = declared.config_record else {
            self.refuse(span, "this package declares no configuration");
            return quote!(::core::unimplemented!());
        };
        let fields: Vec<TokenStream> = declared
            .config_fields
            .iter()
            .enumerate()
            .map(|(index, (field, _))| {
                let slot =
                    u32::try_from(index).expect("a configuration record is shorter than u32");
                let value = self.need(&Need::Derived(Term::Config(slot)));
                let field = syn::Ident::new(field, span);
                quote!(#field: #value)
            })
            .collect();
        quote!(&#name { #(#fields),* })
    }

    /// One binary judgment, rebuilt over its operands' guest values.
    fn judgment(&mut self, left: &Term, right: &Term, op: &TokenStream) -> TokenStream {
        let left = self.term_value(left);
        let right = self.term_value(right);
        quote!((#left #op #right))
    }

    /// The export parameter carrying `need`, binding one if the body has
    /// not needed it before.
    fn need(&mut self, need: &Need) -> TokenStream {
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

    /// The author's own name for the `index`-th declared parameter.
    fn param_ident(&self, index: u32) -> syn::Ident {
        crate::syntax::param_ident(index, self.params)
            .unwrap_or_else(|| value_ident(index as usize))
    }

    /// Bind this method's issuance grant as an export parameter, and
    /// answer the rep the issue call takes.
    fn issuer(&mut self, kind: ResourceKind, mark: &[u8]) -> TokenStream {
        assert!(
            self.out
                .issues
                .as_ref()
                .is_none_or(|(k, m)| *k == kind && m == mark),
            "a method holds one issuance grant, and two of its calls named two resources"
        );
        self.out.issues = Some((kind, mark.to_vec()));
        quote!(__issuer)
    }

    /// Bind the handle for `site` as an export parameter, and answer the
    /// `Handle` the accessors take.
    fn handle(&mut self, site: usize, span: Span) -> TokenStream {
        self.out.handles.insert(site);
        let ident = handle_ident(site);
        let binder = self.out.sites[site].binder;
        if binder == 0 {
            return quote!(#ident);
        }
        // A run's entry is named by the element it was declared for, so
        // it exists inside the loop that declared it and nowhere else.
        if self.depth() < binder {
            self.error(
                span,
                "this handle was declared inside a `for-each`, so it names an entry of \
                 that loop's run — and outside the loop there is no element to name",
            );
        }
        self.out.runs.insert(site);
        let at = run_index_ident(binder - 1);
        quote!(#ident.handle(#at))
    }

    // ---- statements -----------------------------------------------------

    fn block(&mut self, block: &syn::Block) -> TokenStream {
        self.locals.push(BTreeMap::new());
        let statements: Vec<_> = block.stmts.iter().map(|stmt| self.stmt(stmt)).collect();
        self.locals.pop();
        quote!({ #(#statements)* })
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
                let deferred = matches!(eval.code, Code::Term(_))
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
                match unwrap_pat(&local.pat) {
                    syn::Pat::Tuple(tuple) if tuple.elems.len() == parts.len() => {
                        for (element, term) in tuple.elems.iter().cloned().zip(parts) {
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
                     shapes, so no one export parameter can carry what it chooses",
                );
            }
            return Eval {
                val: Val::Term(term.clone()),
                code: Code::Term(term),
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
        // rather than the signature's: a run of verdicts as wide as a
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
        // is none: inside one it is the run's answer, which is already
        // beside the capability the arm declares.
        if flag == Some(Polarity::Taken) && self.binders == 0 {
            self.push_node(Node::BindGuard);
        }
        if let Some((_, else_nodes, _)) = &otherwise {
            for node in else_nodes.clone() {
                self.push_node(node);
            }
            if flag == Some(Polarity::Untaken) && self.binders == 0 {
                self.push_node(Node::BindGuard);
            }
        }

        let cond = match flag {
            // Inside a loop the verdict is the element's, so it is the
            // run that reports it: a site's entry is declared exactly
            // where this arm's guard fired, which is the same question
            // the flag answers at top level.
            Some(polarity) if self.binders > 0 => {
                let verdict = guarded
                    .filter(|site| self.out.runs.contains(site))
                    .map(|site| {
                        let run = handle_ident(site);
                        let at = run_index_ident(self.depth() - 1);
                        quote!(#run.declared(#at))
                    });
                match (verdict, polarity) {
                    (Some(verdict), Polarity::Taken) => verdict,
                    (Some(verdict), Polarity::Untaken) => quote!(!#verdict),
                    // The arm declares a clause the body never operates
                    // through, so there is no run to read the verdict off
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
                code: Code::Term(term),
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
            syn::Expr::Block(block) => {
                let label = &block.label;
                let code = self.block(&block.block);
                Eval::plain(quote!(#label #code))
            }
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
                        code: Code::Term(term),
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
                        code: Code::Term(term),
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
                        code: Code::Term(term),
                    };
                }
                let inner = self.value(inner.code);
                let op = unary.op;
                Eval::plain(quote!(#op #inner))
            }
            syn::Expr::Tuple(tuple) => self.sequence(tuple.elems.iter(), false),
            // A cast can truncate, so the result is not the term it was
            // cast from.
            syn::Expr::Cast(cast) => {
                let inner = self.code(&cast.expr);
                let ty = &cast.ty;
                Eval::plain(quote!(#inner as #ty))
            }
            syn::Expr::Try(try_) => {
                let inner = self.code(&try_.expr);
                Eval::plain(quote!(#inner?))
            }
            syn::Expr::Index(index) => {
                let base = self.code(&index.expr);
                let subscript = self.code(&index.index);
                Eval::plain(quote!(#base[#subscript]))
            }
            syn::Expr::Array(array) => self.sequence(array.elems.iter(), true),
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
                Slot::Deferred(term) => Code::Term(term.clone()),
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
                    Code::Bucket(slot)
                } else {
                    Code::Term(term)
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
                    code: Code::Term(term),
                }
            }
            _ => {
                let code = self.value(base.code);
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
            code: Code::Term(term),
        }
    }

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
                code: Code::Term(term),
            };
        }
        // `Resource::mint(..)` — the one edge with no cell behind it. The
        // declaration names the resource exactly as `issued(Resource)`
        // derives an address from one, so the output projection and the
        // issuance grant come out of the same call, and the kind it
        // states is what picks between a quantity and a list of ids.
        if name == "mint" {
            let Some(issued) = self.issuing_mark(call, "mint") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
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
        // `Resource::burn(funds)` — the inverse, under the same grant.
        // The kind picks the shape the same way the mint's does: an
        // amount leaves a balance, and an instance leaves existence
        // along with the cell that described it.
        if name == "burn" {
            let Some(issued) = self.issuing_mark(call, "burn") else {
                return Eval::absent(call.func.span(), "an undeclared resource");
            };
            return match issued.kind {
                ResourceKind::NonFungible => self.lower_burn_nf(&issued, call),
                ResourceKind::Fungible => self.lower_burn(&issued.mark, call),
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
                code: Code::Term(term),
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
                code: Code::Term(term),
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
                "a contract method cannot call another method of the component — each \
                 method declares only its own body's accesses. Inline the access, or \
                 lift the shared value to a parameter",
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
                    let code = self.pass_through(&receiver, &method, evals, call);
                    return Eval::plain(code);
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
                if call.method == "declared" || call.method == "exclusive" {
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
                if op == Op::Move
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
                if op == Op::Move
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
                code: Code::Term(resource),
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
            Val::Term(term) if method == "take" && matches!(receiver.code, Code::Bucket(_)) => {
                let code = self.pass_through(&receiver, &method, evals, call);
                Eval {
                    val: Val::Produced(Term::ResourceOf(Box::new(term))),
                    code: Code::Rust(code),
                }
            }
            Val::Term(term) => match method.as_str() {
                "resource" => Eval {
                    val: Val::Term(Term::ResourceOf(Box::new(term.clone()))),
                    code: Code::Term(Term::ResourceOf(Box::new(term))),
                },
                // The count of what the receiver names: an edge's
                // instances, or a list argument's elements — which is
                // what derives a move's cap from the move itself.
                "count" => {
                    let inner = if matches!(receiver.code, Code::Bucket(_)) {
                        Term::IdsOf(Box::new(term))
                    } else {
                        term
                    };
                    let counted = Term::Len(Box::new(inner));
                    Eval {
                        val: Val::Term(counted.clone()),
                        code: Code::Term(counted),
                    }
                }
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
                        code: Code::Term(term),
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
                            slot,
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
                            slot,
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
                            slot,
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
                        slot,
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
                if matches!(method, "get" | "peek") && holds_role_table(field) {
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
                            slot,
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
        let order = self.term_value(order);
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

        let depth = self.depth();
        let opened = self.out.sites.len();
        self.scopes.push(Vec::new());
        self.locals.push(BTreeMap::new());
        self.binders += 1;
        match unwrap_pat(&loop_.pat) {
            syn::Pat::Ident(ident) => {
                self.bind(ident.ident.to_string(), Slot::Value(Term::Binding(depth)));
            }
            other => self.bind_pattern(other),
        }
        let statements: Vec<_> = loop_.body.stmts.iter().map(|s| self.stmt(s)).collect();
        self.binders -= 1;
        self.locals.pop();
        let body = self.scopes.pop().unwrap_or_default();

        self.push_node(Node::ForEach {
            list: list_term,
            depth,
            body,
        });

        // The loop's own width is the run's, so the guest walks the
        // expansion the declaration produced rather than a list it does
        // not hold — the element itself is evaluated where the
        // declaration is, and the body reaches it only as a key.
        let Some(run) = (opened..self.out.sites.len())
            .find(|site| self.out.runs.contains(site))
            .map(handle_ident)
        else {
            self.refuse(
                loop_.for_token.span,
                "this `for-each` body declares no access, so there is no run for the \
                 guest to walk and no element for it to read",
            );
            return quote!(::core::unimplemented!());
        };
        let at = run_index_ident(depth);
        quote!(for #at in 0..#run.len() { #(#statements)* })
    }
}

/// Whether a declared parameter is a non-fungible value edge, which
/// carries named instances where a fungible one carries an amount.
fn is_nf_bucket(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "NfBucket"))
}

/// Whether a declared parameter is a value edge, which is the one kind
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

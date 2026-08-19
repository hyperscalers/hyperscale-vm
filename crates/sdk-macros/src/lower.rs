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

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::spanned::Spanned;

use crate::is_named;
use crate::term::{Op, Slot, Term};

/// What kind of state a component field holds, and under which slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// A permanently locked configuration leaf; its fields are the
    /// instance's config slots.
    Locked,
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
        /// The entry cap.
        cap: u32,
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
        /// The entry cap.
        cap: u32,
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
    pub fn resource(&self) -> Option<&'static str> {
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
            (true, true, _) if holds_value => "instance-range",
            (true, true, _) => "range-write",
            (true, false, true) => "range-read",
            // A body that only moves value declares a commutative
            // movement; one that also reads the balance, or assigns it,
            // needs the exclusivity a read-modify-write has. The mode is
            // what the body needs rather than which word it typed.
            (false, true, _) if moves && !writes && !reads => "delta-cell",
            (false, true, _) if holds_value => "amount-cell",
            (false, true, _) => "write-cell",
            (false, false, true) => "read-cell",
            (_, false, false) => {
                if has(Op::Reserve) {
                    "reserve-cell"
                } else if has(Op::Locked) {
                    "locked-cell"
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
    /// One access set per branch of a condition the declaration can
    /// read: the clauses inside carry it, and an execution that does not
    /// meet it declares none of them.
    Guarded {
        /// The condition, as the declaration evaluates it.
        cond: Term,
        /// The clauses inside.
        body: Vec<Self>,
        /// Whether the export takes this arm's verdict, which is true
        /// for exactly one arm of a branch that declares anything.
        binds: bool,
    },
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

/// Whether any clause under these nodes declares an access.
fn declares(nodes: &[Node], sites: &[Site]) -> bool {
    nodes.iter().any(|node| match node {
        Node::Site(index) => sites.get(*index).is_some_and(Site::declares),
        Node::Guarded { body, .. } | Node::ForEach { body, .. } => declares(body, sites),
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
    /// Nothing the guest can produce: a resource address, a table lookup,
    /// a handle in value position.
    Absent(&'static str),
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
    /// The values the export takes, in the order the body needs them.
    pub values: Vec<Need>,
    /// How many fresh ids the body draws.
    pub fresh: usize,
    /// The branches whose verdict the export takes, in the order they
    /// were declared, each saying which arm's clause its flag names.
    pub flags: Vec<Polarity>,
    /// The mark of the resource the body issues, where it issues one, and
    /// so whether the export takes the grant.
    pub issues: Option<Vec<u8>>,
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
    /// Whether the method yields a value at all.
    pub returns: bool,
    /// Why the guest half cannot be emitted, if it cannot. The
    /// declaration still stands: the publish gate judges artifacts, so a
    /// package the SDK cannot execute is one whose guest is written the
    /// long way.
    pub refusal: Option<String>,
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
    /// The value a locked configuration read returns; its fields are
    /// config slots.
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
    const fn absent(why: &'static str) -> Self {
        Self {
            val: Val::Opaque,
            code: Code::Absent(why),
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
        other => other,
    }
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

/// The `Handle` variant a borrowed resource arrives as.
pub fn handle_variant(resource: &str) -> TokenStream {
    match resource {
        "read-cell" => quote!(Read),
        "locked-cell" => quote!(Locked),
        "write-cell" => quote!(Write),
        "amount-cell" => quote!(Amount),
        "delta-cell" => quote!(Delta),
        "reserve-cell" => quote!(Reserve),
        "range-read" => quote!(RangeRead),
        "instance-range" => quote!(InstanceRange),
        _ => quote!(RangeWrite),
    }
}

/// The lowering pass over one method body.
pub struct Lowerer<'a> {
    fields: &'a BTreeMap<String, Field>,
    /// Whether the method claims totality, which is what turns a branch
    /// back into the superset it used to declare: a total leg runs with
    /// every declared handle materialized, and a guarded-out clause
    /// materializes none.
    total: bool,
    /// The protocol's own cells, which exist under every owner and are
    /// reached by accessor rather than declared as fields.
    accessors: &'a BTreeMap<String, Field>,
    config_fields: &'a [(String, syn::Type)],
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
    errors: Vec<syn::Error>,
}

impl<'a> Lowerer<'a> {
    /// Start a pass over a method with these positional parameters.
    pub fn new(
        fields: &'a BTreeMap<String, Field>,
        accessors: &'a BTreeMap<String, Field>,
        config_fields: &'a [(String, syn::Type)],
        params: &'a [(String, syn::Type)],
        returns: bool,
        total: bool,
    ) -> Self {
        Self {
            fields,
            total,
            accessors,
            config_fields,
            params,
            returns,
            locals: vec![BTreeMap::new()],
            out: Lowered::default(),
            scopes: vec![Vec::new()],
            binders: 0,
            guards: Vec::new(),
            errors: Vec::new(),
        }
    }

    /// The state a name refers to: the package's own field, or the
    /// protocol cell an accessor named.
    ///
    /// One lookup because a body cannot tell the two apart once it holds
    /// a handle — what differs is only how the name was reached.
    fn state(&self, name: &str) -> Option<Field> {
        self.fields
            .get(name)
            .or_else(|| self.accessors.get(name))
            .cloned()
    }

    /// Lower a body, or report every reason it could not be.
    ///
    /// The tail expression is evaluated in return position, where a
    /// produced bucket — or a tuple of them — becomes the method's declared
    /// outputs.
    pub fn run(mut self, block: &syn::Block) -> Result<Lowered, Vec<syn::Error>> {
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
        let returned = if let Some(tail) = tail {
            let (outputs, codes) = self.returned(tail);
            self.out.outputs = outputs;
            codes
        } else {
            Vec::new()
        };
        self.locals.pop();

        if self.errors.is_empty() {
            self.out.nodes = self.scopes.pop().unwrap_or_default();
            self.out.body = quote!(#(#statements)*);
            self.out.returns = !returned.is_empty();
            self.out.edges = returned;
            Ok(self.out)
        } else {
            Err(self.errors)
        }
    }

    /// Evaluate an expression in return position, collecting the resources
    /// of every value edge it yields beside the guest code for its amount.
    fn returned(&mut self, expr: &syn::Expr) -> (Vec<Term>, Vec<TokenStream>) {
        match expr {
            syn::Expr::Tuple(tuple) => {
                let mut outputs = Vec::new();
                let mut codes = Vec::new();
                for element in &tuple.elems {
                    let eval = self.expr(element);
                    if let Val::Produced(term) = &eval.val {
                        outputs.push(term.clone());
                        let code = self.value(eval.code);
                        codes.push(code);
                    }
                }
                (outputs, codes)
            }
            syn::Expr::Paren(paren) => self.returned(&paren.expr),
            // An error arm's success side is where the edges are: the arm
            // itself is the declared refusal, and a refusal produces
            // nothing.
            syn::Expr::Call(call) if free_call_name(call).as_deref() == Some("Ok") => call
                .args
                .first()
                .map_or_else(|| (vec![], vec![]), |inner| self.returned(inner)),
            // The refusal itself, which produces nothing. Reached from an
            // early `return Err(..)` as well as from a tail, and neither
            // carries an edge.
            syn::Expr::Call(call) if free_call_name(call).as_deref() == Some("Err") => {
                (vec![], vec![])
            }
            other => {
                let eval = self.expr(other);
                #[allow(clippy::single_match_else)] // the arms are two different returns
                match &eval.val {
                    Val::Produced(term) => {
                        let term = term.clone();
                        let code = self.value(eval.code);
                        (vec![term], vec![code])
                    }
                    // An edge the method was handed and hands on: it
                    // carries the resource the manifest routed it as, and
                    // forwarding one is the case `check_abi` already
                    // admits.
                    Val::Term(term) if matches!(eval.code, Code::Bucket(_)) => {
                        let term = Term::ResourceOf(Box::new(term.clone()));
                        let code = self.value(eval.code);
                        (vec![term], vec![code])
                    }
                    _ => {
                        // A method's results are its edges: what an export
                        // hands back is value the kernel takes ownership
                        // of, and an ordinary value has no shape there.
                        // The declaration still stands — it produces no
                        // edge, which is the truth — so this refuses the
                        // guest half and not the package.
                        let code = self.value(eval.code);
                        self.refuse("a method returning a value that is not a value edge");
                        (vec![], vec![code])
                    }
                }
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
    fn refuse(&mut self, why: &str) {
        if self.out.refusal.is_none() {
            self.out.refusal = Some(why.to_owned());
        }
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
    fn open(
        &mut self,
        target: Target,
        element: Option<syn::Type>,
        declared: Option<Term>,
    ) -> usize {
        if let Some(index) = self.out.sites.iter().position(|s| s.target == target) {
            return index;
        }
        let index = self.out.sites.len();
        // A field that states its resource answers for every leaf under
        // it; one that does not is keyed by the resource, and the key is
        // the material a body named it at.
        //
        // Only where the leaf holds value at all. A point cell says so by
        // its element type, and a cell holding anything else is keyed by
        // whatever its author found useful — a validator id, a name —
        // which is a key and not a resource however it is spelled. An
        // instance collection is narrowed by the resource whose holdings
        // it is, which is the same statement in collection form.
        let holds_value = matches!(&element, Some(ty) if is_named(ty, "Vault"));
        let denomination = declared.or_else(|| match &target {
            Target::Point { material, .. } if holds_value => material.first().cloned(),
            Target::Range { material, .. } | Target::Entry { material, .. } => {
                material.first().cloned()
            }
            // A hashed key and a cursor name an entry, never a resource.
            Target::Point { .. } | Target::KeyedEntry { .. } | Target::Sweep { .. } => None,
        });
        self.out.sites.push(Site {
            target,
            ops: Vec::new(),
            element,
            denomination,
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
            Op::Reserve | Op::Locked => entry
                .ops
                .iter()
                .all(|(prior, _)| *prior == op && op == Op::Locked),
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
                 `issued(b\"..\")` for one the instance derives from its own address",
            );
            None
        };
        match expr {
            // `config.x` — the locked record's slot, by name.
            syn::Expr::Field(access) => {
                let syn::Expr::Path(base) = &*access.base else {
                    return refuse(self);
                };
                let locked = base.path.get_ident().is_some_and(|ident| {
                    self.state(&ident.to_string())
                        .is_some_and(|f| f.kind == FieldKind::Locked)
                });
                let syn::Member::Named(name) = &access.member else {
                    return refuse(self);
                };
                if !locked {
                    return refuse(self);
                }
                let name = name.to_string();
                let Some(index) = self.config_fields.iter().position(|(f, _)| *f == name) else {
                    self.error(
                        expr.span(),
                        "not a field of the component's configuration struct",
                    );
                    return None;
                };
                Some(Term::Config(u32::try_from(index).unwrap_or(0)))
            }
            // `issued(b"..")` — the instance's own resource, by the mark
            // separating it from the instance's others.
            syn::Expr::Call(call) => {
                if free_call_name(call).as_deref() != Some("issued") {
                    return refuse(self);
                }
                call.args
                    .first()
                    .and_then(byte_literal)
                    .map_or_else(|| refuse(self), |mark| Some(Term::SelfResource(mark)))
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
            Term::Config(slot) => self.config_fields.get(*slot as usize).map_or_else(
                || format!("configuration slot {slot}"),
                |(name, _)| format!("`config.{name}`"),
            ),
            Term::SelfResource(mark) => core::str::from_utf8(mark).map_or_else(
                |_| "a resource this instance issues".into(),
                |mark| format!("`issued(b\"{mark}\")`"),
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

    /// Lower `burn(mark, funds)`.
    ///
    /// What it destroys is the resource the mark derives, so an edge a
    /// caller supplied is held to that resource exactly as a credit to a
    /// cell holding it would be — and one the body produced is compared
    /// outright, because no caller is involved to be constrained.
    fn lower_burn(&mut self, mark: &[u8], call: &syn::ExprCall) -> Eval {
        let Some(destroyed) = call.args.iter().nth(1).map(|a| self.expr(a)) else {
            self.error(call.args.span(), "a burn with nothing to destroy");
            return Eval::absent("a burn with no value");
        };
        let held = Term::SelfResource(mark.to_vec());
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
        let grant = self.issuer(mark);
        Eval::plain(quote!(::hyperscale_vm_sdk::state::burn_granted(#grant, #funds)))
    }

    /// Fix what the edge at `param` carries.
    ///
    /// One parameter credited to two cells with different keys is a
    /// method no call satisfies — the edge would have to carry both
    /// resources at once — so the second one is refused where the body
    /// wrote it rather than left for a caller to discover.
    fn denominate(&mut self, param: u32, resource: Term, span: Span) {
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
            Code::Absent(why) => {
                self.refuse(&format!(
                    "this value is not one a guest can reach: {why}. The declaration \
                     stands; the executing body has to be written the long way"
                ));
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
            Term::Arg(_)
            | Term::Config(_)
            | Term::FreshId(_)
            | Term::ResourceOf(_)
            | Term::OrderKey { .. }
            | Term::SelfResource(_)
            | Term::If { .. } => self.need(&Need::Derived(term.clone())),
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
            Term::Lookup { .. }
            | Term::Contains { .. }
            | Term::Field(..)
            | Term::Binding(_)
            | Term::NfBucket { .. } => {
                self.refuse(
                    "this term is evaluated where the declaration is, and the guest \
                     has no way to ask for it",
                );
                quote!(::core::unimplemented!())
            }
        }
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
        self.params.get(index as usize).map_or_else(
            || value_ident(index as usize),
            |(name, _)| syn::Ident::new(name, Span::call_site()),
        )
    }

    /// Bind this method's issuance grant as an export parameter, and
    /// answer the rep the issue call takes.
    fn issuer(&mut self, mark: &[u8]) -> TokenStream {
        self.out.issues = Some(mark.to_vec());
        quote!(__issuer)
    }

    /// Bind the handle for `site` as an export parameter, and answer the
    /// `Handle` the accessors take.
    fn handle(&mut self, site: usize, span: Span) -> TokenStream {
        if self.depth() != 0 {
            self.error(
                span,
                "a clause under a `for-each` has a configuration-dependent handle \
                 count, so it cannot occupy a fixed export parameter",
            );
        }
        self.out.handles.insert(site);
        let ident = handle_ident(site);
        quote!(#ident)
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
                    || Eval::absent("an uninitialised binding"),
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
                    // A locked config read binds a name whose *fields* are
                    // config slots; the binding itself is not a value.
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
                        let names: Vec<_> = tuple.elems.iter().cloned().collect();
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
                if matches!(eval.code, Code::Absent(_)) {
                    // The declaration read something the guest has no
                    // value for. Whatever the body does with the name is
                    // either evaluated elsewhere — a configuration field
                    // is a slot the kernel hands over — or refused at the
                    // line that reads it.
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
    /// The assert and panic family take ordinary expressions, so an access
    /// inside one declares like an access outside it. Any other macro is
    /// opaque tokens — walking past it would silently drop whatever it
    /// contains, so it is refused instead.
    fn macro_call(&mut self, mac: &syn::Macro) -> TokenStream {
        let known = ["assert", "assert_eq", "assert_ne", "panic"]
            .iter()
            .any(|name| mac.path.is_ident(name));
        if !known {
            self.error(
                mac.span(),
                "`#[blueprint]` cannot see into this macro, so an access inside it would \
                 be silently dropped from the declaration — only the assert and panic \
                 family are admitted",
            );
            return quote!();
        }
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

        let (then_nodes, then_code) =
            self.arm(judgment.clone(), |me| me.block(&branch.then_branch));
        let negated = Term::Not(Box::new(judgment.clone()));
        let otherwise = branch.else_branch.as_ref().map(|(_, otherwise)| {
            self.arm(negated.clone(), |me| {
                let code = me.code(otherwise);
                quote!(#code)
            })
        });

        // The guest branches on the declaration's own verdict, so the
        // flag names a clause the arm declared. Where an arm declares
        // none there is nothing to be absent, and the condition stands
        // as the author wrote it.
        let taken = declares(&then_nodes, &self.out.sites);
        let untaken = otherwise
            .as_ref()
            .is_some_and(|(nodes, _)| declares(nodes, &self.out.sites));
        let flag = match (taken, untaken) {
            (true, _) => Some(Polarity::Taken),
            (false, true) => Some(Polarity::Untaken),
            (false, false) => None,
        };
        if taken {
            self.push_node(Node::Guarded {
                cond: judgment,
                body: then_nodes,
                binds: flag == Some(Polarity::Taken),
            });
        }
        if let Some((else_nodes, _)) = &otherwise
            && untaken
        {
            self.push_node(Node::Guarded {
                cond: negated,
                body: else_nodes.clone(),
                binds: flag == Some(Polarity::Untaken),
            });
        }

        let cond = match flag {
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
        let otherwise = otherwise.map(|(_, code)| quote!(else #code));
        Some(Eval::plain(quote!(if #cond #then_code #otherwise)))
    }

    /// One arm, walked into a scope of its own: its clauses and its code.
    fn arm<F>(&mut self, cond: Term, walk: F) -> (Vec<Node>, TokenStream)
    where
        F: FnOnce(&mut Self) -> TokenStream,
    {
        let conjoined = match self.guards.last() {
            Some(outer) => Term::And(Box::new(outer.clone()), Box::new(cond)),
            None => cond,
        };
        self.guards.push(conjoined);
        self.locals.push(BTreeMap::new());
        self.scopes.push(Vec::new());
        let code = walk(self);
        let nodes = self.scopes.pop().unwrap_or_default();
        self.locals.pop();
        self.guards.pop();
        (nodes, code)
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
                    let (produced, _) = self.returned(value);
                    if !produced.is_empty() {
                        self.error(
                            ret.span(),
                            "a produced value edge must leave through the method's tail \
                             expression — the declared outputs are exact, so an early \
                             return's edges cannot be reconciled with the tail's",
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

            // A closure could capture the component and carry accesses the
            // walk cannot attribute to any declaration site.
            syn::Expr::Closure(closure) => {
                self.error(
                    closure.span(),
                    "`#[blueprint]` does not model closures — an access inside one \
                     cannot be attributed to a declaration",
                );
                Eval::absent("a closure")
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
                Eval::absent("an unmodelled expression")
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
                Slot::Config => Code::Absent("the pinned configuration record"),
                Slot::Deferred(term) => Code::Term(term.clone()),
                _ => Code::Rust(quote!(#ident)),
            };
            return Eval {
                val: slot.into(),
                code,
            };
        }
        if let Some(index) = self.params.iter().position(|(p, _)| *p == name) {
            let slot = u32::try_from(index).unwrap_or(0);
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
        let val = if let syn::Lit::Int(int) = &lit.lit
            && let Ok(value) = int.base10_parse::<u64>()
        {
            Val::Term(Term::LitU64(value))
        } else {
            Val::Opaque
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
                code: Code::Absent("a state field in value position"),
            };
        }
        let base = self.expr(&field.base);
        let member = &field.member;
        match (&base.val, member) {
            // `self.config.x` — a configuration field read directly.
            //
            // This declares nothing, and that is the point: configuration
            // is a locked substate, verified once and cached process-wide,
            // so a declaration may consult it without claiming it. Naming
            // the leaf as a locked read is a separate, deliberate act
            // (`self.config.locked()`) that a method only performs when it
            // wants the whole record pinned.
            (
                Val::Field {
                    name: field_name, ..
                },
                syn::Member::Named(name),
            ) if self
                .state(field_name)
                .is_some_and(|f| f.kind == FieldKind::Locked) =>
            {
                self.config_slot(&name.to_string(), field)
            }

            // A field of a value a locked read returned.
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
        let Some(index) = self.config_fields.iter().position(|(f, _)| f == name) else {
            self.error(
                field.span(),
                "not a field of the component's configuration struct",
            );
            return Eval::absent("an unknown configuration field");
        };
        let term = Term::Config(u32::try_from(index).unwrap_or(0));
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
        // `mint(mark, amount)` — the one edge with no cell behind it.
        // The mark names the resource exactly as `issued` derives an
        // address from one, so the output projection and the issuance
        // grant come out of the same call.
        if name == "mint" {
            let Some(mark) = call.args.first().and_then(byte_literal) else {
                self.error(
                    call.args.span(),
                    "the mark separating an instance's resources is part of every key \
                     derived from one, so it must be a byte-string literal",
                );
                return Eval::absent("a computed resource mark");
            };
            let amount = call
                .args
                .iter()
                .nth(1)
                .map_or(Code::Absent("an issue with no amount"), |a| {
                    self.expr(a).code
                });
            let amount = self.value(amount);
            let grant = self.issuer(&mark);
            return Eval {
                val: Val::Produced(Term::SelfResource(mark)),
                code: Code::Rust(quote!(::hyperscale_vm_sdk::state::mint_granted(#grant, #amount))),
            };
        }
        // `burn(mark, funds)` — the inverse, under the same grant.
        if name == "burn" {
            let Some(mark) = call.args.first().and_then(byte_literal) else {
                self.error(
                    call.args.span(),
                    "the mark separating an instance's resources is part of every key \
                     derived from one, so it must be a byte-string literal",
                );
                return Eval::absent("a computed resource mark");
            };
            return self.lower_burn(&mark, call);
        }
        if name == "issued" {
            let mark = call.args.first().and_then(byte_literal);
            let Some(mark) = mark else {
                self.error(
                    call.args.span(),
                    "the mark separating an instance's resources is part of every key \
                     derived from one, so it must be a byte-string literal",
                );
                return Eval::absent("a computed resource mark");
            };
            let term = Term::SelfResource(mark);
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
            if self.accessors.contains_key(&name) {
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
            return Eval::absent("a call to another method of the component");
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
                    return Eval::absent("an undeclared state field");
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
                        return Eval::absent("an underivable collection key");
                    };
                    let mut material = material;
                    material.push(key.clone());
                    return Eval {
                        val: Val::Field { name, material },
                        code: Code::Absent("a collection in value position"),
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
                            return Eval::absent("an underivable instance set");
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
                "lookup" | "get" | "contains" if matches!(args.first(), Some(Val::Term(_))) => {
                    let Some(Val::Term(key)) = args.first() else {
                        return Eval::absent("a lookup with no key");
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
        let Some(field) = self.accessors.get(name).cloned() else {
            return Eval::absent("an unknown protocol cell");
        };
        let evals: Vec<Eval> = call.args.iter().map(|arg| self.expr(arg)).collect();
        let arity = usize::from(!matches!(field.kind, FieldKind::Cell | FieldKind::Locked));
        if evals.len() != arity {
            self.error(call.span(), &format!("`{name}` takes {arity} argument(s)"));
            return Eval::absent("a protocol cell named with the wrong arity");
        }
        match field.kind {
            // A leaf of the family, at the key the accessor was handed.
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
                    return Eval::absent("an underivable collection key");
                };
                Eval {
                    val: Val::Field {
                        name: name.to_owned(),
                        material: vec![key],
                    },
                    code: Code::Absent("a collection in value position"),
                }
            }
            // The cell itself, which the body then reads or writes.
            FieldKind::Cell | FieldKind::Locked => Eval {
                val: Val::Field {
                    name: name.to_owned(),
                    material: Vec::new(),
                },
                code: Code::Absent("a protocol cell in value position"),
            },
            FieldKind::Unordered => Eval::absent("an unordered protocol cell"),
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
            // The locked configuration: a read that excludes nothing,
            // and the value whose fields are the config slots.
            (FieldKind::Locked, "locked") => {
                let site = self.open(
                    Target::Point {
                        slot,
                        material: vec![],
                    },
                    field.element.clone(),
                    declared,
                );
                self.record(site, Op::Locked, None, call.span());
                Eval {
                    val: Val::Config,
                    // The pin is a declaration; the values it covers reach
                    // the guest as evaluated slots, so the record itself
                    // is never decoded.
                    code: Code::Absent("the pinned configuration record"),
                }
            }

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
                    Eval::absent("an underivable key")
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
                    Eval::absent("an underivable order key")
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
                    Eval::absent("an underivable key")
                }
            }

            // An unordered collection's tail from a cursor.
            (FieldKind::Unordered, "sweep") => {
                if let (Some(Val::Term(cursor)), Some(Val::Term(Term::LitU64(cap)))) =
                    (vals.first(), vals.get(1))
                {
                    let site = self.open(
                        Target::Sweep {
                            slot,
                            cursor: cursor.clone(),
                            cap: u32::try_from(*cap).unwrap_or(u32::MAX),
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "a sweep's cursor must be derivable from the arguments, and its entry \
                     cap must be a literal — the cap bounds the work execution may do, so \
                     it is declaration, not data",
                    );
                    Eval::absent("an underivable sweep")
                }
            }

            // A declared interval of an ordered collection.
            (FieldKind::Ordered, "range") => {
                if let (
                    Some(Val::Term(lo)),
                    Some(Val::Term(hi)),
                    Some(Val::Term(Term::LitU64(cap))),
                ) = (vals.first(), vals.get(1), vals.get(2))
                {
                    let site = self.open(
                        Target::Range {
                            slot,
                            material: material.to_vec(),
                            lo: lo.clone(),
                            hi: hi.clone(),
                            cap: u32::try_from(*cap).unwrap_or(u32::MAX),
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "a range's bounds must be derivable from the arguments, and its entry \
                     cap must be a literal — the cap bounds the work execution may do, so \
                     it is declaration, not data",
                    );
                    Eval::absent("an underivable range")
                }
            }

            // The whole of a collection's order-key space.
            (FieldKind::Ordered, "all") => {
                if let Some(Val::Term(Term::LitU64(cap))) = vals.first() {
                    let site = self.open(
                        Target::Range {
                            slot,
                            material: material.to_vec(),
                            lo: Term::LitU128(0),
                            hi: Term::LitU128(u128::MAX),
                            cap: u32::try_from(*cap).unwrap_or(u32::MAX),
                        },
                        field.element.clone(),
                        declared,
                    );
                    Self::interval(site, call.span())
                } else {
                    self.error(
                        call.args.span(),
                        "an interval's entry cap must be a literal — the cap bounds the \
                     work execution may do, so it is declaration, not data",
                    );
                    Eval::absent("an underivable interval")
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
                Eval::absent("an accessor the vocabulary does not name")
            }

            _ => Eval::absent("an accessor this field shape does not have"),
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
        let list = self.expr(&loop_.expr);
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

        // A run of handles whose length depends on configuration cannot
        // occupy a fixed export parameter, so a body that declares a
        // `for-each` declares and does not execute.
        self.refuse(
            "a `for-each` clause expands over instance configuration, so its handles \
             occupy no fixed export parameter",
        );
        let list = self.value(list.code);

        let depth = self.depth();
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
        quote!(for #pat in #list { #(#statements)* })
    }
}

/// The bytes of a byte-string literal, when an expression is one.
fn byte_literal(expr: &syn::Expr) -> Option<Vec<u8>> {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::ByteStr(bytes) => Some(bytes.value()),
            _ => None,
        },
        syn::Expr::Reference(reference) => byte_literal(&reference.expr),
        _ => None,
    }
}

/// Whether a declared parameter is a value edge, which is the one kind
/// the guest holds as a type of its own rather than as a plain value.
fn is_bucket(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "Bucket" || s.ident == "NfBucket"))
}

/// The last segment of a free call's path, when it has one.
fn free_call_name(call: &syn::ExprCall) -> Option<String> {
    let syn::Expr::Path(path) = &*call.func else {
        return None;
    };
    path.path.segments.last().map(|s| s.ident.to_string())
}

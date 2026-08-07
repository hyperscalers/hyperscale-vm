//! Lowering a method body to its access declaration.
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

use std::collections::BTreeMap;

use proc_macro2::Span;
use syn::spanned::Spanned;

use crate::term::{Op, Slot, Term};

/// What kind of state a component field holds, and under which role.
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
}

/// One declared field of the component's state.
#[derive(Clone, Debug)]
pub struct Field {
    /// The role the field's children sit under.
    pub role: u16,
    /// What shape of state it is.
    pub kind: FieldKind,
}

/// One target a body opened a handle on.
#[derive(Clone, Debug)]
pub enum Target {
    /// A single substate leaf under a role.
    Point {
        /// The role.
        role: u16,
        /// The child-key material.
        material: Vec<Term>,
    },
    /// One ordered-collection entry.
    Entry {
        /// The collection's role.
        role: u16,
        /// The entry's order key.
        order: Term,
    },
    /// An interval of a collection's order-key space.
    Range {
        /// The collection's role.
        role: u16,
        /// Inclusive lower bound.
        lo: Term,
        /// Inclusive upper bound.
        hi: Term,
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
}

/// The declaration's clause structure: sites in declaration order, with
/// `for` loops preserved as the `for-each` clauses they become.
#[derive(Clone, Debug)]
pub enum Node {
    /// One declared access, by index into [`Lowered::sites`].
    Site(usize),
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

/// What one lowered method declares.
#[derive(Clone, Debug, Default)]
pub struct Lowered {
    /// Every handle site, in the order the body opened them.
    pub sites: Vec<Site>,
    /// The clause tree over those sites.
    pub nodes: Vec<Node>,
    /// The resources of the value edges the method produces.
    pub outputs: Vec<Term>,
}

/// What a subexpression evaluated to.
#[derive(Clone, Debug)]
enum Val {
    /// A DSL-expressible value.
    Term(Term),
    /// `self.<field>` — not yet an access.
    Field(String),
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
    /// Anything the grammar does not cover.
    Opaque,
}

impl From<Slot> for Val {
    fn from(slot: Slot) -> Self {
        match slot {
            Slot::Value(term) => Self::Term(term),
            Slot::Handle(index) => Self::Handle(index),
            Slot::Produced(term) => Self::Produced(term),
            Slot::Config => Self::Config,
            Slot::Opaque => Self::Opaque,
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

/// Whether an expression is the bare `self` path.
fn is_self(expr: &syn::Expr) -> bool {
    matches!(expr, syn::Expr::Path(path) if path.path.is_ident("self"))
}

/// The lowering pass over one method body.
pub struct Lowerer<'a> {
    fields: &'a BTreeMap<String, Field>,
    config_fields: &'a [String],
    params: &'a [String],
    locals: Vec<BTreeMap<String, Slot>>,
    out: Lowered,
    /// The clause scopes being built, innermost last.
    scopes: Vec<Vec<Node>>,
    errors: Vec<syn::Error>,
}

impl<'a> Lowerer<'a> {
    /// Start a pass over a method with these positional parameters.
    pub fn new(
        fields: &'a BTreeMap<String, Field>,
        config_fields: &'a [String],
        params: &'a [String],
    ) -> Self {
        Self {
            fields,
            config_fields,
            params,
            locals: vec![BTreeMap::new()],
            out: Lowered::default(),
            scopes: vec![Vec::new()],
            errors: Vec::new(),
        }
    }

    /// Lower a body, or report every reason it could not be.
    ///
    /// The tail expression is evaluated in return position, where a
    /// produced bucket — or a tuple of them — becomes the method's declared
    /// outputs.
    pub fn run(mut self, block: &syn::Block) -> Result<Lowered, Vec<syn::Error>> {
        self.locals.push(BTreeMap::new());
        let (body, tail) = split_tail(block);
        for stmt in body {
            self.stmt(stmt);
        }
        if let Some(tail) = tail {
            let value = self.returned(tail);
            self.out.outputs = value;
        }
        self.locals.pop();

        if self.errors.is_empty() {
            self.out.nodes = self.scopes.pop().unwrap_or_default();
            Ok(self.out)
        } else {
            Err(self.errors)
        }
    }

    /// Evaluate an expression in return position, collecting the resources
    /// of every value edge it yields.
    fn returned(&mut self, expr: &syn::Expr) -> Vec<Term> {
        match expr {
            syn::Expr::Tuple(tuple) => tuple
                .elems
                .iter()
                .filter_map(|element| match self.expr(element) {
                    Val::Produced(term) => Some(term),
                    _ => None,
                })
                .collect(),
            syn::Expr::Paren(paren) => self.returned(&paren.expr),
            other => match self.expr(other) {
                Val::Produced(term) => vec![term],
                _ => vec![],
            },
        }
    }

    const fn depth(&self) -> usize {
        self.scopes.len() - 1
    }

    fn error(&mut self, span: Span, message: &str) {
        self.errors.push(syn::Error::new(span, message));
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

    fn open(&mut self, target: Target) -> usize {
        let index = self.out.sites.len();
        self.out.sites.push(Site {
            target,
            ops: Vec::new(),
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
        let compatible = match op {
            Op::Get | Op::Set => entry
                .ops
                .iter()
                .all(|(prior, _)| matches!(prior, Op::Get | Op::Set)),
            Op::Delta => entry
                .ops
                .iter()
                .all(|(prior, _)| matches!(prior, Op::Delta)),
            Op::Reserve | Op::Locked => entry.ops.is_empty(),
        };
        if compatible {
            entry.ops.push((op, param));
        } else {
            self.error(
                span,
                "one handle declares one access mode — a read beside a movement, or a \
                 second reservation, folds to no single mode. Open a separate access \
                 for each mode instead",
            );
        }
    }

    // ---- statements -----------------------------------------------------

    fn block(&mut self, block: &syn::Block) {
        self.locals.push(BTreeMap::new());
        for stmt in &block.stmts {
            self.stmt(stmt);
        }
        self.locals.pop();
    }

    fn stmt(&mut self, stmt: &syn::Stmt) {
        match stmt {
            syn::Stmt::Local(local) => {
                let value = local
                    .init
                    .as_ref()
                    .map_or(Val::Opaque, |init| self.expr(&init.expr));
                if let Some(init) = &local.init
                    && let Some((_, diverge)) = &init.diverge
                {
                    self.expr(diverge);
                }
                let slot = match value {
                    Val::Term(term) => Slot::Value(term),
                    Val::Handle(index) => Slot::Handle(index),
                    Val::Produced(term) => Slot::Produced(term),
                    // A locked config read binds a name whose *fields* are
                    // config slots; the binding itself is not a value.
                    Val::Config => Slot::Config,
                    Val::Field(_) | Val::Opaque => Slot::Opaque,
                };
                // A plain name takes the slot; any other pattern binds its
                // names opaquely, so a destructured piece used as a key is
                // refused at the use site rather than resolved to whatever
                // an outer scope happened to call by the same name.
                match unwrap_pat(&local.pat) {
                    syn::Pat::Ident(ident) => self.bind(ident.ident.to_string(), slot),
                    other => self.bind_pattern(other),
                }
            }
            syn::Stmt::Expr(expr, _) => {
                self.expr(expr);
            }
            syn::Stmt::Macro(mac) => self.macro_call(&mac.mac),
            // A nested item cannot capture the component, so it can hold no
            // state access.
            syn::Stmt::Item(_) => {}
        }
    }

    /// Walk a macro invocation's arguments for accesses, or refuse it.
    ///
    /// The assert and panic family take ordinary expressions, so an access
    /// inside one declares like an access outside it. Any other macro is
    /// opaque tokens — walking past it would silently drop whatever it
    /// contains, so it is refused instead.
    fn macro_call(&mut self, mac: &syn::Macro) {
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
            return;
        }
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        match mac.parse_body_with(parser) {
            Ok(args) => {
                for arg in &args {
                    self.expr(arg);
                }
            }
            Err(_) => self.error(
                mac.span(),
                "these macro arguments do not parse as expressions, so they cannot be \
                 checked for state accesses",
            ),
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
            // Wildcards, literals, paths, rests, and ranges bind nothing.
            _ => {}
        }
    }

    // ---- expressions ----------------------------------------------------

    #[allow(clippy::too_many_lines)]
    fn expr(&mut self, expr: &syn::Expr) -> Val {
        match expr {
            syn::Expr::Path(path) => self.path(path),
            syn::Expr::Lit(lit) => Self::literal(lit),
            syn::Expr::Field(field) => self.field(field),
            syn::Expr::MethodCall(call) => self.method_call(call),
            syn::Expr::Call(call) => self.free_call(call),
            syn::Expr::Reference(reference) => self.expr(&reference.expr),
            syn::Expr::Paren(paren) => self.expr(&paren.expr),
            syn::Expr::Group(group) => self.expr(&group.expr),

            // Control flow: both arms are declared, so the result is a
            // superset of any one execution. Legal, and priced as the
            // superset it is. An `if let` scrutinee is walked and its
            // pattern's names are bound opaquely for the taken branch.
            syn::Expr::If(branch) => {
                self.locals.push(BTreeMap::new());
                self.condition(&branch.cond);
                self.block(&branch.then_branch);
                self.locals.pop();
                if let Some(otherwise) = &branch.else_branch {
                    self.expr(&otherwise.1);
                }
                Val::Opaque
            }
            syn::Expr::Match(match_) => {
                self.expr(&match_.expr);
                for arm in &match_.arms {
                    self.locals.push(BTreeMap::new());
                    self.bind_pattern(&arm.pat);
                    if let Some((_, guard)) = &arm.guard {
                        self.expr(guard);
                    }
                    self.expr(&arm.body);
                    self.locals.pop();
                }
                Val::Opaque
            }
            syn::Expr::Block(block) => {
                self.block(&block.block);
                Val::Opaque
            }
            syn::Expr::ForLoop(loop_) => {
                self.for_loop(loop_);
                Val::Opaque
            }
            syn::Expr::Return(ret) => {
                if let Some(value) = &ret.expr {
                    let produced = self.returned(value);
                    if !produced.is_empty() {
                        self.error(
                            ret.span(),
                            "a produced value edge must leave through the method's tail \
                             expression — the declared outputs are exact, so an early \
                             return's edges cannot be reconciled with the tail's",
                        );
                    }
                }
                Val::Opaque
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
                self.condition(&loop_.cond);
                self.block(&loop_.body);
                self.locals.pop();
                Val::Opaque
            }
            syn::Expr::Loop(loop_) => {
                self.block(&loop_.body);
                Val::Opaque
            }
            syn::Expr::Let(let_) => {
                self.expr(&let_.expr);
                self.bind_pattern(&let_.pat);
                Val::Opaque
            }

            // Assignment forgets the target's slot: after a conditional
            // reassignment the static value is not knowable, so a later
            // use as a key must be refused where it is used rather than
            // declare the stale key.
            syn::Expr::Assign(assign) => {
                self.expr(&assign.right);
                self.assign_target(&assign.left);
                Val::Opaque
            }
            syn::Expr::Binary(binary) => {
                self.expr(&binary.left);
                self.expr(&binary.right);
                if binary_op_assigns(binary.op) {
                    self.assign_target(&binary.left);
                }
                Val::Opaque
            }

            // Forms that carry no access semantics of their own but can
            // contain accesses: walked exhaustively, evaluated to nothing.
            syn::Expr::Unary(unary) => {
                self.expr(&unary.expr);
                Val::Opaque
            }
            syn::Expr::Tuple(tuple) => {
                for element in &tuple.elems {
                    self.expr(element);
                }
                Val::Opaque
            }
            // A cast can truncate, so the result is not the term it was
            // cast from.
            syn::Expr::Cast(cast) => {
                self.expr(&cast.expr);
                Val::Opaque
            }
            syn::Expr::Try(try_) => {
                self.expr(&try_.expr);
                Val::Opaque
            }
            syn::Expr::Index(index) => {
                self.expr(&index.expr);
                self.expr(&index.index);
                Val::Opaque
            }
            syn::Expr::Array(array) => {
                for element in &array.elems {
                    self.expr(element);
                }
                Val::Opaque
            }
            syn::Expr::Repeat(repeat) => {
                self.expr(&repeat.expr);
                self.expr(&repeat.len);
                Val::Opaque
            }
            syn::Expr::Struct(strct) => {
                for field in &strct.fields {
                    self.expr(&field.expr);
                }
                if let Some(rest) = &strct.rest {
                    self.expr(rest);
                }
                Val::Opaque
            }
            syn::Expr::Range(range) => {
                if let Some(start) = &range.start {
                    self.expr(start);
                }
                if let Some(end) = &range.end {
                    self.expr(end);
                }
                Val::Opaque
            }
            syn::Expr::Break(brk) => {
                if let Some(value) = &brk.expr {
                    self.expr(value);
                }
                Val::Opaque
            }
            syn::Expr::Continue(_) => Val::Opaque,
            syn::Expr::Macro(mac) => {
                self.macro_call(&mac.mac);
                Val::Opaque
            }

            // A closure could capture the component and carry accesses the
            // walk cannot attribute to any declaration site.
            syn::Expr::Closure(closure) => {
                self.error(
                    closure.span(),
                    "`#[blueprint]` does not model closures — an access inside one \
                     cannot be attributed to a declaration",
                );
                Val::Opaque
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
                Val::Opaque
            }
        }
    }

    /// Walk an `if`/`while` condition, binding an `if let` pattern's names
    /// opaquely into the scope the caller pushed.
    fn condition(&mut self, cond: &syn::Expr) {
        if let syn::Expr::Let(let_) = cond {
            self.expr(&let_.expr);
            self.bind_pattern(&let_.pat);
        } else {
            self.expr(cond);
        }
    }

    /// Forget the slot an assignment target held, wherever it is bound.
    fn assign_target(&mut self, left: &syn::Expr) {
        if let syn::Expr::Path(path) = left
            && let Some(ident) = path.path.get_ident()
        {
            let name = ident.to_string();
            for scope in self.locals.iter_mut().rev() {
                if let Some(slot) = scope.get_mut(&name) {
                    *slot = Slot::Opaque;
                    return;
                }
            }
        } else {
            self.expr(left);
        }
    }

    fn path(&self, path: &syn::ExprPath) -> Val {
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
            return match segments
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice()
            {
                ["u64", "MAX"] => Val::Term(Term::LitU64(u64::MAX)),
                ["u64", "MIN"] => Val::Term(Term::LitU64(0)),
                _ => Val::Opaque,
            };
        };
        let name = ident.to_string();
        if let Some(slot) = self.lookup(&name) {
            return slot.into();
        }
        if let Some(index) = self.params.iter().position(|p| *p == name) {
            return Val::Term(Term::Arg(u32::try_from(index).unwrap_or(0)));
        }
        Val::Opaque
    }

    fn literal(lit: &syn::ExprLit) -> Val {
        if let syn::Lit::Int(int) = &lit.lit
            && let Ok(value) = int.base10_parse::<u64>()
        {
            return Val::Term(Term::LitU64(value));
        }
        Val::Opaque
    }

    fn field(&mut self, field: &syn::ExprField) -> Val {
        // `self.<name>` names a state field rather than a value.
        if let syn::Expr::Path(path) = &*field.base
            && path.path.is_ident("self")
            && let syn::Member::Named(name) = &field.member
        {
            return Val::Field(name.to_string());
        }
        let base = self.expr(&field.base);
        match (base, &field.member) {
            // `self.config.x` — a configuration field read directly.
            //
            // This declares nothing, and that is the point: configuration
            // is a locked substate, verified once and cached process-wide,
            // so a declaration may consult it without claiming it. Naming
            // the leaf as a locked read is a separate, deliberate act
            // (`self.config.locked()`) that a method only performs when it
            // wants the whole record pinned.
            (Val::Field(field_name), syn::Member::Named(name))
                if self
                    .fields
                    .get(&field_name)
                    .is_some_and(|f| f.kind == FieldKind::Locked) =>
            {
                self.config_slot(&name.to_string(), field)
            }

            // A field of a value a locked read returned.
            (Val::Config, syn::Member::Named(name)) => self.config_slot(&name.to_string(), field),
            (Val::Term(term), syn::Member::Unnamed(index)) => {
                Val::Term(Term::Field(Box::new(term), index.index))
            }
            _ => Val::Opaque,
        }
    }

    /// Resolve a configuration field name to its slot index.
    fn config_slot(&mut self, name: &str, field: &syn::ExprField) -> Val {
        let Some(index) = self.config_fields.iter().position(|f| f == name) else {
            self.error(
                field.span(),
                "not a field of the component's configuration struct",
            );
            return Val::Opaque;
        };
        Val::Term(Term::Config(u32::try_from(index).unwrap_or(0)))
    }

    fn free_call(&mut self, call: &syn::ExprCall) -> Val {
        for arg in &call.args {
            if is_self(arg) {
                self.error(
                    arg.span(),
                    "the component reference cannot be passed on — a callee's accesses \
                     would be invisible to this method's declaration",
                );
            }
        }
        let syn::Expr::Path(path) = &*call.func else {
            for arg in &call.args {
                self.expr(arg);
            }
            return Val::Opaque;
        };
        let name = path
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let args: Vec<Val> = call.args.iter().map(|a| self.expr(a)).collect();
        match (name.as_str(), args.as_slice()) {
            ("pack", [Val::Term(hi), Val::Term(lo)]) => Val::Term(Term::Pack {
                hi: Box::new(hi.clone()),
                lo: Box::new(lo.clone()),
            }),
            // `Bucket::of(resource, amount)` — the explicit spelling for a
            // value edge a method mints rather than moves. The resource is
            // the declaration; the amount is dynamic and never declared.
            ("of", [Val::Term(resource), _]) => Val::Produced(resource.clone()),
            ("fresh_id", []) => Val::Term(Term::FreshId),
            _ => Val::Opaque,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn method_call(&mut self, call: &syn::ExprMethodCall) -> Val {
        // `self.other_method(…)` reaches state this body never names, so
        // its accesses cannot land in this declaration.
        if is_self(&call.receiver) {
            self.error(
                call.span(),
                "a contract method cannot call another method of the component — each \
                 method declares only its own body's accesses. Inline the access, or \
                 lift the shared value to a parameter",
            );
            for arg in &call.args {
                self.expr(arg);
            }
            return Val::Opaque;
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
        let args: Vec<Val> = call.args.iter().map(|a| self.expr(a)).collect();

        match receiver {
            // ---- opening a handle on a state field ----------------------
            Val::Field(name) => {
                let Some(field) = self.fields.get(&name).cloned() else {
                    self.error(
                        call.receiver.span(),
                        "not a declared field of the component's state struct",
                    );
                    return Val::Opaque;
                };
                self.on_field(&field, &method, &args, call)
            }

            // ---- operating through an open handle -----------------------
            Val::Handle(site) => {
                let Some(op) = Op::from_method(&method) else {
                    return Val::Opaque;
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

                // A reservation yields a value edge carrying the vault's
                // own resource — which the site's key material already
                // names, so the output needs no separate declaration.
                if op == Op::Reserve
                    && let Some(Target::Point { material, .. }) =
                        self.out.sites.get(site).map(|s| &s.target)
                    && let Some(resource) = material.first().cloned()
                {
                    return Val::Produced(resource);
                }
                Val::Opaque
            }

            // ---- projections over values --------------------------------
            Val::Produced(resource) => match method.as_str() {
                "resource" => Val::Term(resource),
                _ => Val::Produced(resource),
            },

            Val::Term(term) => match method.as_str() {
                "resource" => Val::Term(Term::ResourceOf(Box::new(term))),
                "lookup" | "get" if matches!(args.first(), Some(Val::Term(_))) => {
                    let Some(Val::Term(key)) = args.first() else {
                        return Val::Opaque;
                    };
                    Val::Term(Term::Lookup {
                        map: Box::new(term),
                        key: Box::new(key.clone()),
                    })
                }
                _ => Val::Opaque,
            },

            Val::Config | Val::Opaque => Val::Opaque,
        }
    }

    fn on_field(
        &mut self,
        field: &Field,
        method: &str,
        args: &[Val],
        call: &syn::ExprMethodCall,
    ) -> Val {
        let role = field.role;
        match (field.kind, method) {
            // The locked configuration: a read that excludes nothing,
            // and the value whose fields are the config slots.
            (FieldKind::Locked, "locked") => {
                let site = self.open(Target::Point {
                    role,
                    material: vec![],
                });
                self.record(site, Op::Locked, None, call.span());
                Val::Config
            }

            // A family of leaves keyed by an address.
            (FieldKind::Keyed, "at") => {
                if let Some(Val::Term(key)) = args.first() {
                    Val::Handle(self.open(Target::Point {
                        role,
                        material: vec![key.clone()],
                    }))
                } else {
                    self.error(
                        call.args.span(),
                        "this key is not derivable from the method's arguments or the \
                     component's configuration. Routing evaluates a declaration before \
                     execution and never reads state, so a key computed from a substate \
                     value cannot be declared — pass it as a parameter instead",
                    );
                    Val::Opaque
                }
            }

            // One entry of an ordered collection.
            (FieldKind::Ordered, "at") => {
                if let Some(Val::Term(order)) = args.first() {
                    Val::Handle(self.open(Target::Entry {
                        role,
                        order: order.clone(),
                    }))
                } else {
                    self.error(
                        call.args.span(),
                        "this order key is not derivable from the method's arguments or the \
                     component's configuration",
                    );
                    Val::Opaque
                }
            }

            // A declared interval of an ordered collection.
            (FieldKind::Ordered, "range") => {
                if let (
                    Some(Val::Term(lo)),
                    Some(Val::Term(hi)),
                    Some(Val::Term(Term::LitU64(cap))),
                ) = (args.first(), args.get(1), args.get(2))
                {
                    Val::Handle(self.open(Target::Range {
                        role,
                        lo: lo.clone(),
                        hi: hi.clone(),
                        cap: u32::try_from(*cap).unwrap_or(u32::MAX),
                    }))
                } else {
                    self.error(
                        call.args.span(),
                        "a range's bounds must be derivable from the arguments, and its entry \
                     cap must be a literal — the cap bounds the work execution may do, so \
                     it is declaration, not data",
                    );
                    Val::Opaque
                }
            }

            // A single leaf: the operation lands directly on it.
            (FieldKind::Cell, _) => {
                if let Some(op) = Op::from_method(method) {
                    let site = self.open(Target::Point {
                        role,
                        material: vec![],
                    });
                    let param = match args.first() {
                        Some(Val::Term(term)) => Some(term.clone()),
                        _ => None,
                    };
                    self.record(site, op, param, call.span());
                }
                Val::Opaque
            }

            _ => Val::Opaque,
        }
    }

    fn for_loop(&mut self, loop_: &syn::ExprForLoop) {
        let Val::Term(list) = self.expr(&loop_.expr) else {
            self.error(
                loop_.expr.span(),
                "a `for` loop in a contract body must range over a configured collection \
                 — that is what bounds the keys it declares. An iterator over runtime \
                 values has no declarable key set",
            );
            return;
        };

        let depth = self.depth();
        self.scopes.push(Vec::new());
        self.locals.push(BTreeMap::new());
        match unwrap_pat(&loop_.pat) {
            syn::Pat::Ident(ident) => {
                self.bind(ident.ident.to_string(), Slot::Value(Term::Binding(depth)));
            }
            other => self.bind_pattern(other),
        }
        for stmt in &loop_.body.stmts {
            self.stmt(stmt);
        }
        self.locals.pop();
        let body = self.scopes.pop().unwrap_or_default();

        self.push_node(Node::ForEach { list, depth, body });
    }
}

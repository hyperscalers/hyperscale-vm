//! The tracer: run a declaration once, symbolically, and keep what it built.
//!
//! This is the mechanism the SDK rests on, and it is deliberately not a
//! proc macro reading the method body. Recovering [`Clause`] trees from
//! compiled contract code would be abstract interpretation of WASM into a
//! strictly weaker language — undecidable in general, and wrong quietly
//! when it fails. Instead the author writes a second, declarative function
//! in ordinary Rust; the tracer calls it with [`crate::sym::Sym`] arguments
//! standing in for the real ones and records the terms it constructs. It
//! terminates because the DSL is total and loop-free: there is nothing to
//! run to a fixpoint.
//!
//! Three things the tracer gets right that a hand-written signature tends
//! not to:
//!
//! - **Binding indices.** [`Expr::Binding`] is de Bruijn — `0` names the
//!   innermost `for-each`. Under nesting, the same bound element takes a
//!   different index at each use site. The tracer records binders by
//!   absolute depth and converts at the point of use, so an author never
//!   writes an index at all.
//! - **Fresh slots.** [`Expr::FreshId`] and [`Expr::FreshKey`] slots must
//!   be unique within a signature. A counter cannot get that wrong.
//! - **The structural bounds.** [`MAX_EXPR_DEPTH`] and
//!   [`MAX_CLAUSE_DEPTH`] are checked here, at build time, rather than at
//!   routing time — where the package is already published and every call
//!   to the method fails.
//!
//! Trace-time violations panic. That is the right severity: the tracer runs
//! in a build step, and every condition it rejects would otherwise become a
//! published contract whose method can never be called.

use hyperscale_vm_effects::{
    AbiParam, Accessibility, AuthRole, Clause, CustodyClaim, Expr, MAX_CLAUSE_DEPTH,
    MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, ModeExpr, ParamType, Presence, RuleExpr, SlotId,
    TargetExpr, Totality, Value,
};

use crate::sym::{Addr, Amount, Key, Kind, Num, Opaque, Seq, Sym, expr_depth};

/// The recorder a declaration is traced against.
///
/// Handed to the declaration closure; every symbolic input comes from it,
/// and every emitted clause lands in it.
pub struct Trace {
    /// The method's declared parameter kinds, checked against every
    /// [`Trace::arg`].
    params: Vec<ParamType>,
    /// Clause scopes, innermost last; `scopes[0]` is the method body.
    scopes: Vec<Vec<Clause>>,
    /// The next unused fresh-derivation slot.
    next_slot: u32,
    /// Resource expressions for the value edges this method produces.
    outputs: Vec<Expr>,
    /// The resource each consumed edge is fixed to, by parameter; sized
    /// to `params` and mostly empty, because most positions take whatever
    /// the cell they land in is keyed by.
    denominations: Vec<Option<Expr>>,
    /// The worst-case effect count, folding `for-each` width per nesting
    /// level.
    worst_case: usize,
    /// The handle bindings, in the order the body opened them.
    handles: Vec<AbiParam>,
    /// The value bindings, in the order the body needs them.
    values: Vec<AbiParam>,
    /// The top-level clause most recently declared, which is the one
    /// [`Trace::bind_handle`] names.
    last_clause: Option<u32>,
    /// Whose authority naming this method requires.
    accessibility: Accessibility,
    /// The mark of the resource this method may issue.
    issues: Option<Vec<u8>>,
    /// Whether the method carries an error arm.
    totality: Totality,
}

impl Trace {
    pub(crate) fn new(params: Vec<ParamType>) -> Self {
        Self {
            denominations: vec![None; params.len()],
            params,
            scopes: vec![Vec::new()],
            next_slot: 0,
            outputs: Vec::new(),
            worst_case: 0,
            handles: Vec::new(),
            values: Vec::new(),
            last_clause: None,
            accessibility: Accessibility::Public,
            issues: None,
            totality: Totality::Infallible,
        }
    }

    /// How many `for-each` binders enclose the current scope.
    const fn depth(&self) -> usize {
        self.scopes.len() - 1
    }

    /// Convert an expression written by the author into the form the
    /// evaluator reads, and check it against the structural bounds.
    ///
    /// Binders are recorded absolute and read relative: a binder introduced
    /// at absolute depth `a`, used where `d` binders are in scope, is
    /// `Binding(d - 1 - a)`. Conversion has to happen at the use site
    /// rather than at construction, because one bound element may be used
    /// at several depths.
    fn lower(&self, expr: Expr) -> Expr {
        let depth = self.depth();
        let lowered = rebind(expr, depth);
        let expr_depth = expr_depth(&lowered);
        assert!(
            expr_depth <= MAX_EXPR_DEPTH,
            "expression nests {expr_depth} deep, past the {MAX_EXPR_DEPTH} the evaluator admits"
        );
        lowered
    }

    /// Lower a run of key material, in the order it is folded.
    fn lower_all(&self, material: &[Sym<Opaque>]) -> Vec<Expr> {
        material
            .iter()
            .map(|m| self.lower(m.expr().clone()))
            .collect()
    }

    /// Emit one clause into the current scope.
    fn emit(&mut self, clause: Clause) {
        if matches!(clause, Clause::Effect { .. }) {
            // One effect under `d` nested binders can declare up to
            // `MAX_FOREACH_ELEMENTS^d` of them.
            let width = MAX_FOREACH_ELEMENTS
                .checked_pow(u32::try_from(self.depth()).unwrap_or(u32::MAX))
                .unwrap_or(usize::MAX);
            self.worst_case = self.worst_case.saturating_add(width);
        }
        let top = self.depth() == 0;
        let scope = self
            .scopes
            .last_mut()
            .expect("the method scope is never popped");
        let index = u32::try_from(scope.len()).unwrap_or(u32::MAX);
        let effect = matches!(clause, Clause::Effect { .. });
        scope.push(clause);
        if top {
            // `AbiParam::Handle` indexes the top-level clause list, so
            // only a clause that lands there can back a handle parameter;
            // a `for-each` clears the mark rather than shadowing it.
            self.last_clause = effect.then_some(index);
        }
    }

    /// The `index`-th manifest argument bound to this call.
    ///
    /// # Panics
    ///
    /// If `index` is past the declared parameters, or if `K` names a
    /// different kind than the parameter list does.
    #[must_use]
    pub fn arg<K: Kind>(&self, index: u32) -> Sym<K> {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the declared parameter list"));
        if let Some(claimed) = K::PARAM {
            assert!(
                claimed == declared,
                "argument {index} is declared {} but read as {}",
                declared.name(),
                K::NAME
            );
        }
        Sym::new(Expr::Arg(index))
    }

    /// The `index`-th field of the target instance's creation-fixed
    /// configuration.
    ///
    /// Config is a locked substate — readable without a declared effect —
    /// which is what lets a declaration consult it while staying pure.
    #[must_use]
    pub const fn config<K: Kind>(&self, index: u32) -> Sym<K> {
        Sym::new(Expr::Config(index))
    }

    /// The target instance's own address.
    #[must_use]
    pub const fn self_addr(&self) -> Sym<Addr> {
        Sym::new(Expr::SelfAddr)
    }

    /// A resource this instance issues, separated from its others by
    /// `mark`.
    ///
    /// Derived from the instance rather than configured, and it has to
    /// be: an instance's address commits its configuration, so a
    /// configured field naming a value derived from that address would
    /// not be expressible. The mark is what lets one instance issue more
    /// than one — a stake unit and the badge that operates the pool are
    /// the same derivation over different material.
    #[must_use]
    pub fn self_resource(&self, mark: &[u8]) -> Sym<Addr> {
        let material = if mark.is_empty() {
            Vec::new()
        } else {
            vec![Expr::Literal(Value::Bytes(mark.to_vec()))]
        };
        Sym::new(Expr::SelfResource { material })
    }

    /// A deterministic fresh 64-bit id, in the next unused slot.
    #[must_use]
    pub const fn fresh_id(&mut self) -> Sym<Num> {
        let slot = self.take_slot();
        Sym::new(Expr::FreshId { slot })
    }

    /// The key of an object this call creates, in the next unused slot.
    #[must_use]
    pub const fn fresh_key(&mut self) -> Sym<Key> {
        let slot = self.take_slot();
        Sym::new(Expr::FreshKey { slot })
    }

    const fn take_slot(&mut self) -> u32 {
        let slot = self.next_slot;
        self.next_slot += 1;
        slot
    }

    /// Declare accesses to one substate leaf.
    #[must_use]
    pub fn point(&mut self, key: &Sym<Key>) -> Access<'_, Leaf> {
        let target = TargetExpr::Point(self.lower(key.expr().clone()));
        Access {
            trace: self,
            target,
            denomination: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare accesses to one ordered-collection entry.
    ///
    /// `material` names the sub-collection under the slot, empty where
    /// the slot holds one collection outright: a collection is its owner,
    /// its slot and what is folded into it, exactly as a keyed leaf is.
    #[must_use]
    pub fn entry(
        &mut self,
        owner: &Sym<Addr>,
        collection: SlotId,
        material: &[Sym<Opaque>],
        order: &Sym<Amount>,
    ) -> Access<'_, Leaf> {
        let target = TargetExpr::Entry {
            owner: self.lower(owner.expr().clone()),
            collection,
            material: self.lower_all(material),
            order: self.lower(order.expr().clone()),
        };
        Access {
            trace: self,
            target,
            denomination: None,
            shape: core::marker::PhantomData,
        }
    }

    /// The order an unordered collection places `key` at: the hash of
    /// the key salted by the collection's owner and slot.
    ///
    /// The derivation is the kernel's, so a guest that has to name the
    /// entry is handed the answer rather than asked to rebuild it — which
    /// is what lets an unordered collection have an executing body at all.
    #[must_use]
    pub fn order_key<K: Kind>(&self, collection: SlotId, key: &Sym<K>) -> Sym<Amount> {
        Sym::new(Expr::OrderKey {
            owner: Box::new(Expr::SelfAddr),
            slot: collection,
            material: vec![self.lower(key.expr().clone())],
        })
    }

    /// Declare accesses to one unordered-collection entry: the entry at
    /// the hash of `key`, salted by the collection's owner and slot.
    #[must_use]
    pub fn keyed_entry(
        &mut self,
        owner: &Sym<Addr>,
        collection: SlotId,
        key: &Sym<Opaque>,
    ) -> Access<'_, Leaf> {
        let owner_expr = self.lower(owner.expr().clone());
        let target = TargetExpr::Entry {
            owner: owner_expr.clone(),
            collection,
            material: vec![],
            order: Expr::OrderKey {
                owner: Box::new(owner_expr),
                slot: collection,
                material: vec![self.lower(key.expr().clone())],
            },
        };
        Access {
            trace: self,
            target,
            denomination: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare accesses to an unordered collection's tail from `cursor`:
    /// the interval `[cursor, u128::MAX]`, capped at `cap` entries.
    ///
    /// Hash order is arbitrary but canonical, so walking it from a cursor
    /// visits every entry exactly once across resumptions — the
    /// pagination-crank shape. The caller passes the cursor as an
    /// argument; `0` starts the walk.
    #[must_use]
    pub fn sweep(
        &mut self,
        owner: &Sym<Addr>,
        collection: SlotId,
        cursor: &Sym<Amount>,
        cap: u32,
    ) -> Access<'_, Interval> {
        let target = TargetExpr::Range {
            owner: self.lower(owner.expr().clone()),
            collection,
            material: vec![],
            lo: self.lower(cursor.expr().clone()),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap,
        };
        Access {
            trace: self,
            target,
            denomination: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare accesses to an interval of a collection's order-key space.
    ///
    /// `cap` bounds the entries execution may touch; the interval's own
    /// magnitude is what [`hyperscale_vm_effects::footprint`] charges, so a
    /// range wider than the method needs is priced as the exclusion it is.
    #[must_use]
    pub fn range(
        &mut self,
        owner: &Sym<Addr>,
        collection: SlotId,
        material: &[Sym<Opaque>],
        lo: &Sym<Amount>,
        hi: &Sym<Amount>,
        cap: u32,
    ) -> Access<'_, Interval> {
        let target = TargetExpr::Range {
            owner: self.lower(owner.expr().clone()),
            collection,
            material: self.lower_all(material),
            lo: self.lower(lo.expr().clone()),
            hi: self.lower(hi.expr().clone()),
            cap,
        };
        Access {
            trace: self,
            target,
            denomination: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare one access set per element of a bounded collection.
    ///
    /// The element is handed to `body` as a symbolic value; its binding
    /// index is the tracer's problem, not the author's.
    ///
    /// # Panics
    ///
    /// If the nesting would pass [`MAX_CLAUSE_DEPTH`].
    pub fn for_each<F>(&mut self, list: &Sym<Seq>, body: F)
    where
        F: FnOnce(&mut Self, Sym<Opaque>),
    {
        // The list is evaluated in the *enclosing* scope, so it lowers
        // before the binder is pushed.
        let list_expr = self.lower(list.expr().clone());
        let binder = self.depth();
        assert!(
            binder < MAX_CLAUSE_DEPTH,
            "for-each nests {} deep, past the {MAX_CLAUSE_DEPTH} the evaluator admits",
            binder + 1
        );

        self.scopes.push(Vec::new());
        body(self, Sym::new(Expr::Binding(absolute(binder))));
        let inner = self
            .scopes
            .pop()
            .expect("the scope pushed above is the one popped");

        self.emit(Clause::ForEach {
            list: list_expr,
            body: inner,
        });
    }

    /// Bind the capability materialized for the clause just declared as
    /// the next of the guest's handle parameters.
    ///
    /// Handles occupy the front of the binding, values the tail, whatever
    /// order the body interleaved them in — which is what makes the
    /// export's parameter list readable rather than an accident of where
    /// each value was first needed.
    ///
    /// # Panics
    ///
    /// If no top-level effect clause has been declared, or if a
    /// `for-each` is open: a clause under one expands over instance
    /// configuration, so it occupies no fixed export parameter.
    pub fn bind_handle(&mut self) {
        assert_eq!(
            self.depth(),
            0,
            "a clause under a for-each has a configuration-dependent handle count, \
             so it cannot occupy a fixed export parameter"
        );
        let clause = self
            .last_clause
            .expect("a handle binding names the clause just declared, and none is");
        self.handles.push(AbiParam::Handle(clause));
    }

    /// Bind the `index`-th declared parameter's edge, which must be one.
    ///
    /// Either edge kind binds the same way — what separates them is the
    /// cell they cross as, and that is the callee's declaration rather
    /// than anything the binding sees.
    ///
    /// # Panics
    ///
    /// If `index` is past the declared parameters or names a kind that is
    /// not an edge — the one value a signature cannot derive.
    pub fn bind_bucket(&mut self, index: u32) {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the declared parameter list"));
        assert!(
            declared.is_edge(),
            "argument {index} is declared {} and carries no value",
            declared.name()
        );
        self.values.push(AbiParam::Bucket(index));
    }

    /// Bind this method's issuance grant, for the resource `mark` names.
    ///
    /// Called by generated code where a body issues or destroys. The mark
    /// is the material separating one of the instance's own resources
    /// from its others, so what a method may create is fixed by the
    /// declaration and cannot be another instance's.
    pub fn bind_issuer(&mut self, mark: &[u8]) {
        self.issues = Some(mark.to_vec());
        self.values.push(AbiParam::Issuer);
    }

    /// Bind a value evaluated over this method's bound inputs.
    pub fn bind_derived<K: Kind>(&mut self, value: &Sym<K>) {
        let expr = self.lower(value.expr().clone());
        self.values.push(AbiParam::Derived(expr));
    }

    /// Record that this method carries an error arm, and may therefore
    /// decline.
    pub const fn fallible(&mut self) {
        self.totality = Totality::Fallible;
    }

    /// Record the total mark: no refusal, and no partial operation
    /// anywhere the body reaches.
    ///
    /// Claimed here and granted elsewhere. The publish gate runs the
    /// artifact scan against the code the claim is attached to and
    /// refuses one it cannot support, and refuses the claim outright from
    /// a published package — so what this records is which methods the
    /// protocol asks to have checked, never a property a package awards
    /// itself.
    pub const fn total(&mut self) {
        self.totality = Totality::Total;
    }

    /// Record that naming this method requires presenting the claim
    /// `identity` evaluates to.
    pub fn guarded(&mut self, identity: &Sym<Addr>) {
        let expr = self.lower(identity.expr().clone());
        self.accessibility = Accessibility::Guarded(RuleExpr::Require(expr));
    }

    /// Record that naming this method requires satisfying `count` of the
    /// claims `identities` evaluate to.
    ///
    /// The threshold a fixed admin set is written as: three configured
    /// badge instances gated at two, rotated by issuing and revoked by
    /// burning, with no redeploy and no configuration slot per admin.
    pub fn guarded_by_threshold(&mut self, count: u8, identities: &[Sym<Addr>]) {
        let rules = identities
            .iter()
            .map(|identity| RuleExpr::Require(self.lower(identity.expr().clone())))
            .collect();
        self.accessibility = Accessibility::Guarded(RuleExpr::CountOf { count, rules });
    }

    /// Record that naming this method requires satisfying the target's own
    /// rule, and mints the target's identity.
    pub fn authorizing(&mut self) {
        self.accessibility = Accessibility::Authorizing;
    }

    /// Record that naming this method requires satisfying `role` of the
    /// target's stored role set.
    pub fn role_gated(&mut self, role: AuthRole) {
        self.accessibility = Accessibility::RoleGated(role);
    }

    /// Record that naming this method requires the target's own rule and
    /// its possession of some of the fungible badge `badge`, and mints
    /// that badge's address.
    pub fn custodial(&mut self, badge: &Sym<Addr>) {
        let badge = self.lower(badge.expr().clone());
        self.accessibility = Accessibility::Custodial(CustodyClaim::Fungible(badge));
    }

    /// Record that naming this method requires the target's own rule and
    /// its possession of instance `id` of `badge`, and mints both that
    /// instance and the badge it is an instance of.
    pub fn custodial_instance(&mut self, badge: &Sym<Addr>, id: &Sym<Amount>) {
        let badge = self.lower(badge.expr().clone());
        let id = self.lower(id.expr().clone());
        self.accessibility = Accessibility::Custodial(CustodyClaim::Instance { badge, id });
    }

    /// Record that this method produces a value edge carrying `resource`.
    ///
    /// Not inferable from a `-> Bucket` return type: the type says an edge
    /// comes out, never which resource it carries. For a pool that is a
    /// configuration field; for a wrapper it may be a projection of an
    /// input. Either way it is a declaration.
    pub fn output(&mut self, resource: &Sym<Addr>) {
        let expr = self.lower(resource.expr().clone());
        self.outputs.push(expr);
    }

    /// Record that the edge at `index` carries `resource`.
    ///
    /// Stated where the body credits a cell it keys by something other
    /// than the arriving resource: the cell's own key is what the value
    /// going into it has to be, and the parameter is where a caller
    /// supplies it. A cell keyed by the bucket's own resource says
    /// nothing and records nothing.
    ///
    /// # Panics
    ///
    /// If `index` is past the declared parameters, names a kind that
    /// carries no value, or already carries a different resource — a
    /// parameter credited to two cells that cannot both be right is a
    /// declaration with no satisfying call.
    pub fn denomination(&mut self, index: u32, resource: &Sym<Addr>) {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the declared parameter list"));
        assert!(
            declared.is_edge(),
            "argument {index} is declared {} and carries no value to denominate",
            declared.name()
        );
        let expr = self.lower(resource.expr().clone());
        let slot = &mut self.denominations[index as usize];
        if let Some(held) = slot {
            assert!(
                *held == expr,
                "argument {index} is credited to cells keyed by {held:?} and by {expr:?}, \
                 and no edge carries both"
            );
            return;
        }
        *slot = Some(expr);
    }

    /// Consume the trace into what it recorded.
    pub(crate) fn finish(mut self) -> Recorded {
        assert_eq!(
            self.scopes.len(),
            1,
            "a for-each scope outlived its closure"
        );
        let clauses = self.scopes.pop().unwrap_or_default();
        let mut abi = self.handles;
        abi.extend(self.values);
        // A method that fixes no position carries no list rather than a
        // list of nothing: most methods are that method, and the two say
        // the same thing everywhere the list is read.
        let denominations = if self.denominations.iter().any(Option::is_some) {
            self.denominations
        } else {
            Vec::new()
        };
        Recorded {
            clauses,
            denominations,
            outputs: self.outputs,
            worst_case: self.worst_case,
            abi,
            accessibility: self.accessibility,
            issues: self.issues,
            totality: self.totality,
        }
    }
}

/// A target that names exactly one leaf: a cell, or one entry of a
/// collection at a declared order key.
///
/// The shape a presence requirement can be about, which is why it is a
/// type rather than a check — [`Access::create`] and [`Access::existing`]
/// exist only on this one.
#[derive(Clone, Copy, Debug)]
pub struct Leaf;

/// A target that names an interval of a collection's order-key space.
///
/// It stays valid whatever entries enter or leave it, which is what
/// makes it declarable ahead of execution — and the same property is why
/// there is no leaf for a presence requirement to be about.
#[derive(Clone, Copy, Debug)]
pub struct Interval;

/// A target awaiting the mode it is accessed under.
///
/// Splitting target from mode is what makes the declaration read as a
/// sentence — `t.point(vault).write()` — and it makes the mode a required
/// choice: there is no way to name a target without saying how it is
/// touched.
///
/// `Shape` is [`Leaf`] or [`Interval`], and it decides which modes the
/// target can be reached under: every mode is on both, and the presence
/// requirements are on the leaf alone.
pub struct Access<'a, Shape> {
    trace: &'a mut Trace,
    target: TargetExpr,
    denomination: Option<Box<Expr>>,
    shape: core::marker::PhantomData<fn() -> Shape>,
}

impl<Shape> Access<'_, Shape> {
    fn declare(self, mode: ModeExpr) {
        self.trace.emit(Clause::Effect {
            target: self.target,
            mode,
            denomination: self.denomination,
        });
    }

    /// State what the accessed cell holds.
    ///
    /// Read by execution rather than by routing: a key is a hash, so a
    /// movement landing on one cannot say which resource it moved unless
    /// the clause that named the cell says so. Stated here, a credit
    /// carrying some other resource is refused by the kernel — which is
    /// what makes the property hold for a package whose metadata nobody
    /// derived.
    #[must_use]
    pub fn holding(mut self, resource: &Sym<Addr>) -> Self {
        let expr = self.trace.lower(resource.expr().clone());
        self.denomination = Some(Box::new(expr));
        self
    }

    /// A fresh coherent read of committed state.
    ///
    /// The costliest read: it excludes both commutative modes as well as
    /// writes. Prefer [`Access::locked`] where the substate never
    /// changes.
    pub fn read(self) {
        self.declare(ModeExpr::Read);
    }

    /// A read of a permanently locked substate: no proof obligation, no
    /// participant, and it excludes nothing. Only a locked target admits
    /// it; a read of mutable state is [`Access::read`].
    pub fn locked(self) {
        self.declare(ModeExpr::Locked);
    }

    /// A commutative increment or decrement; the amount is dynamic and
    /// never part of the declaration.
    pub fn delta(self) {
        self.declare(ModeExpr::Delta);
    }

    /// A conditional decrement, judged feasible against the declared
    /// amount.
    pub fn reserve(self, amount: &Sym<Amount>) {
        let amount = self.trace.lower(amount.expr().clone());
        self.declare(ModeExpr::Reserve(amount));
    }

    /// An exclusive read-modify-write, on a leaf that may or may not be
    /// there.
    pub fn write(self) {
        self.declare(ModeExpr::Write {
            requires: Presence::Either,
        });
    }
}

/// What a write can require of the leaf it lands on — so, only where the
/// target names one. An interval offers neither, which is what makes a
/// requirement nothing could judge a compile error rather than a publish
/// refusal.
impl Access<'_, Leaf> {
    /// The same write, feasible only where the leaf is absent: the
    /// creation a one-way door is made of.
    pub fn create(self) {
        self.declare(ModeExpr::Write {
            requires: Presence::Absent,
        });
    }

    /// The same write, feasible only where the leaf is there.
    pub fn existing(self) {
        self.declare(ModeExpr::Write {
            requires: Presence::Present,
        });
    }
}

/// What one traced declaration produced.
pub(crate) struct Recorded {
    pub(crate) clauses: Vec<Clause>,
    pub(crate) outputs: Vec<Expr>,
    pub(crate) denominations: Vec<Option<Expr>>,
    pub(crate) worst_case: usize,
    pub(crate) abi: Vec<AbiParam>,
    pub(crate) accessibility: Accessibility,
    pub(crate) issues: Option<Vec<u8>>,
    pub(crate) totality: Totality,
}

/// Binders are recorded at `u32::MAX - depth` so that a lowered index —
/// always small — can never be mistaken for an unlowered one.
fn absolute(depth: usize) -> u32 {
    u32::MAX - u32::try_from(depth).unwrap_or(0)
}

/// Rewrite absolute binder marks into the evaluator's relative indices.
fn rebind(expr: Expr, depth: usize) -> Expr {
    match expr {
        Expr::Binding(mark) => {
            let binder = (u32::MAX - mark) as usize;
            assert!(
                binder < depth,
                "a for-each element escaped its closure: used where {depth} binders are in scope, \
                 bound under {}",
                binder + 1
            );
            Expr::Binding(u32::try_from(depth - 1 - binder).unwrap_or(0))
        }
        Expr::Field(inner, index) => Expr::Field(Box::new(rebind(*inner, depth)), index),
        Expr::ResourceOf(inner) => Expr::ResourceOf(Box::new(rebind(*inner, depth))),
        Expr::IdsOf(inner) => Expr::IdsOf(Box::new(rebind(*inner, depth))),
        Expr::Lookup { map, key } => Expr::Lookup {
            map: Box::new(rebind(*map, depth)),
            key: Box::new(rebind(*key, depth)),
        },
        Expr::Pack { hi, lo } => Expr::Pack {
            hi: Box::new(rebind(*hi, depth)),
            lo: Box::new(rebind(*lo, depth)),
        },
        Expr::NfBucket { resource, ids } => Expr::NfBucket {
            resource: Box::new(rebind(*resource, depth)),
            ids: Box::new(rebind(*ids, depth)),
        },
        Expr::List(elements) => Expr::List(
            elements
                .into_iter()
                .map(|element| rebind(element, depth))
                .collect(),
        ),
        Expr::Tuple(fields) => Expr::Tuple(
            fields
                .into_iter()
                .map(|field| rebind(field, depth))
                .collect(),
        ),
        Expr::SelfResource { material } => Expr::SelfResource {
            material: material
                .into_iter()
                .map(|expr| rebind(expr, depth))
                .collect(),
        },
        Expr::ChildKey {
            owner,
            slot,
            material,
        } => Expr::ChildKey {
            owner: Box::new(rebind(*owner, depth)),
            slot,
            material: material.into_iter().map(|m| rebind(m, depth)).collect(),
        },
        Expr::OrderKey {
            owner,
            slot,
            material,
        } => Expr::OrderKey {
            owner: Box::new(rebind(*owner, depth)),
            slot,
            material: material.into_iter().map(|m| rebind(m, depth)).collect(),
        },
        Expr::Not(inner) => Expr::Not(Box::new(rebind(*inner, depth))),
        Expr::And(left, right) => Expr::And(
            Box::new(rebind(*left, depth)),
            Box::new(rebind(*right, depth)),
        ),
        Expr::Or(left, right) => Expr::Or(
            Box::new(rebind(*left, depth)),
            Box::new(rebind(*right, depth)),
        ),
        Expr::Eq(left, right) => Expr::Eq(
            Box::new(rebind(*left, depth)),
            Box::new(rebind(*right, depth)),
        ),
        Expr::Lt(left, right) => Expr::Lt(
            Box::new(rebind(*left, depth)),
            Box::new(rebind(*right, depth)),
        ),
        Expr::Contains { map, key } => Expr::Contains {
            map: Box::new(rebind(*map, depth)),
            key: Box::new(rebind(*key, depth)),
        },
        Expr::If {
            cond,
            then,
            otherwise,
        } => Expr::If {
            cond: Box::new(rebind(*cond, depth)),
            then: Box::new(rebind(*then, depth)),
            otherwise: Box::new(rebind(*otherwise, depth)),
        },
        leaf @ (Expr::Literal(_)
        | Expr::Arg(_)
        | Expr::Config(_)
        | Expr::SelfAddr
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. }) => leaf,
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{
        Accessibility, Clause, Expr, ParamType, RuleExpr, SlotId, TargetExpr,
    };

    use super::{MAX_FOREACH_ELEMENTS, Trace, absolute, rebind};
    use crate::sym::{Addr, Amount, Key, Opaque, Seq, Sym};

    #[test]
    fn a_binder_lowers_to_its_de_bruijn_index() {
        // Outermost binder, used one level deeper, is index 1.
        let outer = Expr::Binding(absolute(0));
        assert_eq!(rebind(outer.clone(), 1), Expr::Binding(0));
        assert_eq!(rebind(outer, 2), Expr::Binding(1));
        // Innermost binder is always index 0.
        assert_eq!(rebind(Expr::Binding(absolute(1)), 2), Expr::Binding(0));
    }

    #[test]
    #[should_panic(expected = "escaped its closure")]
    fn a_binder_used_outside_its_scope_is_rejected() {
        rebind(Expr::Binding(absolute(0)), 0);
    }

    /// A threshold names its branches in order and keeps the count it was
    /// given, so what a fixed admin set declares is the rule a stored one
    /// would have been — the same algebra on the side that declares.
    #[test]
    fn a_declared_threshold_lowers_to_the_rule_it_names() {
        let mut trace = Trace::new(vec![]);
        let admins: Vec<Sym<Addr>> = (0..3).map(|slot| trace.config(slot)).collect();
        trace.guarded_by_threshold(2, &admins);

        let Accessibility::Guarded(RuleExpr::CountOf { count, rules }) =
            trace.finish().accessibility
        else {
            panic!("a threshold declares a counted rule");
        };
        assert_eq!(count, 2);
        assert_eq!(
            rules,
            (0..3)
                .map(|slot| RuleExpr::Require(Expr::Config(slot)))
                .collect::<Vec<_>>(),
            "the branches keep the order they were named in"
        );
    }

    /// One leaf is the degenerate case of the same constructor, so the
    /// single-identity spelling stays a `Require` rather than a threshold
    /// of one — a stored rule the decode gate would refuse to widen.
    #[test]
    fn a_single_identity_guard_is_not_a_threshold() {
        let mut trace = Trace::new(vec![]);
        let owner = trace.self_addr();
        trace.guarded(&owner);
        assert_eq!(
            trace.finish().accessibility,
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfAddr))
        );
    }

    #[test]
    fn fresh_slots_are_unique_within_a_signature() {
        let mut trace = Trace::new(vec![]);
        let a = trace.fresh_key();
        let b = trace.fresh_id();
        let c = trace.fresh_key();
        assert_eq!(a.expr(), &Expr::FreshKey { slot: 0 });
        assert_eq!(b.expr(), &Expr::FreshId { slot: 1 });
        assert_eq!(c.expr(), &Expr::FreshKey { slot: 2 });
    }

    #[test]
    #[should_panic(expected = "declared u128 but read as address")]
    fn an_argument_read_at_the_wrong_kind_is_rejected() {
        let trace = Trace::new(vec![ParamType::U128]);
        let _: Sym<Addr> = trace.arg(0);
    }

    #[test]
    fn nested_for_each_bodies_carry_both_binders() {
        let mut trace = Trace::new(vec![]);
        let outer: Sym<Seq> = trace.config(0);
        trace.for_each(&outer, |t, group| {
            let inner: Sym<Seq> = group.clone().cast();
            t.for_each(&inner, |t, item| {
                // `group` is the outer binder, `item` the inner one.
                let owner = t.self_addr();
                let key: Sym<Key> = owner.child(SlotId(1), &[item, group.clone()]);
                t.point(&key).write();
            });
        });

        let recorded = trace.finish();
        let Clause::ForEach { body, .. } = &recorded.clauses[0] else {
            panic!("expected a for-each")
        };
        let Clause::ForEach { body, .. } = &body[0] else {
            panic!("expected a nested for-each")
        };
        let Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey { material, .. }),
            ..
        } = &body[0]
        else {
            panic!("expected a point write on a child key")
        };
        assert_eq!(material[0], Expr::Binding(0), "the inner element");
        assert_eq!(material[1], Expr::Binding(1), "the outer element");
    }

    #[test]
    fn the_worst_case_folds_for_each_width() {
        let mut trace = Trace::new(vec![]);
        let list: Sym<Seq> = trace.config(0);
        let flat: Sym<Key> = trace.config(1);
        trace.point(&flat).read();
        trace.for_each(&list, |t, item| {
            let key: Sym<Key> = item.cast();
            t.point(&key).write();
        });
        let recorded = trace.finish();
        // One effect at depth 0, one at depth 1 worth `MAX_FOREACH_ELEMENTS`.
        assert_eq!(recorded.worst_case, 1 + MAX_FOREACH_ELEMENTS);
    }

    #[test]
    fn a_range_lowers_its_bounds() {
        let mut trace = Trace::new(vec![ParamType::U128]);
        let owner = trace.self_addr();
        let lo: Sym<Amount> = trace.arg(0);
        let hi: Sym<Amount> = trace.config(0);
        trace.range(&owner, SlotId(4), &[], &lo, &hi, 32).write();
        let recorded = trace.finish();
        assert!(matches!(
            &recorded.clauses[0],
            Clause::Effect {
                target: TargetExpr::Range { cap: 32, .. },
                ..
            }
        ));
    }

    #[test]
    fn opaque_arguments_skip_the_kind_check() {
        let trace = Trace::new(vec![ParamType::Bytes]);
        let _: Sym<Opaque> = trace.arg(0);
    }
}

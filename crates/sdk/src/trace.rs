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
//! - **Fresh slots.** [`Expr::FreshId`] slots must be unique within a
//!   signature. A counter cannot get that wrong.
//! - **The structural bounds.** [`MAX_EXPR_DEPTH`] and
//!   [`MAX_CLAUSE_DEPTH`] are checked here, at build time, rather than at
//!   routing time — where the package is already published and every call
//!   to the method fails.
//!
//! Trace-time violations panic. That is the right severity: the tracer runs
//! in a build step, and every condition it rejects would otherwise become a
//! published contract whose method can never be called.

use std::collections::BTreeMap;

use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, GrantedBehaviour, GrantsExpr, Issuance, Issued, MAX_CLAUSE_DEPTH,
    MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, MAX_RULE_DEPTH, ModeExpr, ParamType, ResourceKind,
    RuleExpr, RuleLeaf, SlotId, SlotRef, TargetExpr, Totality, Value, well_formed,
};
use hyperscale_vm_types::{Moves, Presence};

use crate::sym::{Addr, Flag, Key, Kind, Opaque, Seq, Sym, U64, U128, expr_depth};

/// One node of a gate's rule, built through the tracer.
///
/// Opaque, and deliberately: a rule's shape is static — only its leaves
/// evaluate — so what an author composes is a tree the tracer built and
/// held to the vocabulary's caps as it went, never one a body assembled.
#[derive(Clone, Debug)]
pub struct Requirement(RuleExpr);

/// The recorder a declaration is traced against.
///
/// Handed to the declaration closure; every symbolic input comes from it,
/// and every emitted clause lands in it.
pub struct Trace {
    /// The method's socket kinds, checked against every
    /// [`Trace::arg`].
    params: Vec<ParamType>,
    /// Clause scopes, innermost last; `scopes[0]` is the method body.
    scopes: Vec<Vec<Clause>>,
    /// The conditions clauses are being declared under, innermost last,
    /// each already conjoined with the ones enclosing it.
    guards: Vec<Expr>,
    /// The next unused fresh-derivation slot.
    next_slot: u32,
    /// The rules each of the package's own marks grants, by mark. Read by
    /// every site that names one of the instance's resources, so one
    /// registration fixes the address all of them derive.
    grants: BTreeMap<Vec<u8>, GrantsExpr>,
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
    /// The clause verdicts the export takes, after the handles and
    /// before the values — the order [`Trace::abi`] assembles them in.
    flags: Vec<AbiParam>,
    /// The value bindings, in the order the body needs them.
    values: Vec<AbiParam>,
    /// The top-level clause most recently declared, which is the one
    /// [`Trace::bind_handle`] names.
    last_clause: Option<u32>,
    /// The position in the open loop's body of the site most recently
    /// declared there, which is the one [`Trace::bind_looped`] names.
    last_site: Option<u32>,
    /// The resource this method may issue: its mark and its kind.
    /// The slot of the rule cell this method is gated on and also
    /// writes, which is lowered only once the body has been.
    pending_governed: Option<SlotId>,
    issues: Vec<Issuance>,
    destroys: Vec<u32>,
    /// Whether the method carries an error arm.
    totality: Totality,
    /// Whether the method hands back a value beside its edges.
    answers: bool,
}

impl Trace {
    pub(crate) fn new(params: Vec<ParamType>) -> Self {
        Self {
            denominations: vec![None; params.len()],
            params,
            scopes: vec![Vec::new()],
            next_slot: 0,
            grants: BTreeMap::new(),
            outputs: Vec::new(),
            guards: Vec::new(),
            flags: Vec::new(),
            worst_case: 0,
            handles: Vec::new(),
            values: Vec::new(),
            last_clause: None,
            last_site: None,
            pending_governed: None,
            issues: Vec::new(),
            destroys: Vec::new(),
            totality: Totality::Infallible,
            answers: false,
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

    /// Lower the slot a key is derived under, where an argument names
    /// it rather than the declaration.
    fn lower_slot(&self, slot: SlotRef) -> SlotRef {
        match slot {
            SlotRef::Fixed(slot) => SlotRef::Fixed(slot),
            SlotRef::Reached(expr) => SlotRef::Reached(Box::new(self.lower(*expr))),
        }
    }

    /// Lower a sequence of key material, in the order it is folded.
    fn lower_all(&self, material: &[Sym<Opaque>]) -> Vec<Expr> {
        material
            .iter()
            .map(|m| self.lower(m.expr().clone()))
            .collect()
    }

    /// The clause under whatever guard is in scope.
    fn guarded(&self, clause: Clause) -> Clause {
        let Some(cond) = self.guards.last() else {
            return clause;
        };
        let guard = Some(Box::new(cond.clone()));
        match clause {
            Clause::Effect {
                reach,
                target,
                mode,
                denomination,
                ..
            } => Clause::Effect {
                reach,
                guard,
                target,
                mode,
                denomination,
            },
            Clause::ForEach { list, body, .. } => Clause::ForEach { guard, list, body },
            Clause::Requires { rule, .. } => Clause::Requires { guard, rule },
            Clause::Mints { claim, .. } => Clause::Mints { guard, claim },
        }
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
        let clause = self.guarded(clause);
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
        // `AbiParam::Handle` names a site by its position in the body of the
        // loop directly enclosing it, so only that depth marks one.
        if self.depth() == 1 {
            self.last_site = effect.then_some(index);
        }
    }

    /// The `index`-th manifest argument bound to this call.
    ///
    /// # Panics
    ///
    /// If `index` is past the sockets, or if `K` names a
    /// different kind than the parameter list does.
    #[must_use]
    pub fn arg<K: Kind>(&self, index: u32) -> Sym<K> {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the socket list"));
        if let Some(claimed) = K::PARAM {
            // The symbolic vocabulary has one address kind, so a claim of
            // `Addr` is compatible with every declared narrowing of it.
            let compatible =
                claimed == declared || (claimed == ParamType::Address && declared.is_address());
            assert!(
                compatible,
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
    /// The record admission resolved the target with answers it, so a
    /// declaration consults configuration without declaring anything and
    /// stays pure.
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
    ///
    /// The rules the resource grants ride the derivation, because the
    /// address is the hash of them too — and they are read from what
    /// [`Trace::grants`] registered rather than supplied here, so a gate
    /// naming this resource and the mint that issues it cannot disagree
    /// about which resource they mean.
    #[must_use]
    pub fn self_resource(&self, kind: ResourceKind, mark: &[u8]) -> Sym<Addr> {
        let material = vec![Expr::Literal(Value::Bytes(mark.to_vec()))];
        Sym::new(Expr::SelfResource {
            kind,
            material,
            grants: self.grants_for(mark),
        })
    }

    /// Register the rules one of the package's own marks grants.
    ///
    /// Stated once for the declaration rather than at each site that
    /// names the resource, because it is a property of the package: the
    /// address folds these rules, so a site that named the resource
    /// without them would name a different one. Every site reads what is
    /// registered here, so there is one answer to disagree with.
    pub fn grant(&mut self, mark: &[u8], rules: GrantsExpr) {
        self.grants.insert(mark.to_vec(), rules);
    }

    /// What `mark` grants, or the empty set — which is what every
    /// ungranting resource's address already folds.
    fn grants_for(&self, mark: &[u8]) -> GrantsExpr {
        self.grants.get(mark).cloned().unwrap_or_default()
    }

    /// A deterministic fresh 64-bit id, in the next unused slot.
    #[must_use]
    pub const fn fresh_id(&mut self) -> Sym<U64> {
        let slot = self.take_slot();
        Sym::new(Expr::FreshId { slot })
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
            reach: None,
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
        collection: impl Into<SlotRef>,
        material: &[Sym<Opaque>],
        order: &Sym<U128>,
    ) -> Access<'_, Leaf> {
        let target = TargetExpr::Entry {
            owner: self.lower(owner.expr().clone()),
            collection: self.lower_slot(collection.into()),
            material: self.lower_all(material),
            order: self.lower(order.expr().clone()),
        };
        Access {
            trace: self,
            target,
            denomination: None,
            reach: None,
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
    pub fn order_key<K: Kind>(&self, collection: SlotId, key: &Sym<K>) -> Sym<U128> {
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
            collection: SlotRef::Fixed(collection),
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
            reach: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare accesses to an unordered collection's tail from `cursor`:
    /// the interval `[cursor, u128::MAX]`, capped at `cap` entries.
    ///
    /// Hash order is arbitrary but canonical, so walking it from a cursor
    /// visits every entry exactly once across resumptions — the
    /// pagination-crank shape. The caller passes the cursor as an
    /// argument; `0` starts the walk. The cap evaluates like the cursor,
    /// so the page a sweep reads can be the caller's choice, priced as
    /// the depth it buys.
    #[must_use]
    pub fn sweep(
        &mut self,
        owner: &Sym<Addr>,
        collection: SlotId,
        cursor: &Sym<U128>,
        cap: &Sym<U64>,
    ) -> Access<'_, Interval> {
        let target = TargetExpr::Range {
            owner: self.lower(owner.expr().clone()),
            collection: SlotRef::Fixed(collection),
            material: vec![],
            lo: self.lower(cursor.expr().clone()),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: self.lower(cap.expr().clone()),
        };
        Access {
            trace: self,
            target,
            denomination: None,
            reach: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare accesses to an interval of a collection's order-key space.
    ///
    /// `cap` bounds the entries execution may touch and evaluates like
    /// the bounds beside it. [`hyperscale_vm_effects::footprint`] charges
    /// the interval's own magnitude as the exclusion it is and the cap as
    /// the walk it buys, so a range wider or deeper than the method needs
    /// is priced as what it claims.
    #[must_use]
    pub fn range(
        &mut self,
        owner: &Sym<Addr>,
        collection: impl Into<SlotRef>,
        material: &[Sym<Opaque>],
        lo: &Sym<U128>,
        hi: &Sym<U128>,
        cap: &Sym<U64>,
    ) -> Access<'_, Interval> {
        let target = TargetExpr::Range {
            owner: self.lower(owner.expr().clone()),
            collection: self.lower_slot(collection.into()),
            material: self.lower_all(material),
            lo: self.lower(lo.expr().clone()),
            hi: self.lower(hi.expr().clone()),
            cap: self.lower(cap.expr().clone()),
        };
        Access {
            trace: self,
            target,
            denomination: None,
            reach: None,
            shape: core::marker::PhantomData,
        }
    }

    /// Declare every access `body` reaches under the condition `cond`.
    ///
    /// Clauses land in whatever scope encloses them, so a guard written
    /// inside a `for-each` guards clauses in the loop's body and one at
    /// the top level guards top-level clauses. Nesting folds into the
    /// condition rather than into the tree — `if a { if b { … } }`
    /// guards on their conjunction — so nothing about clause depth
    /// changes and every clause index means what it meant.
    pub fn when<F>(&mut self, cond: &Sym<Flag>, body: F)
    where
        F: FnOnce(&mut Self),
    {
        // Evaluated in the enclosing scope, like a `for-each`'s list:
        // the condition reads the inputs the clauses under it read.
        let cond = self.lower(cond.expr().clone());
        let conjoined = match self.guards.last() {
            Some(outer) => Expr::And(Box::new(outer.clone()), Box::new(cond)),
            None => cond,
        };
        self.guards.push(conjoined);
        body(self);
        self.guards.pop();
    }

    /// Bind the verdict of the clause just declared as a `bool` the
    /// export takes.
    ///
    /// What the guest branches on: the declaration's own evaluation,
    /// reached once by routing, rather than a second copy of the
    /// condition for the two to agree by convention.
    ///
    /// # Panics
    ///
    /// If no clause has been declared for it to name, or if the enclosing
    /// scope is a `for-each`, whose clause count is the instance's rather
    /// than the signature's.
    pub fn bind_guard(&mut self) {
        assert_eq!(
            self.depth(),
            0,
            "a branch inside a for-each declares a configuration-dependent number of \
             clauses, so its verdict cannot occupy a fixed export parameter"
        );
        let clause = self
            .last_clause
            .expect("a guard binding names the clause just declared, and none is");
        self.flags.push(AbiParam::Guard(clause));
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
            guard: None,
            list: list_expr,
            body: inner,
        });
    }

    /// Bind the site just declared inside a `for-each` as the next of
    /// the guest's handle parameters.
    ///
    /// One parameter for the whole expansion, so the export's arity is a
    /// function of the signature whether or not a site sits under a loop
    /// — the width the loop maps over is the instance's, and the guest
    /// asks the site for it.
    ///
    /// # Panics
    ///
    /// If no `for-each` is open, if one is open more than one deep, or if
    /// the clause just declared inside it is not an access.
    pub fn bind_looped(&mut self) {
        assert_eq!(
            self.depth(),
            1,
            "a site inside a loop is declared directly inside one `for-each`"
        );
        let clause = u32::try_from(
            self.scopes
                .first()
                .expect("the method scope is never popped")
                .len(),
        )
        .unwrap_or(u32::MAX);
        let site = self
            .last_site
            .expect("a handle binding names the site just declared, and none is");
        self.handles.push(AbiParam::Handle { clause, site });
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
        self.handles.push(AbiParam::Handle { clause, site: 0 });
    }

    /// Bind the `index`-th socket's edge, which must be one.
    ///
    /// Either edge kind binds the same way — what separates them is the
    /// cell they cross as, and that is the callee's declaration rather
    /// than anything the binding sees.
    ///
    /// # Panics
    ///
    /// If `index` is past the sockets or names a kind that is
    /// not an edge — the one value a signature cannot derive.
    pub fn bind_bucket(&mut self, index: u32) {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the socket list"));
        assert!(
            declared.is_edge(),
            "argument {index} is declared {} and carries no value",
            declared.name()
        );
        self.values.push(AbiParam::Bucket(index));
    }

    /// Record this method's issuance grant, for the resource `mark`
    /// names.
    ///
    /// Called by generated code where a body issues or destroys. The mark
    /// is the material separating one of the instance's own resources
    /// from its others, so what a method may create is fixed by the
    /// declaration and cannot be another instance's; the kind and the
    /// rules the mark grants ride with it because the grant's derivation
    /// folds both.
    ///
    /// The direction is the body's own fact, folded across every issuing
    /// call the walk found: what a frame declares it does is what the
    /// resource's entries hold it to, so a burn-only method is never
    /// asked who may mint.
    ///
    /// Called once per mark the body issues, in the order the lowering
    /// reached them — which is the index each of its calls passes, so a
    /// component founding three resources says which of them it means.
    ///
    /// No binding follows it: the grants are the invocation's, so
    /// nothing crosses the boundary to say so and the export's parameter
    /// list is the same whether a method issues or not.
    pub fn bind_issuer(&mut self, kind: ResourceKind, mark: &[u8], direction: Issued) {
        self.issues.push(Issuance {
            mark: mark.to_vec(),
            kind,
            direction,
            grants: self.grants_for(mark),
        });
    }

    /// Record that this method destroys the edge at `param`.
    ///
    /// Called by generated code where a body destroys value it was
    /// handed rather than value it issues. What separates the two is
    /// whose resource it is: an issuance names a mark this instance
    /// derives, and this names a parameter, so the resource is the
    /// caller's to choose and the rule that admits it is the resource's
    /// own — resolved at admission from the record the caller presented.
    pub fn bind_destroyer(&mut self, param: u32) {
        if !self.destroys.contains(&param) {
            self.destroys.push(param);
        }
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

    /// Record that this method hands back a value beside its edges.
    pub const fn answers(&mut self) {
        self.answers = true;
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

    /// The requirement that the claim `identity` evaluates to is
    /// presented.
    #[must_use]
    pub fn claim(&self, identity: &Sym<Addr>) -> Requirement {
        Requirement(RuleExpr::claim(self.lower(identity.expr().clone())))
    }

    /// The requirement that `count` of `branches` are met.
    ///
    /// One constructor for the whole algebra: a count of one is
    /// disjunction, a count of the branch width is conjunction, and
    /// anything between is the threshold a fixed admin set is written as
    /// — three configured badge instances gated at two, rotated by
    /// issuing and revoked by burning, with no redeploy and no
    /// configuration slot per admin.
    ///
    /// # Panics
    ///
    /// On a tree past the vocabulary's caps, or a threshold nobody meant:
    /// a count of zero admits anyone and a count past the branch width
    /// admits no one. Refused here, on the line that wrote it, rather
    /// than at publish where the shape is all that is left.
    #[must_use]
    pub fn n_of(&self, count: u8, branches: Vec<Requirement>) -> Requirement {
        let rule = RuleExpr::CountOf {
            count,
            rules: branches.into_iter().map(|branch| branch.0).collect(),
        };
        // The node's shape is judged by the vocabulary's own predicate —
        // the one the decode gate and the macro's lowering also apply —
        // so what this refuses cannot fork from what they refuse.
        if let Err(reason) = well_formed(&rule) {
            panic!("{reason}");
        }
        assert!(
            rule.within_caps(0),
            "the rule nests past the {MAX_RULE_DEPTH} the vocabulary admits"
        );
        Requirement(rule)
    }

    /// Record that naming this method requires meeting `rule`.
    pub fn guarded_by(&mut self, rule: Requirement) {
        self.emit(Clause::Requires {
            guard: None,
            rule: rule.0,
        });
    }

    /// Record that naming this method requires satisfying the target's
    /// own stored rule — read through the cell the last emitted clause
    /// declared — and mints the target's identity.
    pub fn authorizing(&mut self) {
        let cell = self.last_point_target();
        self.emit(Clause::Requires {
            guard: None,
            rule: governs(cell),
        });
        self.emit(Clause::Mints {
            guard: None,
            claim: Expr::SelfAddr,
        });
    }

    /// Record that naming this method is governed by the rule stored at
    /// the cell the last emitted clause declared.
    pub fn governed_by(&mut self) {
        let cell = self.last_point_target();
        self.emit(Clause::Requires {
            guard: None,
            rule: governs(cell),
        });
    }

    /// The same, deferred to [`Trace::finish`]: a method that rewrites
    /// the very cell its rule is read from has not lowered that write
    /// yet, and the write is also what serialises a rewrite against a
    /// concurrent sign-in.
    pub const fn governed_by_what_it_writes(&mut self, slot: SlotId) {
        self.pending_governed = Some(slot);
    }

    /// Record that naming this method requires the target's own rule and
    /// its possession of some of the fungible badge `badge`, and mints
    /// that badge's address.
    ///
    /// The rule cell and the possession cell are the two reads the
    /// caller just declared, in that order, so the conditions are keyed
    /// by exactly the expressions the mint names.
    pub fn custodial(&mut self, badge: &Sym<Addr>) {
        let badge = self.lower(badge.expr().clone());
        self.custody(badge.clone());
        self.emit(Clause::Mints {
            guard: None,
            claim: badge,
        });
    }

    /// Record that naming this method requires the target's own rule and
    /// its possession of instance `id` of `badge`, and mints both that
    /// instance and the badge it is an instance of.
    pub fn custodial_instance(&mut self, badge: &Sym<Addr>, id: &Sym<U128>) {
        let badge = self.lower(badge.expr().clone());
        let id = self.lower(id.expr().clone());
        self.custody(badge.clone());
        self.emit(Clause::Mints {
            guard: None,
            claim: Expr::Tuple(vec![badge, id]),
        });
    }

    /// The custody conditions over the two reads just declared: the
    /// stored primary at the rule cell, and possession at the cell the
    /// last clause names.
    fn custody(&mut self, _badge: Expr) {
        let (rule_cell, possession) = self.last_two_targets();
        self.emit(Clause::Requires {
            guard: None,
            rule: governs(rule_cell),
        });
        self.emit(Clause::Requires {
            guard: None,
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(possession),
                expect: Presence::Present,
            }),
        });
    }

    /// The point expression of the last emitted top-level effect clause.
    fn last_point_target(&self) -> Expr {
        let scope = self.scopes.last().expect("the method scope stands");
        match scope.last() {
            Some(Clause::Effect {
                reach: None,
                target: TargetExpr::Point(cell),
                ..
            }) => cell.clone(),
            _ => panic!("a rule-reading gate declares its cell first"),
        }
    }

    /// The point expression and whole target of the last two emitted
    /// top-level effect clauses, in emission order.
    fn last_two_targets(&self) -> (Expr, TargetExpr) {
        let scope = self.scopes.last().expect("the method scope stands");
        let len = scope.len();
        match (scope.get(len.wrapping_sub(2)), scope.get(len - 1)) {
            (
                Some(Clause::Effect {
                    reach: None,
                    target: TargetExpr::Point(cell),
                    ..
                }),
                Some(Clause::Effect {
                    reach: None,
                    target,
                    ..
                }),
            ) => (cell.clone(), target.clone()),
            _ => panic!("a custody gate declares its rule read and its possession read first"),
        }
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
    /// If `index` is past the sockets, names a kind that
    /// carries no value, or already carries a different resource — a
    /// parameter credited to two cells that cannot both be right is a
    /// declaration with no satisfying call.
    pub fn denomination(&mut self, index: u32, resource: &Sym<Addr>) {
        let declared = *self
            .params
            .get(index as usize)
            .unwrap_or_else(|| panic!("argument {index} is past the socket list"));
        assert!(
            declared.is_edge(),
            "argument {index} is declared {} and carries no value to denominate",
            declared.name()
        );
        let expr = self.lower(resource.expr().clone());
        let guard = self.guards.last().cloned();
        let slot = &mut self.denominations[index as usize];
        match (slot.take(), guard) {
            // Two unguarded expressions on one edge is a body that means
            // two things, whatever order they were written in.
            (Some(held), None) => {
                assert!(
                    held == expr,
                    "argument {index} is credited to cells keyed by {held:?} and by {expr:?}, \
                     and no edge carries both"
                );
                *slot = Some(held);
            }
            // Under a guard they are the arms of one selection, so they
            // fold into one expression rather than contradicting. Still
            // exactly one expression, so what a caller reads off the
            // signature stays exact rather than widening to a set.
            (Some(held), Some(cond)) => {
                *slot = Some(Expr::If {
                    cond: Box::new(cond),
                    then: Box::new(expr),
                    otherwise: Box::new(held),
                });
            }
            // A parameter credited under a guard and nowhere else records
            // its guarded expression as though it were unconditional: the
            // promise is what a caller's edge must satisfy, and stating it
            // unconditionally over-constrains admission rather than
            // under-constraining it.
            (None, _) => *slot = Some(expr),
        }
    }

    /// Consume the trace into what it recorded.
    pub(crate) fn finish(mut self) -> Recorded {
        assert_eq!(
            self.scopes.len(),
            1,
            "a for-each scope outlived its closure"
        );
        let mut clauses = self.scopes.pop().unwrap_or_default();
        // A method gated on the cell it rewrites states its rule once the
        // body has been lowered: the write that serialises a rewrite
        // against a concurrent sign-in is also what names the cell.
        if let Some(slot) = self.pending_governed {
            // The gate names its own slot, so it reads its rule from the
            // write on that cell rather than from whichever write the
            // body happens to make first — which is what lets a method
            // gated on one rule write others beside it.
            let cell = clauses
                .iter()
                .find_map(|clause| match clause {
                    Clause::Effect {
                        reach: None,
                        target: TargetExpr::Point(cell),
                        mode: ModeExpr::Write { .. },
                        ..
                    } if matches!(
                        cell,
                        Expr::ChildKey { slot: at, .. } if at.fixed() == Some(slot)
                    ) =>
                    {
                        Some(cell.clone())
                    }
                    _ => None,
                })
                .expect("a method gated on what it writes writes its rule cell");
            clauses.push(Clause::Requires {
                guard: None,
                rule: governs(cell),
            });
        }
        let mut abi = self.handles;
        abi.extend(self.flags);
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
            answers: self.answers,
            worst_case: self.worst_case,
            abi,
            issues: self.issues,
            destroys: self.destroys,
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
    reach: Option<GrantedBehaviour>,
    shape: core::marker::PhantomData<fn() -> Shape>,
}

impl<Shape> Access<'_, Shape> {
    fn declare(self, mode: ModeExpr) {
        self.trace.emit(Clause::Effect {
            reach: self.reach,
            guard: None,
            target: self.target,
            mode,
            denomination: self.denomination,
        });
    }

    /// Declare that this access reaches a prefix that is not the
    /// declaring instance's own, under `behaviour`.
    ///
    /// What the reach costs is shape: the target is keyed first by a
    /// resource, and that resource's entry for `behaviour` is injected
    /// at admission and judged against what the call presented. The
    /// package writes down which authority it is acting under; who holds
    /// that authority is the resource's answer and never this
    /// declaration's.
    #[must_use]
    pub const fn reaching(mut self, behaviour: GrantedBehaviour) -> Self {
        self.reach = Some(behaviour);
        self
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
    /// writes.
    pub fn read(self) {
        self.declare(ModeExpr::Read);
    }

    /// A commutative increment or decrement; the amount is dynamic and
    /// never part of the declaration.
    pub fn delta(self) {
        self.declare(ModeExpr::Delta);
    }

    /// A commutative increment and no decrement — what a method that
    /// only receives says about itself.
    ///
    /// Worth saying because a declaration that carries its direction is
    /// judged on the movement it makes: a resource governing withdrawals
    /// asks nothing of a credit, where a bidirectional access has to
    /// answer for the debit it might have made.
    pub fn credit(self) {
        self.declare(ModeExpr::Credit);
    }

    /// A conditional decrement, judged feasible against the declared
    /// amount.
    pub fn reserve(self, amount: &Sym<U128>) {
        let amount = self.trace.lower(amount.expr().clone());
        self.declare(ModeExpr::Reserve(amount));
    }

    /// An exclusive read-modify-write, on a leaf that may or may not be
    /// there.
    pub fn write(self) {
        self.declare(ModeExpr::Write { moves: Moves::Both });
    }

    /// The same exclusive hold, filing only: value may arrive under it
    /// and may not leave.
    ///
    /// What a collection has instead of a credit. The contention is a
    /// write's either way — an exclusive hold excludes everything — so
    /// what this gives up is nothing a scheduler reads, and what it buys
    /// is being judged on the movement it actually makes: a body that
    /// only receives is not asked for the credential a sender needs.
    pub fn file(self) {
        self.declare(ModeExpr::Write { moves: Moves::In });
    }
}

/// What a write can require of the leaf it lands on — so, only where the
/// target names one. An interval offers neither: a presence over one is
/// a fact about the interval as a whole, which says nothing about the
/// entries a write chooses at execution, so the pairing is a type error
/// rather than a requirement that judges the wrong thing.
///
/// The requirement is a condition clause beside the write, not a mode
/// parameter. It is emitted first, so the write stays the clause its
/// site's handle binding names.
impl Access<'_, Leaf> {
    /// The same write, feasible only where the leaf is absent: the
    /// creation a one-way door is made of.
    pub fn create(self) {
        self.require(Presence::Absent);
    }

    /// The same write, feasible only where the leaf is there.
    pub fn existing(self) {
        self.require(Presence::Present);
    }

    /// A fresh read, feasible only where the leaf is absent — and
    /// reading nothing from it.
    ///
    /// The read-side presence, and the reason it exists is contention: a
    /// requirement carried by the exclusive mode makes every caller
    /// queue behind every other, so a body gating a commutative
    /// operation on a fact would stop being commutative by saying so.
    /// A fresh read excludes nobody and still cannot be admitted where
    /// the leaf is there.
    pub fn vacant(mut self) {
        self.presence(Presence::Absent);
        self.declare(ModeExpr::Read);
    }

    fn require(mut self, presence: Presence) {
        self.presence(presence);
        self.declare(ModeExpr::Write { moves: Moves::Both });
    }

    fn presence(&mut self, presence: Presence) {
        self.trace.emit(Clause::Requires {
            guard: None,
            rule: RuleExpr::Require(RuleLeaf::Presence {
                target: Box::new(self.target.clone()),
                expect: presence,
            }),
        });
    }
}

/// The rule that governs a cell: what is stored there, or — while
/// nothing is — the identity that address itself derives.
///
/// The fallback is a rule rather than something the kernel supplies,
/// which is what lets a key-derived address govern itself before it has
/// any state and lets a package wanting a different answer write a
/// different rule. It is also the one-way door said out loud: once a rule
/// is stored, the branch admitting the bare address can never be met
/// again, because the cell is no longer absent.
fn governs(cell: Expr) -> RuleExpr {
    RuleExpr::CountOf {
        count: 1,
        rules: vec![
            RuleExpr::Require(RuleLeaf::Stored { cell: cell.clone() }),
            RuleExpr::CountOf {
                count: 2,
                rules: vec![
                    RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(TargetExpr::Point(cell)),
                        expect: Presence::Absent,
                    }),
                    RuleExpr::claim(Expr::SelfAddr),
                ],
            },
        ],
    }
}

/// What one traced declaration produced.
pub(crate) struct Recorded {
    pub(crate) clauses: Vec<Clause>,
    pub(crate) outputs: Vec<Expr>,
    pub(crate) answers: bool,
    pub(crate) denominations: Vec<Option<Expr>>,
    pub(crate) worst_case: usize,
    pub(crate) abi: Vec<AbiParam>,
    pub(crate) issues: Vec<Issuance>,
    pub(crate) destroys: Vec<u32>,
    pub(crate) totality: Totality,
}

/// Binders are recorded at `u32::MAX - depth` so that a lowered index —
/// always small — can never be mistaken for an unlowered one.
fn absolute(depth: usize) -> u32 {
    u32::MAX - u32::try_from(depth).unwrap_or(0)
}

/// Rewrite absolute binder marks into the evaluator's relative indices.
fn rebind_slot(slot: SlotRef, depth: usize) -> SlotRef {
    match slot {
        SlotRef::Fixed(slot) => SlotRef::Fixed(slot),
        SlotRef::Reached(expr) => SlotRef::Reached(Box::new(rebind(*expr, depth))),
    }
}

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
        Expr::Len(inner) => Expr::Len(Box::new(rebind(*inner, depth))),
        Expr::Only(inner) => Expr::Only(Box::new(rebind(*inner, depth))),
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
        Expr::SelfResource {
            kind,
            material,
            grants,
        } => Expr::SelfResource {
            kind,
            material: material
                .into_iter()
                .map(|expr| rebind(expr, depth))
                .collect(),
            grants,
        },
        Expr::ChildKey {
            owner,
            slot,
            material,
        } => Expr::ChildKey {
            owner: Box::new(rebind(*owner, depth)),
            slot: rebind_slot(slot, depth),
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
        Expr::Add(left, right) => pair(Expr::Add, *left, *right, depth),
        Expr::And(left, right) => pair(Expr::And, *left, *right, depth),
        Expr::Or(left, right) => pair(Expr::Or, *left, *right, depth),
        Expr::Eq(left, right) => pair(Expr::Eq, *left, *right, depth),
        Expr::Lt(left, right) => pair(Expr::Lt, *left, *right, depth),
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
        | Expr::SelfRecord
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. }) => leaf,
    }
}

/// One two-operand variant, rebound operand by operand.
fn pair(build: fn(Box<Expr>, Box<Expr>) -> Expr, left: Expr, right: Expr, depth: usize) -> Expr {
    build(
        Box::new(rebind(left, depth)),
        Box::new(rebind(right, depth)),
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Clause, Expr, ParamType, RuleExpr, SlotId, TargetExpr};

    use super::{MAX_FOREACH_ELEMENTS, Trace, absolute, rebind};
    use crate::sym::{Addr, Key, Opaque, Seq, Sym, U64, U128};

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
        let branches = admins.iter().map(|admin| trace.claim(admin)).collect();
        let rule = trace.n_of(2, branches);
        trace.guarded_by(rule);

        let recorded = trace.finish();
        let [
            Clause::Requires {
                rule: RuleExpr::CountOf { count, rules },
                ..
            },
        ] = recorded.clauses.as_slice()
        else {
            panic!("a threshold declares a counted rule");
        };
        let (count, rules) = (*count, rules.clone());
        assert_eq!(count, 2);
        assert_eq!(
            rules,
            (0..3)
                .map(|slot| RuleExpr::claim(Expr::Config(slot)))
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
        let rule = trace.claim(&owner);
        trace.guarded_by(rule);
        assert_eq!(
            trace.finish().clauses,
            vec![Clause::Requires {
                guard: None,
                rule: RuleExpr::claim(Expr::SelfAddr),
            }]
        );
    }

    #[test]
    fn fresh_slots_are_unique_within_a_signature() {
        let mut trace = Trace::new(vec![]);
        let a = trace.fresh_id();
        let b = trace.fresh_id();
        let c = trace.fresh_id();
        assert_eq!(a.expr(), &Expr::FreshId { slot: 0 });
        assert_eq!(b.expr(), &Expr::FreshId { slot: 1 });
        assert_eq!(c.expr(), &Expr::FreshId { slot: 2 });
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
            reach: None,
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
        let mut trace = Trace::new(vec![ParamType::U128, ParamType::U64]);
        let owner = trace.self_addr();
        let lo: Sym<U128> = trace.arg(0);
        let hi: Sym<U128> = trace.config(0);
        let cap: Sym<U64> = trace.arg(1);
        trace.range(&owner, SlotId(4), &[], &lo, &hi, &cap).write();
        let recorded = trace.finish();
        assert!(matches!(
            &recorded.clauses[0],
            Clause::Effect {
                reach: None,
                target: TargetExpr::Range {
                    cap: Expr::Arg(1),
                    ..
                },
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

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
    CallSite, Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, ModeExpr,
    ParamType, RoleId, TargetExpr,
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
    /// The method's static call sites.
    calls: Vec<CallSite>,
    /// The worst-case effect count, folding `for-each` width per nesting
    /// level.
    worst_case: usize,
}

impl Trace {
    pub(crate) fn new(params: Vec<ParamType>) -> Self {
        Self {
            params,
            scopes: vec![Vec::new()],
            next_slot: 0,
            outputs: Vec::new(),
            calls: Vec::new(),
            worst_case: 0,
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
        let scope = self
            .scopes
            .last_mut()
            .expect("the method scope is never popped");
        scope.push(clause);
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
    pub fn point(&mut self, key: &Sym<Key>) -> Access<'_> {
        let target = TargetExpr::Point(self.lower(key.expr().clone()));
        Access {
            trace: self,
            target,
        }
    }

    /// Declare accesses to one ordered-collection entry.
    #[must_use]
    pub fn entry(
        &mut self,
        owner: &Sym<Addr>,
        collection: RoleId,
        order: &Sym<Amount>,
    ) -> Access<'_> {
        let target = TargetExpr::Entry {
            owner: self.lower(owner.expr().clone()),
            collection,
            material: vec![],
            order: self.lower(order.expr().clone()),
        };
        Access {
            trace: self,
            target,
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
        collection: RoleId,
        lo: &Sym<Amount>,
        hi: &Sym<Amount>,
        cap: u32,
    ) -> Access<'_> {
        let target = TargetExpr::Range {
            owner: self.lower(owner.expr().clone()),
            collection,
            material: vec![],
            lo: self.lower(lo.expr().clone()),
            hi: self.lower(hi.expr().clone()),
            cap,
        };
        Access {
            trace: self,
            target,
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

    /// Record a static call to `method` on `target`.
    pub fn call<K: Kind>(&mut self, target: &Sym<Addr>, method: &str, args: &[Sym<K>]) {
        let site = CallSite {
            target: self.lower(target.expr().clone()),
            method: method.to_owned(),
            args: args.iter().map(|a| self.lower(a.expr().clone())).collect(),
        };
        self.calls.push(site);
    }

    /// Consume the trace into what it recorded.
    pub(crate) fn finish(mut self) -> Recorded {
        assert_eq!(
            self.scopes.len(),
            1,
            "a for-each scope outlived its closure"
        );
        let clauses = self.scopes.pop().unwrap_or_default();
        Recorded {
            clauses,
            outputs: self.outputs,
            calls: self.calls,
            worst_case: self.worst_case,
        }
    }
}

/// A target awaiting the mode it is accessed under.
///
/// Splitting target from mode is what makes the declaration read as a
/// sentence — `t.point(vault).write()` — and it makes the mode a required
/// choice: there is no way to name a target without saying how it is
/// touched.
pub struct Access<'a> {
    trace: &'a mut Trace,
    target: TargetExpr,
}

impl Access<'_> {
    fn declare(self, mode: ModeExpr) {
        self.trace.emit(Clause::Effect {
            target: self.target,
            mode,
        });
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

    /// An exclusive read-modify-write.
    pub fn write(self) {
        self.declare(ModeExpr::Write);
    }
}

/// What one traced declaration produced.
pub(crate) struct Recorded {
    pub(crate) clauses: Vec<Clause>,
    pub(crate) outputs: Vec<Expr>,
    pub(crate) calls: Vec<CallSite>,
    pub(crate) worst_case: usize,
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
        Expr::Lookup { map, key } => Expr::Lookup {
            map: Box::new(rebind(*map, depth)),
            key: Box::new(rebind(*key, depth)),
        },
        Expr::Pack { hi, lo } => Expr::Pack {
            hi: Box::new(rebind(*hi, depth)),
            lo: Box::new(rebind(*lo, depth)),
        },
        Expr::SelfResource { material } => Expr::SelfResource {
            material: material
                .into_iter()
                .map(|expr| rebind(expr, depth))
                .collect(),
        },
        Expr::ChildKey {
            owner,
            role,
            material,
        } => Expr::ChildKey {
            owner: Box::new(rebind(*owner, depth)),
            role,
            material: material.into_iter().map(|m| rebind(m, depth)).collect(),
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
    use hyperscale_vm_effects::{Clause, Expr, ParamType, RoleId, TargetExpr};

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
                let key: Sym<Key> = owner.child(RoleId(1), &[item, group.clone()]);
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
        trace.range(&owner, RoleId(4), &lo, &hi, 32).write();
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

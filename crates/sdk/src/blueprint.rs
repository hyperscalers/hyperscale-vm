//! Assembling traced declarations into the metadata routing reads.
//!
//! A [`Blueprint`] is the SDK's unit of authorship: a set of named methods,
//! each with its declared parameters and its traced effect signature. Its
//! [`Blueprint::metadata`] is a [`PackageMetadata`] — the exact structure
//! [`hyperscale_vm_effects::route`] consults, with nothing SDK-shaped left
//! in it.
//!
//! Beside the metadata the blueprint carries a [`HandlePlan`]: the ordered
//! shape of the capability handles the kernel must materialize for a call.
//! The metadata alone does not determine this, and that gap is the part of
//! the design most worth being explicit about — see [`HandlePlan`].

use std::collections::BTreeMap;

use hyperscale_vm_effects::{
    Accessibility, Clause, MAX_EFFECTS_PER_SIGNATURE, MethodSignature, ModeExpr, ModeKind,
    PackageMetadata, ParamType, TargetExpr, Totality,
};

use crate::trace::Trace;

/// What kind of target a handle is opened on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetShape {
    /// One substate leaf.
    Point,
    /// One ordered-collection entry.
    Entry,
    /// An interval of a collection's order-key space.
    Range,
}

/// One handle the guest expects, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandleShape {
    /// The mode, which fixes the resource type in
    /// `hyperscale:kernel/state`: each mode of the lattice is its own
    /// resource, so a handle's type is a proof of its mode.
    pub mode: ModeKind,
    /// What the handle is opened on.
    pub target: TargetShape,
    /// How many `for-each` binders enclose the clause. Zero is exactly one
    /// handle; deeper means a run whose length is only known once the
    /// signature is evaluated.
    pub repeat_depth: usize,
}

/// The ordered handles a method's guest export receives.
///
/// The reason this exists as its own structure, rather than being read off
/// the evaluated effect set: **the two orders differ.**
/// [`hyperscale_vm_effects::EffectSet`] is keyed by target and iterates in
/// canonical `(target, mode)` order — it is a set, and it deduplicates and
/// folds reserves. Declaration order is the order the author wrote, which
/// is the order the guest's parameters are in. A kernel that materialized
/// handles by walking the evaluated set would hand `swap` its two reserve
/// cells in an order determined by how two child-key hashes happen to
/// compare, which is stable but arbitrary and changes with the hasher.
///
/// So the handle order has to be the declaration's, and the evaluated set
/// stays what it is for: routing, conflict, and pricing. That makes this
/// plan part of the published package rather than a derived convenience —
/// the guest ABI depends on it.
///
/// [`HandlePlan::is_static`] is the honest caveat: once a clause sits under
/// a `for-each`, the number of handles depends on configuration, so the
/// guest export cannot take them as fixed parameters and needs a list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandlePlan {
    shapes: Vec<HandleShape>,
}

impl HandlePlan {
    /// The handles, in declaration order.
    #[must_use]
    pub fn shapes(&self) -> &[HandleShape] {
        &self.shapes
    }

    /// Whether every handle's position is fixed — no clause under a
    /// `for-each`. Only a static plan lowers to a fixed guest parameter
    /// list.
    #[must_use]
    pub fn is_static(&self) -> bool {
        self.shapes.iter().all(|s| s.repeat_depth == 0)
    }
}

/// One method: what routing reads, plus what the guest bridge needs.
#[derive(Clone, Debug)]
pub struct Method {
    signature: MethodSignature,
    handles: HandlePlan,
    worst_case: usize,
}

impl Method {
    /// The effect signature, as routing consumes it.
    #[must_use]
    pub const fn signature(&self) -> &MethodSignature {
        &self.signature
    }

    /// The handles the guest export receives, in declaration order.
    #[must_use]
    pub const fn handles(&self) -> &HandlePlan {
        &self.handles
    }

    /// The most effects this signature can declare, over every
    /// configuration.
    ///
    /// The real count depends on the lengths of the lists a `for-each` maps
    /// over — configuration, not declaration — so this is the only bound
    /// knowable at build time. Compare against
    /// [`hyperscale_vm_effects::MAX_EFFECTS_PER_SIGNATURE`].
    #[must_use]
    pub const fn worst_case_effects(&self) -> usize {
        self.worst_case
    }

    /// Whether the worst case fits inside the evaluator's per-signature
    /// allowance.
    ///
    /// A method that fails this is not necessarily broken — it is one whose
    /// safe configurations the author now has to bound themselves, because
    /// the tracer cannot. Worth surfacing at build time either way: the
    /// alternative is discovering it when a particular instance's config
    /// makes every call to the method unroutable.
    #[must_use]
    pub const fn worst_case_fits(&self) -> bool {
        self.worst_case <= MAX_EFFECTS_PER_SIGNATURE
    }
}

/// A contract's methods and their declarations.
#[derive(Clone, Debug, Default)]
pub struct Blueprint {
    methods: BTreeMap<String, Method>,
}

impl Blueprint {
    /// Start a blueprint.
    #[must_use]
    pub fn builder() -> Builder {
        Builder {
            blueprint: Self::default(),
        }
    }

    /// One method by name.
    #[must_use]
    pub fn method(&self, name: &str) -> Option<&Method> {
        self.methods.get(name)
    }

    /// Every method, in name order.
    pub fn methods(&self) -> impl Iterator<Item = (&str, &Method)> {
        self.methods.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// The package metadata routing reads — the whole point of the trace.
    #[must_use]
    pub fn metadata(&self) -> PackageMetadata {
        PackageMetadata {
            methods: self
                .methods
                .iter()
                .map(|(name, m)| (name.clone(), m.signature.clone()))
                .collect(),
            events: Vec::new(),
        }
    }
}

/// Accumulates methods into a [`Blueprint`].
pub struct Builder {
    blueprint: Blueprint,
}

impl Builder {
    /// Trace `declare` as the effect signature of `name`.
    ///
    /// `params` is the manifest-facing parameter list — what a caller binds
    /// in a manifest node. It is independently checkable against the
    /// published component's own type section, so it is the one field of
    /// the signature that never has to be taken on trust.
    ///
    /// # Panics
    ///
    /// If the declaration violates a structural bound, reads an argument at
    /// the wrong kind, or lets a `for-each` element escape its closure. All
    /// three would otherwise become a published method that can never be
    /// called.
    #[must_use]
    pub fn method<F>(mut self, name: &str, params: &[ParamType], declare: F) -> Self
    where
        F: FnOnce(&mut Trace),
    {
        let mut trace = Trace::new(params.to_vec());
        declare(&mut trace);
        let recorded = trace.finish();

        let handles = HandlePlan {
            shapes: plan(&recorded.clauses, 0),
        };
        let method = Method {
            signature: MethodSignature {
                // Three things a trace cannot see: whether the method
                // can decline is its export's result type, who may call
                // it is a claim, and how its arguments are built is the
                // export's parameter list. A body determines none of
                // them, and all three are authored beside the WIT and
                // land on the signature there.
                totality: Totality::Infallible,
                accessibility: Accessibility::default(),
                mints: None,
                params: params.to_vec(),
                abi: Vec::new(),
                outputs: recorded.outputs,
                effects: recorded.clauses,
                calls: recorded.calls,
            },
            handles,
            worst_case: recorded.worst_case,
        };
        self.blueprint.methods.insert(name.to_owned(), method);
        self
    }

    /// Finish the blueprint.
    #[must_use]
    pub fn build(self) -> Blueprint {
        self.blueprint
    }
}

/// Walk the clause tree in declaration order, recording one shape per
/// effect.
fn plan(clauses: &[Clause], depth: usize) -> Vec<HandleShape> {
    let mut shapes = Vec::new();
    for clause in clauses {
        match clause {
            Clause::Effect { target, mode } => shapes.push(HandleShape {
                mode: mode_kind(mode),
                target: target_shape(target),
                repeat_depth: depth,
            }),
            Clause::ForEach { body, .. } => shapes.extend(plan(body, depth + 1)),
        }
    }
    shapes
}

const fn mode_kind(mode: &ModeExpr) -> ModeKind {
    match mode {
        ModeExpr::Read => ModeKind::Read,
        ModeExpr::Locked => ModeKind::Locked,
        ModeExpr::Delta => ModeKind::Delta,
        ModeExpr::Reserve(_) => ModeKind::Reserve,
        ModeExpr::Write => ModeKind::Write,
    }
}

const fn target_shape(target: &TargetExpr) -> TargetShape {
    match target {
        TargetExpr::Point(_) => TargetShape::Point,
        TargetExpr::Entry { .. } => TargetShape::Entry,
        TargetExpr::Range { .. } => TargetShape::Range,
    }
}

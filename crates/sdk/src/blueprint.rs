//! Assembling traced declarations into the metadata routing reads.
//!
//! A [`Blueprint`] is the SDK's unit of authorship: a set of named methods,
//! each with its declared parameters and its traced effect signature. Its
//! [`Blueprint::metadata`] is a [`PackageMetadata`] — the exact structure
//! [`hyperscale_vm_effects::route`] consults, with nothing SDK-shaped left
//! in it.
//!
use std::collections::BTreeMap;

use hyperscale_hbor::{HborShape, ShapeRegistry, TypeShape};
use hyperscale_vm_effects::{
    MAX_EFFECTS_PER_SIGNATURE, MethodSignature, PackageMetadata, ParamType, SlotId, SlotKind,
    SlotShape,
};

use crate::state::LeafShape;
use crate::trace::Trace;

/// One method: what routing reads, plus what the guest bridge needs.
#[derive(Clone, Debug)]
pub struct Method {
    signature: MethodSignature,
    worst_case: usize,
}

impl Method {
    /// The effect signature, as routing consumes it.
    #[must_use]
    pub const fn signature(&self) -> &MethodSignature {
        &self.signature
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
    events: Vec<String>,
    errors: Vec<String>,
    roles: Vec<String>,
    types: ShapeRegistry,
    state: BTreeMap<SlotId, SlotShape>,
    config: Vec<String>,
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
            events: self.events.clone(),
            errors: self.errors.clone(),
            roles: self.roles.clone(),
            types: self.types.types().clone(),
            state: self.state.clone(),
            config: self.config.clone(),
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
    /// the wrong kind, lets a `for-each` element escape its closure, or
    /// publishes under a name the package already publishes. All four
    /// would otherwise become a published method that can never be called
    /// — or one that silently replaced another.
    #[must_use]
    pub fn method<F>(mut self, name: &str, params: &[ParamType], declare: F) -> Self
    where
        F: FnOnce(&mut Trace),
    {
        let mut trace = Trace::new(params.to_vec());
        declare(&mut trace);
        let recorded = trace.finish();

        let method = Method {
            signature: MethodSignature {
                totality: recorded.totality,
                issues: recorded.issues,
                params: params.to_vec(),
                abi: recorded.abi,
                outputs: recorded.outputs,
                answers: recorded.answers,
                denominations: recorded.denominations,
                effects: recorded.clauses,
            },
            worst_case: recorded.worst_case,
        };
        let taken = self.blueprint.methods.insert(name.to_owned(), method);
        assert!(
            taken.is_none(),
            "the package already publishes a method named `{name}`"
        );
        self
    }

    /// Declare `T` as the package's next event type, in the order a
    /// receipt event's index refers to.
    ///
    /// The name comes from the type's own shape rather than from a second
    /// spelling beside it, so the table entry and the shape it indexes
    /// cannot disagree about what the event is called.
    ///
    /// # Panics
    ///
    /// If `T` describes as anything but a declared type. An event is a
    /// struct the package declares; a wrapper that describes as its
    /// contents would leave the table naming a shape nobody registered.
    #[must_use]
    pub fn event<T: HborShape>(mut self) -> Self {
        let TypeShape::Ref(name) = T::shape(&mut self.blueprint.types) else {
            panic!("an event is a type the package declares, and describes as one");
        };
        self.blueprint.events.push(name);
        self
    }

    /// Name the configuration's `index`-th field, in the order the
    /// creation-fixed record holds them.
    ///
    /// A value in that record carries its own kind, so the name is the
    /// only thing a consumer cannot recover from the leaf.
    #[must_use]
    pub fn config(mut self, name: &str) -> Self {
        self.blueprint.config.push(name.to_owned());
        self
    }

    /// Declare the slot `name` sits at, and what `T` its leaves hold.
    ///
    /// The slot is the author's own number and the key of the table, so
    /// two fields at one slot are one leaf under two names — which the
    /// state walk refuses before this is reached.
    ///
    /// # Panics
    ///
    /// If two fields claim one slot.
    #[must_use]
    pub fn slot<T: LeafShape>(mut self, slot: u16, name: &str, kind: SlotKind) -> Self {
        let declared = SlotShape {
            name: name.to_owned(),
            kind,
            element: T::leaf_form(&mut self.blueprint.types),
        };
        let taken = self.blueprint.state.insert(SlotId(slot), declared);
        assert!(taken.is_none(), "slot {slot} is already declared");
        self
    }

    /// Declare `T` as a type this package's cells hold: a record, or the
    /// data an instance of one of its marks carries.
    ///
    /// No band and no index — a cell is reached by its key rather than by
    /// a number — so this adds the shape and nothing else. What names it
    /// is the type's own name, which is also the mark's material for an
    /// instance schema.
    #[must_use]
    pub fn declares<T: HborShape>(mut self) -> Self {
        T::shape(&mut self.blueprint.types);
        self
    }

    /// Name the package's `index`-th error code, in the order a declined
    /// invocation's code refers to.
    #[must_use]
    pub fn error(mut self, name: &str) -> Self {
        self.blueprint.errors.push(name.to_owned());
        self
    }

    /// Name the package's `index`-th role, in the band order a stored
    /// role table's entries refer to.
    #[must_use]
    pub fn role(mut self, name: &str) -> Self {
        self.blueprint.roles.push(name.to_owned());
        self
    }

    /// Finish the blueprint.
    #[must_use]
    pub fn build(self) -> Blueprint {
        self.blueprint
    }
}

//! Assembling traced declarations into the metadata routing reads.
//!
//! A [`Blueprint`] is the SDK's unit of authorship: a set of named methods,
//! each with its declared parameters and its traced effect signature. Its
//! [`Blueprint::metadata`] is a [`PackageMetadata`] — the exact structure
//! [`hyperscale_vm_effects::route`] consults, with nothing SDK-shaped left
//! in it.
//!
use std::collections::BTreeMap;

use hyperscale_hbor::ShapeTable;
use hyperscale_vm_effects::{
    MAX_EFFECTS_PER_SIGNATURE, MethodSignature, PackageMetadata, ParamType,
};

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
            types: ShapeTable::new(),
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

    /// Name the package's `index`-th event type, in the order a receipt
    /// event's index refers to.
    #[must_use]
    pub fn event(mut self, name: &str) -> Self {
        self.blueprint.events.push(name.to_owned());
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

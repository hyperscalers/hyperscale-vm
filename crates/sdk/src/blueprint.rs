//! Assembling traced declarations into the metadata admission reads.
//!
//! A [`Blueprint`] is the SDK's unit of authorship: a set of named methods,
//! each with its sockets and its traced effect signature. Its
//! [`Blueprint::metadata`] is a [`PackageMetadata`] — the exact structure
//! [`hyperscale_vm_effects::admit_tree()`] consults, with nothing SDK-shaped
//! left in it.
//!
use std::collections::BTreeMap;

use hyperscale_hbor::node::{max_depth, max_encoded_len};
use hyperscale_hbor::{Capped, HborBound, HborShape, NodeId, ShapeNode, ShapeTable};
use hyperscale_vm_effects::{
    Expr, MAX_EFFECTS_PER_SIGNATURE, MAX_EVENT_TYPES_PER_METHOD, MAX_ISSUANCES_PER_SIGNATURE,
    MethodSignature, PackageMetadata, ParamType, SlotId, SlotKind, SlotShape,
};
use hyperscale_vm_types::{EVENT_FRAME_BYTES, MAX_EVENT_PAYLOAD_BYTES, MAX_SLOT_WIDTH};

use crate::state::LeafShape;
use crate::trace::Trace;

/// One method: what routing reads, plus what the guest bridge needs.
#[derive(Clone, Debug)]
pub struct Method {
    /// The events this method's body may emit, by the name the package
    /// registers them under. Resolved to indices and priced when the
    /// blueprint builds its metadata.
    emits: Vec<String>,
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
    types: ShapeTable,
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

    /// `named`'s events as the signature carries them — their indices in
    /// the package's table, and the widest they encode to between them.
    ///
    /// Every shape has a widest value, so the figure always exists. The
    /// publish gate derives it again and refuses a package whose two
    /// answers differ.
    fn emitted(
        &self,
        method: &str,
        named: &[String],
    ) -> (Capped<Vec<u32>, MAX_EVENT_TYPES_PER_METHOD>, u32) {
        let mut indices = Vec::with_capacity(named.len());
        let mut bytes = 0usize;
        for event in named {
            let index = self
                .events
                .iter()
                .position(|declared| declared == event)
                .unwrap_or_else(|| {
                    panic!("`{method}` emits `{event}`, which the package does not declare")
                });
            let shape = self
                .types
                .named(event)
                .unwrap_or_else(|| panic!("`{event}` declares a shape when it is declared"));
            indices.push(u32::try_from(index).expect("an event table under the index cap"));
            // The framing beside the payload, matching what the publish
            // gate derives and what the kernel meters at emit.
            bytes = bytes
                .saturating_add(EVENT_FRAME_BYTES)
                .saturating_add(self.types.most(shape));
        }
        indices.sort_unstable();
        let indices = Capped::new(indices).unwrap_or_else(|_| {
            panic!("`{method}` emits more than {MAX_EVENT_TYPES_PER_METHOD} event types")
        });
        (
            indices,
            u32::try_from(bytes).expect("an event bound under the transaction cap"),
        )
    }

    /// The package metadata routing reads — the whole point of the trace.
    ///
    /// Each method's events are resolved here rather than where it was
    /// traced: an event registers its shape when the blueprint declares
    /// it, which may be after the method that emits it was recorded.
    ///
    /// # Panics
    ///
    /// If a method names an event the package never declared — an
    /// authoring defect the publish gate would refuse; panicking here
    /// names the method rather than leaving a package that cannot
    /// publish.
    #[must_use]
    pub fn metadata(&self) -> PackageMetadata {
        PackageMetadata {
            methods: self
                .methods
                .iter()
                .map(|(name, m)| {
                    let mut signature = m.signature.clone();
                    let (emits, bytes) = self.emitted(name, &m.emits);
                    signature.emits = emits;
                    signature.event_bytes = bytes;
                    (name.clone(), signature)
                })
                .collect(),
            events: self.events.clone(),
            errors: self.errors.clone(),
            types: self.types.clone(),
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
                issues: recorded.issues.try_into().unwrap_or_else(|_| {
                    panic!("`{name}` issues more than {MAX_ISSUANCES_PER_SIGNATURE} resources")
                }),
                destroys: recorded.destroys.try_into().unwrap_or_else(|_| {
                    panic!("`{name}` destroys more than {MAX_ISSUANCES_PER_SIGNATURE} buckets")
                }),
                params: params.to_vec(),
                abi: recorded.abi,
                outputs: recorded.outputs,
                answers: recorded.answers,
                denominations: recorded.denominations,
                effects: recorded.clauses,
                // Resolved against the event table at `metadata`, since
                // a method may trace before the events it names are
                // registered.
                emits: Capped::empty(),
                event_bytes: 0,
            },
            emits: recorded.emits,
            worst_case: recorded.worst_case,
        };
        let taken = self.blueprint.methods.insert(name.to_owned(), method);
        assert!(
            taken.is_none(),
            "the package already publishes a method named `{name}`"
        );
        self
    }

    /// Add `node` to the package's types, and answer where it sits.
    ///
    /// The one place a static tree becomes published metadata, and the
    /// cross check between the two derivations of a width: the table
    /// measures the node it was handed, and the constant beside the type
    /// folds the same tree. The publish gate measures the table a third
    /// time, from the array alone.
    ///
    /// # Panics
    ///
    /// If the tree is one no decoder follows, or the two derivations
    /// disagree — neither of which a derived type can state.
    fn declared(&mut self, node: &ShapeNode) -> NodeId {
        let id = self
            .blueprint
            .types
            .declare(node)
            .unwrap_or_else(|fault| panic!("a declared type's shape: {fault}"));
        assert_eq!(
            self.blueprint.types.most(id),
            max_encoded_len(node),
            "the table measures the width the type states"
        );
        assert_eq!(
            self.blueprint.types.depth(id),
            max_depth(node),
            "the table measures the depth the type states"
        );
        id
    }

    /// Declare `T` as the package's next event type, in the order a
    /// receipt event's index refers to.
    ///
    /// The name comes from the type's own shape rather than from a second
    /// spelling beside it, so the table entry and the shape it indexes
    /// cannot disagree about what the event is called.
    ///
    /// An event wider than one emit may carry is refused where it is
    /// declared, because the kernel traps on the payload and the trap is
    /// reachable from published code:
    ///
    /// ```compile_fail
    /// use hyperscale_vm_sdk::Blueprint;
    /// use hyperscale_vm_sdk::hbor::{Bytes, Hbor, HborShape};
    ///
    /// #[derive(Hbor, HborShape)]
    /// struct Wide {
    ///     note: Bytes<4096>,
    /// }
    ///
    /// let _ = Blueprint::builder().event::<Wide>();
    /// ```
    ///
    /// # Panics
    ///
    /// If `T` describes as anything but a declared type. An event is a
    /// struct the package declares; a wrapper that describes as its
    /// contents would leave the table naming a shape nobody declared.
    #[must_use]
    pub fn event<T: HborShape>(mut self) -> Self {
        // The cap the kernel traps on, met at the declaration instead:
        // an event past it is a package that publishes and then traps on
        // every emit. The publish gate derives the same figure from the
        // published shape and refuses it there.
        const { assert!(<T as HborBound>::MAX_ENCODED_LEN <= MAX_EVENT_PAYLOAD_BYTES) }
        let ShapeNode::Named { name, .. } = T::NODE else {
            panic!("an event is a type the package declares, and describes as one");
        };
        self.declared(T::NODE);
        self.blueprint.events.push((*name).to_owned());
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

    /// Declare `T`'s leaf shape into the package's types, and answer
    /// where it sits with the width it measures.
    ///
    /// The width is the shape's rather than a second figure beside it:
    /// what a leaf may hold is what its element's encoding can occupy,
    /// and the publish gate derives it again from the published table.
    ///
    /// # Panics
    ///
    /// If the leaf is wider than the width field can carry, which no
    /// type the codec admits reaches.
    fn leaf<T: LeafShape>(&mut self) -> (NodeId, u32) {
        const { assert!(max_encoded_len(T::LEAF) <= MAX_SLOT_WIDTH as usize) }
        let element = self.declared(T::LEAF);
        let width = u32::try_from(self.blueprint.types.most(element))
            .expect("a leaf narrower than the wire's width field");
        (element, width)
    }

    /// Declare the slot `name` sits at, what `T` its leaves hold, and
    /// the width the field declared where `T` does not derive one.
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
        let (element, width) = self.leaf::<T>();
        let declared = SlotShape {
            name: name.to_owned(),
            kind,
            element,
            width,
            denomination: None,
        };
        let taken = self.blueprint.state.insert(SlotId(slot), declared);
        assert!(taken.is_none(), "slot {slot} is already declared");
        self
    }

    /// Declare the vault `name` sits at, holding the resource its
    /// configuration slot names.
    ///
    /// The balance-sheet twin of [`slot`](Self::slot): the field's own
    /// shape — one leaf for a vault, a collection for an instance
    /// family — with the `#[holds(config.<field>)]` resource carried so
    /// a consumer resolves it against the instance's own configuration.
    /// A field holding a resource the package issues declares through
    /// [`slot`](Self::slot) — its address derives from the instance and
    /// nothing about it is a configured value.
    ///
    /// # Panics
    ///
    /// As [`slot`](Self::slot).
    #[must_use]
    pub fn holds_config<T: LeafShape>(
        mut self,
        slot: u16,
        name: &str,
        kind: SlotKind,
        config: u32,
    ) -> Self {
        let (element, width) = self.leaf::<T>();
        let declared = SlotShape {
            name: name.to_owned(),
            kind,
            element,
            width,
            denomination: Some(Expr::Config(config)),
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
    ///
    /// A record no leaf could hold is refused where it is declared:
    ///
    /// ```compile_fail
    /// use hyperscale_vm_sdk::Blueprint;
    /// use hyperscale_vm_sdk::hbor::{Bytes, Hbor, HborShape};
    ///
    /// #[derive(Hbor, HborShape)]
    /// struct Wide {
    ///     note: Bytes<16384>,
    /// }
    ///
    /// let _ = Blueprint::builder().declares::<Wide>();
    /// ```
    #[must_use]
    pub fn declares<T: HborShape>(mut self) -> Self {
        // What a declared type is stored in is a leaf, whatever the slot,
        // and the kernel traps on a write past the slot's width. An
        // instance's data cell is the one with no slot row of its own, so
        // this is where it meets the cap.
        const { assert!(<T as HborBound>::MAX_ENCODED_LEN <= MAX_SLOT_WIDTH as usize) }
        self.declared(T::NODE);
        self
    }

    /// Name the package's `index`-th error code, in the order a declined
    /// invocation's code refers to.
    #[must_use]
    pub fn error(mut self, name: &str) -> Self {
        self.blueprint.errors.push(name.to_owned());
        self
    }

    /// Finish the blueprint.
    #[must_use]
    pub fn build(self) -> Blueprint {
        self.blueprint
    }
}

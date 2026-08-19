//! The envelope tier: intents composed along typed yield edges.
//!
//! A composition is edge addition *between* graphs. Each intent is written
//! on its own — an [`IntentBuilder`] is a [`TypedBuilder`] that can also
//! declare typed holes and export edges — and the [`EnvelopeBuilder`]
//! joins them by wiring one intent's export to another's hole. Nothing an
//! intent contains is rewritten to make a composition fit, which is what
//! lets a subintent's signer sign a declaration and have it mean the same
//! thing in whatever envelope later carries it.
//!
//! The wiring is done from handles rather than from indices. Declaring a
//! parameter answers with the [`Param`] the intent's own graph must
//! consume; the composition's side of the same declaration is a
//! [`YieldSink`], which arrives when the intent enters an envelope.
//! Exporting answers with a [`YieldSource`]. Sinks and sources are affine,
//! so a hole takes one source and a source fills one hole, and both name
//! the intent they came from, so a binding cannot reach an intent or an
//! edge that does not exist.
//!
//! An intent enters an envelope one of two ways, and both hand back sinks
//! the same way. [`EnvelopeBuilder::seal`] takes one the composer wrote.
//! [`EnvelopeBuilder::present`] takes one somebody else signed — built
//! through [`IntentBuilder::declaration`] before any envelope existed, and
//! stored exactly as handed over, because the signature already covering
//! it would not survive a rebuild.
//!
//! What is left is arithmetic over declarations, which the builder checks
//! when it emits: every intent sealed, every declared parameter consumed
//! exactly once inside its graph and bound exactly once outside it.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};

use hyperscale_vm_effects::{
    Constraint, EdgeRef, EnvelopeTree, GraphArg, Hasher, InstanceMeta, InstanceRegistry,
    IntentDecl, MAX_YIELD_PARAMS, ManifestGraph, MetadataCache, Subintent, YieldBinding,
    YieldParam,
};
use hyperscale_vm_types::{Denomination, MAX_SUBINTENTS, PrincipalAddr};

use crate::builder::{Bucket, Param};
use crate::typed::{TypedBuilder, TypedError};

/// Why an envelope could not be composed.
///
/// Every variant is a verdict [`admit_tree`] would also reach, named
/// against the intent the author wrote rather than against a flattened
/// tree they have not finished composing.
///
/// [`admit_tree`]: hyperscale_vm_effects::admit_tree
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeError {
    /// An intent the composition never sealed, so there is no declaration
    /// to carry.
    #[error("intent {intent} was never sealed")]
    UnsealedIntent {
        /// The intent: `0` is the root, `i + 1` is subintent `i`.
        intent: u32,
    },
    /// A declared parameter no node argument consumes — the yielded
    /// bucket would dangle.
    #[error("intent {intent} parameter {param} is never consumed")]
    UnusedYieldParam {
        /// The declaring intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A declared parameter consumed by more than one node argument.
    #[error("intent {intent} parameter {param} is consumed twice")]
    YieldParamReused {
        /// The declaring intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// A parameter reference past what the intent declared — reachable
    /// only from a [`Param`] the tier did not mint.
    #[error("intent {intent} references parameter {param}, which it does not declare")]
    UnboundParam {
        /// The referencing intent.
        intent: u32,
        /// The referenced parameter.
        param: u32,
    },
    /// A declared parameter the composition never bound to a source.
    #[error("intent {intent} parameter {param} is bound to no yield")]
    UnboundYieldParam {
        /// The declaring intent.
        intent: u32,
        /// The parameter position.
        param: u32,
    },
    /// An intent declaring more yield parameters than admission accepts.
    #[error("intent {intent} declares more than {MAX_YIELD_PARAMS} yield parameters")]
    TooManyYieldParams {
        /// The declaring intent.
        intent: u32,
    },
    /// More subintents than an envelope may bind.
    #[error("envelope binds more than {MAX_SUBINTENTS} subintents")]
    TooManySubintents,
    /// An intent's own graph refused to build or type.
    #[error(transparent)]
    Intent(#[from] TypedError),
}

/// Distinguishes concurrently live envelopes, so a handle minted by one
/// cannot be wired into another's slots.
static NEXT_ENVELOPE: AtomicU64 = AtomicU64::new(0);

/// One intent's declared parameter, as the composition names it — the
/// hole side of a declaration, which a binding fills.
///
/// Affine like the [`Param`] it is declared beside: one hole takes one
/// source, so binding the same parameter twice has no spelling.
#[derive(Debug)]
pub struct YieldSink {
    envelope: u64,
    intent: u32,
    position: u32,
}

/// An edge one intent exported, as the composition names it — the source
/// side, which fills exactly one hole.
#[derive(Debug)]
pub struct YieldSource {
    envelope: u64,
    intent: u32,
    edge: EdgeRef,
}

/// One intent under construction: a [`TypedBuilder`] that also declares
/// typed holes and exports edges.
///
/// Dereferences to the builder underneath, so every call reads exactly as
/// it does outside a composition — the wrappers take `&mut` to this and
/// never learn there is an envelope.
pub struct IntentBuilder<'a> {
    graph: TypedBuilder<'a>,
    envelope: u64,
    intent: u32,
    params: Vec<YieldParam>,
}

impl<'a> IntentBuilder<'a> {
    /// An intent written to be signed on its own and handed to a composer
    /// afterwards — a declaration that exists before any envelope does.
    ///
    /// Its holes are bound by whoever presents it, so nothing here mints a
    /// [`YieldSink`]: those come from [`EnvelopeBuilder::present`], on the
    /// composing side, where the intent this declaration will be is known.
    #[must_use]
    pub fn declaration(
        cache: &'a MetadataCache,
        instances: &'a InstanceRegistry,
        hasher: &'a dyn Hasher,
    ) -> Self {
        Self {
            graph: TypedBuilder::new(cache, instances, hasher),
            envelope: NEXT_ENVELOPE.fetch_add(1, Ordering::Relaxed),
            intent: 0,
            params: Vec::new(),
        }
    }

    /// Declare a typed hole: an edge the composition must bind, carrying
    /// `resource` and satisfying `constraints`.
    ///
    /// The [`Param`] is this intent's own obligation — its graph must
    /// consume it exactly once. The composition's obligation to bind the
    /// hole is discharged against a [`YieldSink`], which arrives when the
    /// intent enters an envelope rather than here, so that an intent
    /// written and one presented hand back sinks the same way.
    ///
    /// # Panics
    ///
    /// Past a `u32` of declarations, far beyond [`MAX_YIELD_PARAMS`],
    /// which [`EnvelopeBuilder::seal`] enforces as an error.
    pub fn declare(
        &mut self,
        resource: impl Into<Denomination>,
        constraints: impl IntoIterator<Item = Constraint>,
    ) -> Param {
        let position =
            u32::try_from(self.params.len()).expect("parameters are bounded by MAX_YIELD_PARAMS");
        self.params.push(YieldParam {
            resource: resource.into(),
            constraints: constraints.into_iter().collect(),
        });
        Param(position)
    }

    /// The declaration, for its signer to sign and hand on.
    ///
    /// # Errors
    ///
    /// As [`EnvelopeBuilder::seal`], over this intent alone.
    pub fn into_decl(self) -> Result<IntentDecl, EnvelopeError> {
        self.finish(0)
    }

    /// Build the graph and check that every parameter this intent declared
    /// is consumed by exactly one of its own node arguments.
    fn finish(self, intent: u32) -> Result<IntentDecl, EnvelopeError> {
        if self.params.len() > MAX_YIELD_PARAMS {
            return Err(EnvelopeError::TooManyYieldParams { intent });
        }
        let params = self.params;
        let graph = self.graph.build()?;
        check_params(&graph, params.len(), intent)?;
        Ok(IntentDecl { graph, params })
    }

    /// Consume an output as this intent's yield edge, for the composition
    /// to bind to some intent's declared parameter.
    ///
    /// # Panics
    ///
    /// On a bucket carrying constraints — a yield's constraints are the
    /// consuming parameter's declaration — or one minted elsewhere.
    pub fn export(&mut self, bucket: Bucket) -> YieldSource {
        let edge = self.graph.export(bucket);
        YieldSource {
            envelope: self.envelope,
            intent: self.intent,
            edge,
        }
    }
}

impl<'a> Deref for IntentBuilder<'a> {
    type Target = TypedBuilder<'a>;

    fn deref(&self) -> &Self::Target {
        &self.graph
    }
}

impl DerefMut for IntentBuilder<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.graph
    }
}

/// A composition of intents over typed yield edges.
pub struct EnvelopeBuilder<'a> {
    cache: &'a MetadataCache,
    instances: &'a InstanceRegistry,
    hasher: &'a dyn Hasher,
    id: u64,
    /// The signer of each subintent, in envelope order; the root has none.
    signers: Vec<PrincipalAddr>,
    /// Sealed declarations by slot — `0` is the root — `None` until the
    /// intent is sealed.
    intents: Vec<Option<IntentDecl>>,
    /// The bound source of each declared parameter, by intent and
    /// position.
    bindings: BTreeMap<(u32, u32), YieldBinding>,
    /// The creation-fixed records the tree carries for targets beyond
    /// the genesis registry.
    presented: Vec<InstanceMeta>,
}

impl<'a> EnvelopeBuilder<'a> {
    /// An envelope and its root intent — the composer's own, which every
    /// composition has exactly one of.
    #[must_use]
    pub fn new(
        cache: &'a MetadataCache,
        instances: &'a InstanceRegistry,
        hasher: &'a dyn Hasher,
    ) -> (Self, IntentBuilder<'a>) {
        let id = NEXT_ENVELOPE.fetch_add(1, Ordering::Relaxed);
        let envelope = Self {
            cache,
            instances,
            hasher,
            id,
            signers: Vec::new(),
            intents: vec![None],
            bindings: BTreeMap::new(),
            presented: Vec::new(),
        };
        let root = IntentBuilder {
            graph: TypedBuilder::new(cache, instances, hasher),
            envelope: id,
            intent: 0,
            params: Vec::new(),
        };
        (envelope, root)
    }

    /// Carry `meta` in the tree's instance section, registering the
    /// component address it derives for this envelope's calls.
    ///
    /// The builder resolves targets against the registry it was given,
    /// so a presenting build composes that registry with the same
    /// records first — this records them in the tree, where admission
    /// will compose identically.
    pub fn instance(&mut self, meta: InstanceMeta) {
        self.presented.push(meta);
    }

    /// A separately signed subintent, whose signer owns the nullifier
    /// that makes it once-only.
    ///
    /// # Panics
    ///
    /// Past a `u32` of intents, far beyond [`MAX_SUBINTENTS`], which
    /// [`build`](Self::build) enforces as an error.
    pub fn subintent(&mut self, signer: PrincipalAddr) -> IntentBuilder<'a> {
        let intent = u32::try_from(self.intents.len()).expect("intents fit an index");
        self.signers.push(signer);
        self.intents.push(None);
        IntentBuilder {
            graph: TypedBuilder::new(self.cache, self.instances, self.hasher),
            envelope: self.id,
            intent,
            params: Vec::new(),
        }
    }

    /// Bind a declaration its signer already signed, answering one
    /// [`YieldSink`] per parameter it declares, in declaration order.
    ///
    /// This is what a subintent is for. The signer put their name to a
    /// graph over typed holes before any composer existed; the composition
    /// supplies the sources and alters nothing, so the signature that
    /// already covers the declaration still covers it — which is why the
    /// declaration is stored exactly as handed over rather than rebuilt.
    /// [`subintent`](Self::subintent) is the other case: a leg the
    /// composer writes and signs itself.
    ///
    /// # Errors
    ///
    /// The same refusals [`seal`](Self::seal) reaches over a declaration
    /// the composer wrote, because a composer signing an envelope around a
    /// malformed declaration is a transaction the chain refuses either
    /// way, and refusing it here is the only place it can still be
    /// declined.
    ///
    /// # Panics
    ///
    /// Past a `u32` of intents, far beyond [`MAX_SUBINTENTS`], which
    /// [`build`](Self::build) enforces as an error.
    pub fn present(
        &mut self,
        signer: PrincipalAddr,
        decl: IntentDecl,
    ) -> Result<Vec<YieldSink>, EnvelopeError> {
        let intent = u32::try_from(self.intents.len()).expect("intents fit an index");
        if decl.params.len() > MAX_YIELD_PARAMS {
            return Err(EnvelopeError::TooManyYieldParams { intent });
        }
        check_params(&decl.graph, decl.params.len(), intent)?;
        let sinks = self.sinks(intent, decl.params.len());
        self.signers.push(signer);
        self.intents.push(Some(decl));
        Ok(sinks)
    }

    /// Seal an intent into the envelope, answering one [`YieldSink`] per
    /// parameter it declared, in declaration order.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnusedYieldParam`], [`EnvelopeError::YieldParamReused`]
    /// or [`EnvelopeError::UnboundParam`] for a declaration its graph does
    /// not discharge; [`EnvelopeError::TooManyYieldParams`]; or the graph's
    /// own refusal.
    ///
    /// # Panics
    ///
    /// On an intent from a different envelope, or one sealed twice.
    pub fn seal(&mut self, intent: IntentBuilder<'a>) -> Result<Vec<YieldSink>, EnvelopeError> {
        assert_eq!(
            intent.envelope, self.id,
            "an intent must be sealed into the envelope that opened it"
        );
        let index = intent.intent;
        let slot = usize::try_from(index).expect("minted indices fit");
        assert!(
            self.intents[slot].is_none(),
            "an intent is sealed into the envelope once"
        );
        let decl = intent.finish(index)?;
        let sinks = self.sinks(index, decl.params.len());
        self.intents[slot] = Some(decl);
        Ok(sinks)
    }

    /// One sink per declared parameter of `intent`, in declaration order.
    fn sinks(&self, intent: u32, params: usize) -> Vec<YieldSink> {
        (0..params)
            .map(|position| YieldSink {
                envelope: self.id,
                intent,
                position: u32::try_from(position).expect("bounded by MAX_YIELD_PARAMS"),
            })
            .collect()
    }

    /// Bind a declared hole to the edge that will fill it.
    ///
    /// The whole of composition: an edge is added between two graphs and
    /// neither is touched.
    ///
    /// # Panics
    ///
    /// On a handle minted by a different envelope.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking both handles by value is the wiring; a borrow would let one end serve twice"
    )]
    pub fn bind(&mut self, sink: YieldSink, source: YieldSource) {
        assert!(
            sink.envelope == self.id && source.envelope == self.id,
            "a yield is bound within the envelope that minted it"
        );
        self.bindings.insert(
            (sink.intent, sink.position),
            YieldBinding {
                intent: source.intent,
                edge: source.edge,
            },
        );
    }

    /// Emit the tree: every intent sealed, every declared parameter bound.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnsealedIntent`] for an intent still under
    /// construction; [`EnvelopeError::UnboundYieldParam`] for a hole the
    /// composition left open; [`EnvelopeError::TooManySubintents`].
    ///
    /// # Panics
    ///
    /// Past a `u32` of intents, which [`MAX_SUBINTENTS`] excludes above.
    pub fn build(self) -> Result<EnvelopeTree, EnvelopeError> {
        if self.signers.len() > MAX_SUBINTENTS {
            return Err(EnvelopeError::TooManySubintents);
        }
        let mut decls = Vec::with_capacity(self.intents.len());
        let mut wired = Vec::with_capacity(self.intents.len());
        for (slot, sealed) in self.intents.into_iter().enumerate() {
            let intent = u32::try_from(slot).expect("minted indices fit");
            let decl = sealed.ok_or(EnvelopeError::UnsealedIntent { intent })?;
            let mut bindings = Vec::with_capacity(decl.params.len());
            for position in 0..decl.params.len() {
                let param = u32::try_from(position).expect("bounded by MAX_YIELD_PARAMS");
                bindings.push(
                    *self
                        .bindings
                        .get(&(intent, param))
                        .ok_or(EnvelopeError::UnboundYieldParam { intent, param })?,
                );
            }
            decls.push(decl);
            wired.push(bindings);
        }
        let mut decls = decls.into_iter();
        let mut wired = wired.into_iter();
        let root = decls.next().expect("the root slot always exists");
        let root_bindings = wired.next().expect("the root slot always exists");
        let subintents = self
            .signers
            .into_iter()
            .zip(decls)
            .zip(wired)
            .map(|((signer, decl), bindings)| Subintent {
                decl,
                signer,
                bindings,
            })
            .collect();
        Ok(EnvelopeTree {
            root,
            root_bindings,
            subintents,
            instances: self.presented,
        })
    }
}

/// Check that each of an intent's declared parameters is consumed by
/// exactly one of its own node arguments — admission's own count, run
/// against the intent that declared them.
fn check_params(graph: &ManifestGraph, declared: usize, intent: u32) -> Result<(), EnvelopeError> {
    let mut uses = vec![0u32; declared];
    for node in &graph.nodes {
        for arg in &node.args {
            let GraphArg::Param(position) = arg else {
                continue;
            };
            let slot = usize::try_from(*position)
                .ok()
                .and_then(|position| uses.get_mut(position))
                .ok_or(EnvelopeError::UnboundParam {
                    intent,
                    param: *position,
                })?;
            *slot += 1;
        }
    }
    for (position, count) in uses.iter().enumerate() {
        let param = u32::try_from(position).expect("bounded by MAX_YIELD_PARAMS");
        match count {
            0 => return Err(EnvelopeError::UnusedYieldParam { intent, param }),
            1 => {}
            _ => return Err(EnvelopeError::YieldParamReused { intent, param }),
        }
    }
    Ok(())
}

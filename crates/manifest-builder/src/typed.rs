//! The metadata-typed layer: a builder that resolves its targets.
//!
//! [`GraphBuilder`] reads no metadata, so a call's arity, its argument
//! kinds and its output count are the author's claims, judged where every
//! claim is. A [`TypedBuilder`] asks the same chain admission does, and
//! resolves the target before appending anything: a principal by its
//! class, a component through the record its address derives. With the signature in
//! hand, four of admission's verdicts move to the call site, and the
//! output count stops being a claim at all.
//!
//! It also types the edges. A method's declared output is an expression
//! over its bound inputs, and where those inputs are known at construction
//! the expression evaluates to the resource the edge will carry. The
//! resulting handle is tagged, and a tagged handle asserts its own
//! [`ResourceIs`](hyperscale_vm_effects::Constraint::ResourceIs) when it
//! binds — so the manifest's own guarantee, that a bucket carries what its
//! consumer expected, rides every typed edge without the author writing
//! it. Tags propagate: a split of a typed bucket is two typed buckets.
//! What the layer cannot evaluate it leaves untagged rather than guessing.
//!
//! None of this is judgement. Admission re-derives every one of these
//! properties over the signed form, so a defect here costs a signer a
//! refused transaction and can never admit one the protocol would refuse.

use std::collections::BTreeSet;
use std::marker::PhantomData;
use std::sync::Arc;

use hyperscale_vm_effects::{
    ChainRecords, Constraint, EdgeContent, EdgeRef, EvalBudget, EvalInputs, EvidenceRef, Expr,
    GraphArg, Hash32, Hasher, InstanceMeta, MAX_EXPR_DEPTH, ManifestGraph, ManifestHash,
    MethodSignature, PackageHash, PackageMetadata, ParamType, PresentedGrants, Value,
    evaluate_expr,
};
use hyperscale_vm_types::{Address, CallTarget, PrincipalAddr, ResourceAddr};

use crate::args::Args;
use crate::builder::{Bucket, BuildError, GraphBuilder};

/// Why a call could not be typed against the target's signature.
///
/// Every variant is a verdict admission would also reach, named here
/// against the method the author just wrote rather than against a node
/// index in a graph they have not finished building.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TypedError {
    /// A call target no record resolves.
    #[error("no instance at {0:?}")]
    UnknownInstance(Address),
    /// A target whose package is not in the metadata cache.
    #[error("no package {0:?} in the metadata cache")]
    UnknownPackage(PackageHash),
    /// A target whose package declares no way to make a component of it
    /// actual. Every published package does; the one serving principals
    /// does not, and has no creation to finish.
    #[error("package {0:?} declares no seal")]
    NoSeal(PackageHash),
    /// A method the target's package does not declare.
    #[error("package {package:?} has no method `{method}`")]
    UnknownMethod {
        /// The package consulted.
        package: PackageHash,
        /// The method requested.
        method: String,
    },
    /// An argument count differing from the declared parameters.
    #[error("`{method}` takes {expected} arguments, {found} passed")]
    ArityMismatch {
        /// The method called.
        method: String,
        /// Declared parameter count.
        expected: usize,
        /// Bound argument count.
        found: usize,
    },
    /// A literal of the wrong kind.
    #[error("`{method}` argument {param}: expected {expected}, found {found}")]
    ParamKind {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
        /// The declared kind.
        expected: &'static str,
        /// The bound value's kind.
        found: &'static str,
    },
    /// A literal where the method declares a bucket.
    #[error("`{method}` argument {param}: a bucket parameter needs an edge")]
    LiteralForBucketParam {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
    },
    /// An edge where the method declares a value.
    #[error("`{method}` argument {param}: an edge cannot bind a value parameter")]
    EdgeForValueParam {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
    },
    /// A yield parameter where the method declares a value.
    #[error("`{method}` argument {param}: a yield parameter cannot bind a value parameter")]
    ParamForValueParam {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
    },
    /// Outputs unpacked into a different arity than the method declares.
    #[error("`{method}` produces {declared} outputs, unpacked as {claimed}")]
    OutputArity {
        /// The method called.
        method: String,
        /// The method's declared output count.
        declared: usize,
        /// The arity the caller unpacked into.
        claimed: usize,
    },
    /// A proof presented to a method that admits anyone — admission's
    /// same-named verdict, reached at the call site.
    #[error("`{method}` admits anyone and reads no proof")]
    UnexpectedEvidence {
        /// The method called.
        method: String,
    },
    /// A guarded call composed without a proof — admission's
    /// [`SignatureForGuarded`](hyperscale_vm_effects::AdmissionError::SignatureForGuarded)
    /// verdict, reached at the call site. A signature signs in through
    /// an authorizing method; what it mints there is what a guarded
    /// method takes.
    #[error("`{method}` takes a minted proof; a signature only signs in")]
    SignatureForGuarded {
        /// The method called.
        method: String,
    },
    /// A proof requested from a method that does not mint — admission's
    /// [`UnmintingProof`](hyperscale_vm_effects::AdmissionError::UnmintingProof)
    /// verdict, reached where the proof is requested rather than where it
    /// would be presented.
    #[error("`{method}` mints no identity")]
    UnmintingProof {
        /// The method called.
        method: String,
    },
    /// The graph's own structural refusal, reached at [`TypedBuilder::build`].
    #[error(transparent)]
    Build(#[from] BuildError),
}

/// The identity an authorizing node mints, as a later call of the same
/// graph presents it.
///
/// A node reference rather than a value edge: nothing is conserved, and
/// presenting it twice says nothing presenting it once does not. It
/// carries authority only downward — admission refuses a proof drawn
/// from a node that is not earlier.
///
/// The proof remembers whose identity it carries, so a call acting *as*
/// that identity names no target of its own: the proof is the actor.
#[derive(Clone, Copy, Debug)]
#[must_use = "an unpresented proof authorizes nothing"]
pub struct Proof {
    node: u32,
    target: CallTarget,
}

impl Proof {
    /// The instance whose identity this proof carries — the authorizing
    /// node's target.
    #[must_use]
    pub const fn target(&self) -> CallTarget {
        self.target
    }
}

/// The output edges of one typed call, in slot order.
///
/// Held as a group rather than an array because a method's output count is
/// its signature's, not the caller's: there is no arity to name here, which
/// is what makes naming a slot the producer does not have inexpressible.
/// [`into_array`](Self::into_array) is where a caller states an expected
/// shape and is held to it.
#[derive(Debug)]
#[must_use = "every minted output must be consumed for the graph to build"]
pub struct Outputs {
    method: String,
    buckets: Vec<Bucket>,
    node: u32,
}

impl Outputs {
    /// How many edges the call produced.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.buckets.len()
    }

    /// Whether the call produced no edges.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Unpack into an array, most often by destructuring — `let [taken,
    /// rest] = ….into_array()?` — which is where `N` comes from.
    ///
    /// # Errors
    ///
    /// [`TypedError::OutputArity`] when the method declares some other
    /// number of outputs.
    pub fn into_array<const N: usize>(self) -> Result<[Bucket; N], TypedError> {
        let Self {
            method, buckets, ..
        } = self;
        let declared = buckets.len();
        buckets.try_into().map_err(|_| TypedError::OutputArity {
            method,
            declared,
            claimed: N,
        })
    }

    /// The single edge of a call that produces one.
    ///
    /// # Errors
    ///
    /// [`TypedError::OutputArity`] when the method produces some other
    /// number of outputs.
    pub fn one(self) -> Result<Bucket, TypedError> {
        let [bucket] = self.into_array()?;
        Ok(bucket)
    }

    /// Every edge the call produced, in the order its declaration
    /// yields them.
    ///
    /// What a caller wants where the arity is the callee's answer rather
    /// than a number the call site knows — a bring-up founds one edge
    /// per supply its package states, and the composer files each by the
    /// kind of the resource it founds.
    #[must_use]
    pub fn into_vec(self) -> Vec<Bucket> {
        self.buckets
    }

    /// Discharge a call that produces nothing.
    ///
    /// # Errors
    ///
    /// [`TypedError::OutputArity`] when the method produces an output,
    /// which would then dangle.
    pub fn none(self) -> Result<(), TypedError> {
        let [] = self.into_array()?;
        Ok(())
    }

    /// Split off the handle on what this call answered with, leaving the
    /// edges beside it to be discharged like any other call's.
    ///
    /// Total, and a split rather than a discharge of its own: a method
    /// answers with at most one value and yields any number of edges,
    /// and the two are independent facts about its signature. Answering
    /// is not a third arity — it is a thing that happens alongside
    /// whichever arity the method has.
    ///
    /// The node is what a receipt files an answer under, so handing it
    /// back typed is what lets a reader ask for the answer rather than
    /// count the calls before it.
    pub fn answering<T>(self) -> (Answered<T>, Self) {
        let handle = Answered {
            node: self.node,
            answer: PhantomData,
        };
        (handle, self)
    }
}

/// Where in the graph a value a method answered with will be filed, and
/// what it decodes as.
///
/// A node reference rather than a value: what a call answers is known
/// when the transaction runs and not when the graph is written, so this
/// is the question rather than the answer. A reader hands it to the
/// receipt.
///
/// The type rides along because the method's own signature knows it. A
/// caller that had to name both the position and the type could get
/// either wrong and would learn so from a decode failure rather than
/// from the compiler.
#[derive(Debug)]
pub struct Answered<T> {
    node: u32,
    answer: PhantomData<fn() -> T>,
}

impl<T> Clone for Answered<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for Answered<T> {}

impl<T> Answered<T> {
    /// The node the answer is filed under.
    #[must_use]
    pub const fn node(self) -> u32 {
        self.node
    }
}

/// The identity a construction-time evaluation runs under.
///
/// A transaction's identity is the signed graph's hash, which does not
/// exist while the graph is being written. Nothing reads this: the only
/// expressions that derive from an identity are the fresh-id forms, and
/// [`resolvable`] refuses to evaluate an output expression containing one.
const UNBOUND: ManifestHash = ManifestHash(Hash32([0; 32]));

/// A [`GraphBuilder`] that resolves its targets against the same tables
/// admission consults.
pub struct TypedBuilder<'a> {
    graph: GraphBuilder,
    chain: &'a dyn ChainRecords,
    hasher: &'a dyn Hasher,
}

impl<'a> TypedBuilder<'a> {
    /// A builder with no nodes, typing its calls and resolving its
    /// targets against what `chain` answers for.
    pub fn new(chain: &'a dyn ChainRecords, hasher: &'a dyn Hasher) -> Self {
        Self {
            graph: GraphBuilder::new(),
            chain,
            hasher,
        }
    }

    /// The seal of `target`'s package: the name it publishes under, and
    /// the signature it declares.
    ///
    /// Asked of the declaration rather than looked up by name, which is
    /// the same question the publish gate asks before it admits the
    /// package — so a composition and the gate cannot disagree about
    /// which method makes a component actual.
    ///
    /// Owned, because the caller's next act is to append a call and the
    /// builder cannot be borrowed twice.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnknownInstance`] or [`TypedError::UnknownPackage`]
    /// when the target does not resolve, and [`TypedError::NoSeal`] for
    /// a package that declares none.
    pub fn seal(
        &self,
        target: impl Into<CallTarget>,
    ) -> Result<(String, MethodSignature), TypedError> {
        let target = target.into();
        let meta = self
            .chain
            .instance(target)
            .ok_or_else(|| TypedError::UnknownInstance(target.address()))?;
        let package = self
            .chain
            .package(meta.package)
            .ok_or(TypedError::UnknownPackage(meta.package))?;
        let (name, signature) = package.seal().ok_or(TypedError::NoSeal(meta.package))?;
        Ok((name.to_owned(), signature.clone()))
    }

    /// Append an invocation of `method` on `target`, typed against the
    /// signature the target's package declares.
    ///
    /// The arguments are bound before anything is appended and judged
    /// against the declared parameters, so a refusal here leaves the
    /// builder exactly as it was — the handles it was passed are spent,
    /// as consuming them by value already said, but no node claims them.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnknownInstance`], [`TypedError::UnknownPackage`] or
    /// [`TypedError::UnknownMethod`] when the target or its method does
    /// not resolve; [`TypedError::ArityMismatch`] and the per-argument
    /// kind refusals when the arguments disagree with the signature.
    ///
    /// # Panics
    ///
    /// On a [`Bucket`] argument minted by a different builder.
    pub fn call(
        &mut self,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Outputs, TypedError> {
        self.append(target.into(), method, args, &[])
            .map(|(_, outputs)| outputs)
    }

    /// The same call, presenting `proof` instead of the intent's
    /// signature proof — how a call acts as the account an earlier
    /// authorizing node signed in.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnexpectedEvidence`] on a method that admits anyone,
    /// and everything [`call`](Self::call) refuses.
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    pub fn call_as(
        &mut self,
        proof: Proof,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Outputs, TypedError> {
        self.append(target.into(), method, args, &[proof])
            .map(|(_, outputs)| outputs)
    }

    /// The same call, presenting every proof in `proofs`.
    ///
    /// What a threshold gate takes: satisfying two of three means
    /// presenting two, and each is a node of its own earlier in the same
    /// intent. One proof is [`call_as`](Self::call_as); this is the
    /// general form behind it.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnexpectedEvidence`] on a method that admits
    /// anyone, and everything [`call`](Self::call) refuses.
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    pub fn call_presenting(
        &mut self,
        proofs: &[Proof],
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Outputs, TypedError> {
        self.append(target.into(), method, args, proofs)
            .map(|(_, outputs)| outputs)
    }

    /// Append an invocation of `method`, a minting method of `target`,
    /// and return the proof it mints.
    ///
    /// The call presents the intent's signature proof to its own gate —
    /// signing in starts from a signature. The arguments are the gate's
    /// where it has any: a custodial method names the badge it presents,
    /// where a sign-in names nothing.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnmintingProof`] when the method's accessibility
    /// does not mint, and everything [`call`](Self::call) refuses.
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    pub fn call_minting(
        &mut self,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Proof, TypedError> {
        self.mint(target.into(), method, args, &[])
    }

    /// The same minting call, presenting `proof` instead of the intent's
    /// signature — how a target whose stored rule names another
    /// account's identity is signed into through that account's own
    /// sign-in, and the only way in when the rule names no key the
    /// intent could carry.
    ///
    /// # Errors
    ///
    /// As [`call_minting`](Self::call_minting).
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    pub fn call_minting_as(
        &mut self,
        proof: Proof,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Proof, TypedError> {
        self.mint(target.into(), method, args, &[proof])
    }

    /// The same minting call, presenting every proof in `proofs`.
    ///
    /// What a minting gate over a threshold takes, and the general form
    /// the two above are the empty and one-proof cases of.
    ///
    /// # Errors
    ///
    /// As [`call_minting`](Self::call_minting).
    ///
    /// # Panics
    ///
    /// As [`call`](Self::call).
    pub fn call_minting_presenting(
        &mut self,
        proofs: &[Proof],
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Proof, TypedError> {
        self.mint(target.into(), method, args, proofs)
    }

    fn mint<A: Args>(
        &mut self,
        target: CallTarget,
        method: &str,
        args: A,
        proofs: &[Proof],
    ) -> Result<Proof, TypedError> {
        let (_, package) = self.resolve(target, method)?;
        if !package.methods[method].mints() {
            return Err(TypedError::UnmintingProof {
                method: method.to_owned(),
            });
        }
        let (node, outputs) = self.append(target, method, args, proofs)?;
        outputs.none()?;
        Ok(Proof { node, target })
    }

    /// The instance and package a target's call resolves through, held
    /// as shared handles so the signature can be read out of them for as
    /// long as the caller keeps the pair.
    fn resolve(
        &self,
        target: CallTarget,
        method: &str,
    ) -> Result<(Arc<InstanceMeta>, Arc<PackageMetadata>), TypedError> {
        let meta = self
            .chain
            .instance(target)
            .ok_or_else(|| TypedError::UnknownInstance(target.address()))?;
        let package = self
            .chain
            .package(meta.package)
            .ok_or(TypedError::UnknownPackage(meta.package))?;
        if !package.methods.contains_key(method) {
            return Err(TypedError::UnknownMethod {
                package: meta.package,
                method: method.to_owned(),
            });
        }
        Ok((meta, package))
    }

    fn append(
        &mut self,
        target: CallTarget,
        method: &str,
        args: impl Args,
        proofs: &[Proof],
    ) -> Result<(u32, Outputs), TypedError> {
        let (meta, package) = self.resolve(target, method)?;
        let signature = &package.methods[method];
        let meta = meta.as_ref();
        let hasher = self.hasher;

        let args = args.bind_all(&self.graph);
        let inputs = type_args(method, &args, &signature.params)?;
        let known: Vec<bool> = inputs.iter().map(Option::is_some).collect();
        let values: Vec<Value> = inputs
            .into_iter()
            .map(|value| value.unwrap_or_else(unknown))
            .collect();

        let resources = output_resources(
            signature,
            target,
            meta,
            &values,
            &known,
            self.graph.len(),
            hasher,
        );

        // The signature says which methods take evidence at all, so no
        // call site has to. Signing in starts from the intent's
        // signature; everything guarded presents proofs minted earlier —
        // more than one where the gate is a threshold, since satisfying
        // two of three means presenting two.
        let evidence = match (signature.requires_evidence(), proofs) {
            (false, []) => BTreeSet::new(),
            // A method that issues, destroys or reaches earns its
            // requirement from the resource rather than from its own
            // declaration, so the signature says it admits anyone and
            // the resource says otherwise. Ruling the proof out here
            // would refuse the call before the party who decides has
            // been asked.
            (false, presented) if signature.may_earn_authority() => presented
                .iter()
                .map(|proof| EvidenceRef::Node(proof.node))
                .collect(),
            (false, _) => {
                return Err(TypedError::UnexpectedEvidence {
                    method: method.to_owned(),
                });
            }
            (true, []) => {
                // A signature signs in, so it reaches only a gate that
                // reads a rule; a claim a declaration names takes a
                // proof.
                if !signature.reads_a_rule() {
                    return Err(TypedError::SignatureForGuarded {
                        method: method.to_owned(),
                    });
                }
                BTreeSet::from([EvidenceRef::IntentSignature])
            }
            (true, presented) => presented
                .iter()
                .map(|proof| EvidenceRef::Node(proof.node))
                .collect(),
        };
        let outputs = resources.len();
        let producer = self
            .graph
            .push(target, method.to_owned(), args, resources, evidence);
        let buckets = (0..outputs)
            .map(|slot| {
                let slot = u32::try_from(slot).expect("outputs are bounded by the signature");
                self.graph.mint(producer, slot)
            })
            .collect();
        Ok((
            producer,
            Outputs {
                method: method.to_owned(),
                buckets,
                node: producer,
            },
        ))
    }

    /// Consume an output as a yield edge, as [`GraphBuilder::export`].
    ///
    /// # Panics
    ///
    /// On a bucket carrying constraints, or one minted by a different
    /// builder.
    pub fn export(&mut self, bucket: Bucket) -> EdgeRef {
        self.graph.export(bucket)
    }

    /// Route whatever the author did not: at [`build`](Self::build), every
    /// still-unconsumed output is deposited to `sink`, carrying whatever
    /// resource its producing signature typed it with, instead of refusing
    /// the graph.
    ///
    /// See [`GraphBuilder::rest_to`] for why the sink is a principal and
    /// why there is no default.
    pub const fn rest_to(&mut self, sink: PrincipalAddr) {
        self.graph.rest_to(sink);
    }

    /// The untyped builder underneath, for calls this layer cannot type —
    /// a target the caller holds no record for, or a graph written
    /// deliberately to be refused. Its handles share this one's index
    /// space, so the two paths interleave freely.
    pub const fn untyped(&mut self) -> &mut GraphBuilder {
        &mut self.graph
    }

    /// Emit the graph, checking that every minted output was consumed.
    ///
    /// # Errors
    ///
    /// [`TypedError::Build`] wrapping the structural refusal.
    pub fn build(self) -> Result<ManifestGraph, TypedError> {
        Ok(self.graph.build()?)
    }
}

/// Type each bound argument against the parameter it fills, answering the
/// value an output expression would read at that position — `None` where
/// nothing at construction determines it.
///
/// This is admission's own per-argument check, run against the same
/// declared parameters, one graph earlier.
fn type_args(
    method: &str,
    args: &[GraphArg],
    params: &[ParamType],
) -> Result<Vec<Option<Value>>, TypedError> {
    if args.len() != params.len() {
        return Err(TypedError::ArityMismatch {
            method: method.to_owned(),
            expected: params.len(),
            found: args.len(),
        });
    }
    let mut inputs = Vec::with_capacity(args.len());
    for (position, (arg, param)) in args.iter().zip(params).enumerate() {
        let index = u32::try_from(position).expect("arguments are bounded by the signature");
        let method = || method.to_owned();
        inputs.push(match arg {
            GraphArg::Literal(value) => {
                if param.is_edge() {
                    return Err(TypedError::LiteralForBucketParam {
                        method: method(),
                        param: index,
                    });
                }
                if !param.admits(value) {
                    return Err(TypedError::ParamKind {
                        method: method(),
                        param: index,
                        expected: param.name(),
                        found: value.kind(),
                    });
                }
                Some(value.clone())
            }
            GraphArg::Edge { constraints, .. } => {
                if !param.is_edge() {
                    return Err(TypedError::EdgeForValueParam {
                        method: method(),
                        param: index,
                    });
                }
                edge_resource(constraints).map(|resource| Value::Bucket {
                    resource,
                    // The builder types what it can see: an edge's own
                    // ids are the producing node's, which this pass does
                    // not resolve. What it does know is which kind the
                    // callee declared, and that is what admission judges
                    // the routed edge against.
                    content: if *param == ParamType::NfBucket {
                        EdgeContent::NonFungible { ids: Vec::new() }
                    } else {
                        EdgeContent::Fungible
                    },
                })
            }
            GraphArg::Param(_) => {
                if !param.is_edge() {
                    return Err(TypedError::ParamForValueParam {
                        method: method(),
                        param: index,
                    });
                }
                // A yield edge's resource is the consuming intent's
                // declaration, which lives a tier up from here.
                None
            }
        });
    }
    Ok(inputs)
}

/// What each of a method's declared outputs carries, where the inputs
/// feeding the declaration are known.
///
/// The one derivation both tiers of this crate want: the typed builder
/// tags the handles it mints with it, and the projection reads it back off
/// a graph it was handed. `known` says which of `values` is real; the rest
/// hold [`unknown`], which nothing reaches because [`resolvable`] refuses
/// every expression that would.
pub(crate) fn output_resources(
    signature: &MethodSignature,
    target: CallTarget,
    record: &InstanceMeta,
    values: &[Value],
    known: &[bool],
    node_index: u32,
    hasher: &dyn Hasher,
) -> Vec<Option<ResourceAddr>> {
    // A builder-side projection, not admission: the meter is this
    // call's own, and nothing here reaches a chain verdict.
    let budget = EvalBudget::default();
    let inputs = EvalInputs {
        self_addr: target.address(),
        args: values,
        record,
        node_index,
        identity: UNBOUND,
        grants: PresentedGrants::none(),
        budget: &budget,
    };
    signature
        .outputs
        .iter()
        .map(|expr| {
            if !resolvable(expr, known, 0) {
                return None;
            }
            match evaluate_expr(expr, &inputs, hasher) {
                Ok(Value::Address(address)) => ResourceAddr::try_from(address).ok(),
                Ok(Value::Bucket { resource, .. }) => Some(resource),
                _ => None,
            }
        })
        .collect()
}

/// The value standing in for an input nothing determined.
///
/// Never read: [`resolvable`] is what decides whether an expression may be
/// evaluated at all, and it answers no for every expression reaching an
/// unknown input.
pub(crate) const fn unknown() -> Value {
    Value::Tuple(Vec::new())
}

/// The resource a bound edge was typed with, read off the assertion it
/// carries — which is where a typed handle put it, and where an author
/// asserting one by hand puts it too.
fn edge_resource(constraints: &[Constraint]) -> Option<ResourceAddr> {
    constraints.iter().find_map(|constraint| match constraint {
        Constraint::ResourceIs(resource) => Some(*resource),
        Constraint::MinAmount(_) | Constraint::MaxAmount(_) => None,
    })
}

/// Whether an output expression can be evaluated against what is known at
/// construction.
///
/// Two things a signed graph has that a graph under construction does not:
/// the resource on an edge nothing typed, and the transaction identity the
/// fresh-id forms derive from. An expression reaching either is left to
/// admission, which has both. The depth bound mirrors the evaluator's own,
/// so metadata nested past what any evaluation would accept is refused
/// here rather than recursed into.
fn resolvable(expr: &Expr, known: &[bool], depth: usize) -> bool {
    if depth > MAX_EXPR_DEPTH {
        return false;
    }
    let deeper = |expr| resolvable(expr, known, depth + 1);
    match expr {
        Expr::Literal(_) | Expr::SelfAddr | Expr::SelfRecord | Expr::Config(_) => true,
        Expr::Arg(index) => usize::try_from(*index)
            .ok()
            .and_then(|index| known.get(index).copied())
            .unwrap_or(false),
        // No `for-each` encloses an output expression, and no identity
        // exists to derive from yet.
        Expr::Binding(_) | Expr::FreshId { .. } | Expr::FreshKey { .. } => false,
        Expr::Field(inner, _)
        | Expr::ResourceOf(inner)
        | Expr::IdsOf(inner)
        | Expr::Len(inner)
        | Expr::Only(inner)
        | Expr::Not(inner) => deeper(inner),
        Expr::Lookup { map, key } | Expr::Contains { map, key } => deeper(map) && deeper(key),
        Expr::Pack { hi, lo } => deeper(hi) && deeper(lo),
        Expr::Add(left, right)
        | Expr::And(left, right)
        | Expr::Or(left, right)
        | Expr::Eq(left, right)
        | Expr::Lt(left, right) => deeper(left) && deeper(right),
        // Which arm a conditional takes is a fact about arguments a graph
        // under construction may not have yet, so both arms must resolve
        // before the selection does.
        Expr::If {
            cond,
            then,
            otherwise,
        } => deeper(cond) && deeper(then) && deeper(otherwise),
        Expr::NfBucket { resource, ids } => deeper(resource) && deeper(ids),
        Expr::List(elements) | Expr::Tuple(elements) => elements.iter().all(deeper),
        Expr::SelfResource { material, .. } => material.iter().all(deeper),
        Expr::ChildKey {
            owner, material, ..
        }
        | Expr::OrderKey {
            owner, material, ..
        } => deeper(owner) && material.iter().all(deeper),
    }
}

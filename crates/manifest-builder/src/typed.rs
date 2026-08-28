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

use std::collections::{BTreeMap, BTreeSet};
use std::iter;
use std::marker::PhantomData;
use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::{
    AUTHORIZE_METHOD, PRESENT_BADGE_METHOD, PRESENT_INSTANCE_METHOD,
};
use hyperscale_vm_effects::{
    ChainRecords, Claim, EdgeRef, EvalBudget, EvidenceRef, GraphArg, Hasher, InstanceMeta,
    MAX_PROVEN_PER_SIGNATURE, ManifestGraph, MethodSignature, PackageHash, PackageMetadata, Value,
    claim_text,
};
use hyperscale_vm_types::{Address, AddressClass, CallTarget, PrincipalAddr};

use crate::args::Args;
use crate::builder::{Bucket, BuildError, GraphBuilder};
use crate::projection::{
    earned_claims, eval_inputs, gated_claims, output_resources, proven_claims, typed_values,
};
use crate::unpack::{Arity, Unpacked};

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
    /// Bytes at the wrong width for an exact-width parameter.
    #[error("`{method}` argument {param}: expected [u8; {expected}], found {found} bytes")]
    ParamWidth {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
        /// The declared width.
        expected: u32,
        /// The bound value's length.
        found: usize,
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
    /// A socket where the method declares a value.
    #[error("`{method}` argument {param}: a socket cannot bind a value parameter")]
    SocketForValueParam {
        /// The method called.
        method: String,
        /// The parameter position.
        param: u32,
    },
    /// An output no argument consumed and no yield exported, named
    /// against the method that produced it. The untyped tier's
    /// [`BuildError::DanglingOutput`] keeps indices — it reads no
    /// metadata and has nothing else.
    #[error(
        "output {output} of `{method}` reaches no consumer — route it, or name a rest sink with `rest_to`"
    )]
    DanglingOutput {
        /// The producing method's published name.
        method: String,
        /// The output slot, in declaration order.
        output: u32,
    },
    /// A proof presented by a builder that did not prove it — a node
    /// index means nothing in another intent's graph, and cross-intent
    /// authority travels through a socket, never a foreign handle.
    #[error("a proof must be presented by the builder that proved it")]
    ForeignProof,
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
    /// A guarded call composed without a proof, naming no claim the
    /// composer could prove from the signer's own account — admission's
    /// [`SignatureForGuarded`](hyperscale_vm_effects::AdmissionError::SignatureForGuarded)
    /// verdict, reached at the call site. A signature signs in through
    /// an authorizing method; what it proves there is what a guarded
    /// method takes.
    #[error("`{method}` takes a proven claim; a signature only signs in")]
    SignatureForGuarded {
        /// The method called.
        method: String,
    },
    /// A guarded call inside a `presenting` scope none of whose proofs
    /// covers the gate the composer could read whole — admission's
    /// judgment, reached at the call site with the claim named.
    #[error("`{method}` requires a claim on {claim}, and nothing in scope proves it")]
    UncoveredGate {
        /// The method called.
        method: String,
        /// The first uncovered claim, rendered.
        claim: String,
    },
    /// A proof requested from a method that proves nothing — admission's
    /// [`ProvesNothing`](hyperscale_vm_effects::AdmissionError::ProvesNothing)
    /// verdict, reached where the proof is requested rather than where it
    /// would be presented.
    #[error("`{method}` proves no claim")]
    ProvesNothing {
        /// The method called.
        method: String,
    },
    /// An answer requested from a method whose declaration answers with
    /// no value — refused where the method is named, rather than at the
    /// receipt where nothing would ever be filed.
    #[error("`{method}` answers with no value")]
    AnswersNothing {
        /// The method called.
        method: String,
    },
    /// The graph's own structural refusal, reached at [`TypedBuilder::build`].
    #[error(transparent)]
    Build(#[from] BuildError),
}

mod sealed {
    /// The sealing marker for [`Evidence`](super::Evidence).
    pub trait Sealed {}
    impl Sealed for super::Proof {}
    impl Sealed for &super::Proof {}
    impl Sealed for &[super::Proof] {}
    impl<const N: usize> Sealed for [super::Proof; N] {}
    impl<const N: usize> Sealed for &[super::Proof; N] {}
}

/// What a presenting call hands its target: one proof, or a set of them
/// where the gate is a threshold.
///
/// One parameter for both, because how many claims a gate takes is the
/// gate's own business — a stored rule can be a threshold, and nothing
/// at the call site says so.
pub trait Evidence: sealed::Sealed {
    /// The proofs presented, in the order given.
    fn proofs(self) -> Vec<Proof>;
}

impl Evidence for Proof {
    fn proofs(self) -> Vec<Proof> {
        vec![self]
    }
}

impl Evidence for &Proof {
    fn proofs(self) -> Vec<Proof> {
        vec![*self]
    }
}

impl Evidence for &[Proof] {
    fn proofs(self) -> Vec<Proof> {
        self.to_vec()
    }
}

impl<const N: usize> Evidence for [Proof; N] {
    fn proofs(self) -> Vec<Proof> {
        self.to_vec()
    }
}

impl<const N: usize> Evidence for &[Proof; N] {
    fn proofs(self) -> Vec<Proof> {
        self.to_vec()
    }
}

/// The identity an authorizing node proves, as a later call of the same
/// graph presents it.
///
/// A node reference rather than a value edge: nothing is conserved, and
/// presenting it twice says nothing presenting it once does not. It
/// carries authority only downward — admission refuses a proof drawn
/// from a node that is not earlier.
#[derive(Clone, Copy, Debug)]
#[must_use = "an unpresented proof authorizes nothing"]
pub struct Proof {
    /// The builder that proved it. A node index means nothing in another
    /// intent's graph, so presenting a foreign proof would compile and
    /// then surface at admission in flattened-tree coordinates — the
    /// failure this tier exists to catch at the compose site.
    builder: u64,
    /// How the presenting node names it: a node of the same intent, or
    /// a socket this intent declared for a proof from outside it.
    reference: EvidenceRef,
    /// The claims it proves, as far as construction could read them off
    /// the proving declaration — each proved claim and, for an instance,
    /// the widened subject, exactly as the evaluator widens. What a
    /// `presenting` scope's coverage is judged by; a claim construction
    /// could not evaluate is absent and covers nothing. Sized to the most
    /// a signature may prove, so a method proving several files them all
    /// rather than dropping the tail past the first.
    proves: [Option<Claim>; MAX_PROVEN_PER_SIGNATURE],
}

impl Proof {
    /// The proof a socket will be filled with, presented as this
    /// intent's `position`-th socket.
    pub(crate) fn from_socket(builder: u64, position: u32, claim: Claim) -> Self {
        let widened = claim
            .instance
            .is_some()
            .then(|| Claim::of_subject(claim.subject));
        let mut proves = [None; MAX_PROVEN_PER_SIGNATURE];
        proves[0] = Some(claim);
        proves[1] = widened;
        Self {
            builder,
            reference: EvidenceRef::Socket(position),
            proves,
        }
    }

    /// Whether this proof proves `claim`, on the judge's own equality
    /// terms.
    pub(crate) fn covers(&self, claim: &Claim) -> bool {
        self.proves.iter().flatten().any(|proven| proven == claim)
    }

    /// Whether this builder proved the proof, on [`Bucket`]'s terms.
    ///
    /// [`Bucket`]: crate::Bucket
    pub(crate) const fn proved_by(&self, builder: u64) -> bool {
        self.builder == builder
    }

    /// How a node presents it.
    pub(crate) const fn reference(self) -> EvidenceRef {
        self.reference
    }
}

/// The output edges of one typed call, in slot order.
///
/// Held as a group rather than an array because a method's output count is
/// its signature's, not the caller's: there is no arity to name here, which
/// is what makes naming a slot the producer does not have inexpressible.
/// [`into_array`](Unpacked::into_array) is where a caller states an
/// expected shape and is held to it.
pub type Outputs = Unpacked<Bucket, ProducedBy>;

/// The call whose signature answers an [`Outputs`] arity claim.
#[derive(Debug)]
pub struct ProducedBy {
    pub(crate) method: String,
    pub(crate) node: u32,
    /// Whether the method's declaration answers with a value — what
    /// [`answering`](Outputs::answering) is held to.
    pub(crate) answers: bool,
}

impl Arity for ProducedBy {
    type Error = TypedError;

    fn refuse(self, declared: usize, claimed: usize) -> TypedError {
        TypedError::OutputArity {
            method: self.method,
            declared,
            claimed,
        }
    }
}

impl Outputs {
    /// Split off the handle on what this call answered with, leaving the
    /// edges beside it to be discharged like any other call's.
    ///
    /// A split rather than a discharge of its own: a method answers with
    /// at most one value and yields any number of edges, and the two are
    /// independent facts about its signature. Answering is not a third
    /// arity — it is a thing that happens alongside whichever arity the
    /// method has.
    ///
    /// The node is what a receipt files an answer under, so handing it
    /// back typed is what lets a reader ask for the answer rather than
    /// count the calls before it.
    ///
    /// # Errors
    ///
    /// [`TypedError::AnswersNothing`] on a method whose declaration
    /// answers with no value — refused here, where the method is named,
    /// rather than at the receipt where nothing would ever be filed.
    pub fn answering<T>(self) -> Result<(Answered<T>, Self), TypedError> {
        if !self.context.answers {
            return Err(TypedError::AnswersNothing {
                method: self.context.method,
            });
        }
        let handle = Answered {
            node: self.context.node,
            answer: PhantomData,
        };
        Ok((handle, self))
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
/// The type rides along so the reader is not asked to name one at the
/// receipt. The generated wrappers take it from the method's own
/// signature; records carry no type names, so a hand author's wrong `T`
/// surfaces as a decode failure at the receipt rather than from the
/// compiler.
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

/// A [`GraphBuilder`] that resolves its targets against the same tables
/// admission consults.
pub struct TypedBuilder<'a> {
    graph: GraphBuilder,
    chain: &'a dyn ChainRecords,
    hasher: &'a dyn Hasher,
    /// The principal this intent will be signed as.
    ///
    /// A declared fact rather than a fact about whoever runs the
    /// builder: an agent preparing a subintent for somebody else's
    /// wallet names that somebody, and the intent's own gates hold the
    /// declaration to it. A wrong name is a refusal at the node that
    /// reads it, never a forgery.
    signer: PrincipalAddr,
    /// The nodes already proving a claim, so a second call wanting one
    /// presents the same proof rather than composing a second node.
    proven: BTreeMap<(Address, Option<u64>), Proof>,
    /// The claims whose proof is being composed further up the stack.
    ///
    /// A proof is proven by a call, and that call earns claims of its
    /// own; where one of them is the claim being proven, presenting it
    /// again would recurse without end. The memo above cannot break the
    /// cycle — its entry is written only once the node exists, which is
    /// after the recursion. A claim named here is left to the ancestor
    /// already proving it, so a self-earning account metadata a hostile
    /// chain serves refuses at admission rather than overflowing here.
    ///
    /// An entry is written on the way in and taken out on the way back,
    /// so this holds exactly the frames between the outermost `present`
    /// and the one running: its length is the depth, which is what
    /// [`MAX_PRESENT_DEPTH`] bounds.
    composing: BTreeSet<(Address, Option<u64>)>,
    /// The evidence each enclosing [`presenting`](Self::presenting)
    /// scope holds, innermost last.
    ///
    /// Ambient rather than per-call: a composer who holds a badge says so
    /// once, for a span of calls, and each call inside the span draws it
    /// where its own requirements could want evidence. Presenting a proof
    /// a call does not need says nothing, so the scope only ever adds.
    scopes: Vec<Vec<Proof>>,
}

/// How deep the composer will chain proofs it proves for itself.
///
/// Repetition is what the `presenting` memo catches, and a chain that
/// never repeats escapes it: each badge's record can name a claim on a
/// fresh badge, so the metadata an untrusted chain view serves decides
/// how far this walk goes. The claims are what the *resources* a call
/// names demand, so a legitimate chain is one badge whose movement is
/// gated on holding another; the protocol's own account proves from
/// bodies that declare nothing at all and never reaches two.
const MAX_PRESENT_DEPTH: usize = 4;

impl<'a> TypedBuilder<'a> {
    /// A builder with no nodes, typing its calls and resolving its
    /// targets against what `chain` answers for.
    pub fn new(chain: &'a dyn ChainRecords, hasher: &'a dyn Hasher, signer: PrincipalAddr) -> Self {
        Self {
            graph: GraphBuilder::new(),
            chain,
            hasher,
            signer,
            proven: BTreeMap::new(),
            composing: BTreeSet::new(),
            scopes: Vec::new(),
        }
    }

    /// Run `write` with `evidence` ambient: every call inside the span
    /// draws it where its own requirements could want evidence — a
    /// declared gate, an entry a movement earns, or a behaviour whose
    /// requirement the resource injects — and a call wanting nothing
    /// attaches nothing.
    ///
    /// The scope only ever adds. The builder still proves what it can
    /// from the signer's own account, exactly as it would outside the
    /// scope, so wrapping a span in one never composes a call worse —
    /// what changes is that a requirement only this evidence answers
    /// stops needing a per-call spelling. Scopes nest, and a call inside
    /// both draws from both: presented evidence is a set, and presenting
    /// a proof a gate does not need says nothing.
    ///
    /// Evidence a call names explicitly —
    /// [`call_presenting`](Self::call_presenting) and its proving twin —
    /// is the composer overruling the ambient reading for that call: the
    /// scope stands aside entirely, exactly as it does for the builder's
    /// own composition.
    ///
    /// # Errors
    ///
    /// Whatever `write` itself refuses; the scope adds no refusals.
    ///
    pub fn presenting<R>(
        &mut self,
        evidence: impl Evidence,
        write: impl FnOnce(&mut Self) -> Result<R, TypedError>,
    ) -> Result<R, TypedError> {
        let proofs = evidence.proofs();
        for proof in &proofs {
            if !proof.proved_by(self.graph.id()) {
                return Err(TypedError::ForeignProof);
            }
        }
        self.scopes.push(proofs);
        let written = write(self);
        self.scopes.pop();
        written
    }

    /// The principal this intent will be signed as.
    #[must_use]
    pub const fn signer(&self) -> PrincipalAddr {
        self.signer
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
    pub fn seal_of(
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
    /// A [`Bucket`] made by a different builder does not panic: it is
    /// recorded as [`BuildError::ForeignBucket`] and handed back when the
    /// graph builds.
    pub fn call(
        &mut self,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Outputs, TypedError> {
        self.append(target.into(), method, args, &[])
            .map(|(_, outputs, _)| outputs)
    }

    /// The same call, presenting `evidence` instead of the intent's
    /// signature proof — how a call acts as the account an earlier
    /// authorizing node signed in, and how a threshold gate is met:
    /// satisfying two of three means presenting two, each a node of its
    /// own earlier in the same intent.
    ///
    /// # Errors
    ///
    /// [`TypedError::UnexpectedEvidence`] on a method that admits
    /// anyone, and everything [`call`](Self::call) refuses.
    ///
    /// Its refusal surface is [`call`](Self::call)'s.
    pub fn call_presenting(
        &mut self,
        evidence: impl Evidence,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Outputs, TypedError> {
        self.append(target.into(), method, args, &evidence.proofs())
            .map(|(_, outputs, _)| outputs)
    }

    /// Append an invocation of `method`, a proving method of `target`,
    /// and return the proof it proves.
    ///
    /// The call presents the intent's signature proof to its own gate —
    /// signing in starts from a signature. The arguments are the gate's
    /// where it has any: a custodial method names the badge it presents,
    /// where a sign-in names nothing.
    ///
    /// # Errors
    ///
    /// [`TypedError::ProvesNothing`] when the method's accessibility
    /// proves nothing, and everything [`call`](Self::call) refuses.
    ///
    /// Its refusal surface is [`call`](Self::call)'s.
    pub fn call_proving(
        &mut self,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Proof, TypedError> {
        self.prove(target.into(), method, args, &[])
    }

    /// The same proving call, presenting `evidence` instead of the
    /// intent's signature — how a target whose stored rule names another
    /// account's identity is signed into through that account's own
    /// sign-in, the only way in when the rule names no key the intent
    /// could carry, and with several proofs where the stored rule is a
    /// threshold.
    ///
    /// # Errors
    ///
    /// As [`call_proving`](Self::call_proving).
    ///
    /// Its refusal surface is [`call`](Self::call)'s.
    pub fn call_proving_presenting(
        &mut self,
        evidence: impl Evidence,
        target: impl Into<CallTarget>,
        method: &str,
        args: impl Args,
    ) -> Result<Proof, TypedError> {
        self.prove(target.into(), method, args, &evidence.proofs())
    }

    fn prove<A: Args>(
        &mut self,
        target: CallTarget,
        method: &str,
        args: A,
        proofs: &[Proof],
    ) -> Result<Proof, TypedError> {
        let (_, package) = self.resolve(target, method)?;
        if !package.methods[method].proves() {
            return Err(TypedError::ProvesNothing {
                method: method.to_owned(),
            });
        }
        // Judged before the call is appended, so the refusal leaves the
        // graph exactly as it was: a proving call whose outputs would
        // dangle never becomes a node the author has to unwind.
        let declared = package.methods[method].outputs.len();
        if declared != 0 {
            return Err(TypedError::OutputArity {
                method: method.to_owned(),
                declared,
                claimed: 0,
            });
        }
        let (node, outputs, proves) = self.append(target, method, args, proofs)?;
        outputs.none()?;
        Ok(Proof {
            builder: self.graph.id(),
            reference: EvidenceRef::Node(node),
            proves,
        })
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

    /// Mint what this call's injected authority entries will ask for,
    /// as far as the composer can.
    ///
    /// The entries come from the resources a call names rather than from
    /// its declaration, so nothing about the method being called says a
    /// proof is wanted. Predicted from exactly what admission injects
    /// from, and decided there: a prediction that comes up short refuses
    /// at admission.
    ///
    /// What it can prove is what the protocol's own account offers: the
    /// signer's own identity, and a badge the signer holds. A claim on
    /// anything else — another party's identity, a component's — is one
    /// no composer can prove, and it is left for whoever can.
    fn earned(
        &self,
        signature: &MethodSignature,
        target: CallTarget,
        record: &InstanceMeta,
        args: &[GraphArg],
        values: &[Value],
        known: &[bool],
    ) -> Vec<Claim> {
        let budget = EvalBudget::default();
        let inputs = eval_inputs(target.address(), values, record, 0, &budget);
        earned_claims(signature, args, &inputs, known, self.chain, self.hasher)
    }

    /// The claims the method's own gate names, evaluated as far as the
    /// composer can.
    ///
    /// The counterpart of [`earned`](Self::earned) for the rule the
    /// declaration itself writes, read so a guarded call composed
    /// without a proof can be answered from the signer's own account
    /// before it is refused.
    fn gated(
        &self,
        signature: &MethodSignature,
        target: CallTarget,
        record: &InstanceMeta,
        values: &[Value],
        known: &[bool],
    ) -> (Vec<Claim>, bool) {
        let budget = EvalBudget::default();
        let inputs = eval_inputs(target.address(), values, record, 0, &budget);
        gated_claims(signature, &inputs, known, self.hasher)
    }

    /// What a claim-gated call presents where the caller spelled
    /// nothing: whatever its gate names that the signer's own account
    /// can prove, composed ahead of the call.
    ///
    /// Where the account proves nothing, the enclosing scopes answer for
    /// the call — a gate read whole that nothing in scope covers refuses
    /// with the claim named, and one read only in part is left to
    /// admission, since the leaf construction could not evaluate may be
    /// exactly the claim a scope proves. With no scope at all, the
    /// refusal is the signature's.
    #[allow(clippy::too_many_arguments)] // one judgment, split for the line count
    fn gate_proofs(
        &mut self,
        signature: &MethodSignature,
        target: CallTarget,
        record: &InstanceMeta,
        values: &[Value],
        known: &[bool],
        method: &str,
        scoped: &[Proof],
    ) -> Result<Vec<Proof>, TypedError> {
        let (asked, complete) = self.gated(signature, target, record, values, known);
        // A claim the scope covers is never auto-proven: the composer
        // already answered it, and a second answer composed from the
        // signer's account would be a node that can fail on its own —
        // presenting a badge the signer does not hold, for one.
        let uncovered: Vec<Claim> = asked
            .iter()
            .filter(|claim| !scoped.iter().any(|proof| proof.covers(claim)))
            .copied()
            .collect();
        let any_covered = uncovered.len() < asked.len();
        let proven: Vec<Proof> = uncovered
            .iter()
            .filter_map(|claim| self.present(*claim))
            .collect();
        if proven.is_empty() && !any_covered {
            if scoped.is_empty() {
                return Err(TypedError::SignatureForGuarded {
                    method: method.to_owned(),
                });
            }
            if complete {
                let claim = asked.first().map(claim_text).unwrap_or_default();
                return Err(TypedError::UncoveredGate {
                    method: method.to_owned(),
                    claim,
                });
            }
        }
        Ok(proven)
    }

    /// The claims this call proves, filed on the [`Proof`] handed back
    /// so a scope's coverage can be judged without re-resolving the
    /// call. All `None` for a call that proves nothing.
    fn filed_claims(
        &self,
        signature: &MethodSignature,
        target: CallTarget,
        record: &InstanceMeta,
        values: &[Value],
        known: &[bool],
    ) -> [Option<Claim>; MAX_PROVEN_PER_SIGNATURE] {
        let mut filed = [None; MAX_PROVEN_PER_SIGNATURE];
        if !signature.proves() {
            return filed;
        }
        let budget = EvalBudget::default();
        let inputs = eval_inputs(target.address(), values, record, 0, &budget);
        let claims = proven_claims(signature, &inputs, known, self.hasher);
        for (slot, claim) in filed.iter_mut().zip(claims) {
            *slot = Some(claim);
        }
        filed
    }

    /// The node proving `claim`, composing one where this intent has
    /// none yet.
    ///
    /// Both forms are the account's own and both are satisfied by the
    /// intent's signature, because both gate on the rule governing the
    /// signer's own address — so neither takes a proof of its own and
    /// the composition stays one node deep.
    ///
    /// Answers `None` for a claim it will not prove, which is what the
    /// two bounds below and an unprovable subject all come back as: the
    /// claim is left to whoever can, exactly as one on another party's
    /// identity always was.
    fn present(&mut self, claim: Claim) -> Option<Proof> {
        let key = (claim.subject, claim.instance);
        if let Some(proof) = self.proven.get(&key) {
            return Some(*proof);
        }
        // Past the depth a chain of gated badges is composed to; the
        // records naming each next claim are the chain view's, so
        // nothing here bounds the walk except this.
        if self.composing.len() >= MAX_PRESENT_DEPTH {
            return None;
        }
        // Already proving this claim's proof further up the stack; the
        // ancestor call will file it, and recursing to compose a second
        // would not terminate.
        if !self.composing.insert(key) {
            return None;
        }
        let signer = self.signer;
        let proven = match (claim.subject.class(), claim.instance) {
            (AddressClass::Principal, None) if claim.subject == signer.address() => {
                self.prove(signer.into(), AUTHORIZE_METHOD, (), &[]).ok()
            }
            (AddressClass::Resource | AddressClass::Restricted, None) => self
                .prove(signer.into(), PRESENT_BADGE_METHOD, (claim.subject,), &[])
                .ok(),
            (AddressClass::Resource | AddressClass::Restricted, Some(id)) => self
                .prove(
                    signer.into(),
                    PRESENT_INSTANCE_METHOD,
                    (claim.subject, id),
                    &[],
                )
                .ok(),
            _ => None,
        };
        self.composing.remove(&key);
        let proven = proven?;
        self.proven.insert(key, proven);
        Some(proven)
    }

    /// The graph's identity, for the handles that must remember which
    /// builder made them.
    pub(crate) const fn graph_id(&self) -> u64 {
        self.graph.id()
    }

    /// Build a whole graph in one closure: construct, write, emit.
    ///
    /// The shape every test that wants "a graph doing X" reaches for,
    /// offered here so it is written once rather than per test file.
    ///
    /// # Errors
    ///
    /// [`TypedError`], from the closure's own calls or from
    /// [`build`](Self::build).
    pub fn compose(
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        signer: PrincipalAddr,
        write: impl FnOnce(&mut Self) -> Result<(), TypedError>,
    ) -> Result<ManifestGraph, TypedError> {
        let mut builder = Self::new(chain, hasher, signer);
        write(&mut builder)?;
        builder.build()
    }

    fn append(
        &mut self,
        target: CallTarget,
        method: &str,
        args: impl Args,
        proofs: &[Proof],
    ) -> Result<(u32, Outputs, [Option<Claim>; MAX_PROVEN_PER_SIGNATURE]), TypedError> {
        // A proof's node index means nothing in another intent's graph;
        // cross-intent authority travels through a socket, never by
        // presenting a foreign handle.
        for proof in proofs {
            if !proof.proved_by(self.graph.id()) {
                return Err(TypedError::ForeignProof);
            }
        }
        let (meta, package) = self.resolve(target, method)?;
        let signature = &package.methods[method];
        let meta = meta.as_ref();
        let hasher = self.hasher;

        let args = args.bind_all(&mut self.graph);
        let (values, known) = typed_values(method, &args, &signature.params)?;

        // What the resources this call moves and the authority it
        // exercises demand of it — admission's own injection, mirrored,
        // because none of it is anything the signature says. Computed
        // whether or not the author presented something: it is what says
        // a proof is wanted here, and where nothing can prove one it is
        // still the answer.
        //
        // Minted ahead of the call, since each claim is a node of its
        // own, and only where the author presented nothing: a proof they
        // composed is one they meant, and a second beside it would be
        // the builder overruling them.
        let wanted = self.earned(signature, target, meta, &args, &values, &known);
        // The evidence the enclosing `presenting` scopes hold, where this
        // call could want any: a declared gate, an entry a movement
        // earns, or a behaviour whose requirement the resource injects.
        // Ambient evidence only adds — the builder still proves what it
        // can, and a call wanting nothing attaches nothing, so a scope
        // never makes a call compose differently than it would outside
        // one unless the call wanted evidence.
        let scoped: Vec<Proof> = if proofs.is_empty()
            && (signature.requires_evidence()
                || !wanted.is_empty()
                || signature.may_earn_authority())
        {
            self.scopes.iter().flatten().copied().collect()
        } else {
            Vec::new()
        };
        // A signature signs in, so it reaches only a gate that reads a
        // rule; a claim a declaration names takes a proof — and what the
        // gate names that the signer's own account can prove is proven
        // ahead of the call, exactly as injected requirements are. Only
        // a gate whose every claim is beyond both the composer's reach
        // and the enclosing scopes' refuses, and proving nothing appends
        // nothing, so the refusal leaves the graph as it was.
        let gated: Vec<Proof> =
            if signature.requires_evidence() && proofs.is_empty() && !signature.reads_a_rule() {
                self.gate_proofs(signature, target, meta, &values, &known, method, &scoped)?
            } else {
                Vec::new()
            };
        let earned = if proofs.is_empty() {
            wanted
                .iter()
                .filter(|claim| !scoped.iter().any(|proof| proof.covers(claim)))
                .filter_map(|claim| self.present(*claim))
                .collect()
        } else {
            Vec::new()
        };
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
        // signature; everything guarded presents claims proven earlier —
        // more than one where the gate is a threshold, since satisfying
        // two of three means presenting two.
        let evidence = match (signature.requires_evidence(), proofs) {
            (false, []) if earned.is_empty() => BTreeSet::new(),
            // A method that issues, destroys, reaches or moves value
            // earns its requirement from the resource rather than from
            // its own declaration, so the signature says it admits
            // anyone and the resource says otherwise. Ruling the proof
            // out here would refuse the call before the party who
            // decides has been asked.
            (false, []) => earned.iter().map(|proof| proof.reference()).collect(),
            // An earned claim is the exact answer where there is one —
            // the resource is in hand, so a movement's requirement is
            // known rather than guessed. The signature's own loose
            // reading stands beside it for the cases where the entry
            // depends on something no record settles.
            (false, presented) if !wanted.is_empty() || signature.may_earn_authority() => {
                presented.iter().map(|proof| proof.reference()).collect()
            }
            (false, _) => {
                return Err(TypedError::UnexpectedEvidence {
                    method: method.to_owned(),
                });
            }
            // A method reading a rule takes the intent's signature, and
            // what its movements earned rides beside it — the stored
            // rule answers the sign-in, never the claim a moved
            // resource demands. A guarded method presents what the walk
            // above proved of its gate, and was refused there if that
            // was nothing.
            (true, []) if signature.reads_a_rule() => iter::once(EvidenceRef::IntentSignature)
                .chain(earned.iter().map(|proof| proof.reference()))
                .collect(),
            (true, []) => gated
                .iter()
                .chain(earned.iter())
                .map(|proof| proof.reference())
                .collect(),
            (true, presented) => presented.iter().map(|proof| proof.reference()).collect(),
        };
        // What the enclosing scopes hold rides beside whatever the call
        // resolved for itself: presented evidence is a set, so a proof
        // the builder also proved dedups, and one nothing needs says
        // nothing.
        let evidence: BTreeSet<EvidenceRef> = evidence
            .into_iter()
            .chain(scoped.iter().map(|proof| proof.reference()))
            .collect();
        let proves = self.filed_claims(signature, target, meta, &values, &known);
        let outputs = resources.len();
        let producer = self
            .graph
            .push(target, method.to_owned(), args, resources, evidence);
        let buckets = (0..outputs)
            .map(|slot| {
                let slot = u32::try_from(slot).expect("outputs are bounded by the signature");
                self.graph.edge(producer, slot)
            })
            .collect();
        Ok((
            producer,
            Outputs {
                context: ProducedBy {
                    method: method.to_owned(),
                    node: producer,
                    answers: signature.answers,
                },
                items: buckets,
            },
            proves,
        ))
    }

    /// Consume an output as a yield edge, as [`GraphBuilder::export`].
    ///
    /// A bucket carrying constraints, or one made by a different builder,
    /// does not panic: it poisons the builder and the refusal is handed
    /// back when the graph builds, as [`GraphBuilder::export`] documents.
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

    /// Emit the graph, checking that every output edge was consumed.
    ///
    /// # Errors
    ///
    /// [`TypedError::Build`] wrapping the structural refusal.
    pub fn build(self) -> Result<ManifestGraph, TypedError> {
        // Captured before the graph is consumed, so the one structural
        // refusal made in method-and-output terms can speak them.
        let methods = self.graph.method_names();
        match self.graph.build() {
            Err(BuildError::DanglingOutput { producer, output }) => {
                Err(TypedError::DanglingOutput {
                    method: usize::try_from(producer)
                        .ok()
                        .and_then(|node| methods.get(node).cloned())
                        .unwrap_or_default(),
                    output,
                })
            }
            outcome => Ok(outcome?),
        }
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass};

    use super::*;

    /// A method may prove up to [`MAX_PROVEN_PER_SIGNATURE`] claims, and a
    /// `Proof` files them all: a scope's coverage is judged against every
    /// one, not the first two.
    #[test]
    fn a_proof_files_every_claim_it_proves() {
        let subject = |n: u8| Claim::of_subject(Address::new([n; 31], AddressClass::Component));
        let mut proves = [None; MAX_PROVEN_PER_SIGNATURE];
        let filed: u8 = 5;
        assert!(usize::from(filed) > 2 && usize::from(filed) <= MAX_PROVEN_PER_SIGNATURE);
        for (slot, n) in proves.iter_mut().zip(0..filed) {
            *slot = Some(subject(n));
        }
        let proof = Proof {
            builder: 1,
            reference: EvidenceRef::Node(0),
            proves,
        };
        for n in 0..filed {
            assert!(proof.covers(&subject(n)), "claim {n} is filed and covered");
        }
    }
}

//! The envelope tier: intents composed along the sockets they declare.
//!
//! A composition is addition *between* graphs. Each intent is written on
//! its own — an [`IntentBuilder`] is a [`TypedBuilder`] that can also
//! declare sockets and offer what fills them — and the
//! [`EnvelopeBuilder`] joins them by wiring one intent's offering to
//! another's socket. Nothing an intent contains is rewritten to make a
//! composition fit, which is what lets a subintent's signer sign a
//! declaration and have it mean the same thing in whatever envelope
//! later carries it.
//!
//! The wiring is done from handles rather than from indices. One
//! declared socket has two handles, one per side: inside the intent it
//! is the [`SocketRef`] its own graph names it by, and outside it is an
//! [`OpenSocket`], which arrives when the intent enters an envelope.
//! What fills one is an [`Offered`], answered by exporting an edge or
//! offering a proof. All three name the intent they came from, so a
//! binding cannot reach an intent or a node that does not exist.
//!
//! An intent enters an envelope one of two ways, and both hand back open
//! sockets the same way. [`EnvelopeBuilder::seal`] takes one the composer wrote.
//! [`EnvelopeBuilder::present`] takes one somebody else signed — built
//! through [`IntentBuilder::declaration`] before any envelope existed, and
//! stored exactly as handed over, because the signature already covering
//! it would not survive a rebuild.
//!
//! What is left is arithmetic over declarations, which the builder checks
//! when it emits: every intent sealed, every socket reached inside its
//! graph and filled exactly once outside it. Reached *once* where it
//! carries value, which is conserved, and as often as asked where it
//! carries authority, which is not.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};

use hyperscale_vm_effects::{
    Binding, ChainRecords, Claim, Constraint, EdgeRef, EnvelopeTree, EvidenceRef, Hasher,
    InstanceMeta, IntentDecl, MAX_SOCKETS, MAX_VALUE_DEPTH, ManifestGraph, ResourceMeta, Socket,
    Subintent,
};
use hyperscale_vm_types::{CallTarget, MAX_SUBINTENTS, PrincipalAddr, ResourceAddr};

use crate::builder::{Bucket, SocketRef, next_space};
use crate::projection::graph_records;
use crate::typed::{Proof, TypedBuilder, TypedError};
use crate::unpack::{Arity, Unpacked};

/// Why an envelope could not be composed.
///
/// Every variant is a verdict [`admit_tree`] would also reach —
/// [`SocketArity`](Self::SocketArity) as the socket a miscounting
/// composer leaves unbound — named against the intent the author wrote
/// rather than against a flattened tree they have not finished
/// composing.
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
    /// A socket no node of the declaring graph reaches, so nothing
    /// would consume what the composition puts in it.
    #[error("intent {intent} socket {socket} is never reached")]
    UnconsumedSocket {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A value socket consumed by more than one node argument. An
    /// authority socket is not held to it: a claim presented twice says
    /// nothing presenting it once does not.
    #[error("intent {intent} socket {socket} is consumed twice")]
    SocketReused {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A socket reference past what the intent declared — reachable only
    /// from a declaration the tier did not build.
    #[error("intent {intent} references socket {socket}, which it does not declare")]
    UnknownSocket {
        /// The referencing intent.
        intent: u32,
        /// The socket it named.
        socket: u32,
    },
    /// A socket the composition never filled.
    #[error("intent {intent} socket {socket} is filled by nothing")]
    UnfilledSocket {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// Open sockets unpacked into a different arity than the intent
    /// declares.
    #[error("intent {intent} declares {declared} sockets, unpacked as {claimed}")]
    SocketArity {
        /// The declaring intent.
        intent: u32,
        /// The intent's declared socket count.
        declared: usize,
        /// The arity the composer unpacked into.
        claimed: usize,
    },
    /// A proof offered to a socket that declares value.
    #[error("intent {intent} socket {socket} carries value, which no proof fills")]
    ProofForValueSocket {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// An edge offered to a socket that declares authority.
    #[error("intent {intent} socket {socket} carries authority, which no edge fills")]
    EdgeForAuthoritySocket {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// An intent declaring more sockets than admission accepts.
    #[error("intent {intent} declares more than {MAX_SOCKETS} sockets")]
    TooManySockets {
        /// The declaring intent.
        intent: u32,
    },
    /// More subintents than an envelope may bind.
    #[error("envelope binds more than {MAX_SUBINTENTS} subintents")]
    TooManySubintents,
    /// A presented instance record whose configuration nests past what
    /// the vocabulary encodes — the bound admission holds it to, met at
    /// build so the tree can be hashed before any gate sees it.
    #[error("presented instance {instance}'s configuration nests deeper than {MAX_VALUE_DEPTH}")]
    InstanceValueTooDeep {
        /// The record's position among the presented instances.
        instance: u32,
    },
    /// A socket filled from the intent that declared it. Admission
    /// refuses the shape as a cycle over the whole tree; here it is one
    /// wiring, named against the intent the author wrote.
    #[error("intent {intent} socket {socket} is filled from the intent that declared it")]
    SelfFilledSocket {
        /// The declaring intent, offering to itself.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// An intent's own graph refused to build or type.
    #[error(transparent)]
    Intent(#[from] TypedError),
}

/// One intent's declared socket, as the composition names it — the side
/// a binding fills, against the [`SocketRef`] the intent's own graph
/// reaches it by.
///
/// Affine like the [`Socket`] it is declared beside: one socket takes one
/// offering, so filling the same socket twice has no spelling.
#[derive(Debug)]
pub struct OpenSocket {
    envelope: u64,
    intent: u32,
    position: u32,
}

/// The open sockets an intent enters an envelope with, in declaration
/// order — what [`EnvelopeBuilder::seal`] and [`EnvelopeBuilder::present`]
/// answer.
///
/// The declared count is the intent's, so the composer unpacks by
/// asserting it: [`one`](Unpacked::one) for the common single socket,
/// [`into_array`](Unpacked::into_array) to destructure several,
/// [`none`](Unpacked::none) to discharge an intent declaring none. A
/// wrong count is [`EnvelopeError::SocketArity`] at the unpack rather
/// than a miswired binding at admission.
pub type Sockets = Unpacked<OpenSocket, DeclaredBy>;

/// The intent whose declaration answers a [`Sockets`] arity claim.
#[derive(Debug)]
pub struct DeclaredBy {
    pub(crate) intent: u32,
}

impl Arity for DeclaredBy {
    type Error = EnvelopeError;

    fn refuse(self, declared: usize, claimed: usize) -> EnvelopeError {
        EnvelopeError::SocketArity {
            intent: self.intent,
            declared,
            claimed,
        }
    }
}

/// What one intent hands the composition to fill a socket with: an edge
/// it exported, or a proof one of its nodes mints.
///
/// Affine like the [`OpenSocket`] it answers: one offering fills one
/// socket, so wiring the same handle into two has no spelling — which is
/// what makes an exported edge's linearity hold through composition. The
/// two halves still differ in what offering again means. An edge is
/// yielded once and no second handle on it exists; a proof is not
/// consumed by being offered — the minting node stands where it stood —
/// so [`IntentBuilder::offer`] answers a fresh handle for every socket
/// that asks.
#[derive(Debug)]
pub struct Offered {
    envelope: u64,
    intent: u32,
    offering: Offering,
}

/// Which of the two an offering names.
#[derive(Clone, Copy, Debug)]
enum Offering {
    Edge(EdgeRef),
    Proof(u32),
}

/// A wrong-half offering, refused with both handles handed back.
///
/// An open socket can never be re-minted — its intent seals once — so a
/// refusal that consumed the pair would leave `UnfilledSocket` at build
/// as the only reachable outcome. Affinity holds because the handles
/// ride the error rather than a copy: recover them, route the right
/// halves, and the composition continues.
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct BindRefusal {
    /// The socket, still open.
    pub socket: OpenSocket,
    /// The offering, still unrouted.
    pub offered: Offered,
    /// Why the wiring was refused.
    pub cause: EnvelopeError,
}

// A caller converting through `?` chose not to recover the handles; the
// refusal itself is the envelope vocabulary's.
impl From<BindRefusal> for EnvelopeError {
    fn from(refusal: BindRefusal) -> Self {
        refusal.cause
    }
}

/// One intent under construction: a [`TypedBuilder`] that also declares
/// sockets and exports edges.
///
/// Dereferences to the builder underneath, so every call reads exactly as
/// it does outside a composition — the wrappers take `&mut` to this and
/// never learn there is an envelope.
pub struct IntentBuilder<'a> {
    graph: TypedBuilder<'a>,
    envelope: u64,
    intent: u32,
    sockets: Vec<Socket>,
}

impl<'a> IntentBuilder<'a> {
    /// An intent written to be signed on its own and handed to a composer
    /// afterwards — a declaration that exists before any envelope does.
    ///
    /// Its sockets are filled by whoever presents it, so nothing here mints
    /// an [`OpenSocket`]: those come from [`EnvelopeBuilder::present`], on
    /// the composing side, where the intent this declaration will be is
    /// known.
    #[must_use]
    pub fn declaration(
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        signer: PrincipalAddr,
    ) -> Self {
        Self {
            graph: TypedBuilder::new(chain, hasher, signer),
            envelope: next_space(),
            intent: 0,
            sockets: Vec::new(),
        }
    }

    /// Declare a socket: an edge the composition must bind, carrying
    /// `resource` and satisfying `constraints`.
    ///
    /// The [`Socket`] is this intent's own obligation — its graph must
    /// consume it exactly once. The composition's obligation to fill the
    /// socket is discharged against an [`OpenSocket`], which arrives when
    /// the intent enters an envelope rather than here, so that an intent
    /// written and one presented hand back open sockets the same way.
    ///
    /// # Panics
    ///
    /// Past a `u32` of declarations, far beyond [`MAX_SOCKETS`],
    /// which [`EnvelopeBuilder::seal`] enforces as an error.
    pub fn declare(
        &mut self,
        resource: impl Into<ResourceAddr>,
        constraints: impl IntoIterator<Item = Constraint>,
    ) -> SocketRef {
        let position =
            u32::try_from(self.sockets.len()).expect("sockets are bounded by MAX_SOCKETS");
        self.sockets.push(Socket::Value {
            resource: resource.into(),
            constraints: constraints.into_iter().collect(),
        });
        SocketRef {
            builder: self.graph_id(),
            position,
        }
    }

    /// Declare a socket for a proof carrying `claim`, answering the
    /// [`Proof`] this intent's own calls present it as.
    ///
    /// The one way authority crosses an intent boundary. A node
    /// reference names a node of this intent, and a signer signs their
    /// own intent whole, so nothing here can reach a proof somebody
    /// else's node mints — but a socket names the *claim* and
    /// leaves whose node supplies it to whoever composes. So a holder
    /// signs "an approval from the desk goes here" and never meets the
    /// composition that finds one.
    ///
    /// # Panics
    ///
    /// Past a `u32` of sockets, far beyond the [`MAX_SOCKETS`]
    /// the declaration is held to when it is sealed.
    pub fn declare_proof(&mut self, claim: Claim) -> Proof {
        let position =
            u32::try_from(self.sockets.len()).expect("sockets are bounded by MAX_SOCKETS");
        // The claim's own subject, where a call can be made against it:
        // an identity is callable and a badge is not, which is the same
        // reading the address class gives everywhere.
        let acting = CallTarget::try_from(claim.subject).ok();
        self.sockets.push(Socket::Authority(claim));
        Proof::from_socket(self.graph_id(), position, acting)
    }

    /// The declaration, for its signer to sign and hand on.
    ///
    /// # Errors
    ///
    /// As [`EnvelopeBuilder::seal`], over this intent alone.
    pub fn into_decl(self) -> Result<IntentDecl, EnvelopeError> {
        self.finish(0)
    }

    /// Build the graph and check that every socket this intent declared
    /// is consumed by exactly one of its own node arguments.
    fn finish(self, intent: u32) -> Result<IntentDecl, EnvelopeError> {
        if self.sockets.len() > MAX_SOCKETS {
            return Err(EnvelopeError::TooManySockets { intent });
        }
        let sockets = self.sockets;
        let graph = self.graph.build()?;
        check_sockets(&graph, &sockets, intent)?;
        Ok(IntentDecl { graph, sockets })
    }

    /// Consume an output as this intent's yield edge, for the composition
    /// to fill some intent's socket with.
    ///
    /// # Panics
    ///
    /// On a bucket carrying constraints — a yield's constraints are the
    /// declaring socket's — or one minted elsewhere.
    pub fn export(&mut self, bucket: Bucket) -> Offered {
        let edge = self.graph.export(bucket);
        Offered {
            envelope: self.envelope,
            intent: self.intent,
            offering: Offering::Edge(edge),
        }
    }

    /// Offer a proof this intent's own node minted, for some other
    /// intent's declared socket.
    ///
    /// Nothing is consumed and nothing is exported from the graph: the
    /// node stands where it stood, and what crosses is the claim it
    /// mints. So one minting node answers every socket that asks for it.
    ///
    /// # Panics
    ///
    /// On a proof that itself came through a socket: a socket cannot fill
    /// a socket, and the composition that filled this one is the one that
    /// would have to offer it.
    #[must_use]
    pub fn offer(&self, proof: Proof) -> Offered {
        proof.check(self.graph_id());
        let EvidenceRef::Node(producer) = proof.reference() else {
            panic!("a proof from a socket is not this intent's to offer");
        };
        Offered {
            envelope: self.envelope,
            intent: self.intent,
            offering: Offering::Proof(producer),
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

/// A composition of intents, joined through the sockets they declare.
pub struct EnvelopeBuilder<'a> {
    chain: &'a dyn ChainRecords,
    hasher: &'a dyn Hasher,
    id: u64,
    /// The signer of each subintent, in envelope order; the root has none.
    signers: Vec<PrincipalAddr>,
    /// Sealed declarations by slot — `0` is the root — `None` until the
    /// intent is sealed.
    intents: Vec<Option<IntentDecl>>,
    /// The bound source of each socket, by intent and
    /// position.
    bindings: BTreeMap<(u32, u32), Binding>,
    /// The creation-fixed records the tree carries for targets beyond
    /// the genesis registry.
    presented: Vec<InstanceMeta>,
    /// The resource records this envelope presents — the preimage of
    /// each granting address a gate reads through — in the order the
    /// composer added them.
    grants: Vec<ResourceMeta>,
}

impl<'a> EnvelopeBuilder<'a> {
    /// An envelope and its root intent — the composer's own, which every
    /// composition has exactly one of.
    #[must_use]
    pub fn new(
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        signer: PrincipalAddr,
    ) -> (Self, IntentBuilder<'a>) {
        let id = next_space();
        let envelope = Self {
            chain,
            hasher,
            id,
            signers: Vec::new(),
            intents: vec![None],
            bindings: BTreeMap::new(),
            presented: Vec::new(),
            grants: Vec::new(),
        };
        let root = IntentBuilder {
            graph: TypedBuilder::new(chain, hasher, signer),
            envelope: id,
            intent: 0,
            sockets: Vec::new(),
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

    /// Present a resource's granted-rule record, registered at the
    /// address its own content derives — what a granted gate in this
    /// envelope resolves against, on the terms `instance` states.
    pub fn resource(&mut self, meta: ResourceMeta) {
        self.grants.push(meta);
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
            graph: TypedBuilder::new(self.chain, self.hasher, signer),
            envelope: self.id,
            intent,
            sockets: Vec::new(),
        }
    }

    /// Bind a declaration its signer already signed, answering its
    /// [`Sockets`].
    ///
    /// This is what a subintent is for. The signer put their name to a
    /// graph over sockets before any composer existed; the composition
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
    ) -> Result<Sockets, EnvelopeError> {
        let intent = u32::try_from(self.intents.len()).expect("intents fit an index");
        if decl.sockets.len() > MAX_SOCKETS {
            return Err(EnvelopeError::TooManySockets { intent });
        }
        check_sockets(&decl.graph, &decl.sockets, intent)?;
        let sockets = self.open_sockets(intent, decl.sockets.len());
        self.carry(&decl.graph);
        self.signers.push(signer);
        self.intents.push(Some(decl));
        Ok(sockets)
    }

    /// Seal an intent into the envelope, answering its [`Sockets`].
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnconsumedSocket`], [`EnvelopeError::SocketReused`]
    /// or [`EnvelopeError::UnknownSocket`] for a declaration its graph does
    /// not discharge; [`EnvelopeError::TooManySockets`]; or the graph's
    /// own refusal.
    ///
    /// # Panics
    ///
    /// On an intent from a different envelope, or one sealed twice.
    pub fn seal(&mut self, intent: IntentBuilder<'a>) -> Result<Sockets, EnvelopeError> {
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
        let sockets = self.open_sockets(index, decl.sockets.len());
        self.carry(&decl.graph);
        self.intents[slot] = Some(decl);
        Ok(sockets)
    }

    /// Carry the granted-rule records `graph`'s calls will be resolved
    /// against.
    ///
    /// Run over every intent the envelope carries, written here or
    /// signed elsewhere. A subintent arrives whole, so what its calls
    /// need is readable off it — and the records ride the envelope
    /// rather than any intent, so the composer attaching them touches
    /// nothing a signature covers.
    fn carry(&mut self, graph: &ManifestGraph) {
        for record in graph_records(graph, self.chain, self.hasher) {
            if !self.grants.contains(&record) {
                self.grants.push(record);
            }
        }
    }

    /// One open socket per socket `intent` declares, in declaration
    /// order.
    fn open_sockets(&self, intent: u32, declared: usize) -> Sockets {
        Sockets {
            context: DeclaredBy { intent },
            items: (0..declared)
                .map(|position| OpenSocket {
                    envelope: self.id,
                    intent,
                    position: u32::try_from(position).expect("bounded by MAX_SOCKETS"),
                })
                .collect(),
        }
    }

    /// Fill a socket with what another intent offers — the edge it
    /// exported, or the proof one of its nodes mints.
    ///
    /// The whole of composition: a link is added between two graphs and
    /// neither is touched. The socket's own declaration types the link,
    /// so an offering of the wrong half is refused at the wiring — and
    /// the refusal hands both handles back, so the composer can still
    /// route the right one.
    ///
    /// # Errors
    ///
    /// [`BindRefusal`], carrying the socket and the offering, where the
    /// offering is not the half the socket declares it takes.
    ///
    /// # Panics
    ///
    /// On a handle minted by a different envelope.
    pub fn bind(&mut self, socket: OpenSocket, offered: Offered) -> Result<(), BindRefusal> {
        assert!(
            socket.envelope == self.id && offered.envelope == self.id,
            "a socket is filled within the envelope that opened it"
        );
        // A socket is a dependency on another intent; one filled from
        // its own would stall the interleave and die at admission as
        // `CyclicSockets`, in coordinates the author never wrote.
        if socket.intent == offered.intent {
            let cause = EnvelopeError::SelfFilledSocket {
                intent: socket.intent,
                socket: socket.position,
            };
            return Err(BindRefusal {
                socket,
                offered,
                cause,
            });
        }
        let slot = usize::try_from(socket.intent).expect("minted indices fit");
        let position = usize::try_from(socket.position).expect("bounded by MAX_SOCKETS");
        let declared = &self.intents[slot]
            .as_ref()
            .expect("an open socket names an intent the envelope holds")
            .sockets[position];
        let binding = match (declared, offered.offering) {
            (Socket::Value { .. }, Offering::Edge(edge)) => Binding::Value {
                intent: offered.intent,
                edge,
            },
            (Socket::Authority(_), Offering::Proof(producer)) => Binding::Authority {
                intent: offered.intent,
                producer,
            },
            (Socket::Value { .. }, Offering::Proof(_)) => {
                let cause = EnvelopeError::ProofForValueSocket {
                    intent: socket.intent,
                    socket: socket.position,
                };
                return Err(BindRefusal {
                    socket,
                    offered,
                    cause,
                });
            }
            (Socket::Authority(_), Offering::Edge(_)) => {
                let cause = EnvelopeError::EdgeForAuthoritySocket {
                    intent: socket.intent,
                    socket: socket.position,
                };
                return Err(BindRefusal {
                    socket,
                    offered,
                    cause,
                });
            }
        };
        self.bindings
            .insert((socket.intent, socket.position), binding);
        Ok(())
    }

    /// Emit the tree: every intent sealed, every socket bound.
    ///
    /// # Errors
    ///
    /// [`EnvelopeError::UnsealedIntent`] for an intent still under
    /// construction; [`EnvelopeError::UnfilledSocket`] for a socket the
    /// composition left open; [`EnvelopeError::TooManySubintents`].
    ///
    /// # Panics
    ///
    /// Past a `u32` of intents, which [`MAX_SUBINTENTS`] excludes above.
    pub fn build(self) -> Result<EnvelopeTree, EnvelopeError> {
        if self.signers.len() > MAX_SUBINTENTS {
            return Err(EnvelopeError::TooManySubintents);
        }
        // Graph literals meet this bound at the call that binds them;
        // presented records are registered whole, so their configuration
        // values meet it here.
        for (index, meta) in self.presented.iter().enumerate() {
            if meta
                .config
                .iter()
                .any(|value| value.depth() > MAX_VALUE_DEPTH)
            {
                return Err(EnvelopeError::InstanceValueTooDeep {
                    instance: u32::try_from(index).unwrap_or(u32::MAX),
                });
            }
        }
        let mut decls = Vec::with_capacity(self.intents.len());
        let mut wired = Vec::with_capacity(self.intents.len());
        for (slot, sealed) in self.intents.into_iter().enumerate() {
            let intent = u32::try_from(slot).expect("minted indices fit");
            let decl = sealed.ok_or(EnvelopeError::UnsealedIntent { intent })?;
            let mut bindings = Vec::with_capacity(decl.sockets.len());
            for position in 0..decl.sockets.len() {
                let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
                bindings.push(
                    *self
                        .bindings
                        .get(&(intent, socket))
                        .ok_or(EnvelopeError::UnfilledSocket { intent, socket })?,
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
            resources: self.grants,
        })
    }
}

/// Check that each of an intent's sockets is consumed by
/// exactly one of its own node arguments — admission's own count, run
/// against the intent that declared them.
fn check_sockets(
    graph: &ManifestGraph,
    declared: &[Socket],
    intent: u32,
) -> Result<(), EnvelopeError> {
    let mut uses = vec![0u32; declared.len()];
    for node in &graph.nodes {
        for position in node.sockets() {
            let slot = usize::try_from(position)
                .ok()
                .and_then(|position| uses.get_mut(position))
                .ok_or(EnvelopeError::UnknownSocket {
                    intent,
                    socket: position,
                })?;
            *slot += 1;
        }
    }
    for (position, count) in uses.iter().enumerate() {
        let socket = u32::try_from(position).expect("bounded by MAX_SOCKETS");
        if *count == 0 {
            return Err(EnvelopeError::UnconsumedSocket { intent, socket });
        }
        // Value is conserved and authority is not: an edge fills one
        // argument, and a claim presented twice says nothing presenting
        // it once does not.
        if matches!(declared.get(position), Some(Socket::Value { .. })) && *count > 1 {
            return Err(EnvelopeError::SocketReused { intent, socket });
        }
    }
    Ok(())
}

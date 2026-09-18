//! The intent tier: one intent, the interface it declares, and the
//! members it composes.
//!
//! An intent is written on its own — an [`IntentBuilder`] is a
//! [`TypedBuilder`] that can also declare sockets and gives — and
//! composes others by adopting them. Composition is addition *between*
//! declarations: a member arrives signed and is stored exactly as handed
//! over, its composer supplies what fills its sockets and takes what it
//! gives, and nothing inside it is rewritten to make the composition
//! fit. That is what lets a member's signer sign a declaration and have
//! it mean the same thing in whatever tree later carries it. The same
//! builder is a leaf, a group in the middle, or the root: which one it
//! is depends on whether it adopts anybody and on how it is finished —
//! as an [`Intent`] for its attester, or as the tree with the records.
//!
//! The wiring is done from handles rather than from indices. One
//! declared socket has two handles, one per side: inside the declaring
//! intent it is the [`SocketRef`] its own graph names it by, and to the
//! composer it is an [`OpenSocket`], which arrives with the member's
//! [`Interface`] when the member is adopted. What fills one is whatever
//! the composer holds: an edge of its own graph, a socket of its own
//! passed through, a give of one of its members, or a claim — a proof
//! of its own node or socket, or an account it acts as. Every handle
//! names the builder it came from, so a binding cannot reach an intent
//! or a node that is not the composer's own — which is scope, read from
//! this side.
//!
//! A member's give is taken the same three ways admission counts: as an
//! argument of the composer's own calls, wired into a sibling's socket,
//! or given on as the composer's own. A give handle is affine, so each
//! is taken once by construction, and the builder checks when it emits
//! what the handles cannot carry: every socket reached inside its graph
//! and filled exactly once outside it, every give taken, every member's
//! wiring complete. Reached *once* where it carries value, which is
//! conserved, and as often as asked where it carries authority, which
//! is not.

use std::ops::{Deref, DerefMut};

use hyperscale_hbor::Capped;
use hyperscale_vm_effects::{
    AdmissionError, Binding, ChainRecords, Claim, ClaimRef, Constraint, GiveRef, GraphArg, Hasher,
    InstanceMeta, Intent, IntentHeader, IntentTree, MAX_ACCOUNTS, Member, ResourceMeta,
    SignedIntent, Socket, ValueRef, check_structure,
};
use hyperscale_vm_types::{PrincipalAddr, ResourceAddr};

use crate::builder::{Bucket, SocketRef};
use crate::projection::graph_records;
use crate::typed::{Proof, TypedBuilder, TypedError};
use crate::unpack::{Arity, Unpacked};

/// Why an intent could not be composed.
///
/// Every variant is a verdict [`admit_tree`] would also reach, named
/// against the intent the author wrote rather than against a flattened
/// tree they have not finished composing: `intent` is `0` for the intent
/// being written and `i + 1` for its `i`-th member, and a member's give
/// is named by the member's position and the give's.
///
/// [`admit_tree`]: hyperscale_vm_effects::admit_tree
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IntentError {
    /// A handle from a different builder at a wiring — a socket is
    /// filled, and a give taken, by the intent that composes it.
    #[error("a socket is filled by the intent that composes it")]
    ForeignBinding,
    /// A socket the composition never filled. On the intent being
    /// written itself, a socket nobody above it could fill — the root
    /// declares none.
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
    /// Gives unpacked into a different arity than the intent declares.
    #[error("intent {intent} declares {declared} gives, unpacked as {claimed}")]
    GiveArity {
        /// The declaring intent.
        intent: u32,
        /// The intent's declared give count.
        declared: usize,
        /// The arity the composer unpacked into.
        claimed: usize,
    },
    /// Authority — a proof, or an account — offered to a socket that
    /// declares value.
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
    /// An edge or a give wired into a socket while carrying constraints
    /// of its own. What fills a socket is bounded by the socket's
    /// declaration, and taking the handle's constraints here would drop
    /// them silently.
    #[error(
        "intent {intent} socket {socket} bounds what fills it; the offering's constraints belong on a consuming argument"
    )]
    ConstrainedOffering {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
    },
    /// A member's give given on while carrying constraints of its own. A
    /// give carries what the member offers, bounded by whoever consumes
    /// it above, so constraints on it belong on a consuming argument.
    #[error(
        "intent {intent} give {give} is given on as it is; its constraints belong on a consuming argument"
    )]
    ConstrainedGive {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        give: u32,
    },
    /// An account granted that the granting intent does not act as. A
    /// grant lends a signature, and the only signatures an intent holds
    /// are those of the accounts it declares.
    #[error(
        "intent {intent} socket {socket} is granted {account:?}, which the granter does not act as"
    )]
    GrantNotHeld {
        /// The declaring intent.
        intent: u32,
        /// Its position in the declaration.
        socket: u32,
        /// The account granted.
        account: PrincipalAddr,
    },
    /// A member's socket filled from that member's own give: a
    /// dependency on itself, which admission refuses as a cycle over the
    /// whole tree and the wiring refuses against the intent the author
    /// wrote.
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
    /// A declaration admission would refuse on its shape alone: a
    /// socket reached from the wrong channel, never or twice; a give
    /// naming nothing; a member's give taken never or twice; the caps;
    /// and, at the top, the tree's own shape. The rule is admission's
    /// ([`check_structure`]), stated once; only the numbering is the
    /// builder's.
    ///
    /// [`check_structure`]: hyperscale_vm_effects::check_structure
    #[error("{0}")]
    Structure(#[from] AdmissionError),
}

/// One member's declared socket, as its composer names it — the side a
/// binding fills, against the [`SocketRef`] the member's own graph
/// reaches it by.
///
/// Affine like the [`Socket`] it is declared beside: one socket takes one
/// offering, so filling the same socket twice has no spelling.
#[derive(Debug)]
pub struct OpenSocket {
    builder: u64,
    member: u32,
    position: u32,
}

/// One member's give, as its composer holds it.
///
/// A handle on the value the member offers, taken exactly once — as an
/// argument of the composer's own call, wired into a sibling's socket,
/// or given on as the composer's own.
///
/// Affine because a give is value and value is conserved. As an argument
/// it carries the consumer's constraints, like a [`Bucket`]; wired into
/// a socket it carries none, since the socket's declaration bounds what
/// fills it.
#[derive(Debug)]
#[must_use = "a member's give must be taken for its composer's build to pass"]
pub struct Given {
    builder: u64,
    give: GiveRef,
    constraints: Vec<Constraint>,
}

impl Given {
    /// Assert a constraint the consuming argument will be held to.
    pub fn constrain(mut self, constraint: Constraint) -> Self {
        self.constraints.push(constraint);
        self
    }

    /// Assert that the give carries at least `amount`.
    pub fn min(self, amount: u128) -> Self {
        self.constrain(Constraint::MinAmount(amount))
    }

    /// Assert that the give carries at most `amount`.
    pub fn max(self, amount: u128) -> Self {
        self.constrain(Constraint::MaxAmount(amount))
    }

    /// The argument this give binds as, in the composer's own graph.
    pub(crate) fn into_arg(self) -> GraphArg {
        GraphArg::give(self.give, self.constraints)
    }

    /// Whether `builder` is the composer holding this give.
    pub(crate) const fn held_by(&self, builder: u64) -> bool {
        self.builder == builder
    }
}

/// The open sockets a member is adopted with, in declaration order.
///
/// The declared count is the member's, so the composer unpacks by
/// asserting it: [`one`](Unpacked::one) for the common single socket,
/// [`into_array`](Unpacked::into_array) to destructure several,
/// [`none`](Unpacked::none) to discharge a member declaring none. A
/// wrong count is [`IntentError::SocketArity`] at the unpack rather
/// than a miswired binding at admission.
pub type Sockets = Unpacked<OpenSocket, DeclaredBy>;

/// The gives a member is adopted with, in declaration order, unpacked
/// as [`Sockets`] are and refused as [`IntentError::GiveArity`].
pub type Gives = Unpacked<Given, GivenBy>;

/// A member's interface as its composer receives it: what it takes and
/// what it gives, both as affine handles.
#[derive(Debug)]
pub struct Interface {
    /// The member's sockets, for the composer to fill.
    pub sockets: Sockets,
    /// The member's gives, for the composer to take.
    pub gives: Gives,
}

/// The intent whose declaration answers a [`Sockets`] arity claim.
#[derive(Debug)]
pub struct DeclaredBy {
    pub(crate) intent: u32,
}

impl Arity for DeclaredBy {
    type Error = IntentError;

    fn refuse(self, declared: usize, claimed: usize) -> IntentError {
        IntentError::SocketArity {
            intent: self.intent,
            declared,
            claimed,
        }
    }
}

/// The intent whose declaration answers a [`Gives`] arity claim.
#[derive(Debug)]
pub struct GivenBy {
    pub(crate) intent: u32,
}

impl Arity for GivenBy {
    type Error = IntentError;

    fn refuse(self, declared: usize, claimed: usize) -> IntentError {
        IntentError::GiveArity {
            intent: self.intent,
            declared,
            claimed,
        }
    }
}

/// What a composer puts in one of a member's sockets: something it
/// holds.
///
/// Value is an edge of the composer's own graph, a socket of its own
/// passed through, or a give of one of its members. Authority is a claim
/// the composer holds — a proof of its own node or socket, or an account
/// it acts as, which its signature carries. Every handle names the
/// builder that minted it, so what a composer can offer is exactly what
/// it can spell, and nothing of a member's inside reaches a wiring.
///
/// Each handle converts into this, so a wiring names the handle
/// directly: `bind(socket, funds)`, `bind(socket, approval)`,
/// `bind(socket, ALICE)`.
#[derive(Debug)]
pub enum Offered {
    /// An edge of the composer's own graph, yielded to the member.
    Edge(Bucket),
    /// A value socket of the composer's own, passed through.
    Socket(SocketRef),
    /// A give of one of the composer's members.
    Give(Given),
    /// A proof the composer holds: one of its own nodes' or one of its
    /// own sockets'.
    Proof(Box<Proof>),
    /// An account the composer acts as, granted by its signature.
    Account(PrincipalAddr),
}

impl From<Bucket> for Offered {
    fn from(bucket: Bucket) -> Self {
        Self::Edge(bucket)
    }
}

impl From<SocketRef> for Offered {
    fn from(socket: SocketRef) -> Self {
        Self::Socket(socket)
    }
}

impl From<Given> for Offered {
    fn from(given: Given) -> Self {
        Self::Give(given)
    }
}

impl From<Proof> for Offered {
    fn from(proof: Proof) -> Self {
        Self::Proof(Box::new(proof))
    }
}

impl From<PrincipalAddr> for Offered {
    fn from(account: PrincipalAddr) -> Self {
        Self::Account(account)
    }
}

/// A refused wiring, with both handles handed back.
///
/// An open socket can never be re-minted — its member is adopted once —
/// so a refusal that consumed the pair would leave `UnfilledSocket` at
/// build as the only reachable outcome. Affinity holds because the
/// handles ride the error rather than a copy: recover them, route the
/// right halves, and the composition continues. Boxed, since it carries
/// the offering whole.
#[derive(Debug, thiserror::Error)]
#[error("{cause}")]
pub struct BindRefusal {
    /// The socket, still open.
    pub socket: OpenSocket,
    /// The offering, still unrouted.
    pub offered: Offered,
    /// Why the wiring was refused.
    pub cause: IntentError,
}

// A caller converting through `?` chose not to recover the handles; the
// refusal itself is the intent vocabulary's.
impl From<Box<BindRefusal>> for IntentError {
    fn from(refusal: Box<BindRefusal>) -> Self {
        refusal.cause
    }
}

/// A member as its composer holds it: the signed intent, and what has
/// been wired into each of its sockets so far.
struct Placed {
    signed: SignedIntent,
    wiring: Vec<Option<Binding>>,
}

/// One intent under construction: a [`TypedBuilder`] that also declares
/// its interface and composes members.
///
/// Dereferences to the builder underneath, so every call reads exactly as
/// it does outside a composition — the wrappers take `&mut` to this and
/// never learn there is a tree.
pub struct IntentBuilder<'a> {
    graph: TypedBuilder<'a>,
    chain: &'a dyn ChainRecords,
    hasher: &'a dyn Hasher,
    header: IntentHeader,
    /// The principals whose keys attest the intent, where they are not
    /// the accounts' own.
    attested_by: Option<Vec<PrincipalAddr>>,
    sockets: Vec<Socket>,
    gives: Vec<ValueRef>,
    members: Vec<Placed>,
}

impl<'a> IntentBuilder<'a> {
    /// An intent acting as `account` under `header`, attested by that
    /// account's own key.
    #[must_use]
    pub fn new(
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        account: PrincipalAddr,
        header: IntentHeader,
    ) -> Self {
        Self::with_graph(
            TypedBuilder::new(chain, hasher, account),
            chain,
            hasher,
            header,
        )
    }

    /// An intent acting as every one of `accounts` under `header` —
    /// how a party composes across their own accounts, with one
    /// attesting set answering each account's gates and signing in on
    /// each account's shard.
    ///
    /// # Errors
    ///
    /// [`TypedError::NoAccount`] on an empty list: an intent acting as
    /// nobody has no nullifier and no sign-in, and admission refuses it.
    pub fn acting_as(
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        accounts: &[PrincipalAddr],
        header: IntentHeader,
    ) -> Result<Self, TypedError> {
        let graph = TypedBuilder::acting_as(chain, hasher, accounts)?;
        Ok(Self::with_graph(graph, chain, hasher, header))
    }

    fn with_graph(
        graph: TypedBuilder<'a>,
        chain: &'a dyn ChainRecords,
        hasher: &'a dyn Hasher,
        header: IntentHeader,
    ) -> Self {
        Self {
            graph,
            chain,
            hasher,
            header,
            attested_by: None,
            sockets: Vec::new(),
            gives: Vec::new(),
            members: Vec::new(),
        }
    }

    /// Declare the principals whose keys attest this intent, in the
    /// order their attestations will stand beside it.
    ///
    /// Left undeclared, the accounts attest themselves: each account's
    /// own key signs. Declared, the set is whatever each account's
    /// stored rule has to admit — a delegate's key acting as an account
    /// it does not derive, or the several keys a threshold names. Signed
    /// content: the set is in the intent's hash, so one intent admits
    /// exactly one.
    pub fn attested_by(&mut self, principals: impl IntoIterator<Item = PrincipalAddr>) {
        self.attested_by = Some(principals.into_iter().collect());
    }

    /// Declare a socket: an edge the composer must wire, carrying
    /// `resource` and satisfying `constraints`.
    ///
    /// The [`Socket`] is this intent's own obligation — its graph must
    /// consume it exactly once, or its wiring pass it on to exactly one
    /// member. The composer's obligation to fill the socket is
    /// discharged against an [`OpenSocket`], which the composer receives
    /// when it adopts this intent.
    ///
    /// # Panics
    ///
    /// Past a `u32` of declarations, far beyond [`MAX_SOCKETS`](hyperscale_vm_effects::admission::MAX_SOCKETS), which
    /// the finish enforces as an error.
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
    /// [`Proof`] this intent's own calls present it as — and, since the
    /// proof is this intent's to hold, the one it may grant on into a
    /// member's socket.
    ///
    /// The one way authority crosses an intent boundary. A node
    /// reference names a node of this intent, and a signer signs their
    /// own intent whole, so nothing here can reach a proof somebody
    /// else's node mints — but a socket names the *claim* and leaves
    /// whose node supplies it to whoever composes. So a holder signs "an
    /// approval from the desk goes here" and never meets the composition
    /// that finds one.
    ///
    /// # Panics
    ///
    /// Past a `u32` of sockets, far beyond the [`MAX_SOCKETS`](hyperscale_vm_effects::admission::MAX_SOCKETS) the
    /// declaration is held to when it is finished.
    pub fn declare_proof(&mut self, claim: Claim) -> Proof {
        let position =
            u32::try_from(self.sockets.len()).expect("sockets are bounded by MAX_SOCKETS");
        self.sockets.push(Socket::Authority(claim));
        Proof::from_socket(self.graph_id(), position, claim)
    }

    /// Give an output of this intent's own graph to whoever composes it.
    ///
    /// Declared in the intent's signed interface, by position, so a
    /// composer takes exactly what the signer offered. A bucket carrying
    /// constraints or one minted elsewhere poisons the graph, on
    /// [`GraphBuilder::export`]'s terms, and the finish hands the
    /// mistake back.
    ///
    /// [`GraphBuilder::export`]: crate::GraphBuilder::export
    pub fn give(&mut self, bucket: Bucket) {
        let edge = self.graph.export(bucket);
        self.gives.push(ValueRef::Edge(edge));
    }

    /// Give a member's give on to whoever composes this intent: how a
    /// group exposes a product assembled beneath it, without the
    /// composer above ever seeing the member.
    ///
    /// # Errors
    ///
    /// [`IntentError::ForeignBinding`] on a give another builder holds;
    /// [`IntentError::ConstrainedGive`] on one carrying constraints,
    /// which a give has no place for.
    pub fn give_on(&mut self, given: Given) -> Result<(), IntentError> {
        let Given {
            builder,
            give,
            constraints,
        } = given;
        if builder != self.graph_id() {
            return Err(IntentError::ForeignBinding);
        }
        if !constraints.is_empty() {
            return Err(IntentError::ConstrainedGive {
                intent: give.member + 1,
                give: give.give,
            });
        }
        self.gives.push(ValueRef::Give(give));
        Ok(())
    }

    /// Compose a signed intent as a member, answering its [`Interface`].
    ///
    /// The signer put their name to a graph over sockets and gives
    /// before any composer existed; the composer supplies the sources,
    /// takes the gives, and alters nothing, so the attestations already
    /// covering the declaration still cover it — which is why it is
    /// stored exactly as handed over rather than rebuilt. A member the
    /// composer writes itself is an [`IntentBuilder`] finished with
    /// [`into_decl`](Self::into_decl) and adopted unsigned, for its
    /// attester to sign inside the tree.
    ///
    /// # Errors
    ///
    /// The refusals [`into_decl`](Self::into_decl) reaches over a
    /// declaration the composer wrote, judged here over one it did not:
    /// a composer signing a tree around a malformed declaration is a
    /// transaction the chain refuses either way, and refusing it here is
    /// the only place it can still be declined.
    ///
    /// # Panics
    ///
    /// Past a `u32` of members, far beyond [`MAX_INTENTS`](hyperscale_vm_types::MAX_INTENTS), which
    /// [`build`](Self::build) enforces as an error.
    pub fn adopt(&mut self, signed: impl Into<SignedIntent>) -> Result<Interface, IntentError> {
        let signed = signed.into();
        let member = u32::try_from(self.members.len()).expect("members fit an index");
        let intent = member + 1;
        let decl = &signed.intent;
        check_structure(decl, intent)?;
        let builder = self.graph_id();
        let sockets = Sockets {
            context: DeclaredBy { intent },
            items: (0..decl.sockets.len())
                .map(|position| OpenSocket {
                    builder,
                    member,
                    position: u32::try_from(position).expect("bounded by MAX_SOCKETS"),
                })
                .collect(),
        };
        let gives = Gives {
            context: GivenBy { intent },
            items: (0..decl.gives.len())
                .map(|give| Given {
                    builder,
                    give: GiveRef {
                        member,
                        give: u32::try_from(give).expect("bounded by MAX_SOCKETS"),
                    },
                    constraints: Vec::new(),
                })
                .collect(),
        };
        self.members.push(Placed {
            wiring: vec![None; decl.sockets.len()],
            signed,
        });
        Ok(Interface { sockets, gives })
    }

    /// Fill a member's socket with something this intent holds.
    ///
    /// The whole of composition: a link is added between two
    /// declarations and neither is touched. The socket's own declaration
    /// types the link, so an offering of the wrong half is refused at
    /// the wiring — and the refusal hands both handles back, so the
    /// composer can still route the right one.
    ///
    /// # Errors
    ///
    /// [`BindRefusal`], carrying the socket and the offering, where the
    /// offering is not the half the socket declares it takes; where
    /// either handle was minted by a different builder
    /// ([`IntentError::ForeignBinding`]); where an account granted is
    /// not one this intent acts as ([`IntentError::GrantNotHeld`]);
    /// where an edge or a give arrives carrying constraints
    /// ([`IntentError::ConstrainedOffering`]); or where a member's
    /// socket is filled from its own give
    /// ([`IntentError::SelfFilledSocket`]).
    ///
    /// # Panics
    ///
    /// Never for a socket this builder minted: the member index was
    /// bounded when the socket was opened.
    pub fn bind(
        &mut self,
        socket: OpenSocket,
        offered: impl Into<Offered>,
    ) -> Result<(), Box<BindRefusal>> {
        let offered = offered.into();
        let wiring = match self.wiring_of(&socket, &offered) {
            Ok(wiring) => wiring,
            Err(cause) => {
                return Err(Box::new(BindRefusal {
                    socket,
                    offered,
                    cause,
                }));
            }
        };
        // A bucket is spent from the graph only once the wiring is known
        // to hold, so a refusal hands it back unspent.
        let binding = match wiring {
            Wiring::Ready(binding) => binding,
            Wiring::Edge => {
                let Offered::Edge(bucket) = offered else {
                    unreachable!("an edge wiring comes from an edge offering");
                };
                Binding::Value(ValueRef::Edge(self.graph.export(bucket)))
            }
        };
        let member = usize::try_from(socket.member).expect("minted indices fit");
        let position = usize::try_from(socket.position).expect("bounded by MAX_SOCKETS");
        self.members[member].wiring[position] = Some(binding);
        Ok(())
    }

    /// The binding `offered` makes for `socket`, judged without spending
    /// anything: an edge is only marked spent once the wiring holds.
    fn wiring_of(&self, socket: &OpenSocket, offered: &Offered) -> Result<Wiring, IntentError> {
        let id = self.graph_id();
        if socket.builder != id {
            return Err(IntentError::ForeignBinding);
        }
        let foreign = match offered {
            Offered::Edge(bucket) => bucket.builder != id,
            Offered::Socket(passed) => passed.builder != id,
            Offered::Give(given) => !given.held_by(id),
            Offered::Proof(proof) => !proof.proved_by(id),
            Offered::Account(_) => false,
        };
        if foreign {
            return Err(IntentError::ForeignBinding);
        }
        let at = (socket.member + 1, socket.position);
        let member = usize::try_from(socket.member).expect("minted indices fit");
        let position = usize::try_from(socket.position).expect("bounded by MAX_SOCKETS");
        let declared = &self.members[member].signed.intent.sockets[position];
        match (declared, offered) {
            (Socket::Value { .. }, Offered::Proof(_) | Offered::Account(_)) => {
                Err(IntentError::ProofForValueSocket {
                    intent: at.0,
                    socket: at.1,
                })
            }
            (Socket::Authority(_), Offered::Edge(_) | Offered::Socket(_) | Offered::Give(_)) => {
                Err(IntentError::EdgeForAuthoritySocket {
                    intent: at.0,
                    socket: at.1,
                })
            }
            (Socket::Value { .. }, Offered::Edge(bucket)) => {
                if bucket.constraints.is_empty() {
                    Ok(Wiring::Edge)
                } else {
                    Err(IntentError::ConstrainedOffering {
                        intent: at.0,
                        socket: at.1,
                    })
                }
            }
            (Socket::Value { .. }, Offered::Socket(passed)) => Ok(Wiring::Ready(Binding::Value(
                ValueRef::Socket(passed.position),
            ))),
            (Socket::Value { .. }, Offered::Give(given)) => {
                // A member fed from its own give waits on itself: a cycle
                // admission names in tree coordinates, refused here
                // against the member the author placed.
                if given.give.member == socket.member {
                    return Err(IntentError::SelfFilledSocket {
                        intent: at.0,
                        socket: at.1,
                    });
                }
                if !given.constraints.is_empty() {
                    return Err(IntentError::ConstrainedOffering {
                        intent: at.0,
                        socket: at.1,
                    });
                }
                Ok(Wiring::Ready(Binding::Value(ValueRef::Give(given.give))))
            }
            (Socket::Authority(_), Offered::Proof(proof)) => {
                // A proof is a claim this intent holds, named as the
                // intent names it: what a node presents is what a
                // composer grants.
                Ok(Wiring::Ready(Binding::Authority(proof.reference())))
            }
            (Socket::Authority(_), Offered::Account(account)) => {
                if !self.graph.accounts().contains(account) {
                    return Err(IntentError::GrantNotHeld {
                        intent: at.0,
                        socket: at.1,
                        account: *account,
                    });
                }
                Ok(Wiring::Ready(Binding::Authority(ClaimRef::Account(
                    *account,
                ))))
            }
        }
    }

    /// The declaration, for its attesters to sign and a composer to
    /// adopt.
    ///
    /// # Errors
    ///
    /// [`IntentError::Structure`] for a declaration its graph does not
    /// discharge — a socket never or twice reached, a member's give
    /// nothing took, the caps; [`IntentError::UnfilledSocket`] for a
    /// member's socket the wiring left open; or the graph's own refusal.
    pub fn into_decl(self) -> Result<Intent, IntentError> {
        self.finish()
    }

    /// Emit the tree: this intent as the root, every member's wiring
    /// complete, presenting no record beyond the genesis registry.
    ///
    /// # Errors
    ///
    /// As [`build_presenting`](Self::build_presenting).
    pub fn build(self) -> Result<IntentTree, IntentError> {
        self.build_presenting(Vec::new(), Vec::new())
    }

    /// Emit the tree: this intent as the root, every member's wiring
    /// complete, the records beside it.
    ///
    /// `instances` are the creation-fixed records the tree carries for
    /// targets beyond the genesis registry, registering the component
    /// address each derives for this tree's calls. The builder resolves
    /// targets against the registry it was given, so a presenting build
    /// composes that registry with the same records first — this
    /// records them in the tree, where admission will compose
    /// identically. `resources` are the granted-rule records the tree
    /// presents, each registered at the address its own content
    /// derives — what a granted gate in this tree resolves against.
    ///
    /// # Errors
    ///
    /// As [`into_decl`](Self::into_decl), and [`IntentError::Structure`]
    /// for the tree's own shape: a root declaring an interface nobody
    /// above it could serve, too many intents, too deep a tree, a
    /// presented record nesting past the value bound.
    pub fn build_presenting(
        self,
        instances: Vec<InstanceMeta>,
        resources: Vec<ResourceMeta>,
    ) -> Result<IntentTree, IntentError> {
        let chain = self.chain;
        let hasher = self.hasher;
        let root = self.finish()?;
        let records = |_| IntentError::Structure(AdmissionError::TooManyNodes);
        let mut tree = IntentTree {
            root,
            instances: instances.try_into().map_err(records)?,
            resources: resources.try_into().map_err(records)?,
        };
        // The tree's own shape: its caps, its depth, and a root
        // declaring no interface. Graph literals met the value bound at
        // the call that bound them; presented records are registered
        // whole, so theirs is met here.
        tree.check_shape()?;
        let intents = tree.intents();
        // The granted-rule records every call in the tree resolves
        // against, read off every graph the tree carries. A member
        // arrives whole, so what its calls need is readable off it — and
        // the records ride the tree rather than any intent, so attaching
        // them touches nothing a signature covers.
        let found: Vec<ResourceMeta> = intents
            .iter()
            .flat_map(|intent| graph_records(&intent.graph, chain, hasher))
            .collect();
        for record in found {
            if !tree.resources.contains(&record) {
                tree.resources.push(record).map_err(records)?;
            }
        }
        Ok(tree)
    }

    /// Build the graph, close every member's wiring, and check what the
    /// handles cannot carry: every socket of this intent consumed
    /// exactly once, every give of every member taken.
    fn finish(self) -> Result<Intent, IntentError> {
        // Each list holds its cap in its type; a builder that outgrew one
        // is refused with the shape error admission would have raised.
        let structure = IntentError::Structure;
        let accounts: Capped<Vec<PrincipalAddr>, MAX_ACCOUNTS> = self
            .graph
            .accounts()
            .to_vec()
            .try_into()
            .map_err(|_| structure(AdmissionError::TooManyAccounts { intent: 0 }))?;
        let graph = self.graph.build()?;
        let mut members = Vec::with_capacity(self.members.len());
        for (index, placed) in self.members.into_iter().enumerate() {
            let intent = u32::try_from(index).expect("minted indices fit") + 1;
            let mut wiring = Vec::with_capacity(placed.wiring.len());
            for (position, binding) in placed.wiring.into_iter().enumerate() {
                wiring.push(binding.ok_or_else(|| IntentError::UnfilledSocket {
                    intent,
                    socket: u32::try_from(position).expect("bounded by MAX_SOCKETS"),
                })?);
            }
            members.push(Member {
                signed: placed.signed,
                wiring: wiring
                    .try_into()
                    .map_err(|_| structure(AdmissionError::TooManySockets { intent }))?,
            });
        }
        let attested_by = match self.attested_by {
            Some(attesters) => attesters
                .try_into()
                .map_err(|_| structure(AdmissionError::TooManyAttesters { intent: 0 }))?,
            None => accounts.clone(),
        };
        let intent = Intent {
            header: self.header,
            attested_by,
            accounts,
            graph,
            sockets: self
                .sockets
                .try_into()
                .map_err(|_| structure(AdmissionError::TooManySockets { intent: 0 }))?,
            gives: self
                .gives
                .try_into()
                .map_err(|_| structure(AdmissionError::TooManyGives { intent: 0 }))?,
            members: members
                .try_into()
                .map_err(|_| structure(AdmissionError::TooManyIntents))?,
        };
        check_structure(&intent, 0)?;
        Ok(intent)
    }
}

/// A wiring judged to hold, before anything is spent on it.
enum Wiring {
    /// The binding, complete.
    Ready(Binding),
    /// An edge of the composer's own graph, to be exported once the
    /// wiring is recorded.
    Edge,
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

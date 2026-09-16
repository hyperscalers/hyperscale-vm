//! The tree, flattened and resolved: every intent in preorder, and what
//! fills every socket and every give.
//!
//! Everything below the interface layer — the interleave, the
//! node-by-node lowering, the kernel — sees a flat list of intents whose
//! sockets are filled from named nodes. This is where that list comes
//! from. A composer contains its members, so the walk is the structure;
//! the wiring each composer signs names its own edges, its members'
//! gives, its own sockets and its own accounts, so every source is
//! followed to the node or the account that ultimately stands behind it.
//! Scope is judged on the way: a grant of an account the granting intent
//! does not act as, or of a claim its own socket does not carry, is
//! refused here, and nothing downstream can reach an authority socket by
//! any other path.

use hyperscale_vm_types::ResourceAddr;

use super::AdmissionError;
use super::compose::{Fill, Proven};
use crate::claim::Claim;
use crate::envelope::{
    Binding, ClaimSource, Give, Intent, MAX_ACCOUNTS, MAX_TREE_DEPTH, Socket, ValueSource,
};
use crate::graph::{EdgeRef, GiveRef, GraphNode};

/// One member's give, followed to the node that produces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Yielded {
    /// The intent whose graph produces the edge.
    pub(crate) intent: u32,
    /// The edge, in that graph.
    pub(crate) edge: EdgeRef,
}

/// One intent's interface as the flat checker consumes it: what fills
/// each of its sockets, how often its own wiring passes each socket on,
/// and where each of its members' gives comes from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Interface {
    /// One fill per declared socket.
    pub(crate) fills: Vec<Fill>,
    /// Per declared socket, how many of this intent's own wiring
    /// entries pass it on to a member. A use like any node's, counted
    /// beside them.
    pub(crate) wired_uses: Vec<u32>,
    /// Per member, per give, the node that produces it.
    pub(crate) member_gives: Vec<Vec<Yielded>>,
}

impl Interface {
    /// The give a `GraphArg::Give` or a `ValueSource::Give` of this
    /// intent names, where it names one.
    pub(crate) fn give(&self, give: GiveRef) -> Option<Yielded> {
        self.member_gives
            .get(usize::try_from(give.member).ok()?)?
            .get(usize::try_from(give.give).ok()?)
            .copied()
    }
}

/// The resolved tree: one interface per intent, in tree order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTree {
    interfaces: Vec<Interface>,
}

impl ResolvedTree {
    /// The interfaces, in tree order.
    pub(crate) fn views(&self) -> impl Iterator<Item = &Interface> {
        self.interfaces.iter()
    }
}

/// The tree flattened: every intent in preorder, and which composes
/// which.
pub struct Flattened<'a> {
    intents: Vec<&'a Intent>,
    /// Each intent's composer, and its position among that composer's
    /// members. `None` for the root.
    parent: Vec<Option<(usize, usize)>>,
}

impl<'a> Flattened<'a> {
    /// The intents, in tree order.
    pub fn intents(&self) -> &[&'a Intent] {
        &self.intents
    }

    /// The composer of `intent` and `intent`'s position among its
    /// members, or nothing for the root.
    fn composer_of(&self, intent: usize) -> Option<(usize, usize)> {
        self.parent[intent]
    }
}

/// One step of the preorder walk: the intent, its composer and position,
/// and its depth.
type Visit<'a> = (&'a Intent, Option<(usize, usize)>, usize);

/// Walk `root` in preorder, holding every intent to what the tree admits
/// of it: a depth under [`MAX_TREE_DEPTH`], at least one account, and
/// terms on the root alone.
///
/// # Errors
///
/// Any [`AdmissionError`] the structure earns.
pub fn flatten(root: &Intent) -> Result<Flattened<'_>, AdmissionError> {
    let mut intents = Vec::new();
    let mut parent = Vec::new();
    let mut stack: Vec<Visit<'_>> = vec![(root, None, 1)];
    while let Some((intent, composer, depth)) = stack.pop() {
        let at = intents.len();
        if depth > MAX_TREE_DEPTH {
            return Err(AdmissionError::TreeTooDeep { intent: as_u32(at) });
        }
        if intent.accounts.is_empty() {
            return Err(AdmissionError::NoAccount { intent: as_u32(at) });
        }
        if intent.accounts.len() > MAX_ACCOUNTS {
            return Err(AdmissionError::TooManyAccounts { intent: as_u32(at) });
        }
        intents.push(intent);
        parent.push(composer);
        for (position, member) in intent.members.iter().enumerate().rev() {
            stack.push((&member.intent, Some((at, position)), depth + 1));
        }
    }
    Ok(Flattened { intents, parent })
}

/// Resolve every interface of a flattened tree.
///
/// # Errors
///
/// Any [`AdmissionError`] the wiring earns.
pub fn resolve_tree(flat: &Flattened<'_>) -> Result<ResolvedTree, AdmissionError> {
    let resolver = Resolver {
        intents: &flat.intents,
        structure: flat,
    };
    resolver.resolve()
}

struct Resolver<'a> {
    intents: &'a [&'a Intent],
    structure: &'a Flattened<'a>,
}

impl Resolver<'_> {
    fn resolve(&self) -> Result<ResolvedTree, AdmissionError> {
        // Gives first: a value socket may be filled from one, and each
        // is consumed exactly once above the intent that declares it,
        // whichever of the three ways the composer takes it.
        let mut member_gives: Vec<Vec<Vec<Yielded>>> = Vec::with_capacity(self.intents.len());
        for (at, intent) in self.intents.iter().enumerate() {
            let mut per_member = Vec::with_capacity(intent.members.len());
            for position in 0..intent.members.len() {
                let member = self.member(at, position);
                let mut per_give = Vec::with_capacity(self.intents[member].gives.len());
                for give in 0..self.intents[member].gives.len() {
                    per_give.push(self.yielded(member, give)?);
                }
                per_member.push(per_give);
            }
            member_gives.push(per_member);
        }
        self.check_give_uses()?;

        let mut interfaces = Vec::with_capacity(self.intents.len());
        for (at, intent) in self.intents.iter().enumerate() {
            let mut fills = Vec::with_capacity(intent.sockets.len());
            for socket in 0..intent.sockets.len() {
                fills.push(self.fill(at, socket)?);
            }
            let mut wired_uses = vec![0u32; intent.sockets.len()];
            for binding in intent.members.iter().flat_map(|member| &member.wiring) {
                let passed = match binding {
                    Binding::Value(ValueSource::Socket(socket))
                    | Binding::Authority(ClaimSource::Socket(socket)) => Some(*socket),
                    Binding::Value(ValueSource::Edge(_) | ValueSource::Give(_))
                    | Binding::Authority(ClaimSource::Node(_) | ClaimSource::Account(_)) => None,
                };
                if let Some(count) = passed
                    .and_then(|socket| usize::try_from(socket).ok())
                    .and_then(|socket| wired_uses.get_mut(socket))
                {
                    *count += 1;
                }
            }
            interfaces.push(Interface {
                fills,
                wired_uses,
                member_gives: member_gives[at].clone(),
            });
        }
        Ok(ResolvedTree { interfaces })
    }

    /// The `position`-th member of `composer`, as the walk numbered it.
    fn member(&self, composer: usize, position: usize) -> usize {
        self.structure
            .parent
            .iter()
            .position(|parent| *parent == Some((composer, position)))
            .expect("the walk placed every member it numbered")
    }

    /// Follow `give` of `intent` down to the edge that produces it.
    fn yielded(&self, intent: usize, give: usize) -> Result<Yielded, AdmissionError> {
        let unknown = || AdmissionError::UnknownGive {
            intent: as_u32(intent),
            give: as_u32(give),
        };
        match self.intents[intent].gives[give] {
            Give::Edge(edge) => {
                let producer = usize::try_from(edge.producer).map_err(|_| unknown())?;
                if producer >= self.intents[intent].graph.nodes.len() {
                    return Err(unknown());
                }
                Ok(Yielded {
                    intent: as_u32(intent),
                    edge,
                })
            }
            Give::Member(GiveRef {
                member,
                give: inner,
            }) => {
                let member = usize::try_from(member).map_err(|_| unknown())?;
                if member >= self.intents[intent].members.len() {
                    return Err(unknown());
                }
                let child = self.member(intent, member);
                let inner = usize::try_from(inner).map_err(|_| unknown())?;
                if inner >= self.intents[child].gives.len() {
                    return Err(unknown());
                }
                self.yielded(child, inner)
            }
        }
    }

    /// Every give is consumed exactly once by the intent above it: as
    /// an argument of the composer's graph, in the composer's wiring, or
    /// in the composer's own gives. A give the root declares has nobody
    /// above it and is refused as unconsumed.
    fn check_give_uses(&self) -> Result<(), AdmissionError> {
        for (at, intent) in self.intents.iter().enumerate() {
            let mut uses: Vec<Vec<u32>> = (0..intent.members.len())
                .map(|position| vec![0u32; self.intents[self.member(at, position)].gives.len()])
                .collect();
            let taken = intent
                .graph
                .nodes
                .iter()
                .flat_map(GraphNode::gives)
                .chain(
                    intent
                        .members
                        .iter()
                        .flat_map(|member| &member.wiring)
                        .filter_map(|binding| match binding {
                            Binding::Value(ValueSource::Give(give)) => Some(*give),
                            Binding::Value(ValueSource::Edge(_) | ValueSource::Socket(_))
                            | Binding::Authority(_) => None,
                        }),
                )
                .chain(intent.gives.iter().filter_map(|give| match give {
                    Give::Member(give) => Some(*give),
                    Give::Edge(_) => None,
                }));
            for give in taken {
                if let Some(count) = usize::try_from(give.member)
                    .ok()
                    .and_then(|member| uses.get_mut(member))
                    .and_then(|gives| {
                        usize::try_from(give.give)
                            .ok()
                            .and_then(|g| gives.get_mut(g))
                    })
                {
                    *count += 1;
                }
                // An out-of-range reference is refused where it is read:
                // by the lowering for an argument, by `fill` for wiring,
                // by `yielded` for a give.
            }
            for (position, counts) in uses.iter().enumerate() {
                let member = as_u32(self.member(at, position));
                for (give, count) in counts.iter().enumerate() {
                    match *count {
                        0 => {
                            return Err(AdmissionError::UnconsumedGive {
                                intent: member,
                                give: as_u32(give),
                            });
                        }
                        1 => {}
                        _ => {
                            return Err(AdmissionError::GiveReused {
                                intent: member,
                                give: as_u32(give),
                            });
                        }
                    }
                }
            }
        }
        if let Some(root) = self.intents.first()
            && !root.gives.is_empty()
        {
            return Err(AdmissionError::UnconsumedGive { intent: 0, give: 0 });
        }
        Ok(())
    }

    /// What fills socket `socket` of `intent`: the composer's wiring
    /// entry for it, followed to the node or the account behind it.
    ///
    /// The root declares no sockets, so a chain of pass-throughs ends
    /// at an intent whose composer fills the socket from something of
    /// its own.
    fn fill(&self, intent: usize, socket: usize) -> Result<Fill, AdmissionError> {
        let at = (as_u32(intent), as_u32(socket));
        let Some((composer, position)) = self.structure.composer_of(intent) else {
            // The root: nothing above it fills anything.
            return Err(unknown_binding(at));
        };
        let wiring = &self.intents[composer].members[position].wiring;
        if wiring.len() != self.intents[intent].sockets.len() {
            return Err(AdmissionError::BindingArity {
                intent: at.0,
                expected: self.intents[intent].sockets.len(),
                found: wiring.len(),
            });
        }
        match (&self.intents[intent].sockets[socket], wiring[socket]) {
            (Socket::Value { resource, .. }, Binding::Value(source)) => {
                self.fill_value(composer, *resource, source, at)
            }
            (Socket::Authority(wanted), Binding::Authority(source)) => {
                self.fill_authority(composer, *wanted, source, at)
            }
            (Socket::Value { .. }, Binding::Authority(_)) => {
                Err(AdmissionError::SocketKindMismatch {
                    intent: at.0,
                    socket: at.1,
                    declared: "value",
                    offered: "a proof",
                })
            }
            (Socket::Authority(_), Binding::Value(_)) => Err(AdmissionError::SocketKindMismatch {
                intent: at.0,
                socket: at.1,
                declared: "authority",
                offered: "an edge",
            }),
        }
    }

    /// The edge `composer` wires into a value socket declared for
    /// `resource`, at `at`.
    fn fill_value(
        &self,
        composer: usize,
        resource: ResourceAddr,
        source: ValueSource,
        at: (u32, u32),
    ) -> Result<Fill, AdmissionError> {
        let above = &self.intents[composer];
        match source {
            ValueSource::Edge(edge) => {
                let producer = usize::try_from(edge.producer).map_err(|_| unknown_binding(at))?;
                if producer >= above.graph.nodes.len() {
                    return Err(unknown_binding(at));
                }
                Ok(Fill::Value {
                    intent: as_u32(composer),
                    edge,
                    through: Vec::new(),
                })
            }
            ValueSource::Give(give) => {
                let member = usize::try_from(give.member).map_err(|_| unknown_binding(at))?;
                if member >= above.members.len() {
                    return Err(unknown_binding(at));
                }
                let child = self.member(composer, member);
                let inner = usize::try_from(give.give).map_err(|_| unknown_binding(at))?;
                if inner >= self.intents[child].gives.len() {
                    return Err(unknown_binding(at));
                }
                let yielded = self.yielded(child, inner)?;
                Ok(Fill::Value {
                    intent: yielded.intent,
                    edge: yielded.edge,
                    through: Vec::new(),
                })
            }
            ValueSource::Socket(passed) => {
                let passed = usize::try_from(passed).map_err(|_| unknown_binding(at))?;
                let Some(Socket::Value {
                    resource: carried,
                    constraints,
                }) = above.sockets.get(passed)
                else {
                    return Err(unknown_binding(at));
                };
                if *carried != resource {
                    return Err(AdmissionError::SocketResourceMismatch {
                        intent: at.0,
                        socket: at.1,
                    });
                }
                let Fill::Value {
                    intent,
                    edge,
                    mut through,
                } = self.fill(composer, passed)?
                else {
                    unreachable!("a value socket resolves to a value fill");
                };
                // The composer's own constraints on what it passes
                // through bind beside the declaring intent's: every
                // signer along the chain constrained the edge.
                through.extend_from_slice(constraints);
                Ok(Fill::Value {
                    intent,
                    edge,
                    through,
                })
            }
        }
    }

    /// The claim `composer` grants into an authority socket declared for
    /// `wanted`, at `at`. The whole of scope: an account the composer
    /// acts as, so its own signer consented to lending it; or a socket
    /// of the composer's own carrying the same claim, which whoever
    /// composed the composer filled in turn.
    fn fill_authority(
        &self,
        composer: usize,
        wanted: Claim,
        source: ClaimSource,
        at: (u32, u32),
    ) -> Result<Fill, AdmissionError> {
        let above = &self.intents[composer];
        match source {
            ClaimSource::Node(producer) => {
                let node = usize::try_from(producer).map_err(|_| unknown_binding(at))?;
                if node >= above.graph.nodes.len() {
                    return Err(unknown_binding(at));
                }
                Ok(Fill::Authority {
                    intent: as_u32(composer),
                    from: Proven::Node(producer),
                })
            }
            ClaimSource::Account(account) => {
                if !above.accounts.contains(&account) {
                    return Err(AdmissionError::GrantNotHeld {
                        intent: at.0,
                        socket: at.1,
                        account,
                    });
                }
                check_claim(wanted, Claim::of_subject(account.address()), at)?;
                Ok(Fill::Authority {
                    intent: as_u32(composer),
                    from: Proven::Account(account),
                })
            }
            ClaimSource::Socket(passed) => {
                let passed = usize::try_from(passed).map_err(|_| unknown_binding(at))?;
                let Some(Socket::Authority(carried)) = above.sockets.get(passed) else {
                    return Err(unknown_binding(at));
                };
                check_claim(wanted, *carried, at)?;
                self.fill(composer, passed)
            }
        }
    }
}

/// A binding naming a node, a give or a socket the composer does not
/// hold, at `at`.
const fn unknown_binding(at: (u32, u32)) -> AdmissionError {
    AdmissionError::UnknownBinding {
        intent: at.0,
        socket: at.1,
    }
}

/// The socket's own declaration fixes which claim may arrive, as it does
/// for a proof.
fn check_claim(wanted: Claim, granted: Claim, at: (u32, u32)) -> Result<(), AdmissionError> {
    if wanted == granted {
        Ok(())
    } else {
        Err(AdmissionError::GrantClaimMismatch {
            intent: at.0,
            socket: at.1,
        })
    }
}

/// An index as the refusal vocabulary carries it. Bounded by
/// `MAX_INTENTS` and `MAX_SOCKETS`, which the caps enforce before
/// anything here runs.
fn as_u32(index: usize) -> u32 {
    u32::try_from(index).expect("indices are bounded by the wire caps")
}

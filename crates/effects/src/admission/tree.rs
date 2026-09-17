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

use std::collections::BTreeSet;

use hyperscale_vm_types::{
    IntentHash, MAX_ATTESTATIONS, MAX_INTENTS, MAX_MANIFEST_NODES, ResourceAddr,
};

use super::compose::{Fill, Produced};
use super::{AdmissionError, MAX_SOCKETS};
use crate::claim::Claim;
use crate::graph::{ClaimRef, GiveRef, GraphNode, ValueRef};
use crate::hash::{Hash32, Hasher};
use crate::intent::{Binding, Intent, MAX_ACCOUNTS, MAX_TREE_DEPTH, Socket};

/// One intent's wiring resolved, as the flat checker consumes it: what
/// fills each of its sockets, how often its own wiring passes each
/// socket on, and where each of its members' gives comes from.
///
/// Not the interface — that is the sockets and gives the intent
/// declared and signed. This is what the tree put behind them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Resolution {
    /// One fill per declared socket.
    pub(crate) fills: Vec<Fill>,
    /// Per member, per give, the edge that produces it.
    pub(crate) member_gives: Vec<Vec<Produced>>,
}

impl Resolution {
    /// The give a `ValueRef::Give` of this intent names, where it names
    /// one.
    pub(crate) fn give(&self, give: GiveRef) -> Option<Produced> {
        self.member_gives
            .get(usize::try_from(give.member).ok()?)?
            .get(usize::try_from(give.give).ok()?)
            .copied()
    }
}

/// The resolved tree: one resolution per intent, in tree order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedTree {
    resolutions: Vec<Resolution>,
}

impl ResolvedTree {
    /// The resolutions, in tree order.
    pub(crate) fn resolutions(&self) -> impl Iterator<Item = &Resolution> {
        self.resolutions.iter()
    }
}

/// The tree flattened: every intent in preorder, and which composes
/// which.
pub struct Flattened<'a> {
    intents: Vec<&'a Intent>,
    /// Each intent's composer, and its position among that composer's
    /// members. `None` for the root.
    parent: Vec<Option<(usize, usize)>>,
    /// Each intent's members, by their positions in the walk, in the
    /// order the composer holds them.
    children: Vec<Vec<usize>>,
    /// Each intent's depth: one for the root, one more per level.
    depth: Vec<usize>,
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

    /// The `position`-th member of `composer`, as the walk numbered it.
    fn member(&self, composer: usize, position: usize) -> usize {
        self.children[composer][position]
    }

    /// Every intent's hash, in tree order, each computed once: members
    /// before their composer, so a composer's preimage takes its
    /// members' hashes as computed rather than recomputing the subtree
    /// beneath each.
    pub fn hashes(&self, hasher: &dyn Hasher) -> Vec<IntentHash> {
        let mut computed = vec![IntentHash(Hash32([0; 32])); self.intents.len()];
        for (at, intent) in self.intents.iter().enumerate().rev() {
            let members: Vec<IntentHash> = self.children[at]
                .iter()
                .map(|&member| computed[member])
                .collect();
            computed[at] = intent.hash_over(&members, hasher);
        }
        computed
    }
}

/// One step of the preorder walk: the intent, its composer and position,
/// and its depth.
type Visit<'a> = (&'a Intent, Option<(usize, usize)>, usize);

/// Walk `root` in preorder, numbering every intent and recording which
/// composes which and how deep each sits. Judges nothing.
pub fn walk(root: &Intent) -> Flattened<'_> {
    let mut intents = Vec::new();
    let mut parent = Vec::new();
    let mut children: Vec<Vec<usize>> = Vec::new();
    let mut depth = Vec::new();
    let mut stack: Vec<Visit<'_>> = vec![(root, None, 1)];
    while let Some((intent, composer, level)) = stack.pop() {
        let at = intents.len();
        if let Some((composer, _)) = composer {
            children[composer].push(at);
        }
        intents.push(intent);
        parent.push(composer);
        children.push(Vec::with_capacity(intent.members.len()));
        depth.push(level);
        for (position, member) in intent.members.iter().enumerate().rev() {
            stack.push((&member.signed.intent, Some((at, position)), level + 1));
        }
    }
    Flattened {
        intents,
        parent,
        children,
        depth,
    }
}

/// Walk `root` in preorder, holding the tree to its shape: no more
/// intents than [`MAX_INTENTS`], none deeper than [`MAX_TREE_DEPTH`],
/// no more nodes between them than [`MAX_MANIFEST_NODES`]; every intent
/// acting as at least one account and at most [`MAX_ACCOUNTS`], none
/// twice; attested by at least one principal and at most
/// [`MAX_ATTESTATIONS`], none twice; every member wired once per socket
/// it declares; every intent structurally sound on
/// [`check_structure`]'s terms; and the root declaring no interface,
/// since nothing is above it.
///
/// The whole of what admission holds a tree to before it reads any
/// binding, and what [`decode_tree`](crate::decode_tree) holds a
/// stranger's bytes to before anything walks them — so nothing
/// downstream runs over a tree past its caps.
///
/// # Errors
///
/// Any [`AdmissionError`] the structure earns.
pub fn flatten(root: &Intent) -> Result<Flattened<'_>, AdmissionError> {
    let flat = walk(root);
    if flat.intents.len() > MAX_INTENTS {
        return Err(AdmissionError::TooManyIntents);
    }
    let nodes: usize = flat
        .intents
        .iter()
        .map(|intent| intent.graph.nodes.len())
        .sum();
    if nodes > MAX_MANIFEST_NODES {
        return Err(AdmissionError::TooManyNodes);
    }
    for (at, intent) in flat.intents.iter().enumerate() {
        let intent_index = as_u32(at);
        if flat.depth[at] > MAX_TREE_DEPTH {
            return Err(AdmissionError::TreeTooDeep {
                intent: intent_index,
            });
        }
        if intent.accounts.is_empty() {
            return Err(AdmissionError::NoAccount {
                intent: intent_index,
            });
        }
        if intent.accounts.len() > MAX_ACCOUNTS {
            return Err(AdmissionError::TooManyAccounts {
                intent: intent_index,
            });
        }
        if intent.accounts.iter().collect::<BTreeSet<_>>().len() != intent.accounts.len() {
            return Err(AdmissionError::DuplicateAccount {
                intent: intent_index,
            });
        }
        if intent.attested_by.is_empty() {
            return Err(AdmissionError::NoAttester {
                intent: intent_index,
            });
        }
        if intent.attested_by.len() > MAX_ATTESTATIONS {
            return Err(AdmissionError::TooManyAttesters {
                intent: intent_index,
            });
        }
        if intent.attested_by.iter().collect::<BTreeSet<_>>().len() != intent.attested_by.len() {
            return Err(AdmissionError::DuplicateAttester {
                intent: intent_index,
            });
        }
        for (position, member) in intent.members.iter().enumerate() {
            let declared = member.signed.intent.sockets.len();
            if member.wiring.len() != declared {
                return Err(AdmissionError::BindingArity {
                    intent: as_u32(flat.member(at, position)),
                    expected: declared,
                    found: member.wiring.len(),
                });
            }
        }
        check_structure(intent, intent_index)?;
    }
    if !root.sockets.is_empty() {
        return Err(AdmissionError::RootSockets { socket: 0 });
    }
    if !root.gives.is_empty() {
        return Err(AdmissionError::RootGives { give: 0 });
    }
    Ok(flat)
}

/// Hold one intent to what its own declaration says, resolving nothing
/// against the tree.
///
/// Every socket its graph and its wiring reach is declared and reached
/// from the channel its kind speaks — a value socket by exactly one
/// argument or pass-through, an authority socket by at least one
/// presentation or grant; every give names an output of its own graph
/// or a give of a member it has; and every member's give is taken
/// exactly once, as an argument, in the wiring, or given on.
///
/// The one statement of these rules. Admission holds every intent of a
/// tree to it through [`flatten`], and the builder holds an intent to it
/// as it is finished and every member to it as it is adopted, so what
/// the builder refuses is exactly what admission would. `at` is the
/// intent's number in whatever the caller is numbering — its position
/// in tree order here, the builder's own coordinates there.
///
/// A reference past what a member or a socket declares is left to
/// whoever reads it against the tree: the wiring's sources are the
/// resolver's, and an argument's are the lowering's.
///
/// # Errors
///
/// Any [`AdmissionError`] the declaration earns.
pub fn check_structure(intent: &Intent, at: u32) -> Result<(), AdmissionError> {
    if intent.sockets.len() > MAX_SOCKETS {
        return Err(AdmissionError::TooManySockets { intent: at });
    }
    if intent.gives.len() > MAX_SOCKETS {
        return Err(AdmissionError::TooManyGives { intent: at });
    }
    check_socket_uses(intent, at)?;
    check_gives_held(intent, at)?;
    check_member_gives_taken(intent, at)
}

/// Every socket declared, reached from the right channel, and reached
/// once where value and at least once where authority.
fn check_socket_uses(intent: &Intent, at: u32) -> Result<(), AdmissionError> {
    let mut uses = vec![0u32; intent.sockets.len()];
    let mut reach = |socket: u32, as_value: bool, node: Option<u32>| {
        let Some((position, declared)) = usize::try_from(socket)
            .ok()
            .and_then(|position| Some((position, intent.sockets.get(position)?)))
        else {
            // A node naming a socket the intent does not declare is the
            // declaration's own defect; wiring naming one is the
            // resolver's to refuse against the member it fills.
            return node.map_or(Ok(()), |node| {
                Err(AdmissionError::UnknownSocket {
                    intent: at,
                    node,
                    socket,
                })
            });
        };
        let value = matches!(declared, Socket::Value { .. });
        if value != as_value {
            return Err(AdmissionError::SocketKindMismatch {
                intent: at,
                socket,
                declared: if value { "value" } else { "authority" },
                offered: if as_value { "an edge" } else { "a proof" },
            });
        }
        uses[position] += 1;
        Ok(())
    };
    for (index, node) in intent.graph.nodes.iter().enumerate() {
        let node_index = as_u32(index);
        for socket in node.args.iter().filter_map(|arg| arg.source()?.socket()) {
            reach(socket, true, Some(node_index))?;
        }
        for reference in &node.evidence {
            if let ClaimRef::Socket(socket) = reference {
                reach(*socket, false, Some(node_index))?;
            }
        }
    }
    for binding in intent.members.iter().flat_map(|member| &member.wiring) {
        match binding {
            Binding::Value(ValueRef::Socket(socket)) => reach(*socket, true, None)?,
            Binding::Authority(ClaimRef::Socket(socket)) => reach(*socket, false, None)?,
            Binding::Value(ValueRef::Edge(_) | ValueRef::Give(_))
            | Binding::Authority(ClaimRef::Node(_) | ClaimRef::Account(_)) => {}
        }
    }
    for (position, count) in uses.iter().enumerate() {
        let socket = as_u32(position);
        if *count == 0 {
            return Err(AdmissionError::UnconsumedSocket { intent: at, socket });
        }
        // Value is conserved and authority is not: an edge fills one
        // argument, and presenting a claim twice says nothing
        // presenting it once does not.
        if matches!(intent.sockets[position], Socket::Value { .. }) && *count > 1 {
            return Err(AdmissionError::SocketReused { intent: at, socket });
        }
    }
    Ok(())
}

/// Every give an output of the intent's own graph, or a give of a
/// member it has. Never a socket of its own, which would route the
/// composer's value back to it.
fn check_gives_held(intent: &Intent, at: u32) -> Result<(), AdmissionError> {
    for (position, give) in intent.gives.iter().enumerate() {
        let held = match give {
            ValueRef::Edge(edge) => usize::try_from(edge.producer)
                .is_ok_and(|producer| producer < intent.graph.nodes.len()),
            ValueRef::Give(give) => usize::try_from(give.member)
                .ok()
                .and_then(|member| intent.members.get(member))
                .zip(usize::try_from(give.give).ok())
                .is_some_and(|(member, give)| give < member.signed.intent.gives.len()),
            ValueRef::Socket(_) => false,
        };
        if !held {
            return Err(AdmissionError::UnknownGive {
                intent: at,
                give: as_u32(position),
            });
        }
    }
    Ok(())
}

/// Every member's give taken exactly once: as an argument, in the
/// wiring, or given on.
fn check_member_gives_taken(intent: &Intent, at: u32) -> Result<(), AdmissionError> {
    let mut counts: Vec<Vec<u32>> = intent
        .members
        .iter()
        .map(|member| vec![0u32; member.signed.intent.gives.len()])
        .collect();
    let consumptions = intent
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
                    Binding::Value(source) => source.give(),
                    Binding::Authority(_) => None,
                }),
        )
        .chain(intent.gives.iter().filter_map(|give| give.give()));
    for give in consumptions {
        if let Some(count) = usize::try_from(give.member)
            .ok()
            .and_then(|member| counts.get_mut(member))
            .and_then(|gives| {
                usize::try_from(give.give)
                    .ok()
                    .and_then(|g| gives.get_mut(g))
            })
        {
            *count += 1;
        }
    }
    for (member, per_give) in counts.iter().enumerate() {
        for (give, count) in per_give.iter().enumerate() {
            match *count {
                1 => {}
                0 => {
                    return Err(AdmissionError::UnconsumedGive {
                        intent: at,
                        member: as_u32(member),
                        give: as_u32(give),
                    });
                }
                _ => {
                    return Err(AdmissionError::GiveReused {
                        intent: at,
                        member: as_u32(member),
                        give: as_u32(give),
                    });
                }
            }
        }
    }
    Ok(())
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
        let mut member_gives: Vec<Vec<Vec<Produced>>> = Vec::with_capacity(self.intents.len());
        for (at, intent) in self.intents.iter().enumerate() {
            let mut per_member = Vec::with_capacity(intent.members.len());
            for position in 0..intent.members.len() {
                let member = self.structure.member(at, position);
                let mut per_give = Vec::with_capacity(self.intents[member].gives.len());
                for give in 0..self.intents[member].gives.len() {
                    per_give.push(self.yielded(member, give)?);
                }
                per_member.push(per_give);
            }
            member_gives.push(per_member);
        }

        let mut resolutions = Vec::with_capacity(self.intents.len());
        for (at, intent) in self.intents.iter().enumerate() {
            let mut fills = Vec::with_capacity(intent.sockets.len());
            for socket in 0..intent.sockets.len() {
                fills.push(self.fill(at, socket)?);
            }
            resolutions.push(Resolution {
                fills,
                member_gives: member_gives[at].clone(),
            });
        }
        Ok(ResolvedTree { resolutions })
    }

    /// Follow `give` of `intent` down to the edge that produces it.
    fn yielded(&self, intent: usize, give: usize) -> Result<Produced, AdmissionError> {
        let unknown = || AdmissionError::UnknownGive {
            intent: as_u32(intent),
            give: as_u32(give),
        };
        match self.intents[intent].gives[give] {
            ValueRef::Edge(edge) => {
                let producer = usize::try_from(edge.producer).map_err(|_| unknown())?;
                if producer >= self.intents[intent].graph.nodes.len() {
                    return Err(unknown());
                }
                Ok(Produced {
                    intent: as_u32(intent),
                    edge,
                })
            }
            ValueRef::Give(GiveRef {
                member,
                give: inner,
            }) => {
                let member = usize::try_from(member).map_err(|_| unknown())?;
                if member >= self.intents[intent].members.len() {
                    return Err(unknown());
                }
                let child = self.structure.member(intent, member);
                let inner = usize::try_from(inner).map_err(|_| unknown())?;
                if inner >= self.intents[child].gives.len() {
                    return Err(unknown());
                }
                self.yielded(child, inner)
            }
            // A socket of the giving intent's own is filled from above:
            // giving it back up would route the composer's value to
            // itself, so a give names an edge or a member's give alone.
            ValueRef::Socket(_) => Err(unknown()),
        }
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
        // One binding per declared socket, held by the walk before any
        // is read.
        let wiring = &self.intents[composer].members[position].wiring;
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
        source: ValueRef,
        at: (u32, u32),
    ) -> Result<Fill, AdmissionError> {
        let above = &self.intents[composer];
        match source {
            ValueRef::Edge(edge) => {
                let producer = usize::try_from(edge.producer).map_err(|_| unknown_binding(at))?;
                if producer >= above.graph.nodes.len() {
                    return Err(unknown_binding(at));
                }
                Ok(Fill::Value {
                    produced: Produced {
                        intent: as_u32(composer),
                        edge,
                    },
                    through: Vec::new(),
                })
            }
            ValueRef::Give(give) => {
                let member = usize::try_from(give.member).map_err(|_| unknown_binding(at))?;
                if member >= above.members.len() {
                    return Err(unknown_binding(at));
                }
                let child = self.structure.member(composer, member);
                let inner = usize::try_from(give.give).map_err(|_| unknown_binding(at))?;
                if inner >= self.intents[child].gives.len() {
                    return Err(unknown_binding(at));
                }
                Ok(Fill::Value {
                    produced: self.yielded(child, inner)?,
                    through: Vec::new(),
                })
            }
            ValueRef::Socket(passed) => {
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
                    produced,
                    mut through,
                } = self.fill(composer, passed)?
                else {
                    unreachable!("a value socket resolves to a value fill");
                };
                // The composer's own constraints on what it passes
                // through bind beside the declaring intent's: every
                // signer along the chain constrained the edge.
                through.extend_from_slice(constraints);
                Ok(Fill::Value { produced, through })
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
        source: ClaimRef,
        at: (u32, u32),
    ) -> Result<Fill, AdmissionError> {
        let above = &self.intents[composer];
        match source {
            ClaimRef::Node(producer) => {
                let node = usize::try_from(producer).map_err(|_| unknown_binding(at))?;
                if node >= above.graph.nodes.len() {
                    return Err(unknown_binding(at));
                }
                Ok(Fill::Claim {
                    intent: as_u32(composer),
                    node: producer,
                })
            }
            ClaimRef::Account(account) => {
                if !above.accounts.contains(&account) {
                    return Err(AdmissionError::GrantNotHeld {
                        intent: at.0,
                        socket: at.1,
                        account,
                    });
                }
                check_claim(wanted, Claim::of_subject(account.address()), at)?;
                Ok(Fill::Account(account))
            }
            ClaimRef::Socket(passed) => {
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

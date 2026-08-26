//! The resource record: what an issuer declares about a resource.
//!
//! A resource address is pure derivation — provenance is the identity —
//! and this cell is what the identity points at: the resource's kind and
//! its display quantization, written by the issuer under its own prefix.
//! Minting and burning stay the issuer's own declared effects on vaults;
//! the record says what they issue, never how much of it exists.

use hyperscale_hbor::{
    DecodeError, EncodeError, Hbor, HborShape, from_slice_with_depth, to_vec, to_vec_with_depth,
};
use hyperscale_vm_types::{Address, AddressClass, CollectionId, Moves, ResourceAddr, SubstateKey};

use crate::auth::RuleBytes;
use crate::dsl::{Expr, SlotRef, TargetExpr};
use crate::hash::{Hash32, Hasher};
use crate::presented::Presented;
use crate::rule::{GrantClaim, GrantRuleExpr, Holding, SealedLeaf, StoredRule, always, never};
use crate::types::{
    Value, child_key, collection_id, genesis_publisher, granting_resource_address, resource_address,
};
pub use crate::vocabulary::{INSTANCE, NF_VAULT, RESOURCE};

/// What a resource is: divisible value, or named instances.
///
/// Derivation material before it is anything else: the discriminant is
/// folded into [`resource_address`](crate::types::resource_address), so
/// one address names one kind and a resource minted as both kinds is
/// two resources rather than a conflation. The same vocabulary types an
/// edge — declared, evaluated from the producing method's output
/// projection, and never sniffed from what crosses: the kind is what
/// admission binds a consumer's parameter against, and what a signed
/// bound is judged in the terms of.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum ResourceKind {
    /// Divisible value: linear amounts in vault cells; edges carry
    /// 16-byte quantities.
    Fungible,
    /// Named instances held as sub-collection entries; edges carry id
    /// sets.
    NonFungible,
}

impl ResourceKind {
    /// The kind's derivation byte: the part [`resource_address`] folds
    /// between the minter and the material.
    ///
    /// [`resource_address`]: crate::types::resource_address
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Fungible => 0,
            Self::NonFungible => 1,
        }
    }
}

/// The resource `instance` issues under `mark` — the material
/// separating it from the instance's other issues.
///
/// The one spelling of how a mark becomes derivation material: one part,
/// whatever the mark says. The authoring surface reaches the same
/// address by evaluating `SelfResource` over the mark a `#[resource]`
/// declaration carries, and the routed grant is lowered through this, so
/// the two agree because they are one code path pinned by one test.
///
/// A mark is a resource's own name, which publish holds every issuance
/// to — so there is no mark that folds to no material, and no address a
/// package reaches by saying less. The fee resource sits where saying
/// nothing would have landed, and its minter runs no code at all.
#[must_use]
pub fn issued_resource(
    hasher: &dyn Hasher,
    instance: impl Into<Address>,
    kind: ResourceKind,
    mark: &[u8],
) -> ResourceAddr {
    granting_issued_resource(hasher, instance, kind, &ResourceGrants::new(), mark)
}

/// The same derivation, over a mark that grants rules.
///
/// Beside [`issued_resource`] rather than inside it so the mark's
/// encoding into derivation material is spelled once: the granting-nothing form
/// is this one over the empty set, which is what every granting-nothing
/// resource's address already folds.
#[must_use]
pub fn granting_issued_resource(
    hasher: &dyn Hasher,
    instance: impl Into<Address>,
    kind: ResourceKind,
    rules: &ResourceGrants,
    mark: &[u8],
) -> ResourceAddr {
    let material = [Value::Bytes(mark.to_vec()).canonical_bytes()];
    granting_resource_address(hasher, instance, kind, rules, &material)
}

/// The decoder cap for a record cell: the one variant frame a record is,
/// its scalar payload adding no level of its own.
///
/// Exactly what the shape takes, so a record that grows a nested field
/// fails to encode until somebody raises this on purpose — which is what
/// the fallible [`to_cell`](ResourceRecord::to_cell) is for. Public
/// because the record crosses one boundary: the authoring surface writes
/// the cell a client later decodes, and the two agree by reading it here.
pub const RECORD_WIRE_DEPTH: usize = 1;

/// One resource's record cell: what a client learns about a resource
/// that its address cannot be read backwards to give them.
///
/// The kind is restated rather than stated — the address commits it, and
/// nothing on-chain consults the record — and the display width rides the
/// fungible arm because that is the only arm it means anything on:
/// instances are whole by construction, so a non-fungible record has
/// nothing to say beyond existing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor, HborShape)]
pub enum ResourceRecord {
    /// Linear amounts in vault cells; edges carry 16-byte quantities.
    Fungible {
        /// How many base-10 subunit digits a client renders. Amounts are
        /// integers of the smallest unit everywhere in the kernel, and
        /// nothing on-chain consults this — so it is what a balance is
        /// *shown* as and never what the protocol will hold a mint to.
        /// A resource wanting whole units enforces that in its own
        /// bodies.
        display_digits: u8,
    },
    /// Named instances held as sub-collection entries; edges carry id
    /// sets.
    NonFungible,
}

impl ResourceRecord {
    /// The kind this record restates, which is the one its resource's
    /// address already commits.
    #[must_use]
    pub const fn kind(&self) -> ResourceKind {
        match self {
            Self::Fungible { .. } => ResourceKind::Fungible,
            Self::NonFungible => ResourceKind::NonFungible,
        }
    }

    /// The record's canonical cell bytes.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] only on an encoder failure no well-formed record
    /// can reach; surfaced rather than swallowed so a future field's cap
    /// lands somewhere.
    pub fn to_cell(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec_with_depth(self, RECORD_WIRE_DEPTH)
    }

    /// One record from its canonical cell bytes.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on trailing bytes or a non-canonical form.
    pub fn from_cell(bytes: &[u8]) -> Result<Self, DecodeError> {
        from_slice_with_depth(bytes, RECORD_WIRE_DEPTH)
    }
}

/// What a declaration reaching a foreign prefix is allowed to name
/// there.
///
/// The reach is admitted by the reached resource's own entry, so what it
/// may touch is what that entry is about. A freeze entry is about the
/// holder's halt flag, which the vocabulary fixes at one slot; a recall
/// entry is about the value, which the holder keeps at whatever slot
/// they like — so the first is pinned by its slot and the second by its
/// denomination, which is the only thing that says a cell holds value at
/// all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReachedCell {
    /// The holder's halt flag, at the vocabulary's slot for it.
    Halt,
    /// Whatever cell the holder keeps the resource in.
    Holding,
}

/// A behaviour a resource's granted rules govern.
///
/// The set the address cannot answer by arithmetic: who may mint is the
/// derivation's, and these are the rest. Closed like the role band — a
/// behaviour is assigned or it is not one, and adding one is a protocol
/// version change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor, HborShape)]
pub enum GrantedBehaviour {
    /// Bringing supply into existence.
    #[hbor(discriminant = 0)]
    Mint,
    /// Taking supply out of it.
    #[hbor(discriminant = 1)]
    Burn,
    /// Debiting a holding: a reserve, a delta, a write on a value cell,
    /// or a take from an instance interval.
    #[hbor(discriminant = 2)]
    Withdraw,
    /// Crediting one.
    #[hbor(discriminant = 3)]
    Deposit,
    /// Halting a holder's movement of the resource, both ways at once.
    #[hbor(discriminant = 4)]
    Freeze,
    /// Reaching a holding under a prefix that is not the reacher's.
    #[hbor(discriminant = 5)]
    Recall,
}

impl GrantedBehaviour {
    /// Every behaviour, in discriminant order.
    pub const ALL: [Self; 6] = [
        Self::Mint,
        Self::Burn,
        Self::Withdraw,
        Self::Deposit,
        Self::Freeze,
        Self::Recall,
    ];

    /// Which movement entries an access moving these directions earns.
    ///
    /// Both directions through one access are asked both, which
    /// over-binds: a holder permitted to send is asked for the receiving
    /// credential too. That is what a directional access buys — a method
    /// moving one way says so and is judged on that alone.
    ///
    /// Here rather than beside either mode vocabulary because there are
    /// two of them — the declared [`ModeExpr`](crate::dsl::ModeExpr) a
    /// composer reads and the evaluated [`Mode`] admission injects
    /// against — and a table each is two tables that can disagree about
    /// who a movement is judged against.
    ///
    /// [`Mode`]: hyperscale_vm_types::Mode
    #[must_use]
    pub const fn earned_by(moves: Moves) -> &'static [Self] {
        match moves {
            Moves::In => &[Self::Deposit],
            Moves::Out => &[Self::Withdraw],
            Moves::Both => &[Self::Withdraw, Self::Deposit],
        }
    }

    /// Whether this behaviour asks about the actor rather than the
    /// holder.
    ///
    /// An actor question is a capability the kernel otherwise withholds,
    /// so a caller requests it and the node's evidence answers. A holder
    /// question is about the party whose cell is moving, which evidence
    /// cannot answer — the caller of the frame declaring a credit is
    /// systematically not the party being credited.
    #[must_use]
    pub const fn asks_about_the_actor(self) -> bool {
        match self {
            Self::Mint | Self::Burn | Self::Freeze | Self::Recall => true,
            Self::Withdraw | Self::Deposit => false,
        }
    }

    /// What this behaviour's entry demands of a frame speaking as
    /// `speaking_for`, or nothing where it demands nothing of it.
    ///
    /// **A frame speaks for itself.** An entry the executing instance's
    /// own claim already satisfies is one nothing is demanded for, which
    /// reproduces the derivation gate exactly: a component minting its
    /// own resource is not refused for presenting nothing, and a rule
    /// naming a badge instead still means delegated authority.
    ///
    /// The subtraction is **an actor question's alone**. A holder
    /// question resolves against the party whose cell moves, and the
    /// executing frame's identity says nothing about them — so a
    /// movement entry is demanded of the frame whoever the frame is.
    ///
    /// Here rather than at each injection because the answer is the one
    /// thing a composer and admission must agree on exactly: a composer
    /// that subtracts where admission does not presents nothing for an
    /// entry that fires, and one that subtracts less presents evidence
    /// nothing reads. Either way the graph it emits is one admission
    /// refuses.
    ///
    /// # Errors
    ///
    /// [`DecodeError`] on entry bytes that are not a rule within the
    /// vocabulary's caps.
    pub fn demanded(
        self,
        entry: &RuleBytes,
        speaking_for: Option<Presented>,
    ) -> Result<Option<StoredRule>, DecodeError> {
        let rule = entry.decode()?;
        if self.asks_about_the_actor() && speaking_for.is_some_and(|own| rule.satisfied_by(&[own]))
        {
            return Ok(None);
        }
        Ok(Some(rule))
    }

    /// Why this behaviour does not admit `rule`, or nothing if it does.
    ///
    /// **An actor question's rule reads claims**, because a caller
    /// requests a capability and the node's evidence answers — and a
    /// holding leaf there would have no owner to resolve against, since
    /// an authority entry governs a frame rather than a cell.
    ///
    /// **A holder question's rule may read either.** A holding asks a
    /// standing fact about the party whose cell moves; a claim asks
    /// whether this transaction was approved. Those are two different
    /// questions and a movement entry may want either, or both — the
    /// register that says who may hold, and the per-transfer sign-off
    /// that says whether this one goes.
    ///
    /// And **the constant that restates a behaviour's own default is
    /// refused**, since absence already says it: everyone-may for a
    /// movement, which absence permits, and no-one-may for an authority,
    /// which absence withholds.
    #[must_use]
    pub fn refuses(self, rule: &StoredRule) -> Option<GrantsResolveError> {
        let actor = self.asks_about_the_actor();
        if actor
            && rule
                .leaves()
                .any(|leaf| !matches!(leaf, SealedLeaf::Claim(_)))
        {
            return Some(GrantsResolveError::WrongQuestion(self));
        }
        let restates = *rule == if actor { never() } else { always() };
        restates.then_some(GrantsResolveError::RestatesAbsence(self))
    }

    /// The cell a declaration reaching a foreign prefix under this
    /// behaviour may name, or nothing where the behaviour is not the
    /// issuer's to reach with.
    ///
    /// The two the issuer initiates: taking value out of a prefix that
    /// is not theirs, and writing the flag that halts one. Every other
    /// behaviour is about the party whose own cell is moving, so a
    /// declaration reaching under one of those would be claiming an
    /// authority over the wrong question.
    ///
    /// Which cell, rather than only whether: an entry admits a reach for
    /// what that entry is about, and without saying so one admitted
    /// reach would be a licence to write any cell under the prefix.
    #[must_use]
    pub const fn reaches(self) -> Option<ReachedCell> {
        match self {
            Self::Freeze => Some(ReachedCell::Halt),
            Self::Recall => Some(ReachedCell::Holding),
            Self::Mint | Self::Burn | Self::Withdraw | Self::Deposit => None,
        }
    }

    /// Whether absence of this resource's rules would let a movement
    /// proceed that the rules forbid — the one question the address
    /// class answers without a lookup.
    ///
    /// `Freeze` is here despite asking about the actor: granting it puts
    /// a halt read on every movement, and that read fails open when the
    /// record is withheld.
    #[must_use]
    pub const fn restricts_movement(self) -> bool {
        match self {
            Self::Withdraw | Self::Deposit | Self::Freeze => true,
            Self::Mint | Self::Burn | Self::Recall => false,
        }
    }
}

/// The granted entries a resource's address commits to, by behaviour.
///
/// The same sorted-list discipline the role table keeps, and the same
/// opacity where an entry holds a rule: the bytes decode where the rule
/// is judged, under the vocabulary's own caps. **An absent entry injects
/// no requirement**, which withholds a capability the kernel otherwise
/// holds back and permits a movement it does not. Immutability is the
/// derivation rather than a promise — the commitment rides the address,
/// so an entry that changed would be a different resource.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor, HborShape)]
#[hbor(transparent, validate = ascending_behaviours)]
pub struct ResourceGrants(Vec<(GrantedBehaviour, RuleBytes)>);

/// The list's canonical-order rule: behaviours strictly ascending.
fn ascending_behaviours(rules: &ResourceGrants) -> Result<(), &'static str> {
    rules
        .0
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
        .then_some(())
        .ok_or("granted behaviours must be ascending and distinct")
}

impl ResourceGrants {
    /// The empty set, which grants nothing and denies every behaviour.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// What is granted for `behaviour`, where anything is. An absent
    /// entry injects no requirement, which withholds a capability and
    /// permits a movement.
    #[must_use]
    pub fn get(&self, behaviour: GrantedBehaviour) -> Option<&RuleBytes> {
        self.0
            .binary_search_by_key(&behaviour, |(b, _)| *b)
            .ok()
            .map(|index| &self.0[index].1)
    }

    /// Whether any entry restricts a movement anyone could otherwise
    /// make — the question [`AddressClass::Restricted`] answers without
    /// a lookup, asked of the entries rather than of a list of names.
    ///
    /// [`AddressClass::Restricted`]: hyperscale_vm_types::AddressClass::Restricted
    #[must_use]
    pub fn restricts_movement(&self) -> bool {
        self.0
            .iter()
            .any(|(behaviour, _)| behaviour.restricts_movement())
    }

    /// The class an address sealing these grants carries.
    #[must_use]
    pub fn address_class(&self) -> AddressClass {
        if self.restricts_movement() {
            AddressClass::Restricted
        } else {
            AddressClass::Resource
        }
    }

    /// Grant `entry` for `behaviour`, replacing what was there.
    pub fn set(&mut self, behaviour: GrantedBehaviour, entry: RuleBytes) {
        match self.0.binary_search_by_key(&behaviour, |(b, _)| *b) {
            Ok(index) => self.0[index].1 = entry,
            Err(index) => self.0.insert(index, (behaviour, entry)),
        }
    }

    /// The commitment the address folds: a domain-separated hash of the
    /// canonical encoding, the empty set committed like any other so a
    /// granting resource and one that grants nothing can never collide.
    ///
    /// # Panics
    ///
    /// Only on an encoder failure no well-formed list can reach — the
    /// same standing every wire-bounded value has.
    #[must_use]
    pub fn commitment(&self, hasher: &dyn Hasher) -> Hash32 {
        let bytes = to_vec(self).expect("a granted-rules list is a wire-bounded value");
        hasher.hash(DOMAIN_RESOURCE_GRANTS, &[&bytes])
    }
}

const DOMAIN_RESOURCE_GRANTS: &[u8] = b"hyperscale-vm/granted-rules";

/// The granted entries a declaration commits, before the instance
/// issuing them is known.
///
/// [`ResourceGrants`] as a package writes it down: the same
/// behaviour-keyed list under the same ascending discipline, holding
/// declared forms rather than the bytes they seal to. What separates
/// them is what a leaf names — a declared leaf names a derivation, and
/// resolving one against an instance is what [`Self::resolve`] does.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hbor)]
#[hbor(transparent, validate = ascending_declared_behaviours)]
pub struct GrantsExpr(Vec<(GrantedBehaviour, GrantRuleExpr)>);

fn ascending_declared_behaviours(rules: &GrantsExpr) -> Result<(), &'static str> {
    rules
        .0
        .windows(2)
        .all(|pair| pair[0].0 < pair[1].0)
        .then_some(())
        .ok_or("granted behaviours must be ascending and distinct")
}

impl GrantsExpr {
    /// The empty set, which grants nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self(Vec::new())
    }

    /// Whether this declaration grants anything at all.
    ///
    /// The one question the derivation asks before doing any work: an
    /// empty set resolves to the empty [`ResourceGrants`], which is what
    /// every ungranting resource's address already folds.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Grant `rule` for `behaviour`, replacing what was there.
    pub fn set(&mut self, behaviour: GrantedBehaviour, rule: GrantRuleExpr) {
        match self.0.binary_search_by_key(&behaviour, |(b, _)| *b) {
            Ok(index) => self.0[index].1 = rule,
            Err(index) => self.0.insert(index, (behaviour, rule)),
        }
    }

    /// What is declared for `behaviour`, where anything is. An absent
    /// entry withholds the capability, which is what makes capped supply
    /// the absence of a `Mint` entry rather than a field beside one.
    #[must_use]
    pub fn get(&self, behaviour: GrantedBehaviour) -> Option<&GrantRuleExpr> {
        self.0
            .binary_search_by_key(&behaviour, |(b, _)| *b)
            .ok()
            .map(|index| &self.0[index].1)
    }

    /// Every behaviour granted here, with the rule declared for it.
    pub fn iter(&self) -> impl Iterator<Item = (GrantedBehaviour, &GrantRuleExpr)> {
        self.0.iter().map(|(behaviour, rule)| (*behaviour, rule))
    }

    /// Resolve every declared rule against the instance that issues the
    /// resource, and the configuration that instance's address folds.
    ///
    /// # Errors
    ///
    /// [`GrantsResolveError`] for a configuration field the record does
    /// not have or whose value names no claim, and for a rule whose
    /// resolved form is past the caps a stored rule is held to.
    pub fn resolve(
        &self,
        hasher: &dyn Hasher,
        instance: Address,
        config: &[Value],
    ) -> Result<ResourceGrants, GrantsResolveError> {
        self.resolve_link(hasher, instance, config, 0)
    }

    /// [`Self::resolve`] at a known position in the badge chain.
    ///
    /// `link` counts how many badges deep this set already sits. A
    /// resource's own rules are the first link and may name a badge; that
    /// badge's rules are the second and may not, so the chain one address
    /// folds is one link long. Held here rather than only at publish so
    /// the bound is a property of the derivation itself — the address is
    /// a hash of these bytes, and nothing that cannot be resolved may
    /// derive one.
    fn resolve_link(
        &self,
        hasher: &dyn Hasher,
        instance: Address,
        config: &[Value],
        link: usize,
    ) -> Result<ResourceGrants, GrantsResolveError> {
        let mut resolved = ResourceGrants::new();
        for (behaviour, entry) in self.iter() {
            let stored = resolve_rule(hasher, instance, config, entry, behaviour, link)?;
            if let Some(refusal) = behaviour.refuses(&stored) {
                return Err(refusal);
            }
            // The caps hold the *resolved* rule, which is not the one
            // the author wrote: a configuration leaf naming a badge with
            // no kind resolves to two held leaves, so a set inside the
            // budget as declared can be past it as sealed.
            //
            // Asked here rather than left to the encoder, because the
            // encoder does not ask. HBOR's validation hook runs on
            // decode, so `try_from` enforces the wire depth and the
            // branch width and reads the leaf count nowhere — and a
            // resource sealed past it derives an address whose rules
            // nothing can decode, which is a resource nobody may ever
            // move.
            if !stored.within_caps(0) {
                return Err(GrantsResolveError::PastTheCaps);
            }
            let sealed =
                RuleBytes::try_from(&stored).map_err(|_| GrantsResolveError::PastTheCaps)?;
            resolved.set(behaviour, sealed);
        }
        Ok(resolved)
    }
}

/// Why a declared granted set does not resolve against an instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantsResolveError {
    /// A leaf naming a configuration field the record does not have.
    #[error("granted rule names configuration field {0}, which the record does not have")]
    NoSuchField(u32),
    /// A configuration field whose value names no claim — a package
    /// address, a protocol role, anything not callable and not a
    /// resource.
    #[error("granted rule names configuration field {0}, whose value names no claim")]
    NotAClaim(u32),
    /// A resolved rule past the caps a stored rule is held to.
    #[error("a resolved granted rule is past the caps a stored rule is held to")]
    PastTheCaps,
    /// A badge whose own rules name a badge: the chain one address folds
    /// is one link long.
    #[error("a granted rule names a badge whose own rules name a badge")]
    BadgeChainTooDeep,
    /// A rule reading the wrong side: claims where the behaviour asks
    /// about the holder, or holdings where it asks about the actor.
    #[error("{0:?} asks about the other party than the rule written for it reads")]
    WrongQuestion(GrantedBehaviour),
    /// A constant restating what an absent entry already says.
    #[error("{0:?} is granted what its absence already says")]
    RestatesAbsence(GrantedBehaviour),
}

/// Resolve a declared rule into the sealed one an address folds.
///
/// Which sealed leaf a declared one becomes is the behaviour's and the
/// subject's, never the leaf's own spelling. An **actor question** asks
/// what a caller presented and seals a claim, whatever it names. A
/// **holder question** asks what the subject makes answerable: a badge
/// can be held, so it seals a holding; an identity cannot, so it seals
/// the claim that names it. A package therefore writes one derivation
/// and never a second spelling for the second question.
fn resolve_rule(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    rule: &GrantRuleExpr,
    behaviour: GrantedBehaviour,
    link: usize,
) -> Result<StoredRule, GrantsResolveError> {
    Ok(match rule {
        GrantRuleExpr::Require(claim) => {
            if behaviour.asks_about_the_actor() {
                StoredRule::claim(resolve_claim(hasher, instance, config, claim, link)?)
            } else {
                resolve_holding(hasher, instance, config, claim, link)?
            }
        }
        GrantRuleExpr::CountOf { count, rules } => StoredRule::CountOf {
            count: *count,
            rules: rules
                .iter()
                .map(|rule| resolve_rule(hasher, instance, config, rule, behaviour, link))
                .collect::<Result<_, _>>()?,
        },
    })
}

fn resolve_claim(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    claim: &GrantClaim,
    link: usize,
) -> Result<Presented, GrantsResolveError> {
    Ok(match claim {
        GrantClaim::SelfAddr => Presented::of_address(instance)
            .expect("an instance issuing a resource is a callable address"),
        GrantClaim::SelfBadge { mark, kind, rules } => Presented::of_subject(self_badge(
            hasher, instance, config, *kind, mark, rules, link,
        )?),
        GrantClaim::SelfInstance { mark, id, rules } => Presented::of_instance(
            self_badge(
                hasher,
                instance,
                config,
                ResourceKind::NonFungible,
                mark,
                rules,
                link,
            )?,
            *id,
        ),
        GrantClaim::Config(slot) => configured(config, *slot)?,
    })
}

/// Resolve a declared leaf into the question a movement entry asks about
/// its subject.
///
/// **A resource can be held; an identity can only be presented.** So the
/// subject decides which of the two questions this leaf is: a badge asks
/// a standing fact about the party whose cell moves, and an identity
/// asks whether this transaction was approved. Neither is a second
/// spelling — the address class answers it, the same reading
/// [`Presented::of_address`] gives every declared address.
///
/// Where a subject's holding of a badge lives is the badge's kind's
/// answer: a balance is one point cell keyed by what it holds, and
/// instances are entries of the subject's collection for it. A leaf
/// naming a badge the package issues carries the kind its address folds,
/// so it asks the one shape.
fn resolve_holding(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    claim: &GrantClaim,
    link: usize,
) -> Result<StoredRule, GrantsResolveError> {
    let (badge, holding) = match claim {
        // Nothing holds an identity, so naming one asks the only other
        // question there is: was a claim on it presented. An issuer
        // writing this wants per-transfer approval rather than a
        // standing register, and an approver they can replace names
        // their own component here — a rule naming an identity is frozen
        // for the life of the resource, and one naming a component's is
        // frozen at the component rather than at whoever runs it.
        GrantClaim::SelfAddr => {
            return Ok(StoredRule::claim(
                Presented::of_address(instance)
                    .expect("an instance issuing a resource is a callable address"),
            ));
        }
        GrantClaim::SelfBadge { mark, kind, rules } => (
            self_badge(hasher, instance, config, *kind, mark, rules, link)?,
            match kind {
                ResourceKind::Fungible => Holding::Balance,
                ResourceKind::NonFungible => Holding::AnyInstance,
            },
        ),
        GrantClaim::SelfInstance { mark, id, rules } => (
            self_badge(
                hasher,
                instance,
                config,
                ResourceKind::NonFungible,
                mark,
                rules,
                link,
            )?,
            Holding::Instance(*id),
        ),
        GrantClaim::Config(slot) => {
            let named = configured(config, *slot)?;
            let Some(badge) = named.badge() else {
                // A configured identity, on [`GrantClaim::SelfAddr`]'s
                // terms: nothing holds it, so what the entry asks is
                // whether this transaction carried a claim on it.
                return Ok(StoredRule::claim(named));
            };
            let Some(id) = named.instance else {
                // A configuration field carries an address and no kind,
                // so the rule asks both shapes. At most one of them can
                // ever be occupied, and the second read is what a leaf
                // pays for not having said which.
                return Ok(StoredRule::CountOf {
                    count: 1,
                    rules: vec![
                        StoredRule::held(badge, Holding::Balance),
                        StoredRule::held(badge, Holding::AnyInstance),
                    ],
                });
            };
            (badge, Holding::Instance(id))
        }
    };
    Ok(StoredRule::held(badge, holding))
}

/// The claim a configuration field names.
fn configured(config: &[Value], slot: u32) -> Result<Presented, GrantsResolveError> {
    let value = config
        .get(slot as usize)
        .ok_or(GrantsResolveError::NoSuchField(slot))?;
    Presented::of(value).ok_or(GrantsResolveError::NotAClaim(slot))
}

/// A badge the issuing instance also issues, at the address its own
/// granted rules derive.
///
/// A badge named inside a granted rule derives through its own rules,
/// because an address is the hash of them — the granting-nothing form
/// would name an address nothing is minted at the moment the badge
/// grants anything, which a soulbound credential always does. The chain
/// is one link long, so what a badge's rules name is a claim needing no
/// address of its own.
fn self_badge(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    kind: ResourceKind,
    mark: &[u8],
    rules: &GrantsExpr,
    link: usize,
) -> Result<ResourceAddr, GrantsResolveError> {
    if link > 0 {
        return Err(GrantsResolveError::BadgeChainTooDeep);
    }
    let rules = rules.resolve_link(hasher, instance, config, link + 1)?;
    Ok(granting_issued_resource(
        hasher, instance, kind, &rules, mark,
    ))
}

/// A presented resource record: the address preimage, carried in the
/// envelope and verified by re-derivation.
///
/// The same standing an instance's record has — a presented claim
/// rather than trusted state. The address is the hash of exactly these
/// four, so a holder checks a resource's granted rules by recomputing
/// the derivation, with no cell read anywhere in the path; a false
/// record derives a different address, and the resource it lied about
/// stays exactly what it was.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct ResourceMeta {
    /// The instance whose namespace the address sits in.
    ///
    /// Provenance, not authority: who may mint is the `Mint` entry's
    /// answer, and this is only what keeps two issuers' identically
    /// configured resources from colliding.
    pub namespace: Address,
    /// The kind the derivation folds.
    pub kind: ResourceKind,
    /// The material separating the namespace's resources, as the
    /// canonical byte parts the derivation hashes.
    #[hbor(max = MAX_RESOURCE_MATERIAL_PARTS)]
    pub material: Vec<Vec<u8>>,
    /// The granted rules whose commitment the address folds.
    pub rules: ResourceGrants,
}

/// The material parts one resource derivation may fold — a wire bound
/// on a presented record's list, matching the one part a mark occupies
/// with room for compound material.
pub const MAX_RESOURCE_MATERIAL_PARTS: usize = 4;

impl ResourceMeta {
    /// The address these four derive.
    #[must_use]
    pub fn address(&self, hasher: &dyn Hasher) -> ResourceAddr {
        granting_resource_address(
            hasher,
            self.namespace,
            self.kind,
            &self.rules,
            &self.material,
        )
    }
}

/// The protocol's fee and transfer resource: the unmarked issue of the
/// genesis publisher.
///
/// A resource like any other, and it grants nothing: with no `Mint`
/// entry its supply is fixed at creation and no authority anywhere can
/// raise it, and with no movement entry it costs nothing on the transfer
/// path and carries the plain class. Supply moves only where the protocol
/// writes state directly.
///
/// The one unmarked resource in the system, because a package's issues
/// are all declared and a declaration carries a name. Nothing rests on
/// that beyond legibility: the empty grant table is what makes this
/// unmintable.
#[must_use]
pub fn xrd(hasher: &dyn Hasher) -> ResourceAddr {
    resource_address(
        hasher,
        genesis_publisher(hasher),
        ResourceKind::Fungible,
        &[],
    )
}

/// The record cell for `resource` under `issuer`: the canonical child at
/// the `RESOURCE` slot, keyed by the resource's own address.
///
/// Computable by anyone who knows the issuer — which the resource's
/// derivation names — so reaching a record is level-one access like
/// reaching a vault, never a search.
#[must_use]
pub fn resource_record_key(
    hasher: &dyn Hasher,
    issuer: impl Into<Address>,
    resource: impl Into<Address>,
) -> SubstateKey {
    child_key(
        hasher,
        issuer,
        RESOURCE,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The holdings sub-collection for `resource` under `holder`: the
/// `(NF_VAULT, resource)` fold whose entries, at the instance's id as
/// the order key, are the instances the holder has.
///
/// The declaring side spells the same fold as an entry target with the
/// resource as its collection material; this is that identity for
/// everything that consults holdings directly — a possession
/// condition's read, the linearity oracle's scan.
#[must_use]
pub fn holdings_collection(
    hasher: &dyn Hasher,
    holder: impl Into<Address>,
    resource: impl Into<Address>,
) -> CollectionId {
    collection_id(
        hasher,
        holder.into(),
        NF_VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

/// The declaring side's spelling of that same fold: the whole
/// `(NF_VAULT, resource)` interval under the declaring instance, at most
/// `cap` entries of it.
///
/// Every holdings declaration is this one shape — deposit and withdraw
/// range over it — so a declaration that spells the fold any other way
/// is refused rather than silently unmatched. The cap is ordinarily the
/// count of the ids the call itself names — `Len` over the argument or
/// the edge's id projection — so a move declares exactly the walk it
/// performs, and a full edge always fits the interval filing it by
/// construction.
#[must_use]
pub fn holdings_range(resource: Expr, cap: Expr) -> TargetExpr {
    TargetExpr::Range {
        owner: Expr::SelfAddr,
        collection: SlotRef::Fixed(NF_VAULT),
        material: vec![resource],
        lo: Expr::Literal(Value::U128(0)),
        hi: Expr::Literal(Value::U128(u128::MAX)),
        cap,
    }
}

/// One entry of that same interval: the instance of `resource` this
/// holder keeps at `id`.
///
/// Minting an instance claim takes a `Holds { Present }` condition over
/// exactly this target, keyed by the same badge and id expressions the
/// mint names — which is what makes the instance verified and the
/// instance minted one thing. An entry is also the cheaper access: one
/// leaf rather than a scan the whole id space is declared over.
#[must_use]
pub fn holdings_entry(resource: Expr, id: Expr) -> TargetExpr {
    TargetExpr::Entry {
        owner: Expr::SelfAddr,
        collection: SlotRef::Fixed(NF_VAULT),
        material: vec![resource],
        order: id,
    }
}

/// The data cell for one instance of `resource` under `issuer`, keyed by
/// the resource and the instance's id.
///
/// Under the issuer rather than the holder, so the cell never moves — a
/// transfer renames a holdings entry and touches no data.
///
/// A mint declares this leaf absent, so creating an instance and
/// overwriting one are different declarations and the shard holding the
/// leaf tells them apart before any body runs. What that buys is the
/// collision case: a fresh id is derived from the envelope and the
/// creating node's position, so two mints agreeing on one is not
/// something either sender can arrange, and the requirement is what
/// makes the unlucky one a refusal rather than a silent rewrite of an
/// instance somebody already holds.
#[must_use]
pub fn instance_data_key(
    hasher: &dyn Hasher,
    issuer: impl Into<Address>,
    resource: impl Into<Address>,
    id: u64,
) -> SubstateKey {
    child_key(
        hasher,
        issuer,
        INSTANCE,
        &[
            Value::Address(resource.into()).canonical_bytes(),
            Value::U64(id).canonical_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::assert_canonical;
    use hyperscale_vm_types::{Address, AddressClass, ResourceAddr};

    use super::{
        GrantedBehaviour, ResourceKind, ResourceRecord, always, genesis_publisher,
        holdings_collection, instance_data_key, never, resource_record_key,
    };
    use crate::hash::TestHasher;
    use crate::presented::Presented;
    use crate::rule::{Holding, StoredRule};

    #[test]
    fn records_round_trip_canonically() {
        for record in [
            ResourceRecord::Fungible { display_digits: 18 },
            ResourceRecord::NonFungible,
        ] {
            assert_canonical(&record);
            let bytes = record.to_cell().unwrap();
            assert_eq!(ResourceRecord::from_cell(&bytes).unwrap(), record);
            // The kind a client reads off the record is the kind its
            // address was derived through.
            assert_eq!(
                record.kind(),
                match record {
                    ResourceRecord::Fungible { .. } => ResourceKind::Fungible,
                    ResourceRecord::NonFungible => ResourceKind::NonFungible,
                }
            );
        }
    }

    #[test]
    fn record_keys_separate_by_issuer_and_resource() {
        let publisher = genesis_publisher(&TestHasher);
        let xrd = super::xrd(&TestHasher);
        let other_issuer = Address::new([7; 31], AddressClass::Component);
        let other_resource = Address::new([8; 31], AddressClass::Resource);

        let key = resource_record_key(&TestHasher, publisher, xrd);
        assert_eq!(key.owner, publisher.address(), "records live at the issuer");
        assert_ne!(
            key,
            resource_record_key(&TestHasher, other_issuer, xrd),
            "another issuer is another cell"
        );
        assert_ne!(
            key,
            resource_record_key(&TestHasher, publisher, other_resource),
            "another resource is another cell"
        );
    }

    #[test]
    fn holdings_collections_separate_by_holder_and_resource() {
        let holder = Address::new([1; 31], AddressClass::Component);
        let other_holder = Address::new([2; 31], AddressClass::Component);
        let resource = Address::new([3; 31], AddressClass::Resource);
        let other_resource = Address::new([4; 31], AddressClass::Resource);

        let collection = holdings_collection(&TestHasher, holder, resource);
        assert_eq!(
            collection,
            holdings_collection(&TestHasher, holder, resource),
            "the fold is a pure derivation"
        );
        assert_ne!(
            collection,
            holdings_collection(&TestHasher, other_holder, resource),
            "another holder holds elsewhere"
        );
        assert_ne!(
            collection,
            holdings_collection(&TestHasher, holder, other_resource),
            "another resource is another sub-collection"
        );
    }

    #[test]
    fn instance_data_keys_separate_by_resource_and_id() {
        let issuer = Address::new([1; 31], AddressClass::Component);
        let resource = Address::new([3; 31], AddressClass::Resource);
        let other_resource = Address::new([4; 31], AddressClass::Resource);

        let key = instance_data_key(&TestHasher, issuer, resource, 7);
        assert_eq!(key.owner, issuer, "instance data lives at the issuer");
        assert_ne!(
            key,
            instance_data_key(&TestHasher, issuer, resource, 8),
            "another instance is another cell"
        );
        assert_ne!(
            key,
            instance_data_key(&TestHasher, issuer, other_resource, 7),
            "another resource is another cell"
        );
    }

    /// An actor question reads claims and nothing else; a holder
    /// question reads either, and may read both.
    ///
    /// The asymmetry is not a preference. An authority entry governs a
    /// *frame*, so there is no cell for a holding leaf to resolve
    /// against and one there would name nothing. A movement entry
    /// governs a cell, and the two leaves ask two different questions
    /// about it: a holding is a standing fact about the party whose cell
    /// moves, a claim is whether this transaction was approved. A
    /// resource may want either, or both.
    ///
    /// The constant restating a behaviour's own default is refused
    /// either way, since absence already says it.
    #[test]
    fn a_behaviour_reads_the_side_its_question_is_about() {
        let badge = ResourceAddr::new([0x77; 31]);
        let claims = StoredRule::claim(Presented::of_subject(badge));
        let holds = StoredRule::held(badge, Holding::Balance);
        let both = StoredRule::CountOf {
            count: 2,
            rules: vec![claims.clone(), holds.clone()],
        };

        for behaviour in GrantedBehaviour::ALL {
            let actor = behaviour.asks_about_the_actor();
            assert!(
                behaviour.refuses(&claims).is_none(),
                "{behaviour:?} over a claim",
            );
            assert_eq!(
                behaviour.refuses(&holds).is_none(),
                !actor,
                "{behaviour:?} over a holding",
            );
            assert_eq!(
                behaviour.refuses(&both).is_none(),
                !actor,
                "{behaviour:?} over both",
            );
            // The constant absence already says is refused; the other one
            // is the statement absence cannot make.
            let (restated, statable) = if actor {
                (never(), always())
            } else {
                (always(), never())
            };
            assert!(behaviour.refuses(&restated).is_some());
            assert!(behaviour.refuses(&statable).is_none());
        }
    }
}

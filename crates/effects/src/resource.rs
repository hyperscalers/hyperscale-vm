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
use hyperscale_vm_types::{Address, AddressClass, CollectionId, ResourceAddr, SubstateKey};

use crate::auth::RoleBytes;
use crate::dsl::{Expr, TargetExpr};
use crate::hash::{Hash32, Hasher};
use crate::presented::Presented;
use crate::rule::{GrantClaim, GrantRuleExpr, StoredRule};
use crate::types::{
    Value, child_key, collection_id, granting_resource_address, native_address, resource_address,
};
use crate::vocabulary::GENESIS_PUBLISHER;
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

    /// Whether this behaviour admits `entry` as a spelling.
    ///
    /// Each state has exactly one spelling, so a behaviour refuses the
    /// arm that would be a second way of saying what absence already
    /// says — `Never` for an authority, which absence withholds anyway,
    /// and `Open` for a movement, which absence already permits. A
    /// credential is `Deposit`'s alone.
    #[must_use]
    pub const fn admits(self, entry: &Grant) -> bool {
        match entry {
            // A rule is judged against a caller's evidence, which only an
            // actor question has, and only an actor question can be
            // opened to everyone. A movement's requirement can land on a
            // frame that may not turn a caller away — over-approximating
            // direction puts it on the credit side, where the method is
            // total — so what it asks is a fact about the mover, and the
            // two spellings it has are a credential or nothing at all.
            Grant::Open | Grant::Rule(_) => self.asks_about_the_actor(),
            Grant::Never | Grant::Credential(_) => !self.asks_about_the_actor(),
        }
    }

    /// [`Self::admits`] over the declared form, which has the same arms.
    #[must_use]
    pub const fn admits_expr(self, entry: &GrantExpr) -> bool {
        match entry {
            GrantExpr::Open | GrantExpr::Rule(_) => self.asks_about_the_actor(),
            GrantExpr::Never | GrantExpr::Credential(_) => !self.asks_about_the_actor(),
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

/// What one granted entry says, sealed.
///
/// Three answers rather than a rule and two magic rule values, so no
/// evaluator meets a tree it has to recognise as meaning something other
/// than what it says. Which answers a behaviour admits is
/// [`GrantedBehaviour::admits`]'s, and a spelling it does not admit is a
/// second way of saying what absence already says.
#[derive(Clone, Debug, PartialEq, Eq, Hbor, HborShape)]
pub enum Grant {
    /// Anyone may. Only an authority entry admits it: for a movement,
    /// this is what an absent entry already means.
    Open,
    /// Nobody may, ever. Only a movement entry admits it: for an
    /// authority, absence already withholds.
    Never,
    /// Whoever satisfies these bytes, decoded where the rule is judged
    /// and against the leaf vocabulary the behaviour selects.
    Rule(RoleBytes),
    /// Whoever holds this badge — one presence question, no rule.
    ///
    /// `Deposit` alone, and it carries a bare address rather than a
    /// one-leaf rule because a credit lands on a method that cannot
    /// refuse: only a condition is enforceable there, and a condition is
    /// one leaf. Making that structural is what stops a rule needing
    /// evidence from being written where no evidence can arrive.
    Credential(ResourceAddr),
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
pub struct ResourceGrants(Vec<(GrantedBehaviour, Grant)>);

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
    pub fn get(&self, behaviour: GrantedBehaviour) -> Option<&Grant> {
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
    pub fn set(&mut self, behaviour: GrantedBehaviour, entry: Grant) {
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

/// One granted entry as a package writes it down.
///
/// [`Grant`]'s arms over declared forms: the rule holds a tree whose
/// leaves name derivations rather than resolved claims, and the
/// credential names a badge the same way.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum GrantExpr {
    /// Anyone may.
    Open,
    /// Nobody may, ever.
    Never,
    /// Whoever satisfies this rule.
    Rule(GrantRuleExpr),
    /// Whoever holds the badge this claim names.
    Credential(GrantClaim),
}

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
pub struct GrantsExpr(Vec<(GrantedBehaviour, GrantExpr)>);

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
    pub fn set(&mut self, behaviour: GrantedBehaviour, rule: GrantExpr) {
        match self.0.binary_search_by_key(&behaviour, |(b, _)| *b) {
            Ok(index) => self.0[index].1 = rule,
            Err(index) => self.0.insert(index, (behaviour, rule)),
        }
    }

    /// Every behaviour granted here, with the rule declared for it.
    pub fn iter(&self) -> impl Iterator<Item = (GrantedBehaviour, &GrantExpr)> {
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
        let mut resolved = ResourceGrants::new();
        for (behaviour, entry) in self.iter() {
            let sealed = match entry {
                GrantExpr::Open => Grant::Open,
                GrantExpr::Never => Grant::Never,
                GrantExpr::Rule(rule) => {
                    let stored = resolve_rule(hasher, instance, config, rule)?;
                    Grant::Rule(
                        RoleBytes::try_from(&stored)
                            .map_err(|_| GrantsResolveError::PastTheCaps)?,
                    )
                }
                GrantExpr::Credential(claim) => {
                    let presented = resolve_claim(hasher, instance, config, claim)?;
                    // A credential is one leaf under the mover's own
                    // prefix, and only a fungible holding is one leaf: a
                    // non-fungible one is entries at ids, whose
                    // collection-wide presence is an interval nothing on
                    // the transfer path may walk.
                    let Presented::Resource(badge) = presented else {
                        return Err(GrantsResolveError::NotAFungibleBadge);
                    };
                    Grant::Credential(badge)
                }
            };
            if !behaviour.admits(&sealed) {
                return Err(GrantsResolveError::UnadmittedSpelling(behaviour));
            }
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
    /// A credential naming something that is not a fungible badge.
    #[error("a granted credential names something that is not a fungible badge")]
    NotAFungibleBadge,
    /// A spelling the behaviour does not admit — a second way of saying
    /// what an absent entry already says.
    #[error("{0:?} does not admit the spelling its grant was written with")]
    UnadmittedSpelling(GrantedBehaviour),
}

fn resolve_rule(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    rule: &GrantRuleExpr,
) -> Result<StoredRule, GrantsResolveError> {
    Ok(match rule {
        GrantRuleExpr::Require(claim) => {
            StoredRule::Require(resolve_claim(hasher, instance, config, claim)?)
        }
        GrantRuleExpr::CountOf { count, rules } => StoredRule::CountOf {
            count: *count,
            rules: rules
                .iter()
                .map(|rule| resolve_rule(hasher, instance, config, rule))
                .collect::<Result<_, _>>()?,
        },
    })
}

fn resolve_claim(
    hasher: &dyn Hasher,
    instance: Address,
    config: &[Value],
    claim: &GrantClaim,
) -> Result<Presented, GrantsResolveError> {
    // A badge named inside a granted rule derives through the form that
    // grants nothing, which keeps the derivation well-founded: nothing
    // here can name a resource whose own rules are still being computed.
    let badge = |kind, mark: &[u8]| issued_resource(hasher, instance, kind, mark);
    Ok(match claim {
        GrantClaim::SelfAddr => Presented::of_address(instance)
            .expect("an instance issuing a resource is a callable address"),
        GrantClaim::SelfBadge { mark } => Presented::Resource(badge(ResourceKind::Fungible, mark)),
        GrantClaim::SelfInstance { mark, id } => {
            Presented::Instance(badge(ResourceKind::NonFungible, mark), *id)
        }
        GrantClaim::Config(slot) => {
            let value = config
                .get(*slot as usize)
                .ok_or(GrantsResolveError::NoSuchField(*slot))?;
            Presented::of(value).ok_or(GrantsResolveError::NotAClaim(*slot))?
        }
    })
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
    let publisher = native_address(hasher, GENESIS_PUBLISHER);
    resource_address(hasher, publisher, ResourceKind::Fungible, &[])
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
        collection: NF_VAULT,
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
        collection: NF_VAULT,
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
        Grant, GrantedBehaviour, ResourceKind, ResourceRecord, holdings_collection,
        instance_data_key, resource_record_key,
    };
    use crate::auth::RoleBytes;
    use crate::hash::TestHasher;
    use crate::presented::Presented;
    use crate::rule::StoredRule;
    use crate::types::native_address;
    use crate::vocabulary::GENESIS_PUBLISHER;

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
        let publisher = native_address(&TestHasher, GENESIS_PUBLISHER);
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

    /// Each state has exactly one spelling, and which spellings a
    /// behaviour admits follows from whose property its rule is about.
    ///
    /// An actor question is asked of a caller, so it can hold a rule and
    /// can be opened to everyone. A movement's requirement can land on a
    /// frame that may not turn a caller away — over-approximating
    /// direction puts it on the credit side, and the method that lands
    /// there is total — so it asks a fact about the mover instead, and a
    /// rule is not a spelling it has.
    #[test]
    fn a_behaviour_admits_one_spelling_per_state() {
        let badge = ResourceAddr::new([0x77; 31]);
        let rule = RoleBytes::try_from(&StoredRule::Require(Presented::Resource(badge)))
            .expect("a rule encodes");
        for behaviour in GrantedBehaviour::ALL {
            let actor = behaviour.asks_about_the_actor();
            assert_eq!(behaviour.admits(&Grant::Open), actor, "{behaviour:?} open");
            assert_eq!(
                behaviour.admits(&Grant::Never),
                !actor,
                "{behaviour:?} never"
            );
            assert_eq!(
                behaviour.admits(&Grant::Rule(rule.clone())),
                actor,
                "{behaviour:?} rule"
            );
            assert_eq!(
                behaviour.admits(&Grant::Credential(badge)),
                !actor,
                "{behaviour:?} credential"
            );
        }

        // Which is to say: the two movements take a credential or nothing
        // at all, and every authority takes a rule or everyone.
        assert!(!GrantedBehaviour::Withdraw.admits(&Grant::Rule(rule.clone())));
        assert!(!GrantedBehaviour::Deposit.admits(&Grant::Rule(rule)));
        assert!(GrantedBehaviour::Withdraw.admits(&Grant::Credential(badge)));
        assert!(GrantedBehaviour::Mint.admits(&Grant::Open));
    }
}

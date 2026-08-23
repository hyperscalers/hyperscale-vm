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
use hyperscale_vm_types::{Address, CollectionId, ResourceAddr, SubstateKey};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
pub enum GrantedBehaviour {
    /// Reaching the resource out of a holder's own account, through
    /// that account's own method and no other way.
    #[hbor(discriminant = 0)]
    Recall,
    /// Halting the resource's movement.
    #[hbor(discriminant = 1)]
    Freeze,
    /// Restricting where a deposit lands — a destination, never a
    /// refusal: a deposit the rule declines lands in the claims cell.
    #[hbor(discriminant = 2)]
    Deposit,
}

/// The granted rules a resource's address commits to: rules by
/// behaviour, each as the bytes it was handed.
///
/// The same sorted-list discipline the role table keeps, and the same
/// opacity: a rule's bytes decode where the rule is judged, under the
/// vocabulary's own caps. **An absent entry denies.** Immutability is
/// the derivation rather than a promise — the commitment rides the
/// address, so a rule that changed would be a different resource.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
#[hbor(transparent, validate = ascending_behaviours)]
pub struct ResourceGrants(Vec<(GrantedBehaviour, RoleBytes)>);

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

    /// The rule granted for `behaviour`, where one is.
    #[must_use]
    pub fn rule(&self, behaviour: GrantedBehaviour) -> Option<&RoleBytes> {
        self.0
            .binary_search_by_key(&behaviour, |(b, _)| *b)
            .ok()
            .map(|index| &self.0[index].1)
    }

    /// Grant `bytes` for `behaviour`, replacing what was there.
    pub fn set(&mut self, behaviour: GrantedBehaviour, bytes: RoleBytes) {
        match self.0.binary_search_by_key(&behaviour, |(b, _)| *b) {
            Ok(index) => self.0[index].1 = bytes,
            Err(index) => self.0.insert(index, (behaviour, bytes)),
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

/// The granted rules a declaration commits, before the instance issuing
/// them is known.
///
/// [`ResourceGrants`] as a package writes it down: the same
/// behaviour-keyed list under the same ascending discipline, holding the
/// rule's tree rather than the bytes it encodes to. What separates them
/// is what a leaf names — a declared leaf names a derivation, and
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
        let mut resolved = ResourceGrants::new();
        for (behaviour, rule) in self.iter() {
            let stored = resolve_rule(hasher, instance, config, rule)?;
            let bytes =
                RoleBytes::try_from(&stored).map_err(|_| GrantsResolveError::PastTheCaps)?;
            resolved.set(behaviour, bytes);
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
    /// The instance whose provenance the address commits.
    pub minter: Address,
    /// The kind the derivation folds.
    pub kind: ResourceKind,
    /// The material separating the minter's resources, as the canonical
    /// byte parts the derivation hashes.
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
        granting_resource_address(hasher, self.minter, self.kind, &self.rules, &self.material)
    }
}

/// The protocol's fee and transfer resource: the unmarked issue of the
/// genesis publisher.
///
/// A resource like any other — the minter is the one address no signer
/// reaches, which is exactly the strength the fee resource needs: no
/// transaction can present a method of the publisher, so who may mint it
/// is nobody, by the same arithmetic that answers it for every resource.
/// Supply moves only where the protocol writes state directly.
///
/// The one unmarked resource in the system, because a package's issues
/// are all declared and a declaration carries a name. Nothing rests on
/// that beyond legibility: the minter is what makes this unmintable.
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
    use hyperscale_vm_types::{Address, AddressClass};

    use super::{
        ResourceKind, ResourceRecord, holdings_collection, instance_data_key, resource_record_key,
    };
    use crate::hash::TestHasher;
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
}

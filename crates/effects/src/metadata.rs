//! Package metadata: effect signatures and static call sites, cached by
//! content address.

use std::collections::BTreeMap;

use hyperscale_hbor::{EncodeError, Hbor, to_vec};
use thiserror::Error;

use crate::auth::{AuthRole, RoleSet};
use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::hash::{Hash32, Hasher};
use crate::rule::Rule;
use crate::types::{
    Address, CallTarget, ComponentAddr, RoleId, SubstateKey, Value, child_key, component_address,
    config_hash,
};

/// A published package's identity: the hash of its artifact, which covers
/// the metadata section, so metadata is immutable with the package.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Hbor)]
#[hbor(transparent)]
pub struct PackageHash(pub Hash32);

const DOMAIN_PACKAGE: &[u8] = b"hyperscale-vm/package";

/// The content address of a package artifact — the identity the metadata
/// cache keys on and instances bind to.
#[must_use]
pub fn package_hash(hasher: &dyn Hasher, artifact: &[u8]) -> PackageHash {
    PackageHash(hasher.hash(DOMAIN_PACKAGE, &[artifact]))
}

/// The reserved role a publisher's package cells key under.
///
/// Outside the blueprint-reachable role space — blueprint signatures name
/// vault, claims, config and entropy — so the cell is reachable by the
/// publish path and by nothing else.
pub const PACKAGE_ROLE: RoleId = RoleId(0xFFFE);

/// Where `publisher`'s copy of the package addressed by `package` lives.
///
/// Keyed by content address under the publisher, so republishing the
/// same artifact is the same cell — which is what makes publishing
/// idempotent rather than a conflict.
#[must_use]
pub fn package_key(
    hasher: &dyn Hasher,
    publisher: impl Into<Address>,
    package: PackageHash,
) -> SubstateKey {
    child_key(hasher, publisher, PACKAGE_ROLE, &[package.0.0.to_vec()])
}

/// A static call site: the callee named by an input-derived address, its
/// method, and the callee's arguments as expressions over the caller's
/// inputs.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct CallSite {
    /// The callee instance; must evaluate to an address.
    pub target: Expr,
    /// The callee method.
    pub method: String,
    /// The callee's arguments, bound from the caller's inputs.
    pub args: Vec<Expr>,
}

/// A method parameter's admitted kind. Bucket parameters consume a value
/// edge; every other kind binds a literal or envelope input.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hbor)]
pub enum ParamType {
    /// An unsigned 64-bit integer.
    U64,
    /// An unsigned 128-bit integer.
    U128,
    /// Opaque bytes.
    Bytes,
    /// A global object's address.
    Address,
    /// A value edge; its resource type is static, its amount dynamic.
    Bucket,
    /// An authority rule, carried as its canonical bytes and decoded
    /// under the vocabulary caps at admission — so a rule past either
    /// cap is refused before anything signs.
    Rule,
    /// A full role set — three rules, canonical bytes — decoded under
    /// the same vocabulary caps at admission, for the same reason.
    RoleSet,
}

impl ParamType {
    /// The kind name, for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Bytes => "bytes",
            Self::Address => "address",
            Self::Bucket => "bucket",
            Self::Rule => "rule",
            Self::RoleSet => "role-set",
        }
    }

    /// Whether a literal value has this kind. Buckets are never literals —
    /// they arrive only as edges, and a rule is bytes that decode under
    /// the vocabulary caps.
    #[must_use]
    pub fn admits(self, value: &Value) -> bool {
        match (self, value) {
            (Self::U64, Value::U64(_))
            | (Self::U128, Value::U128(_))
            | (Self::Bytes, Value::Bytes(_))
            | (Self::Address, Value::Address(_)) => true,
            (Self::Rule, Value::Bytes(bytes)) => Rule::from_slice(bytes).is_ok(),
            (Self::RoleSet, Value::Bytes(bytes)) => RoleSet::from_slice(bytes).is_ok(),
            _ => false,
        }
    }
}

/// How one guest ABI parameter is built at invocation.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum AbiParam {
    /// The capability materialized for this method's effect clause.
    ///
    /// Names a clause rather than a position in the materialized table:
    /// a `for-each` clause expands over instance configuration, so table
    /// positions past one would depend on configuration rather than on
    /// the signature. A clause that does not evaluate to exactly one
    /// target cannot be a handle parameter, and naming one is a
    /// deterministic refusal at materialization.
    Handle(u32),
    /// The runtime amount of this declared [`ParamType::Bucket`]
    /// parameter.
    ///
    /// The one value a signature cannot derive: a bucket's resource type
    /// is static but its amount is whatever the producing node actually
    /// returned, which does not exist until that node runs.
    Bucket(u32),
    /// A value evaluated over the method's bound inputs.
    ///
    /// The same evaluation the effect clauses run, against the same
    /// inputs — arguments, instance configuration, and the identity,
    /// node and frame a fresh id derives from — so an argument the guest
    /// reads is bounded and deterministic on exactly the terms a declared
    /// target already is. Everything but a bucket's amount lands here.
    Derived(Expr),
}

/// Whose authority a method's target admits.
///
/// A package declares this beside the code it describes, because an
/// address is a hash and nothing about a target can be read off it: only
/// the package knows whether a method spends the target's funds, writes
/// its leaves, or merely offers something to whoever asks.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub enum Accessibility {
    /// Anyone may name this method on this target. What the caller
    /// supplies is the caller's own, gated wherever it was obtained.
    #[default]
    Public,
    /// Naming this method requires presenting the identity this
    /// expression evaluates to, over the target's own inputs.
    ///
    /// `SelfAddr` is a method only the target itself may be made to
    /// perform; a configuration slot is how an object nobody owns admits
    /// somebody, since a pool's address derives from no key while a
    /// configured field can name an identity that does.
    ///
    /// Every identity a method can require is one the target itself
    /// names, so an authority verdict never reaches state under a prefix
    /// the manifest did not name. Authority held by somebody else is a
    /// call to *them*, which the manifest writes down like any other.
    Guarded(Expr),
    /// Naming this method requires satisfying the target's own rule, and
    /// doing so mints the target's identity as evidence for later nodes
    /// of the same intent.
    ///
    /// The one gate that is the target's rule rather than an identity an
    /// expression names. Minting is a property of this accessibility and
    /// of nothing else, so a caller cannot conjure a target's authority
    /// by pointing evidence at a method that merely does something.
    Authorizing,
    /// Naming this method requires satisfying one of the target's stored
    /// roles — which one is named here — and mints nothing.
    ///
    /// The recovery surface: judged like an authorizing gate, against
    /// the role set that governs at the transaction clock, but a
    /// role-gated node is never a proof, so recovery authority opens
    /// recovery methods and nothing else.
    RoleGated(AuthRole),
}

/// A method's declared access. Its transitive effect set is the fold of its
/// callees' signatures over the static call graph, which is acyclic — a DAG
/// fold, never a fixpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct MethodSignature {
    /// Whose authority naming this method on this target requires.
    pub accessibility: Accessibility,
    /// The method's parameter kinds, in order; admission types every node
    /// against them.
    pub params: Vec<ParamType>,
    /// The static resource type of each value edge the method produces, as
    /// an expression over the method's bound inputs.
    pub outputs: Vec<Expr>,
    /// The method's own effect clauses.
    pub effects: Vec<Clause>,
    /// How the guest's ABI parameters are built, one entry per exported
    /// parameter in the export's own order.
    ///
    /// A declared parameter list has no arity relation to the ABI: the
    /// capability table mediates, so a method declaring one bucket and two
    /// effects can export two arguments of which one is a handle for the
    /// first effect's target and the other the bucket's bytes. Nothing
    /// else in the signature says which, and without saying it a caller
    /// has to know the method — which is why a dispatch table that knows
    /// every method by name is the only thing that can call one.
    ///
    /// Authored beside the signature and content-addressed with the code,
    /// so the binding cannot drift from the ABI it describes.
    pub abi: Vec<AbiParam>,
    /// The method's static call sites.
    pub calls: Vec<CallSite>,
}

/// Why a signature's ABI binding cannot be honoured.
///
/// Every clause is a pure function of the metadata, so the verdict is the
/// same wherever it is reached: at publish, where it refuses the artifact,
/// and at routing, where it refuses a call to a package that reached the
/// cache without one.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// An authorizing method whose declaration is not exactly one point
    /// read — the cell its stored rule lives in, which the gate
    /// evaluates and the read provisions.
    #[error("an authorizing method declares exactly one point read: its rule cell")]
    AuthorizingShape,
    /// A role-gated method whose declaration is not exactly one point
    /// write — the cell its stored roles live in. The write is where
    /// the gate's cell comes from, and it serializes role rewrites
    /// against concurrent sign-ins.
    #[error("a role-gated method declares exactly one point write: its rule cell")]
    RoleGatedShape,
    /// A handle binding naming an effect clause the signature does not
    /// declare.
    #[error("ABI parameter {position} names effect clause {clause}, past the {declared} declared")]
    NoSuchClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
        /// How many clauses the signature declares.
        declared: u32,
    },
    /// A bucket binding naming a parameter the signature does not declare.
    #[error("ABI parameter {position} names parameter {param}, past the {declared} declared")]
    NoSuchParam {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// How many parameters the signature declares.
        declared: u32,
    },
    /// A bucket binding naming a parameter that is not a bucket.
    ///
    /// A bucket's amount is the one value a signature cannot derive,
    /// which is the whole reason the variant exists; naming any other
    /// parameter through it asks for bytes that are already static.
    #[error("ABI parameter {position} takes the amount of parameter {param}, which is {kind}")]
    NotABucket {
        /// The ABI parameter position.
        position: u32,
        /// The parameter it names.
        param: u32,
        /// What that parameter actually is.
        kind: &'static str,
    },
    /// An authority expression reading what the caller supplies.
    ///
    /// A caller who names the identity they must present can always
    /// present it, so the method reads as guarded and admits everyone.
    #[error("the authority this method requires is one its caller names")]
    CallerNamedAuthority,
    /// One bucket parameter carried by more than one ABI parameter.
    ///
    /// A bucket carried by *none* is well-formed: a method that forwards
    /// its funds to a callee never reads the amount itself, so nothing in
    /// its own ABI carries it. Carrying it twice has no such reading —
    /// the guest would receive one edge's bytes under two names.
    #[error("parameter {param} is a bucket carried by {carried} ABI parameters")]
    BucketCarriedTwice {
        /// The declared parameter.
        param: u32,
        /// How many ABI parameters name it.
        carried: u32,
    },
}

/// Judge a signature's ABI binding against the declaration it is a
/// binding for.
///
/// A binding says where each of the guest's arguments comes from, and a
/// caller that cannot resolve one cannot invoke the method at all — so an
/// unresolvable binding is a package that publishes and then traps for
/// everyone.
///
/// What this cannot judge is the binding against the component's real
/// ABI: that needs the artifact, and it belongs with whoever holds one.
///
/// # Errors
///
/// Any [`AbiError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_abi(signature: &MethodSignature) -> Result<(), AbiError> {
    if let Accessibility::Guarded(identity) = &signature.accessibility
        && identity.reads_call_inputs()
    {
        return Err(AbiError::CallerNamedAuthority);
    }
    // An authorizing method's whole declaration is the cell its stored
    // rule lives in: one point read, which is what the gate evaluates at
    // admission and what provisions the cell to every participant.
    if matches!(signature.accessibility, Accessibility::Authorizing)
        && !matches!(
            signature.effects.as_slice(),
            [Clause::Effect {
                target: TargetExpr::Point(_),
                mode: ModeExpr::Read,
            }]
        )
    {
        return Err(AbiError::AuthorizingShape);
    }
    // A role-gated method's whole declaration is the same cell as an
    // exclusive write: the gate reads it, the body rewrites it, and the
    // exclusivity keeps a role rewrite out of any wave that signs in
    // under the roles it replaces.
    if matches!(signature.accessibility, Accessibility::RoleGated(_))
        && !matches!(
            signature.effects.as_slice(),
            [Clause::Effect {
                target: TargetExpr::Point(_),
                mode: ModeExpr::Write,
            }]
        )
    {
        return Err(AbiError::RoleGatedShape);
    }
    let bound = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
    let mut carried = vec![0u32; signature.params.len()];
    for (index, binding) in signature.abi.iter().enumerate() {
        let position = bound(index);
        match binding {
            AbiParam::Handle(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                if declared.is_none() {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                }
            }
            AbiParam::Bucket(param) => {
                let slot = usize::try_from(*param).map_err(|_| AbiError::NoSuchParam {
                    position,
                    param: *param,
                    declared: bound(signature.params.len()),
                })?;
                match signature.params.get(slot) {
                    Some(ParamType::Bucket) => carried[slot] += 1,
                    Some(other) => {
                        return Err(AbiError::NotABucket {
                            position,
                            param: *param,
                            kind: other.name(),
                        });
                    }
                    None => {
                        return Err(AbiError::NoSuchParam {
                            position,
                            param: *param,
                            declared: bound(signature.params.len()),
                        });
                    }
                }
            }
            // A derived binding is an expression over the same inputs the
            // effect clauses read, so its argument and configuration
            // references are bounded by the same evaluation every node
            // runs at routing. Repeating that walk here would be a second
            // opinion on it.
            AbiParam::Derived(_) => {}
        }
    }
    for (param, count) in carried.iter().enumerate() {
        if *count > 1 {
            return Err(AbiError::BucketCarriedTwice {
                param: bound(param),
                carried: *count,
            });
        }
    }
    Ok(())
}

/// Why a signature's declared effects are not its to declare.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    /// A clause targeting a prefix the declaring instance does not own.
    #[error("effect clause {clause} targets a prefix the instance does not own")]
    ForeignPrefix {
        /// The clause's position in a preorder walk of the signature's
        /// effects, `for-each` bodies counted in place.
        clause: u32,
    },
}

/// Whether a target names the declaring instance's own prefix.
///
/// The owner half of a key is either written as `SelfAddr` or derived
/// under it: a fresh key is minted under the instance that creates it, and
/// a child key names its owner outright. Everything else — an argument, a
/// configuration slot, a `for-each` binding, a literal — is another
/// object's prefix, whatever the author meant by it.
fn targets_own_prefix(target: &TargetExpr) -> bool {
    match target {
        TargetExpr::Point(key) => match key {
            Expr::ChildKey { owner, .. } => matches!(**owner, Expr::SelfAddr),
            Expr::FreshKey { .. } => true,
            _ => false,
        },
        TargetExpr::Entry { owner, .. } | TargetExpr::Range { owner, .. } => {
            matches!(owner, Expr::SelfAddr)
        }
    }
}

/// Judge a signature's declared effects against the prefix they are the
/// signature's to declare.
///
/// A declaration bounds what execution may touch, and this bounds what a
/// declaration may claim: an object's cells are reachable by calling it,
/// never by naming them. Refused here so an author hears about it, and
/// again on the evaluated effect at routing, where no expression shape can
/// be overlooked.
///
/// # Errors
///
/// [`DeclarationError`]; verdicts are deterministic and identical on every
/// node.
pub fn check_declarations(signature: &MethodSignature) -> Result<(), DeclarationError> {
    fn walk(clauses: &[Clause], next: &mut u32) -> Result<(), DeclarationError> {
        for clause in clauses {
            let clause_index = *next;
            *next = next.saturating_add(1);
            match clause {
                Clause::Effect { target, .. } => {
                    if !targets_own_prefix(target) {
                        return Err(DeclarationError::ForeignPrefix {
                            clause: clause_index,
                        });
                    }
                }
                Clause::ForEach { body, .. } => walk(body, next)?,
            }
        }
        Ok(())
    }
    walk(&signature.effects, &mut 0)
}

/// Everything routing reads about a published package.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct PackageMetadata {
    /// Effect signatures by method name.
    pub methods: BTreeMap<String, MethodSignature>,
    /// The package's event names, in the index order a receipt event's
    /// type refers to.
    ///
    /// Nothing on the execution path reads this: an event carries the
    /// index, and the kernel bounds it without resolving it. The table is
    /// what lets a consumer name what it read, and it can only mean one
    /// thing because a package is content-addressed and immutable.
    pub events: Vec<String>,
}

/// The content-addressed metadata cache. An entry never invalidates —
/// equal hash means equal artifact — so publishing is idempotent and
/// first-write-wins.
#[derive(Clone, Debug, Default)]
pub struct MetadataCache {
    packages: BTreeMap<PackageHash, PackageMetadata>,
}

impl MetadataCache {
    /// An empty cache.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            packages: BTreeMap::new(),
        }
    }

    /// Add a package's metadata under its content address.
    pub fn publish(&mut self, hash: PackageHash, metadata: PackageMetadata) {
        self.packages.entry(hash).or_insert(metadata);
    }

    /// Look up a package's metadata.
    #[must_use]
    pub fn get(&self, hash: PackageHash) -> Option<&PackageMetadata> {
        self.packages.get(&hash)
    }
}

/// An instance's creation-fixed record: the package it runs, the
/// configuration it was created under, and the salt separating it from
/// every other instance of the same two.
///
/// A presented claim rather than trusted state. A component's address is
/// the hash of exactly these three, so a holder checks the record by
/// recomputing the address rather than by consulting a registry — which
/// is what lets any shard verify any target with no foreign reads, and
/// what makes a false package claim a hash collision rather than a
/// lookup that disagrees.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct InstanceMeta {
    /// The package the instance runs.
    pub package: PackageHash,
    /// The instance's creation-fixed configuration fields.
    #[hbor(max = MAX_CONFIG_FIELDS)]
    pub config: Vec<Value>,
    /// The creating transaction's fresh id, which separates two
    /// instances made from one package under one configuration.
    pub salt: Hash32,
}

/// The bound on an instance's configuration fields.
///
/// A signature indexes them positionally with a `u32`, and the whole list
/// is hashed into the instance's address, so the cap is what keeps a
/// presented certificate's decode bounded by its own declaration.
pub const MAX_CONFIG_FIELDS: usize = 64;

impl InstanceMeta {
    /// The configuration leaf's stored bytes — the canonical encoding
    /// creation locks into the `CONFIG` cell.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] if the configuration is past the vocabulary's own
    /// caps, which no admitted creation can have produced.
    pub fn config_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        to_vec(&self.config)
    }

    /// The address this record derives.
    ///
    /// The creation side of the same equality [`Self::derives`] checks:
    /// an instance's address is a function of what it is, so whoever
    /// creates one computes the address rather than choosing it. The class
    /// is not a claim about the result either — a record derives a
    /// component and nothing else, so the derivation answers with one.
    ///
    /// # Panics
    ///
    /// If the configuration is past the vocabulary's own caps, which no
    /// admitted creation can have produced.
    #[must_use]
    pub fn address(&self, hasher: &dyn Hasher) -> ComponentAddr {
        let bytes = self
            .config_bytes()
            .expect("an admitted configuration encodes");
        component_address(hasher, self.package, config_hash(hasher, &bytes), self.salt)
    }

    /// Whether this record derives `address`.
    ///
    /// The whole of certificate admission: the address commits the
    /// package, the configuration leaf's bytes and the salt, so equality
    /// here is the verification and there is nothing else to consult. The
    /// question is total over every class — an address of any other one is
    /// an address no record derives.
    #[must_use]
    pub fn derives(&self, hasher: &dyn Hasher, address: impl Into<Address>) -> bool {
        let Ok(bytes) = self.config_bytes() else {
            return false;
        };
        component_address(hasher, self.package, config_hash(hasher, &bytes), self.salt)
            == address.into()
    }
}

/// A presented certificate that does not derive the address it claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("the presented record does not derive the address it claims")]
pub struct CertificateMismatch;

/// Addresses to the creation-fixed record each one derives.
///
/// A verified cache, not an authority: every entry was checked against
/// the address that keys it, so a lookup here answers the same question
/// recomputing the derivation would, at the cost of a map probe instead
/// of a hash.
///
/// Principals are not entries. A principal address commits auth material
/// rather than code, and the code serving every principal is
/// protocol-defined — so one record answers for all of them, and an
/// account needs nothing registered before it can be called.
#[derive(Clone, Debug, Default)]
pub struct InstanceRegistry {
    principal: Option<InstanceMeta>,
    instances: BTreeMap<Address, InstanceMeta>,
}

impl InstanceRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            principal: None,
            instances: BTreeMap::new(),
        }
    }

    /// Bind the package that serves every principal address.
    ///
    /// The protocol's own account blueprint, resolved by class rather
    /// than by certificate: a principal's address derives from a key, so
    /// there is no package hash in it to check a claim against.
    pub fn serve_principals(&mut self, package: PackageHash) {
        self.principal = Some(InstanceMeta {
            package,
            config: Vec::new(),
            salt: Hash32([0; 32]),
        });
    }

    /// Admit a presented record for `address`, verifying that it derives
    /// it.
    ///
    /// # Errors
    ///
    /// [`CertificateMismatch`] when the record derives some other
    /// address — the refusal that replaces a lookup coming back empty.
    pub fn admit(
        &mut self,
        hasher: &dyn Hasher,
        address: impl Into<Address>,
        meta: InstanceMeta,
    ) -> Result<(), CertificateMismatch> {
        let address = address.into();
        if !meta.derives(hasher, address) {
            return Err(CertificateMismatch);
        }
        self.instances.entry(address).or_insert(meta);
        Ok(())
    }

    /// Admit a record at the address it derives, and answer that address.
    ///
    /// What creation does: an instance's address is a function of its
    /// package, its configuration and its salt, so the creator computes
    /// it rather than choosing one and recording the association.
    ///
    /// # Panics
    ///
    /// If the configuration is past the vocabulary's own caps.
    pub fn create(&mut self, hasher: &dyn Hasher, meta: InstanceMeta) -> ComponentAddr {
        let address = meta.address(hasher);
        self.instances.entry(address.address()).or_insert(meta);
        address
    }

    /// Look up the creation-fixed record serving a call target.
    ///
    /// Both classes a target can carry are answered here and nothing else
    /// arrives: a principal resolves to the protocol's account blueprint
    /// by its class alone, an instance to the record its address derives.
    #[must_use]
    pub fn get(&self, target: impl Into<CallTarget>) -> Option<&InstanceMeta> {
        match target.into() {
            CallTarget::Principal(_) => self.principal.as_ref(),
            CallTarget::Component(address) => self.instances.get(&address.address()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::TestHasher;
    use crate::types::PrincipalAddr;

    #[test]
    fn a_record_is_admitted_only_at_the_address_it_derives() {
        let meta = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![Value::U64(7)],
            salt: Hash32([2; 32]),
        };
        let address = meta.address(&TestHasher);
        assert!(meta.derives(&TestHasher, address));

        let mut registry = InstanceRegistry::new();
        assert_eq!(registry.admit(&TestHasher, address, meta.clone()), Ok(()));
        assert_eq!(registry.get(address), Some(&meta));

        // Any other address is a claim the derivation refuses.
        let elsewhere = ComponentAddr::new([9; 31]);
        assert_eq!(
            registry.admit(&TestHasher, elsewhere, meta),
            Err(CertificateMismatch)
        );
        assert_eq!(registry.get(elsewhere), None);
    }

    #[test]
    fn a_false_package_claim_is_refused_by_verification() {
        let honest = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![],
            salt: Hash32([2; 32]),
        };
        let address = honest.address(&TestHasher);
        // The same instance, claimed to run somebody else's code. There
        // is no lookup to disagree with: the address commits the package,
        // so the claim would need a hash collision to stand.
        let forged = InstanceMeta {
            package: PackageHash(Hash32([0xFF; 32])),
            ..honest.clone()
        };
        assert!(!forged.derives(&TestHasher, address));
        let mut registry = InstanceRegistry::new();
        assert_eq!(
            registry.admit(&TestHasher, address, forged),
            Err(CertificateMismatch)
        );

        // And the configuration is committed on the same terms.
        let reconfigured = InstanceMeta {
            config: vec![Value::U64(1)],
            ..honest
        };
        assert!(!reconfigured.derives(&TestHasher, address));
    }

    #[test]
    fn every_principal_resolves_without_an_entry() {
        let package = PackageHash(Hash32([3; 32]));
        let mut registry = InstanceRegistry::new();
        assert_eq!(
            registry.get(PrincipalAddr::new([1; 31])),
            None,
            "until the protocol's blueprint is bound"
        );
        registry.serve_principals(package);
        // One record answers for every principal: an account's identity
        // is in its address, so there is nothing per-account to hold.
        for seed in [1u8, 2, 0xFF] {
            let principal = PrincipalAddr::new([seed; 31]);
            assert_eq!(registry.get(principal).map(|m| m.package), Some(package));
        }
        // A component still needs its record.
        assert_eq!(registry.get(ComponentAddr::new([1; 31])), None);
    }

    #[test]
    fn the_config_leaf_bytes_are_what_the_address_commits() {
        let meta = InstanceMeta {
            package: PackageHash(Hash32([1; 32])),
            config: vec![Value::U64(7), Value::U128(9)],
            salt: Hash32([2; 32]),
        };
        // Certificate and state agree by literal byte equality: the
        // preimage is the encoding creation locks into the leaf.
        let bytes = meta.config_bytes().expect("the config encodes");
        assert_eq!(bytes, to_vec(&meta.config).unwrap());
        assert_eq!(
            meta.address(&TestHasher),
            component_address(
                &TestHasher,
                meta.package,
                config_hash(&TestHasher, &bytes),
                meta.salt,
            )
        );
    }
    use super::{
        AbiError, AbiParam, Accessibility, DeclarationError, MetadataCache, MethodSignature,
        PackageHash, PackageMetadata, ParamType, check_abi, check_declarations,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::hash::Hash32;
    use crate::stdlib::{
        account_metadata, amm_metadata, book_metadata, splitter_metadata, staking_metadata,
    };
    use crate::types::AddressClass;

    /// Every stdlib package, in the order the exhaustive tests read them.
    fn stdlib() -> Vec<(&'static str, PackageMetadata)> {
        vec![
            ("account", account_metadata()),
            ("amm", amm_metadata()),
            ("book", book_metadata()),
            ("splitter", splitter_metadata()),
            ("staking", staking_metadata()),
        ]
    }

    fn clause() -> Clause {
        Clause::Effect {
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Delta,
        }
    }

    fn signature(params: Vec<ParamType>, abi: Vec<AbiParam>) -> MethodSignature {
        MethodSignature {
            params,
            abi,
            effects: vec![clause()],
            ..MethodSignature::default()
        }
    }

    #[test]
    fn publish_is_first_write_wins() {
        let hash = PackageHash(Hash32([1; 32]));
        let mut cache = MetadataCache::new();
        let mut first = PackageMetadata::default();
        first.methods.insert("m".into(), MethodSignature::default());
        cache.publish(hash, first.clone());
        cache.publish(hash, PackageMetadata::default());
        assert_eq!(cache.get(hash), Some(&first));
    }

    #[test]
    fn a_binding_resolves_against_its_own_signature() {
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        assert!(matches!(
            check_abi(&signature(vec![], vec![AbiParam::Handle(1)])),
            Err(AbiError::NoSuchClause { clause: 1, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![ParamType::U64], vec![AbiParam::Bucket(0)])),
            Err(AbiError::NotABucket { param: 0, .. })
        ));
        assert!(matches!(
            check_abi(&signature(vec![], vec![AbiParam::Bucket(3)])),
            Err(AbiError::NoSuchParam { param: 3, .. })
        ));
    }

    /// A method requiring an identity its own caller names admits
    /// everyone while reading as guarded, so the declaration is refused
    /// where the package publishes.
    #[test]
    fn an_authority_the_caller_names_is_refused() {
        let guarded = |identity: Expr| MethodSignature {
            accessibility: Accessibility::Guarded(identity),
            ..MethodSignature::default()
        };
        assert_eq!(check_abi(&guarded(Expr::SelfAddr)), Ok(()));
        assert_eq!(check_abi(&guarded(Expr::Config(0))), Ok(()));
        assert_eq!(
            check_abi(&guarded(Expr::Arg(0))),
            Err(AbiError::CallerNamedAuthority)
        );
        // And however deeply the argument is buried.
        assert_eq!(
            check_abi(&guarded(Expr::ResourceOf(Box::new(Expr::Field(
                Box::new(Expr::Arg(1)),
                0
            ))))),
            Err(AbiError::CallerNamedAuthority)
        );
    }

    #[test]
    fn a_bucket_is_carried_at_most_once() {
        // A guest receiving one edge's bytes under two names.
        assert!(matches!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Bucket(0), AbiParam::Bucket(0)],
            )),
            Err(AbiError::BucketCarriedTwice {
                param: 0,
                carried: 2
            })
        ));
        // Two buckets, each carried once, in either order.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket, ParamType::U128, ParamType::Bucket],
                vec![AbiParam::Bucket(2), AbiParam::Bucket(0)],
            )),
            Ok(())
        );
        // A bucket the declaring method forwards to a callee: its own
        // guest never reads the amount, so its own ABI carries nothing.
        // The edge's signed bound is still checked where the edge
        // resolves, which is a property of the node and not of the ABI.
        assert_eq!(
            check_abi(&signature(
                vec![ParamType::Bucket],
                vec![AbiParam::Handle(0)]
            )),
            Ok(())
        );
    }

    /// Exhaustive over the stdlib: whatever a package may declare, an
    /// authored one declares only its own.
    #[test]
    fn every_authored_signature_declares_its_own_prefix() {
        for (package, metadata) in stdlib() {
            for (name, signature) in &metadata.methods {
                assert_eq!(check_declarations(signature), Ok(()), "{package}::{name}");
            }
        }
    }

    /// Every way a signature can write somebody else's prefix, refused
    /// where its author can see it.
    #[test]
    fn a_signature_reaching_another_prefix_is_refused() {
        let declaring = |target: TargetExpr| MethodSignature {
            effects: vec![Clause::Effect {
                target,
                mode: ModeExpr::Delta,
            }],
            ..MethodSignature::default()
        };
        let child_of = |owner: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(owner),
                role: RoleId(1),
                material: vec![],
            })
        };

        // Its own prefix, however the key under it is derived.
        assert_eq!(
            check_declarations(&declaring(child_of(Expr::SelfAddr))),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(TargetExpr::Point(Expr::FreshKey { slot: 0 }))),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(TargetExpr::Entry {
                owner: Expr::SelfAddr,
                collection: RoleId(2),
                order: Expr::Literal(Value::U128(0)),
            })),
            Ok(())
        );

        // An argument, a configuration slot, and a literal: three ways of
        // naming an object that never agreed to be named.
        for owner in [
            Expr::Arg(0),
            Expr::Config(0),
            Expr::Literal(Value::Address(Address::new(
                [9; 31],
                AddressClass::Component,
            ))),
        ] {
            assert_eq!(
                check_declarations(&declaring(child_of(owner))),
                Err(DeclarationError::ForeignPrefix { clause: 0 })
            );
        }

        // And inside a `for-each` body, where the element is the owner.
        let looped = MethodSignature {
            effects: vec![Clause::ForEach {
                list: Expr::Arg(0),
                body: vec![Clause::Effect {
                    target: child_of(Expr::Binding(0)),
                    mode: ModeExpr::Delta,
                }],
            }],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&looped),
            Err(DeclarationError::ForeignPrefix { clause: 1 })
        );
    }

    #[test]
    fn every_authored_signature_is_well_formed() {
        // The stdlib is the corpus's whole surface, so a rule it breaks
        // is a rule nothing else could be held to.
        for (package, metadata) in stdlib() {
            for (name, signature) in &metadata.methods {
                assert_eq!(check_abi(signature), Ok(()), "{package}::{name}");
            }
        }
    }

    #[test]
    fn every_stdlib_method_declares_who_may_call_it() {
        // Exhaustive on purpose. `Public` is the default, so a method
        // added without a thought about its callers gets the permissive
        // value silently — and the shape that is easiest to miss moves no
        // funds at all: `stamp-entropy` writes a leaf under its target's
        // prefix and consumes nothing, which is the same class as any
        // later per-account module. Adding a method breaks this list,
        // which is the point.
        let expected = [
            ("account", "authorize", Accessibility::Authorizing),
            (
                "account",
                "cancel",
                Accessibility::RoleGated(AuthRole::Primary),
            ),
            (
                "account",
                "confirm",
                Accessibility::RoleGated(AuthRole::Confirmation),
            ),
            ("account", "deposit", Accessibility::Public),
            (
                "account",
                "propose",
                Accessibility::RoleGated(AuthRole::Recovery),
            ),
            (
                "account",
                "securify",
                Accessibility::Guarded(Expr::SelfAddr),
            ),
            (
                "account",
                "stamp-entropy",
                Accessibility::Guarded(Expr::SelfAddr),
            ),
            (
                "account",
                "withdraw",
                Accessibility::Guarded(Expr::SelfAddr),
            ),
            ("amm", "swap", Accessibility::Public),
            ("book", "fill-asks", Accessibility::Public),
            ("book", "place-ask", Accessibility::Public),
            ("splitter", "take", Accessibility::Public),
            (
                "staking",
                "cast-param-vote",
                Accessibility::Guarded(Expr::Config(1)),
            ),
            (
                "staking",
                "clear-param-vote",
                Accessibility::Guarded(Expr::Config(1)),
            ),
            (
                "staking",
                "deactivate-validator",
                Accessibility::Guarded(Expr::Config(1)),
            ),
            (
                "staking",
                "register-validator",
                Accessibility::Guarded(Expr::Config(1)),
            ),
            ("staking", "stake", Accessibility::Public),
            ("staking", "unjail", Accessibility::Guarded(Expr::Config(1))),
            ("staking", "unstake", Accessibility::Public),
        ];
        let packages = stdlib();
        let declared: Vec<_> = packages
            .iter()
            .flat_map(|(package, metadata)| {
                metadata.methods.iter().map(move |(name, signature)| {
                    (*package, name.as_str(), signature.accessibility.clone())
                })
            })
            .collect();
        assert_eq!(declared, expected);
    }
}

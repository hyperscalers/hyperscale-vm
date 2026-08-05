//! Package metadata: effect signatures and static call sites, cached by
//! content address.

use std::collections::BTreeMap;

use hyperscale_hbor::Hbor;

use crate::dsl::{Clause, Expr};
use crate::hash::{Hash32, Hasher};
use crate::types::{Address, Value};

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
        }
    }

    /// Whether a literal value has this kind. Buckets are never literals —
    /// they arrive only as edges.
    #[must_use]
    pub const fn admits(self, value: &Value) -> bool {
        matches!(
            (self, value),
            (Self::U64, Value::U64(_))
                | (Self::U128, Value::U128(_))
                | (Self::Bytes, Value::Bytes(_))
                | (Self::Address, Value::Address(_))
        )
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
///
/// Every value is a whole rule rather than a fragment of a language. The
/// expression language that replaces them says the same things at more
/// length — `Public` is the absent requirement, and each of the others
/// requires one virtual signature badge — so a value substitutes rather
/// than being extended into.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hbor)]
pub enum Accessibility {
    /// Anyone may name this method on this target. What the caller
    /// supplies is the caller's own, gated wherever it was obtained.
    #[default]
    Public,
    /// Only an envelope carrying the target's own authority may name it.
    /// The satisfier is a signature the target's address derives from.
    RequiresTargetAuth,
    /// Only an envelope carrying the authority of the principal named at
    /// this slot of the target's creation-fixed configuration may name
    /// it. The satisfier is a signature that principal's address derives
    /// from.
    ///
    /// This is how an object nobody owns admits somebody: a pool
    /// instance's address derives from no key, so its own authority is
    /// unsatisfiable, while a configuration field can name a principal
    /// whose is not. Fixed at creation like the rest of an instance's
    /// configuration, which is what keeps the check a pure function of
    /// signed content and immutable metadata.
    RequiresConfiguredAuth(u32),
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

/// An instance's creation-fixed record: its package and its immutable
/// configuration.
///
/// These are locked substates — verified once, cached process-wide — which
/// is what lets routing consult them and stay state-free.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceMeta {
    /// The package the instance runs.
    pub package: PackageHash,
    /// The instance's creation-fixed configuration fields.
    pub config: Vec<Value>,
}

/// Instance address to creation-fixed record.
#[derive(Clone, Debug, Default)]
pub struct InstanceRegistry {
    instances: BTreeMap<Address, InstanceMeta>,
}

impl InstanceRegistry {
    /// An empty registry.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instances: BTreeMap::new(),
        }
    }

    /// Record an instance's creation-fixed metadata.
    pub fn register(&mut self, address: Address, meta: InstanceMeta) {
        self.instances.entry(address).or_insert(meta);
    }

    /// Look up an instance's creation-fixed metadata.
    #[must_use]
    pub fn get(&self, address: Address) -> Option<&InstanceMeta> {
        self.instances.get(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AbiError, AbiParam, Accessibility, MetadataCache, MethodSignature, PackageHash,
        PackageMetadata, ParamType, check_abi,
    };
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
    use crate::hash::Hash32;
    use crate::stdlib::{
        account_metadata, amm_metadata, book_metadata, splitter_metadata, staking_metadata,
    };

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
            ("account", "deposit", Accessibility::Public),
            (
                "account",
                "stamp-entropy",
                Accessibility::RequiresTargetAuth,
            ),
            ("account", "withdraw", Accessibility::RequiresTargetAuth),
            ("amm", "swap", Accessibility::Public),
            ("book", "fill-asks", Accessibility::Public),
            ("book", "place-ask", Accessibility::Public),
            ("splitter", "take", Accessibility::Public),
            (
                "staking",
                "cast-param-vote",
                Accessibility::RequiresConfiguredAuth(2),
            ),
            (
                "staking",
                "clear-param-vote",
                Accessibility::RequiresConfiguredAuth(2),
            ),
            (
                "staking",
                "deactivate-validator",
                Accessibility::RequiresConfiguredAuth(2),
            ),
            (
                "staking",
                "register-validator",
                Accessibility::RequiresConfiguredAuth(2),
            ),
            ("staking", "stake", Accessibility::Public),
            (
                "staking",
                "unjail",
                Accessibility::RequiresConfiguredAuth(2),
            ),
            ("staking", "unstake", Accessibility::Public),
        ];
        let packages = stdlib();
        let declared: Vec<_> = packages
            .iter()
            .flat_map(|(package, metadata)| {
                metadata.methods.iter().map(move |(name, signature)| {
                    (*package, name.as_str(), signature.accessibility)
                })
            })
            .collect();
        assert_eq!(declared, expected);
    }
}

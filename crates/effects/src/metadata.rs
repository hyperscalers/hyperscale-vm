//! Package metadata: effect signatures, cached by content address.

use std::collections::BTreeMap;

use hyperscale_hbor::{EncodeError, Hbor, to_vec};
use hyperscale_vm_types::{MAX_ERROR_CODES, MAX_EVENT_TYPES};
use thiserror::Error;

use crate::auth::{AuthRole, RoleSet};
use crate::dsl::{
    Clause, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, MAX_RANGE_CAP,
    ModeExpr, TargetExpr, materialized_kind,
};
use crate::hash::{Hash32, Hasher};
use crate::invoke::EdgeKind;
use crate::resource::holdings_entry;
use crate::rule::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, RuleExpr, StoredRule};
use crate::types::{
    Address, CallTarget, ComponentAddr, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, Presence, SlotId,
    SubstateKey, Value, child_key, component_address, config_hash,
};
use crate::vocabulary::{AUTH, CLAIMS, CONFIG, INSTANCE, NF_VAULT, RESOURCE, VAULT};
use crate::{KERNEL_SLOT_BASE, PACKAGE_SLOT_BASE};

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
/// In the kernel's own band at the top of the role space, above anything
/// the protocol vocabulary or a package numbers into, so the cell is
/// reachable by the publish path and by nothing else.
pub const PACKAGE_SLOT: SlotId = SlotId(0xFFFE);

const _: () = assert!(PACKAGE_SLOT.0 >= KERNEL_SLOT_BASE);

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
    child_key(hasher, publisher, PACKAGE_SLOT, &[package.0.0.to_vec()])
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
    /// A fungible value edge; its resource type is static, its amount
    /// dynamic.
    ///
    /// Which of the two edge kinds a method consumes is part of its
    /// signature rather than a fact about whichever edge is routed in:
    /// the two cross the boundary as different cells, so a callee that
    /// did not say would be one whose guest had to sniff what it was
    /// handed.
    Bucket,
    /// An authority rule, carried as its canonical bytes and decoded as
    /// the vocabulary at admission — so a rule past a cap, or with a
    /// degenerate threshold, is refused before anything signs.
    Rule,
    /// A full role set — three rules, canonical bytes — decoded as the
    /// vocabulary at admission, for the same reason.
    RoleSet,
    /// A set of non-fungible instance ids: a list of distinct `u64`s
    /// within the per-edge cap. Signed manifest content — a transfer
    /// names the ids it moves; nothing about an instance is resolved at
    /// execution.
    Ids,
    /// A non-fungible value edge, carrying the instances it moves rather
    /// than an amount.
    NfBucket,
}

impl ParamType {
    /// Whether this kind is a value edge, of either edge kind.
    ///
    /// What the two share is how they are supplied — an edge, never a
    /// literal — and how they are bound, through [`AbiParam::Bucket`].
    /// What separates them is the cell they cross as.
    #[must_use]
    pub const fn is_edge(self) -> bool {
        matches!(self, Self::Bucket | Self::NfBucket)
    }

    /// The edge kind this parameter accepts, if it is an edge at all.
    #[must_use]
    pub const fn edge_kind(self) -> Option<EdgeKind> {
        match self {
            Self::Bucket => Some(EdgeKind::Fungible),
            Self::NfBucket => Some(EdgeKind::NonFungible),
            _ => None,
        }
    }

    /// The kind name, for diagnostics.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::Bytes => "bytes",
            Self::Address => "address",
            Self::Bucket => "bucket",
            Self::NfBucket => "nf-bucket",
            Self::Rule => "rule",
            Self::RoleSet => "role-set",
            Self::Ids => "ids",
        }
    }

    /// Whether a literal value has this kind. Buckets are never literals —
    /// they arrive only as edges, and a rule is bytes that decode as the
    /// vocabulary.
    #[must_use]
    pub fn admits(self, value: &Value) -> bool {
        match (self, value) {
            (Self::U64, Value::U64(_))
            | (Self::U128, Value::U128(_))
            | (Self::Bytes, Value::Bytes(_))
            | (Self::Address, Value::Address(_)) => true,
            (Self::Rule, Value::Bytes(bytes)) => StoredRule::from_slice(bytes).is_ok(),
            (Self::RoleSet, Value::Bytes(bytes)) => RoleSet::from_slice(bytes).is_ok(),
            (Self::Ids, Value::List(elements)) => {
                elements.len() <= MAX_IDS_PER_EDGE
                    && elements.iter().enumerate().all(|(position, element)| {
                        matches!(element, Value::U64(_)) && !elements[..position].contains(element)
                    })
            }
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
    /// The value edge this declared [`ParamType::Bucket`] parameter is
    /// bound to.
    ///
    /// The one argument a signature cannot derive: which bucket it is
    /// depends on what the producing node handed back, which does not
    /// exist until that node runs.
    Bucket(u32),
    /// This invocation's authority to issue.
    ///
    /// Granted by the walk from the method's own declared outputs, so a
    /// binding naming one where the signature issues nothing is a
    /// package asking for a handle nothing would hand it.
    Issuer,
    /// Whether the clause this names was declared: the guard's own
    /// verdict, as a `bool` the export takes.
    ///
    /// Answered from [`Declaration::clause_taken`], which the evaluation
    /// routing already ran has recorded — so the guest branches on the
    /// declaration rather than on a second copy of the condition, and
    /// there is nothing for the two to disagree about. A body whose
    /// control flow diverges from the flag it was handed reaches a
    /// capability that was never materialized, which is a defect and
    /// traps as one.
    ///
    /// [`Declaration::clause_taken`]: crate::dsl::Declaration::clause_taken
    Guard(u32),
    /// A value evaluated over the method's bound inputs.
    ///
    /// The same evaluation the effect clauses run, against the same
    /// inputs — arguments, instance configuration, and the identity,
    /// node and frame a fresh id derives from — so an argument the guest
    /// reads is bounded and deterministic on exactly the terms a declared
    /// target already is. Everything but a value edge lands here.
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
    /// Naming this method requires satisfying this rule, over the
    /// target's own inputs.
    ///
    /// `Require(SelfAddr)` is a method only the target itself may be
    /// made to perform; a configuration slot is how an object nobody
    /// owns admits somebody, since a pool's address derives from no key
    /// while a configured field can name a claim that does. A threshold
    /// over configured slots is how a fixed admin set says "two of these
    /// three" — the same algebra a stored rule has, on the side that
    /// declares rather than stores.
    ///
    /// Every claim a method can require is one the target itself names,
    /// so an authority verdict never reaches state under a prefix the
    /// manifest did not name. Authority held by somebody else is a call
    /// to *them*, which the manifest writes down like any other.
    Guarded(RuleExpr),
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
    /// Naming this method requires satisfying the target's own rule
    /// *and* the target holding what this claim names — and doing so
    /// mints that badge as evidence.
    ///
    /// Holding as the third way to mint a proof. Judged like an
    /// authorizing gate over the same stored rule — the holder acts,
    /// nobody else presents its badges — with the claim's own possession
    /// read beside it: the badge-keyed vault non-empty, or the holdings
    /// entry at the named id. The whole declaration is the shape
    /// [`gate`] pins: the rule cell's read and that one possession read,
    /// keyed by exactly the expressions the mint names, so the claim
    /// minted and the thing held cannot name different resources.
    ///
    /// A possession gate mints the badge rather than the holder's own
    /// identity, so what a guarded consumer matches is the thing held,
    /// never who holds it. Exactly this accessibility names what it
    /// mints: an authorizing method always mints the target itself —
    /// letting it name anything else would be forgeable identity, since
    /// satisfying one's own stored rule is no feat — while a custodial
    /// mint is honest by construction, the same expressions keying the
    /// possession read its gate judges.
    ///
    /// [`gate`]: MethodSignature::gate
    Custodial(CustodyClaim),
}

/// Which shape of badge a custody gate is about, and how possession of
/// it is read.
///
/// A resource is issued as one or the other, so the claim says which.
/// Declaring both and admitting either — which is what a single
/// disjunction over the vault and the whole holdings interval amounts to
/// — leaves the declaration unable to say what the method is for, and
/// makes every holder of a badge resource one authority. A resource used
/// both ways takes a method per shape.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum CustodyClaim {
    /// A fungible badge: held when the badge-keyed vault is non-zero.
    Fungible(Expr),
    /// One instance: held when the badge-keyed holdings entry at this id
    /// is there.
    Instance {
        /// The badge resource.
        badge: Expr,
        /// Which instance of it, as the entry's own order key.
        id: Expr,
    },
}

impl CustodyClaim {
    /// The badge expression, whichever shape the claim takes.
    #[must_use]
    pub const fn badge(&self) -> &Expr {
        match self {
            Self::Fungible(badge) | Self::Instance { badge, .. } => badge,
        }
    }
}

impl Accessibility {
    /// Whether naming the method requires presenting anything.
    ///
    /// The one authority question the signed form answers on its own:
    /// whether what is presented satisfies the target is the target's
    /// own business, answered where its state is.
    #[must_use]
    pub const fn requires_evidence(&self) -> bool {
        !matches!(self, Self::Public)
    }

    /// Whether the gate judges against a rule the target stores, rather
    /// than an identity the declaration names.
    ///
    /// What the intent's own signature may reach, and nothing else: a
    /// signature signs in, and whether the key behind it still holds the
    /// account's authority is the stored rule's answer. An identity a
    /// declaration names is not something a signature can stand in for.
    #[must_use]
    pub const fn reads_a_rule(&self) -> bool {
        matches!(
            self,
            Self::Authorizing | Self::RoleGated(_) | Self::Custodial(_)
        )
    }

    /// Whether naming the method mints evidence for later nodes of the
    /// same intent.
    #[must_use]
    pub const fn mints(&self) -> bool {
        matches!(self, Self::Authorizing | Self::Custodial(_))
    }
}

/// How completely a method can be relied on to return.
///
/// Three states rather than a flag, because the two facts behind them are
/// not the same fact and one does not imply the other. An error arm is
/// visible in the signature and says the method can fail on its own terms.
/// Trap freedom is not visible anywhere — a trap leaves the type system
/// entirely — so ruling it out takes analysis of the body rather than a
/// reading of its declaration.
///
/// The ordering is what a caller may assume, weakest first. The default
/// is not the weakest but the commonest: the mark is a function of the
/// component type rather than a claim an author may under-shoot, and a
/// method with no error arm is the shape most methods have.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hbor)]
pub enum Totality {
    /// The signature carries an error arm, so the method fails on its own
    /// terms and every caller has a failure to handle. The publish gate
    /// admits this mark exactly over an export that carries one.
    Fallible,
    /// No error arm, and nothing established about traps. Necessary for
    /// [`Total`](Self::Total) and not sufficient for it: fuel exhaustion
    /// and a panicking body are both still reachable from here.
    #[default]
    Infallible,
    /// No error arm, and the publish-time checker established the rest:
    /// no partial operation anywhere in the body, and a static
    /// fuel bound the transaction pre-charges so exhaustion cannot occur
    /// at execution. Never authored — a package claims it and the check
    /// grants it, because a claim a package could simply assert about
    /// itself would carry no weight for the shards that rely on it.
    Total,
}

impl Totality {
    /// Whether a caller may commit without waiting to hear back.
    #[must_use]
    pub const fn is_total(self) -> bool {
        matches!(self, Self::Total)
    }
}

/// A method's declared access: every effect the method itself reaches,
/// and no further — a frame declares only under its own instance's
/// prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hbor)]
pub struct MethodSignature {
    /// Whose authority naming this method on this target requires.
    pub accessibility: Accessibility,
    /// How completely the method returns: whether a caller has a failure
    /// to handle, and whether anything rules out a trap.
    ///
    /// What a leg's decomposition turns on — an outbound leg commits
    /// locally and offers no veto, so it must be one that cannot come
    /// back with a refusal or a trap for the core to have to answer.
    pub totality: Totality,
    /// The mark of the resource this method may bring into or out of
    /// existence, where it may.
    ///
    /// A mark rather than an address: it is the material separating one
    /// of the instance's own resources from its others, so naming another
    /// instance's is not something this field can say. The walk grants
    /// the issuance handle against it, and the gate holds the export to
    /// taking one exactly when it is present.
    pub issues: Option<Vec<u8>>,
    /// The method's parameter kinds, in order; admission types every node
    /// against them.
    pub params: Vec<ParamType>,
    /// The static resource type of each value edge the method produces, as
    /// an expression over the method's bound inputs.
    pub outputs: Vec<Expr>,
    /// The resource each value edge the method *consumes* must carry, as
    /// an expression over the method's bound inputs; `None` at a position
    /// that takes any resource.
    ///
    /// The dual of `outputs`, and one entry per parameter, so a position
    /// indexes both this and `params`. What fixes an entry is the body: a
    /// bucket credited to a cell the method keys by something other than
    /// that bucket's own resource is a bucket the method can only mean one
    /// resource by. A cell keyed by the arriving resource fixes nothing,
    /// which is what a wallet is, and leaves the position open.
    ///
    /// Not derivable from the effects alone: a clause names the cell and
    /// never which parameter feeds it.
    pub denominations: Vec<Option<Expr>>,
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
}

/// The whole shape of a method's gate: what a caller presents, and what
/// the declaration reads to judge it.
///
/// One shape rather than one accessor per accessibility, because the
/// choice of refusal is a function of the accessibility the accessor
/// just matched on. A caller left to draw its own conclusion from a
/// `None` is a caller free to disagree about which gate it is looking
/// at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateShape<'a> {
    /// Nothing to present, and nothing read to judge it.
    Open,
    /// The rule a caller's presented set must satisfy, over the target's
    /// own inputs.
    Guarded(&'a RuleExpr),
    /// A rule the target stores, and the role that judges: the primary
    /// for a sign-in, the named role for a recovery op.
    Rule {
        /// The cell expression the stored rules live at.
        cell: &'a Expr,
        /// The role the presented set must satisfy.
        role: AuthRole,
    },
    /// The holder's stored primary, and the badge the declaration reads
    /// possession of and the gate mints.
    Custody {
        /// The cell expression the holder's stored rules live at.
        cell: &'a Expr,
        /// What is held, and how the declaration reads it.
        claim: &'a CustodyClaim,
    },
}

impl MethodSignature {
    /// The gate's whole shape: what a caller must present, and what the
    /// declaration reads to judge it.
    ///
    /// `Ok` exactly when the accessibility and the declaration agree on
    /// the shape that accessibility pins. A rule-reading gate declares
    /// one point clause — read for a sign-in, which is what provisions
    /// the cell to every participant, and exclusively written for a
    /// recovery op, which keeps a role rewrite out of any wave that
    /// signs in under the roles it replaces. A custodial gate declares
    /// that read and the one possession read its claim's shape names,
    /// keyed by *exactly* the badge it mints, which is what makes the
    /// claim minted and the thing held one resource.
    ///
    /// Every judge of the shape asks here, so none can drift: the
    /// publish check refuses a signature this refuses, and admission
    /// re-asks, so a cached package that never passed one refuses rather
    /// than lowering an ungated node.
    ///
    /// # Errors
    ///
    /// The shape refusal named for the accessibility that was declared.
    pub fn gate(&self) -> Result<GateShape<'_>, AbiError> {
        match &self.accessibility {
            Accessibility::Public => Ok(GateShape::Open),
            Accessibility::Guarded(rule) => Ok(GateShape::Guarded(rule)),
            Accessibility::Authorizing => self
                .rule_point(&|mode| matches!(mode, ModeExpr::Read))
                .map(|cell| GateShape::Rule {
                    cell,
                    role: AuthRole::Primary,
                })
                .ok_or(AbiError::AuthorizingShape),
            Accessibility::RoleGated(role) => self
                .rule_point(&|mode| matches!(mode, ModeExpr::Write { .. }))
                .map(|cell| GateShape::Rule { cell, role: *role })
                .ok_or(AbiError::RoleGatedShape),
            Accessibility::Custodial(claim) => self.custody(claim).ok_or(AbiError::CustodialShape),
        }
    }

    /// The cell a rule-reading gate judges at, when the declaration is
    /// one point clause `admits` accepts and nothing else.
    ///
    /// Taken as a predicate rather than as a mode, because what a
    /// role-gated method owes is exclusivity on its rule cell — that is
    /// what serializes a role rewrite against a concurrent sign-in — and
    /// a write's presence requirement is orthogonal to it. A method that
    /// creates its own rule cell, or that requires one already there, is
    /// gated on the same cell in the same mode.
    fn rule_point(&self, admits: &dyn Fn(&ModeExpr) -> bool) -> Option<&Expr> {
        match self.effects.as_slice() {
            [
                Clause::Effect {
                    target: TargetExpr::Point(cell),
                    mode: declared,
                    ..
                },
            ] if admits(declared) => Some(cell),
            _ => None,
        }
    }

    /// The custody shape over `claim`: the holder's rule cell, and the
    /// one possession read the claim's shape names — the badge-keyed
    /// vault, or the badge's holdings entry at the id.
    fn custody<'a>(&'a self, claim: &'a CustodyClaim) -> Option<GateShape<'a>> {
        let [
            Clause::Effect {
                target: TargetExpr::Point(cell),
                mode: ModeExpr::Read,
                ..
            },
            Clause::Effect {
                target: possession,
                mode: ModeExpr::Read,
                ..
            },
        ] = self.effects.as_slice()
        else {
            return None;
        };
        let pinned = match claim {
            CustodyClaim::Fungible(badge) => TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: VAULT,
                material: vec![badge.clone()],
            }),
            CustodyClaim::Instance { badge, id } => holdings_entry(badge.clone(), id.clone()),
        };
        (*possession == pinned).then_some(GateShape::Custody { cell, claim })
    }
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
    /// An issuance grant bound by a method that declares no issued
    /// resource. The walk grants one from the declaration, so there would
    /// be nothing to hand over.
    #[error("ABI parameter {position} takes an issuance grant, but nothing is issued")]
    IssuerWithoutIssuedOutput {
        /// The ABI parameter position.
        position: u32,
    },
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
    /// A guard binding naming a clause that carries no guard. Its
    /// verdict is the constant true, which no export needs told.
    #[error("ABI parameter {position} takes the verdict of clause {clause}, which has no guard")]
    UnguardedClause {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
    },
    /// A handle binding naming a clause that is not a single access.
    ///
    /// A `for-each` clause expands over configuration, so it backs no
    /// fixed export parameter — a refusal routing would otherwise reach
    /// by arity, made here where the signature is judged.
    #[error("ABI parameter {position} borrows clause {clause}, which is not a single access")]
    NotAnAccess {
        /// The ABI parameter position.
        position: u32,
        /// The clause it names.
        clause: u32,
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
    /// A rule leaf reading what the caller supplies.
    ///
    /// A caller who names the claim they must present can always present
    /// it, so the method reads as guarded and admits everyone. Every
    /// leaf answers, because one caller-named branch of a threshold is
    /// one branch the caller satisfies for free.
    #[error("the authority this method requires is one its caller names")]
    CallerNamedAuthority,
    /// A custodial method whose declaration is not the pinned custody
    /// shape: the holder's rule cell read, and the one possession read
    /// its claim names, keyed by exactly the expressions the gate mints.
    ///
    /// Which read that is follows from the claim, because a resource is
    /// issued fungible or non-fungible and never both: a fungible claim
    /// reads the badge-keyed vault, an instance claim the badge's
    /// holdings entry at the id it names.
    #[error(
        "a custodial method declares two reads: its rule cell, and the \
         badge-keyed vault for a fungible claim or the holdings entry at \
         the id for an instance one"
    )]
    CustodialShape,
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
    if let Accessibility::Guarded(rule) = &signature.accessibility
        && rule.reads_call_inputs()
    {
        return Err(AbiError::CallerNamedAuthority);
    }
    // A gated method's whole declaration is what its gate judges at, in
    // the shape its accessibility pins.
    signature.gate()?;
    let bound = |count: usize| u32::try_from(count).unwrap_or(u32::MAX);
    let mut carried = vec![0u32; signature.params.len()];
    for (index, binding) in signature.abi.iter().enumerate() {
        let position = bound(index);
        match binding {
            AbiParam::Handle(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let Some(declared) = declared else {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                };
                if !matches!(declared, Clause::Effect { .. }) {
                    return Err(AbiError::NotAnAccess {
                        position,
                        clause: *clause,
                    });
                }
            }
            AbiParam::Guard(clause) => {
                let declared = usize::try_from(*clause)
                    .ok()
                    .and_then(|index| signature.effects.get(index));
                let Some(declared) = declared else {
                    return Err(AbiError::NoSuchClause {
                        position,
                        clause: *clause,
                        declared: bound(signature.effects.len()),
                    });
                };
                if declared.guard().is_none() {
                    return Err(AbiError::UnguardedClause {
                        position,
                        clause: *clause,
                    });
                }
            }
            // The grant is the method's own declaration, so a binding
            // that names one where nothing is issued asks for a handle
            // the walk would not hand over.
            AbiParam::Issuer => {
                if signature.issues.is_none() {
                    return Err(AbiError::IssuerWithoutIssuedOutput { position });
                }
            }
            AbiParam::Bucket(param) => {
                let slot = usize::try_from(*param).map_err(|_| AbiError::NoSuchParam {
                    position,
                    param: *param,
                    declared: bound(signature.params.len()),
                })?;
                match signature.params.get(slot) {
                    Some(kind) if kind.is_edge() => carried[slot] += 1,
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
    /// A method claiming totality behind a gate that can turn it away.
    #[error("a total method admits every caller, and this one is gated")]
    GatedTotality,
    /// A method claiming totality over a guarded clause. A total leg
    /// runs with every declared handle materialized, and a guarded-out
    /// clause materializes none.
    #[error("a total method materialises every handle it declares, and a guard leaves one absent")]
    GuardedTotality,
    /// Two writes on one target requiring opposite presences.
    ///
    /// Refused here as well as where the set is built, because metadata
    /// can be authored rather than derived: the macro sees the body and
    /// refuses at the second call site, and this sees only what was
    /// published.
    #[error("two write clauses on one target require opposite presences")]
    PresenceConflict,
    /// A presence requirement on a target that names no single leaf.
    ///
    /// `Absent` and `Present` are what a write requires of *the leaf it
    /// lands on*, and an interval has none: it stays valid whatever
    /// entries enter or leave it, which is the property that makes it
    /// declarable ahead of execution at all. A point and a collection
    /// entry each name one leaf and carry the requirement; a range
    /// carries only the indifferent one.
    #[error("effect clause {clause} requires a presence of an interval, which names no leaf")]
    PresenceOnInterval {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A denomination list that does not line up with the parameters it
    /// indexes.
    #[error("{found} denominations against {expected} parameters")]
    DenominationArity {
        /// The declared parameter count.
        expected: usize,
        /// The denomination count.
        found: usize,
    },
    /// A denomination at a parameter that carries no value.
    #[error("parameter {param} is declared {kind} and carries no value to denominate")]
    DenominationKind {
        /// The offending position.
        param: u32,
        /// The kind declared there.
        kind: &'static str,
    },
    /// A clause naming a protocol cell in a shape that cell does not
    /// have.
    #[error("effect clause {clause} names slot {slot}, which {wanted}")]
    ProtocolSlotShape {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
        /// The slot named.
        slot: u16,
        /// The shape that slot does have.
        wanted: &'static str,
    },
    /// A denomination that is not the key the cell is reached by.
    ///
    /// A value cell is keyed by what it holds, so a declaration naming a
    /// resource names the key again — which is what makes two clauses
    /// reaching one leaf agree about its contents by construction rather
    /// than by comparison. Disagreeing about what a cell holds is naming
    /// a different cell.
    #[error("effect clause {clause} denominates a cell in something its key does not name")]
    DenominationNotKeyed {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A commutative movement that does not say what it moves.
    ///
    /// `Delta` and `Reserve` move value and do nothing else, so the cell
    /// they name holds value and the declaration owes an answer about
    /// what. Refused again at materialization, which has the evaluated
    /// key to name it by; this is the same verdict where an author can
    /// hear it.
    #[error("effect clause {clause} moves value without saying what it moves")]
    UndenominatedMovement {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// A clause naming a slot no cell is assigned: unassigned below
    /// [`PACKAGE_SLOT_BASE`], or the kernel's own band at the top.
    #[error("effect clause {clause} names slot {slot}, which no cell is assigned")]
    ReservedSlot {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
        /// The slot named.
        slot: u16,
    },
    /// A mode and target pairing the world hands out no handle for.
    ///
    /// Every declared access is a capability a body borrows, and which
    /// one is a function of the target's shape and the mode: a leaf is
    /// read, locked, rewritten or moved through, and an interval is read
    /// or rewritten. A pairing outside that materializes nothing, so it
    /// is a clause every call aborts at — and a declaration stating an
    /// access no execution can hold is worse than one that never
    /// published. Refused again at materialization, which is where the
    /// abort would have come from.
    #[error("effect clause {clause} pairs a mode and a target no handle is built for")]
    UnsupportedAccess {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
        clause: u32,
    },
    /// Two clauses reaching one cell and disagreeing about what it holds.
    ///
    /// A denomination chooses which handle the clause materializes, so a
    /// leaf one clause denominates and another does not is a leaf a body
    /// holds twice: once as the cell value moves through, once as the
    /// cell bytes are written to. Writing a balance through the second
    /// and debiting it through the first is value from nowhere.
    ///
    /// Refused again at materialization, which has the evaluated keys;
    /// this is the same verdict where an author can hear it.
    #[error("effect clause {clause} names a cell another clause says holds something else")]
    MixedContents {
        /// The clause's position in a preorder walk of the signature's
        /// effects.
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

/// What a target names as the thing whose contents are one fact: the
/// leaf a point names, or the collection an entry or an interval sits in.
///
/// Not the target itself, because two intervals of one collection are two
/// targets over one set of entries — so an interval saying its entries
/// are instances and an overlapping one saying they are bytes are two
/// answers about the same entries, and comparing targets would let them
/// both through.
#[derive(PartialEq, Eq)]
enum Contents<'a> {
    /// One leaf, as the expression naming it.
    Leaf(&'a Expr),
    /// Every entry of one collection, as the owner and identity it hangs
    /// under.
    Entries(&'a Expr, SlotId, &'a [Expr]),
}

/// Which cell's contents a clause is an answer about.
fn contents(target: &TargetExpr) -> Contents<'_> {
    match target {
        TargetExpr::Point(key) => Contents::Leaf(key),
        TargetExpr::Entry {
            owner,
            collection,
            material,
            ..
        }
        | TargetExpr::Range {
            owner,
            collection,
            material,
            ..
        } => Contents::Entries(owner, *collection, material),
    }
}

/// The slot a target names, and the material keying it there.
///
/// Both point shapes and both collection shapes carry one: a child key
/// spells the slot beside its material, and a collection carries it as
/// the identity its entries hang under. A fresh key is the exception and
/// answers `None` — it is a local id minted under the owner rather than
/// a child of any slot, so there is nothing for the vocabulary to be
/// about.
fn slot_of(target: &TargetExpr) -> Option<(SlotId, &[Expr])> {
    match target {
        TargetExpr::Point(Expr::ChildKey { slot, material, .. }) => Some((*slot, material)),
        TargetExpr::Point(_) => None,
        TargetExpr::Entry {
            collection,
            material,
            ..
        }
        | TargetExpr::Range {
            collection,
            material,
            ..
        } => Some((*collection, material)),
    }
}

/// Judge a clause naming a cell the protocol derives keys for.
///
/// The vocabulary below [`PACKAGE_SLOT_BASE`] is the set of cells an
/// engine finds without consulting any metadata, which is what makes
/// their values protocol facts rather than one package's business. A
/// fact has a shape: a vault holds an amount keyed by the resource it
/// holds, a record is written when the thing it describes comes into
/// being, a configuration leaf is locked. So the shape is not the
/// declaring package's to choose either, and a clause naming one of
/// these cells any other way is a clause whose leaf would be read as
/// something it does not hold.
///
/// Judgeable at all because the slot is authenticated by the derivation
/// that consumes it: [`child_key`] hashes the slot into the key, and
/// [`targets_own_prefix`] admits no point target that reaches a leaf
/// without spelling one. A declaration landing on a vault therefore
/// *says* `VAULT`, and cannot be written to land there while saying
/// something else.
///
/// The kernel's own band at the top is refused outright, as is any slot
/// below the base the vocabulary has not assigned. Neither names a cell,
/// and a slot naming no cell has no shape to be held to.
fn protocol_shape(
    clause: u32,
    target: &TargetExpr,
    mode: &ModeExpr,
    denomination: Option<&Expr>,
) -> Result<(), DeclarationError> {
    let Some((slot, material)) = slot_of(target) else {
        return Ok(());
    };
    let reserved = || DeclarationError::ReservedSlot {
        clause,
        slot: slot.0,
    };
    if slot.0 >= KERNEL_SLOT_BASE {
        return Err(reserved());
    }
    if slot.0 >= PACKAGE_SLOT_BASE {
        return Ok(());
    }
    let Some((shaped, wanted)) = vocabulary_shape(slot, target, material, mode, denomination)
    else {
        return Err(reserved());
    };
    if shaped {
        Ok(())
    } else {
        Err(DeclarationError::ProtocolSlotShape {
            clause,
            slot: slot.0,
            wanted,
        })
    }
}

/// Whether a clause's target, mode and denomination are the shape the
/// vocabulary fixes for `slot`, and the sentence saying what that shape
/// is. `None` where the vocabulary assigns the slot no cell at all.
///
/// One arm per cell, and the sentence beside each is what an author is
/// told: a refusal naming only the slot number would leave them to read
/// this table out of the source.
fn vocabulary_shape(
    slot: SlotId,
    target: &TargetExpr,
    material: &[Expr],
    mode: &ModeExpr,
    denomination: Option<&Expr>,
) -> Option<(bool, &'static str)> {
    let point = matches!(target, TargetExpr::Point(_));
    // A value cell is keyed by what it holds, so where the declaration
    // names a resource it names the key again. The key is what makes one
    // leaf hold one resource; a second answer beside it would be the
    // leaf and the declaration disagreeing about what came out of it.
    //
    // Named wherever value can move, and optional on a read: a read
    // opens no bucket and credits no cell, so nothing consults what the
    // leaf holds, and the custody gate's possession read is exactly that
    // — the balance is a yes or no rather than a quantity going
    // anywhere.
    let moves_value = matches!(
        mode,
        ModeExpr::Write { .. } | ModeExpr::Delta | ModeExpr::Reserve(_)
    );
    let keyed_by_what_it_holds = match (material, denomination) {
        ([held], Some(named)) => named == held,
        ([_], None) => !moves_value,
        _ => false,
    };
    let bare = material.is_empty() && denomination.is_none();
    let keyed = |terms: usize| material.len() == terms && denomination.is_none();
    let creates = matches!(
        mode,
        ModeExpr::Read
            | ModeExpr::Write {
                requires: Presence::Absent
            }
    );

    let (shaped, wanted) = match slot {
        VAULT => (
            point
                && keyed_by_what_it_holds
                && matches!(
                    mode,
                    ModeExpr::Read
                        | ModeExpr::Write { .. }
                        | ModeExpr::Delta
                        | ModeExpr::Reserve(_)
                ),
            "holds a fungible balance: one leaf, keyed by the resource it holds, \
             denominated in that resource wherever value moves, and never locked",
        ),
        CLAIMS => (
            point
                && keyed_by_what_it_holds
                && matches!(
                    mode,
                    ModeExpr::Read
                        | ModeExpr::Write { .. }
                        | ModeExpr::Delta
                        | ModeExpr::Reserve(_)
                ),
            "is the delivery fallback beside a vault, and holds value on the same \
             terms: one leaf, keyed by the resource it holds and denominated in that \
             resource wherever value moves",
        ),
        // Instances are a quantity too, and the interval they sit in is
        // the holdings of exactly one resource.
        NF_VAULT => (
            !point
                && keyed_by_what_it_holds
                && matches!(mode, ModeExpr::Read | ModeExpr::Write { .. }),
            "holds a resource's instances: an interval or one of its entries, keyed by \
             that resource and denominated in it wherever instances move",
        ),
        CONFIG => (
            point && bare && matches!(mode, ModeExpr::Locked | ModeExpr::Read),
            "is the creation-fixed configuration leaf: one leaf, no material, and \
             nothing rewrites it",
        ),
        AUTH => (
            point && bare && matches!(mode, ModeExpr::Read | ModeExpr::Write { .. }),
            "is the stored authority cell: one leaf, no material, read or rewritten whole",
        ),
        // A record and an instance's data are written when the thing
        // they describe comes into existence and not again, so creating
        // one and overwriting one are different declarations and the
        // shard holding the leaf tells them apart before any body runs.
        RESOURCE => (
            point && keyed(1) && creates,
            "is a resource's record under its issuer: one leaf, keyed by the resource, \
             written where absent",
        ),
        INSTANCE => (
            point && keyed(2) && creates,
            "is an instance's data under its issuer: one leaf, keyed by the resource and \
             the id, written where absent",
        ),
        // Below the base and spoken for by nothing: the vocabulary
        // reserves room for a cell it has not defined yet, and a slot
        // naming no cell has no shape to be held to.
        _ => return None,
    };
    Some((shaped, wanted))
}

/// Every effect clause of a signature, `for-each` bodies counted in
/// place — the same preorder the clause indices name.
fn flat_clauses(clauses: &[Clause]) -> Vec<&Clause> {
    let mut flat = Vec::new();
    let mut stack: Vec<&Clause> = clauses.iter().rev().collect();
    while let Some(clause) = stack.pop() {
        flat.push(clause);
        if let Clause::ForEach { body, .. } = clause {
            stack.extend(body.iter().rev());
        }
    }
    flat
}

/// Whether two clauses' guards are each other's negation, so no
/// evaluation declares both.
///
/// Syntactic, because this runs at publish where no arguments exist —
/// the same standard the target comparison beside it holds to. An
/// unguarded clause is complementary to nothing: it fires always, so it
/// meets whatever else lands on its target.
fn complementary(left: Option<&Expr>, right: Option<&Expr>) -> bool {
    let (Some(left), Some(right)) = (left, right) else {
        return false;
    };
    matches!(left, Expr::Not(inner) if inner.as_ref() == right)
        || matches!(right, Expr::Not(inner) if inner.as_ref() == left)
}

/// Judge one access clause: whose prefix it names, which cell under that
/// prefix, whether the world hands out a handle for reaching it that way,
/// what that cell holds, and what it requires of the leaf.
///
/// Ordered as an author would want to hear it. A clause reaching a
/// stranger's leaf is wrong about more than its shape, and a clause
/// naming a protocol cell hears that cell's own sentence before the
/// general rules the sentence is a special case of.
fn judge_access(clause: u32, access: &Clause) -> Result<(), DeclarationError> {
    let Clause::Effect {
        target,
        mode,
        denomination,
        ..
    } = access
    else {
        return Ok(());
    };
    let denomination = denomination.as_deref();
    if !targets_own_prefix(target) {
        return Err(DeclarationError::ForeignPrefix { clause });
    }
    protocol_shape(clause, target, mode, denomination)?;
    // And whether the world hands out anything for this pairing at all.
    // Asked of the clause through the same function an engine reads a
    // handle's type off, so publish refuses exactly what materialization
    // could not have built.
    if materialized_kind(access).is_none() {
        return Err(DeclarationError::UnsupportedAccess { clause });
    }
    // What a cell holds is part of the key it is reached by, so the two
    // are one expression written twice. A fresh key carries no material
    // and so holds no value: nothing could find it again to take any
    // out.
    if let Some(held) = denomination
        && slot_of(target).is_none_or(|(_, material)| material.first() != Some(held))
    {
        return Err(DeclarationError::DenominationNotKeyed { clause });
    }
    if denomination.is_none() && matches!(mode, ModeExpr::Delta | ModeExpr::Reserve(_)) {
        return Err(DeclarationError::UndenominatedMovement { clause });
    }
    // A presence requirement is about the leaf a write lands on, and an
    // interval has none. Refused here so an author hears about it, and
    // again at materialization, which honours the requirement rather
    // than reading past it.
    if matches!(
        (target, mode),
        (
            TargetExpr::Range { .. },
            ModeExpr::Write {
                requires: Presence::Absent | Presence::Present,
            },
        )
    ) {
        return Err(DeclarationError::PresenceOnInterval { clause });
    }
    Ok(())
}

/// Judge a signature's declared effects against the prefix and the cells
/// they are the signature's to declare.
///
/// A declaration bounds what execution may touch, and this bounds what a
/// declaration may claim. Two questions, and the answers are independent.
/// Whose prefix: an object's cells are reachable by calling it, never by
/// naming them — refused here so an author hears about it, and again on
/// the evaluated effect at routing, where no expression shape can be
/// overlooked. Which cell under that prefix: everything an engine derives
/// a key for without reading metadata has a shape, and a package reaching
/// one of those leaves reaches it in that shape or not at all.
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
                Clause::Effect { .. } => judge_access(clause_index, clause)?,
                Clause::ForEach { body, .. } => walk(body, next)?,
            }
        }
        Ok(())
    }
    // Two writes on one target that can both fire are one write, and a
    // presence requirement each way is a requirement nothing satisfies.
    //
    // Compared by target expression rather than by evaluated key,
    // because this runs at publish where no arguments exist — which
    // catches the contradiction an author wrote and leaves the one two
    // different expressions happen to evaluate onto for the set to fold.
    //
    // Two clauses that cannot both fire are not a contradiction, and
    // "create it if absent, otherwise update it" is exactly the shape
    // that takes. So the comparison reads guards beside targets and lets
    // complementary ones through — syntactically complementary, one the
    // `Not` of the other, which is what an `if`/`else` emits and the
    // same standard the target comparison beside it already holds to.
    // The evaluated conflict in `EffectSet::insert` is untouched: two
    // clauses that cannot both fire never both land.
    //
    // Every pair rather than a fold into one requirement per target,
    // because co-firing is a relation between two clauses and not a
    // property of the target they share: a clause complementary to one
    // of the others still meets all the rest, and a fold that stopped at
    // the first meeting would never ask about them. Nothing is lost by
    // comparing originals — `Either` meets everything, so an accumulated
    // requirement is only ever one of the two it came from, and a
    // contradiction a fold could reach is one some pair already has.
    let writes: Vec<(&TargetExpr, Option<&Expr>, Presence)> = flat_clauses(&signature.effects)
        .into_iter()
        .filter_map(|clause| match clause {
            Clause::Effect {
                guard,
                target,
                mode: ModeExpr::Write { requires },
                ..
            } => Some((target, guard.as_deref(), *requires)),
            _ => None,
        })
        .collect();
    for (index, (target, guard, requires)) in writes.iter().enumerate() {
        for (seen, seen_guard, prior) in &writes[..index] {
            if seen == target && !complementary(*seen_guard, *guard) {
                prior
                    .meet(*requires)
                    .ok_or(DeclarationError::PresenceConflict)?;
            }
        }
    }
    // What a cell holds is a fact about the cell rather than about the
    // clause that reached it, and the denomination is what chooses which
    // handle a clause materializes — so a leaf one clause denominates
    // and another does not is a leaf a body holds as a vault and as a
    // byte cell at once. Writing a balance through the byte handle and
    // debiting it through the value one is a balance nothing moved.
    //
    // Folded by container rather than by target: two intervals of one
    // collection are two targets over one set of entries, and the
    // disagreement is about the entries.
    //
    // No guard exemption, unlike the presence fold above. A presence is
    // a question one execution answers, and complementary arms answer it
    // differently on purpose; what a cell holds is not a question an
    // execution answers at all.
    let mut holds: Vec<(Contents<'_>, bool)> = Vec::new();
    for (index, clause) in flat_clauses(&signature.effects).iter().enumerate() {
        let Clause::Effect {
            target,
            denomination,
            ..
        } = clause
        else {
            continue;
        };
        let clause = u32::try_from(index).unwrap_or(u32::MAX);
        let cell = contents(target);
        let value = denomination.is_some();
        match holds.iter().find(|(seen, _)| *seen == cell) {
            Some((_, held)) if *held != value => {
                return Err(DeclarationError::MixedContents { clause });
            }
            Some(_) => {}
            None => holds.push((cell, value)),
        }
    }
    // A gate is an error arm the vocabulary can see. Trap freedom is what
    // the artifact scan establishes, and it says nothing about whether the
    // call is admitted at all — a guarded method turns callers away for
    // reasons the body never runs to discover, which is exactly the
    // refusal a total leg promises cannot happen.
    if signature.totality.is_total() && signature.accessibility != Accessibility::Public {
        return Err(DeclarationError::GatedTotality);
    }
    // Trap freedom for a total leg rests on every handle being
    // materialized from the declared effect set, and an absent
    // capability is precisely a change to that. Precision is what a
    // total method trades for the mark, and it trades it in the one
    // direction that keeps both properties true.
    if signature.totality.is_total()
        && (flat_clauses(&signature.effects)
            .iter()
            .any(|clause| clause.guard().is_some())
            || signature
                .abi
                .iter()
                .any(|binding| matches!(binding, AbiParam::Guard(_))))
    {
        return Err(DeclarationError::GuardedTotality);
    }
    // A denomination is read at the position it indexes, so a list that
    // does not cover the parameters is one whose entries name positions
    // nobody agrees on. An empty list is the method that denominates
    // nothing, which is most of them.
    if !signature.denominations.is_empty()
        && signature.denominations.len() != signature.params.len()
    {
        return Err(DeclarationError::DenominationArity {
            expected: signature.params.len(),
            found: signature.denominations.len(),
        });
    }
    for (position, denomination) in signature.denominations.iter().enumerate() {
        let param = u32::try_from(position).unwrap_or(u32::MAX);
        if denomination.is_some()
            && let Some(kind) = signature
                .params
                .get(position)
                .filter(|kind| !kind.is_edge())
        {
            return Err(DeclarationError::DenominationKind {
                param,
                kind: kind.name(),
            });
        }
    }
    walk(&signature.effects, &mut 0)
}

/// Why metadata is past a bound the vocabulary fixes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct MetadataBoundsError(pub String);

/// Reject metadata past a bound the vocabulary fixes.
///
/// The depth walks mirror the evaluator's own recursion — same starting
/// depth, same comparison — so a signature this accepts is one
/// evaluation will not refuse on structure alone, and the event table
/// stays inside the index an emitted event can carry.
///
/// # Errors
///
/// [`MetadataBoundsError`]; verdicts are deterministic and identical on
/// every node.
pub fn check_metadata(metadata: &PackageMetadata) -> Result<(), MetadataBoundsError> {
    if metadata.events.len() > MAX_EVENT_TYPES as usize {
        return Err(MetadataBoundsError(format!(
            "event table names {} types, past the {MAX_EVENT_TYPES} an event index can reach",
            metadata.events.len()
        )));
    }
    if metadata.errors.len() > MAX_ERROR_CODES as usize {
        return Err(MetadataBoundsError(format!(
            "error table names {} codes, past the {MAX_ERROR_CODES} a declined code can reach",
            metadata.errors.len()
        )));
    }
    for (name, signature) in &metadata.methods {
        check_signature_bounds(signature)
            .map_err(|error| MetadataBoundsError(format!("method {name:?}: {}", error.0)))?;
    }
    Ok(())
}

/// A declared rule under the caps a stored one is decoded under, and
/// every leaf under the expression caps.
fn check_rule_bounds(rule: &RuleExpr) -> Result<(), MetadataBoundsError> {
    if !rule.within_caps(0) {
        return Err(MetadataBoundsError(format!(
            "a declared rule nests past {MAX_RULE_DEPTH}, branches past \
             {MAX_RULE_BRANCHES}, or holds a threshold nobody meant"
        )));
    }
    match rule {
        RuleExpr::Require(claim) => check_expr_bounds(claim, 0),
        RuleExpr::CountOf { rules, .. } => rules.iter().try_for_each(check_rule_bounds),
    }
}

fn check_signature_bounds(signature: &MethodSignature) -> Result<(), MetadataBoundsError> {
    match &signature.accessibility {
        Accessibility::Guarded(rule) => check_rule_bounds(rule)?,
        Accessibility::Custodial(CustodyClaim::Fungible(badge)) => check_expr_bounds(badge, 0)?,
        Accessibility::Custodial(CustodyClaim::Instance { badge, id }) => {
            check_expr_bounds(badge, 0)?;
            check_expr_bounds(id, 0)?;
        }
        Accessibility::Public | Accessibility::Authorizing | Accessibility::RoleGated(_) => {}
    }
    for output in &signature.outputs {
        check_expr_bounds(output, 0)?;
    }
    for denomination in signature.denominations.iter().flatten() {
        check_expr_bounds(denomination, 0)?;
    }
    for param in &signature.abi {
        if let AbiParam::Derived(expr) = param {
            check_expr_bounds(expr, 0)?;
        }
    }
    let mut declared = 0usize;
    check_clause_bounds(&signature.effects, 0, &mut declared)
}

fn check_clause_bounds(
    clauses: &[Clause],
    depth: usize,
    declared: &mut usize,
) -> Result<(), MetadataBoundsError> {
    if depth > MAX_CLAUSE_DEPTH {
        return Err(MetadataBoundsError(format!(
            "for-each clauses nest deeper than {MAX_CLAUSE_DEPTH}"
        )));
    }
    for clause in clauses {
        match clause {
            Clause::Effect {
                guard,
                target,
                mode,
                denomination,
            } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                *declared += 1;
                if *declared > MAX_EFFECTS_PER_SIGNATURE {
                    return Err(MetadataBoundsError(format!(
                        "signature declares more than {MAX_EFFECTS_PER_SIGNATURE} effects"
                    )));
                }
                check_target_bounds(target)?;
                check_mode_bounds(mode)?;
                if let Some(denomination) = denomination {
                    check_expr_bounds(denomination, 0)?;
                }
            }
            Clause::ForEach { guard, list, body } => {
                if let Some(cond) = guard {
                    check_expr_bounds(cond, 0)?;
                }
                check_expr_bounds(list, 0)?;
                check_clause_bounds(body, depth + 1, declared)?;
            }
        }
    }
    Ok(())
}

fn check_target_bounds(target: &TargetExpr) -> Result<(), MetadataBoundsError> {
    match target {
        TargetExpr::Point(key) => check_expr_bounds(key, 0),
        TargetExpr::Entry {
            owner,
            material,
            order,
            ..
        } => {
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(order, 0)
        }
        TargetExpr::Range {
            owner,
            material,
            lo,
            hi,
            cap,
            ..
        } => {
            if *cap > MAX_RANGE_CAP {
                return Err(MetadataBoundsError(format!(
                    "range clause caps {cap} entries, past the {MAX_RANGE_CAP} a scan may lift"
                )));
            }
            check_expr_bounds(owner, 0)?;
            for part in material {
                check_expr_bounds(part, 0)?;
            }
            check_expr_bounds(lo, 0)?;
            check_expr_bounds(hi, 0)
        }
    }
}

fn check_mode_bounds(mode: &ModeExpr) -> Result<(), MetadataBoundsError> {
    match mode {
        ModeExpr::Read | ModeExpr::Delta | ModeExpr::Write { .. } | ModeExpr::Locked => Ok(()),
        ModeExpr::Reserve(amount) => check_expr_bounds(amount, 0),
    }
}

fn check_expr_bounds(expr: &Expr, depth: usize) -> Result<(), MetadataBoundsError> {
    if depth > MAX_EXPR_DEPTH {
        return Err(MetadataBoundsError(format!(
            "expression nests deeper than {MAX_EXPR_DEPTH}"
        )));
    }
    let deeper = depth + 1;
    match expr {
        Expr::Literal(literal) => {
            if literal.depth() > MAX_VALUE_DEPTH {
                return Err(MetadataBoundsError(format!(
                    "literal nests deeper than {MAX_VALUE_DEPTH}"
                )));
            }
            Ok(())
        }
        Expr::Arg(_)
        | Expr::Config(_)
        | Expr::Binding(_)
        | Expr::SelfAddr
        | Expr::FreshId { .. }
        | Expr::FreshKey { .. } => Ok(()),
        Expr::Field(inner, _) | Expr::ResourceOf(inner) | Expr::IdsOf(inner) | Expr::Not(inner) => {
            check_expr_bounds(inner, deeper)
        }
        Expr::If {
            cond,
            then,
            otherwise,
        } => {
            check_expr_bounds(cond, deeper)?;
            check_expr_bounds(then, deeper)?;
            check_expr_bounds(otherwise, deeper)
        }
        Expr::Lookup {
            map: first,
            key: second,
        }
        | Expr::Contains {
            map: first,
            key: second,
        }
        | Expr::Pack {
            hi: first,
            lo: second,
        }
        | Expr::NfBucket {
            resource: first,
            ids: second,
        }
        | Expr::And(first, second)
        | Expr::Or(first, second)
        | Expr::Eq(first, second)
        | Expr::Lt(first, second) => {
            check_expr_bounds(first, deeper)?;
            check_expr_bounds(second, deeper)
        }
        Expr::List(elements) | Expr::Tuple(elements) => {
            for element in elements {
                check_expr_bounds(element, deeper)?;
            }
            Ok(())
        }
        Expr::SelfResource { material } => {
            for part in material {
                check_expr_bounds(part, deeper)?;
            }
            Ok(())
        }
        Expr::ChildKey {
            owner, material, ..
        }
        | Expr::OrderKey {
            owner, material, ..
        } => {
            check_expr_bounds(owner, deeper)?;
            for part in material {
                check_expr_bounds(part, deeper)?;
            }
            Ok(())
        }
    }
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
    /// The package's error names, in the index order a declined
    /// invocation's code refers to.
    ///
    /// The same shape as [`events`](Self::events) and for the same
    /// reasons: the kernel bounds a returned code without resolving it,
    /// the table is what turns that code into something a wallet can
    /// render, and immutability is what stops an index coming to mean
    /// something else. Empty for a package whose methods cannot decline.
    pub errors: Vec<String>,
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

    /// This registry extended by presented records, each registered at
    /// exactly the address it derives.
    ///
    /// The per-envelope composition derivation runs over: the base is
    /// what genesis serves, and a presented record can only enable calls
    /// to the one address its own content derives — a "false" claim
    /// registers a different instance, and the intended target stays
    /// unresolvable. First registration wins, so a presented record
    /// cannot displace a genesis one.
    #[must_use]
    pub fn with_instances(&self, records: &[InstanceMeta], hasher: &dyn Hasher) -> Self {
        let mut composed = self.clone();
        for meta in records {
            composed.create(hasher, meta.clone());
        }
        composed
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
    use crate::envelope::NULLIFIER_SLOT;
    use crate::hash::TestHasher;
    use crate::types::{PrincipalAddr, package_slot};

    /// A signature whose only effect points at `expr`.
    fn signature_over(expr: Expr) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(expr),
                mode: ModeExpr::Write {
                    requires: Presence::Either,
                },
                denomination: None,
            }],
            ..MethodSignature::default()
        }
    }

    fn one_method(signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert("m".into(), signature);
        metadata
    }

    /// Both sides of a bound: the structure at it is admitted, the one
    /// past it refused.
    fn assert_bounded(admitted: &PackageMetadata, refused: &PackageMetadata) {
        assert_eq!(check_metadata(admitted), Ok(()));
        assert!(
            check_metadata(refused).is_err(),
            "the checker admitted a structure past the bound"
        );
    }

    /// A left-nested projection chain, the shape the evaluator's own
    /// depth test uses.
    fn nested_projection(depth: usize) -> Expr {
        let mut expr = Expr::Arg(0);
        for _ in 0..depth {
            expr = Expr::Field(Box::new(expr), 0);
        }
        expr
    }

    fn nested_foreach(depth: usize) -> Clause {
        let mut clause = Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        for _ in 0..depth {
            clause = Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![clause],
            };
        }
        clause
    }

    #[test]
    fn expression_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH))),
            &one_method(signature_over(nested_projection(MAX_EXPR_DEPTH + 1))),
        );
    }

    #[test]
    fn abi_expressions_are_bounded_like_every_other_walk() {
        let derived = |depth: usize| MethodSignature {
            totality: Totality::Fallible,
            abi: vec![AbiParam::Derived(nested_projection(depth))],
            ..MethodSignature::default()
        };
        assert_bounded(
            &one_method(derived(MAX_EXPR_DEPTH)),
            &one_method(derived(MAX_EXPR_DEPTH + 1)),
        );
    }

    #[test]
    fn clause_nesting_is_bounded_where_the_evaluator_bounds_it() {
        assert_bounded(
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH)],
                ..MethodSignature::default()
            }),
            &one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![nested_foreach(MAX_CLAUSE_DEPTH + 1)],
                ..MethodSignature::default()
            }),
        );
    }

    #[test]
    fn a_range_cap_is_bounded_where_a_scan_pays_for_it() {
        // Nothing else in a declaration prices the cap: `footprint`
        // charges the interval's magnitude and conflict reads its bounds,
        // and both are the same for a page of one entry and a page of
        // four billion.
        let capped = |cap: u32| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::Effect {
                    guard: None,
                    target: TargetExpr::Range {
                        owner: Expr::SelfAddr,
                        collection: SlotId(PACKAGE_SLOT_BASE),
                        material: vec![],
                        lo: Expr::Literal(Value::U128(0)),
                        hi: Expr::Literal(Value::U128(u128::MAX)),
                        cap,
                    },
                    mode: ModeExpr::Read,
                    denomination: None,
                }],
                ..MethodSignature::default()
            })
        };
        assert_bounded(&capped(MAX_RANGE_CAP), &capped(MAX_RANGE_CAP + 1));
    }

    #[test]
    fn a_clause_tree_wider_than_a_signature_can_declare_is_refused() {
        let effect = Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let with = |count: usize| {
            one_method(MethodSignature {
                totality: Totality::Fallible,
                effects: vec![effect.clone(); count],
                ..MethodSignature::default()
            })
        };
        assert_bounded(
            &with(MAX_EFFECTS_PER_SIGNATURE),
            &with(MAX_EFFECTS_PER_SIGNATURE + 1),
        );
    }

    #[test]
    fn every_judgment_walks_its_subterms_at_publish() {
        // What a new variant costs is one recursive case, and a missing
        // one is silent: the subterm slips past publish and the package
        // is already immutable when routing refuses every call over it.
        // So the deep term is buried in each position in turn.
        let wrapped = |inner: &Expr| {
            let inner = || Box::new(inner.clone());
            let shallow = || Box::new(Expr::SelfAddr);
            vec![
                Expr::Not(inner()),
                Expr::And(inner(), shallow()),
                Expr::And(shallow(), inner()),
                Expr::Or(inner(), shallow()),
                Expr::Or(shallow(), inner()),
                Expr::Eq(inner(), shallow()),
                Expr::Eq(shallow(), inner()),
                Expr::Lt(inner(), shallow()),
                Expr::Lt(shallow(), inner()),
                Expr::Contains {
                    map: inner(),
                    key: shallow(),
                },
                Expr::Contains {
                    map: shallow(),
                    key: inner(),
                },
                Expr::If {
                    cond: inner(),
                    then: shallow(),
                    otherwise: shallow(),
                },
                Expr::If {
                    cond: shallow(),
                    then: inner(),
                    otherwise: shallow(),
                },
                Expr::If {
                    cond: shallow(),
                    then: shallow(),
                    otherwise: inner(),
                },
            ]
        };
        // One level down, so the chain that fits exactly still fits and
        // the one at the bound no longer does.
        for (admitted, refused) in wrapped(&nested_projection(MAX_EXPR_DEPTH - 1))
            .into_iter()
            .zip(wrapped(&nested_projection(MAX_EXPR_DEPTH)))
        {
            assert_bounded(
                &one_method(signature_over(admitted)),
                &one_method(signature_over(refused)),
            );
        }
    }

    #[test]
    fn literal_nesting_is_bounded_where_admission_bounds_it() {
        let literal = |depth: usize| {
            let mut value = Value::U64(0);
            for _ in 1..depth {
                value = Value::Tuple(vec![value]);
            }
            Expr::Literal(value)
        };
        assert_bounded(
            &one_method(signature_over(literal(MAX_VALUE_DEPTH))),
            &one_method(signature_over(literal(MAX_VALUE_DEPTH + 1))),
        );
    }

    /// Both name tables are bounded by the index that reaches them: the
    /// kernel checks an emitted event type and a returned error code
    /// without holding the metadata, so a table longer than the ceiling
    /// would name entries nothing could ever refer to.
    #[test]
    fn a_name_table_past_the_index_the_kernel_accepts_is_refused() {
        let events = |len: usize| PackageMetadata {
            events: vec![String::new(); len],
            ..PackageMetadata::default()
        };
        assert_bounded(
            &events(MAX_EVENT_TYPES as usize),
            &events(MAX_EVENT_TYPES as usize + 1),
        );

        let errors = |len: usize| PackageMetadata {
            errors: vec![String::new(); len],
            ..PackageMetadata::default()
        };
        assert_bounded(
            &errors(MAX_ERROR_CODES as usize),
            &errors(MAX_ERROR_CODES as usize + 1),
        );
    }

    #[test]
    fn an_ids_parameter_admits_only_a_bounded_duplicate_free_id_list() {
        let ids = |raw: &[u64]| Value::List(raw.iter().copied().map(Value::U64).collect());
        assert!(ParamType::Ids.admits(&ids(&[])));
        assert!(ParamType::Ids.admits(&ids(&[7, 9])));
        assert!(!ParamType::Ids.admits(&ids(&[7, 7])), "a duplicate id");
        let over_cap: Vec<u64> = (0..=MAX_IDS_PER_EDGE as u64).collect();
        assert!(!ParamType::Ids.admits(&ids(&over_cap)), "past the cap");
        assert!(
            !ParamType::Ids.admits(&Value::List(vec![Value::U128(7)])),
            "an element that is not an id"
        );
        assert!(!ParamType::Ids.admits(&Value::U64(7)), "not a list at all");
    }

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
    use crate::resource::holdings_range;
    use crate::types::AddressClass;

    fn clause() -> Clause {
        Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Delta,
            denomination: None,
        }
    }

    fn signature(params: Vec<ParamType>, abi: Vec<AbiParam>) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
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

    /// A rule-reading method's whole declaration is the cell its gate
    /// judges at: one point clause, read for a sign-in, exclusively
    /// written for a recovery op. Anything else is refused where the
    /// package publishes, under the accessibility's own error.
    #[test]
    fn a_rule_reading_method_declares_exactly_its_cell() {
        let shaped = |accessibility, mode| MethodSignature {
            totality: Totality::Fallible,
            accessibility,
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::SelfAddr),
                mode,
                denomination: None,
            }],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_abi(&shaped(Accessibility::Authorizing, ModeExpr::Read)),
            Ok(())
        );
        assert_eq!(
            check_abi(&shaped(
                Accessibility::RoleGated(AuthRole::Recovery),
                ModeExpr::Write {
                    requires: Presence::Either
                }
            )),
            Ok(())
        );

        // The right clause under the wrong mode, and no clause at all.
        assert_eq!(
            check_abi(&shaped(
                Accessibility::Authorizing,
                ModeExpr::Write {
                    requires: Presence::Either
                }
            )),
            Err(AbiError::AuthorizingShape)
        );
        assert_eq!(
            check_abi(&shaped(
                Accessibility::RoleGated(AuthRole::Primary),
                ModeExpr::Read
            )),
            Err(AbiError::RoleGatedShape)
        );
        assert_eq!(
            check_abi(&MethodSignature {
                totality: Totality::Fallible,
                accessibility: Accessibility::Authorizing,
                ..MethodSignature::default()
            }),
            Err(AbiError::AuthorizingShape)
        );

        // The accessor itself names the judging role.
        let sign_in = shaped(Accessibility::Authorizing, ModeExpr::Read);
        assert!(matches!(
            sign_in.gate(),
            Ok(GateShape::Rule {
                role: AuthRole::Primary,
                ..
            })
        ));
        let confirm = shaped(
            Accessibility::RoleGated(AuthRole::Confirmation),
            ModeExpr::Write {
                requires: Presence::Either,
            },
        );
        assert!(matches!(
            confirm.gate(),
            Ok(GateShape::Rule {
                role: AuthRole::Confirmation,
                ..
            })
        ));
        assert_eq!(MethodSignature::default().gate(), Ok(GateShape::Open));
    }

    /// A method requiring an identity its own caller names admits
    /// everyone while reading as guarded, so the declaration is refused
    /// where the package publishes.
    #[test]
    fn an_authority_the_caller_names_is_refused() {
        let guarded = |rule: RuleExpr| MethodSignature {
            totality: Totality::Fallible,
            accessibility: Accessibility::Guarded(rule),
            ..MethodSignature::default()
        };
        let require = |expr| guarded(RuleExpr::Require(expr));
        assert_eq!(check_abi(&require(Expr::SelfAddr)), Ok(()));
        assert_eq!(check_abi(&require(Expr::Config(0))), Ok(()));
        assert_eq!(
            check_abi(&require(Expr::Arg(0))),
            Err(AbiError::CallerNamedAuthority)
        );
        // And however deeply the argument is buried.
        assert_eq!(
            check_abi(&require(Expr::ResourceOf(Box::new(Expr::Field(
                Box::new(Expr::Arg(1)),
                0
            ))))),
            Err(AbiError::CallerNamedAuthority)
        );

        // One caller-named branch of a threshold is one branch the
        // caller satisfies for free, so every leaf answers.
        assert_eq!(
            check_abi(&guarded(RuleExpr::CountOf {
                count: 2,
                rules: vec![
                    RuleExpr::Require(Expr::Config(0)),
                    RuleExpr::Require(Expr::Config(1)),
                    RuleExpr::Require(Expr::Arg(0)),
                ],
            })),
            Err(AbiError::CallerNamedAuthority)
        );
    }

    /// A declared threshold sits under the caps a stored one is decoded
    /// under, so a signature that publishes cannot evaluate into a rule
    /// the decode gate would refuse.
    #[test]
    fn a_declared_rule_is_held_to_the_stored_rules_caps() {
        let guarded = |rule: RuleExpr| PackageMetadata {
            methods: BTreeMap::from([(
                "m".to_owned(),
                MethodSignature {
                    accessibility: Accessibility::Guarded(rule),
                    ..MethodSignature::default()
                },
            )]),
            ..PackageMetadata::default()
        };
        let leaf = || RuleExpr::Require(Expr::Config(0));
        let nest = |levels: usize| {
            let mut rule = leaf();
            for _ in 0..levels {
                rule = RuleExpr::CountOf {
                    count: 1,
                    rules: vec![rule],
                };
            }
            rule
        };

        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH - 1))).is_ok());
        assert!(check_metadata(&guarded(nest(MAX_RULE_DEPTH))).is_err());
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES],
            }))
            .is_ok()
        );
        assert!(
            check_metadata(&guarded(RuleExpr::CountOf {
                count: 1,
                rules: vec![leaf(); MAX_RULE_BRANCHES + 1],
            }))
            .is_err()
        );

        // The degenerate thresholds a stored rule is refused for: one
        // that admits anyone, and one that admits no one.
        for count in [0, 3] {
            assert!(
                check_metadata(&guarded(RuleExpr::CountOf {
                    count,
                    rules: vec![leaf(), leaf()],
                }))
                .is_err()
            );
        }
    }

    /// The custody shape: one possession read behind the rule cell's
    /// own, keyed by exactly what the gate mints — the badge-keyed vault
    /// for a fungible claim, the holdings entry at the id for an
    /// instance one.
    #[test]
    fn the_custody_shape_ties_possession_to_what_is_minted() {
        let shaped = |claim: CustodyClaim, effects| MethodSignature {
            totality: Totality::Fallible,
            accessibility: Accessibility::Custodial(claim),
            effects,
            ..MethodSignature::default()
        };
        let rule = || Clause::Effect {
            guard: None,
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        let read = |target| Clause::Effect {
            guard: None,
            target,
            mode: ModeExpr::Read,
            denomination: None,
        };
        let vault = |key: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: VAULT,
                material: vec![key],
            })
        };
        let badge = Expr::Arg(0);
        let id = Expr::Arg(1);

        // A fungible claim: the vault keyed by the badge it mints.
        let fungible = CustodyClaim::Fungible(badge.clone());
        let well_formed = shaped(fungible.clone(), vec![rule(), read(vault(badge.clone()))]);
        assert_eq!(check_abi(&well_formed), Ok(()));
        assert!(matches!(well_formed.gate(), Ok(GateShape::Custody { .. })));

        // An instance claim: the holdings entry at the id it mints.
        let instance = CustodyClaim::Instance {
            badge: badge.clone(),
            id: id.clone(),
        };
        let well_formed = shaped(
            instance.clone(),
            vec![rule(), read(holdings_entry(badge.clone(), id.clone()))],
        );
        assert_eq!(check_abi(&well_formed), Ok(()));
        assert!(matches!(well_formed.gate(), Ok(GateShape::Custody { .. })));

        // A possession read keyed by anything but what is minted would
        // verify holding one thing while minting another.
        assert_eq!(
            check_abi(&shaped(
                fungible.clone(),
                vec![rule(), read(vault(Expr::Arg(1)))]
            )),
            Err(AbiError::CustodialShape)
        );
        assert_eq!(
            check_abi(&shaped(
                instance.clone(),
                vec![rule(), read(holdings_entry(Expr::Arg(2), id.clone()))]
            )),
            Err(AbiError::CustodialShape)
        );
        assert_eq!(
            check_abi(&shaped(
                instance.clone(),
                vec![rule(), read(holdings_entry(badge.clone(), Expr::Arg(2)))]
            )),
            Err(AbiError::CustodialShape)
        );

        // Each claim admits its own shape of read and not the other's:
        // a resource is issued as one or the other, and the declaration
        // says which.
        assert_eq!(
            check_abi(&shaped(
                fungible.clone(),
                vec![rule(), read(holdings_entry(badge.clone(), id))]
            )),
            Err(AbiError::CustodialShape)
        );
        assert_eq!(
            check_abi(&shaped(instance, vec![rule(), read(vault(badge.clone()))])),
            Err(AbiError::CustodialShape)
        );

        // The rule cell's read alone, with no possession beside it, and
        // the old three-clause shape that declared both and meant
        // either.
        assert_eq!(
            check_abi(&shaped(fungible.clone(), vec![rule()])),
            Err(AbiError::CustodialShape)
        );
        assert_eq!(
            check_abi(&shaped(
                fungible,
                vec![
                    rule(),
                    read(vault(badge.clone())),
                    read(holdings_range(badge, 1)),
                ]
            )),
            Err(AbiError::CustodialShape)
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

    /// What a total mark cannot survive, read off the declaration rather
    /// than off the code.
    ///
    /// A leg reads the mark and commits without waiting, so what it has
    /// to exclude is every way the method could still come back with a
    /// refusal. The artifact scan covers the one that leaves the type
    /// system — a trap — and this is the one it cannot see: a gate that
    /// turns the caller away before the body runs.
    #[test]
    fn a_total_mark_needs_a_body_the_declaration_answers_for() {
        let total = |signature: MethodSignature| MethodSignature {
            totality: Totality::Total,
            ..signature
        };

        // The shape that admits: public, and answering for itself.
        assert_eq!(
            check_declarations(&total(MethodSignature::default())),
            Ok(())
        );

        // Every gate is a caller this method can turn away.
        for accessibility in [
            Accessibility::Guarded(RuleExpr::Require(Expr::SelfAddr)),
            Accessibility::Authorizing,
            Accessibility::Custodial(CustodyClaim::Fungible(Expr::Arg(0))),
            Accessibility::RoleGated(AuthRole::Primary),
        ] {
            assert_eq!(
                check_declarations(&total(MethodSignature {
                    accessibility,
                    ..MethodSignature::default()
                })),
                Err(DeclarationError::GatedTotality),
            );
        }
    }

    /// A presence requirement is about the leaf a write lands on, so the
    /// targets that name one carry it and the interval does not. Refused
    /// at publish, where an author hears about it — and again at
    /// materialization, which honours the requirement rather than
    /// reading past it.
    #[test]
    fn a_presence_requirement_needs_a_target_that_names_a_leaf() {
        let declared = |target, requires| {
            check_declarations(&MethodSignature {
                effects: vec![Clause::Effect {
                    guard: None,
                    target,
                    mode: ModeExpr::Write { requires },
                    denomination: None,
                }],
                ..MethodSignature::default()
            })
        };
        let point = TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
        });
        let entry = TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
            order: Expr::Literal(Value::U128(7)),
        };
        let range = TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: SlotId(PACKAGE_SLOT_BASE),
            material: vec![],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: 4,
        };

        for requires in [Presence::Absent, Presence::Present] {
            // A cell and one collection entry each name exactly one leaf.
            assert_eq!(declared(point.clone(), requires), Ok(()), "{requires:?}");
            assert_eq!(declared(entry.clone(), requires), Ok(()), "{requires:?}");
            // An interval names none.
            assert_eq!(
                declared(range.clone(), requires),
                Err(DeclarationError::PresenceOnInterval { clause: 0 }),
                "{requires:?}"
            );
        }

        // The indifferent requirement is what every range write carries.
        assert_eq!(declared(range, Presence::Either), Ok(()));
    }

    /// "Create it if absent, otherwise update it" is two writes on one
    /// cell requiring opposite presences, and it is not a contradiction:
    /// no evaluation declares both. Complementarity is syntactic,
    /// because publish has no arguments — the same standard the target
    /// comparison beside it holds to.
    #[test]
    fn complementary_guards_carry_opposite_presences_and_nothing_else_does() {
        let cond = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        let write = |guard: Option<Expr>, requires| Clause::Effect {
            guard: guard.map(Box::new),
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![],
            }),
            mode: ModeExpr::Write { requires },
            denomination: None,
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // What an `if`/`else` emits, in either order.
        let negated = Expr::Not(Box::new(cond()));
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(negated.clone()), Presence::Present),
            ]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                write(Some(negated), Presence::Present),
                write(Some(cond()), Presence::Absent),
            ]),
            Ok(())
        );

        // Two guards that are merely different can both hold, so the
        // contradiction stands.
        let other = Expr::Eq(Box::new(Expr::Arg(1)), Box::new(Expr::Config(0)));
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(other), Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );

        // And a guard is complementary to nothing when the other clause
        // fires always.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(None, Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
    }

    /// Every pair of writes that can both fire is compared, not just the
    /// first that meets.
    ///
    /// Complementarity is a relation between two clauses rather than a
    /// property of the target they share, so a clause complementary to
    /// one of the others still meets all the rest — and a fold that
    /// stopped at the first meeting would carry a contradiction past the
    /// gate for the evaluated set to find later, where an author cannot
    /// hear it.
    #[test]
    fn a_write_meets_every_other_write_it_can_fire_beside() {
        let cond = || Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        let write = |guard: Option<Expr>, requires| Clause::Effect {
            guard: guard.map(Box::new),
            target: own_point(package_slot(0), vec![]),
            mode: ModeExpr::Write { requires },
            denomination: None,
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        // The arms of one branch, and a third clause that fires always.
        // It meets the first, which agrees with it — and contradicts the
        // second, which is the pair the fold would never have asked
        // about.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
                write(None, Presence::Absent),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
        // The same three in the order that hides it best: the always-
        // firing clause is written first, so the arm that agrees with it
        // is met before the arm that does not.
        assert_eq!(
            declared(vec![
                write(None, Presence::Absent),
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
            ]),
            Err(DeclarationError::PresenceConflict)
        );
        // And the shape that is not a contradiction still stands beside
        // a third clause nothing disagrees with.
        assert_eq!(
            declared(vec![
                write(Some(cond()), Presence::Absent),
                write(Some(Expr::Not(Box::new(cond()))), Presence::Present),
                write(None, Presence::Either),
            ]),
            Ok(())
        );
    }

    /// A declaration states an access some execution can hold, or it does
    /// not publish.
    ///
    /// The world hands out one handle per declared access and reads its
    /// type off the target's shape and the mode. A pairing it has no
    /// handle for is a clause every call aborts at — and the gate that
    /// exists to answer an author is the place to say so, rather than
    /// leaving a package published and unusable.
    #[test]
    fn a_pairing_no_handle_is_built_for_does_not_publish() {
        let declared = |target, mode, denomination: Option<Expr>| {
            check_declarations(&MethodSignature {
                effects: vec![Clause::Effect {
                    guard: None,
                    target,
                    mode,
                    denomination: denomination.map(Box::new),
                }],
                ..MethodSignature::default()
            })
        };
        let entry = || TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: package_slot(0),
            material: vec![a_resource()],
            order: Expr::Literal(Value::U128(1)),
        };
        let interval = || own_interval(package_slot(1), vec![a_resource()]);
        let refused = Err(DeclarationError::UnsupportedAccess { clause: 0 });

        // Value moves through a leaf, never through an interval: a
        // collection's entries move by being named, which is what a
        // rewrite of the interval is.
        for target in [entry(), interval()] {
            for mode in [ModeExpr::Delta, ModeExpr::Reserve(Expr::Arg(0))] {
                assert_eq!(
                    declared(target.clone(), mode.clone(), Some(a_resource())),
                    refused,
                    "{target:?} {mode:?}"
                );
            }
            // Nor is a collection something a locked read names: what a
            // lock pins is one leaf's value.
            assert_eq!(declared(target.clone(), ModeExpr::Locked, None), refused);
            // The two it does have.
            assert_eq!(declared(target.clone(), ModeExpr::Read, None), Ok(()));
            assert_eq!(
                declared(
                    target,
                    ModeExpr::Write {
                        requires: Presence::Either
                    },
                    Some(a_resource()),
                ),
                Ok(())
            );
        }
    }

    /// Trap freedom for a total leg rests on every declared handle being
    /// materialized, and a guarded-out clause materializes none. The
    /// mark and the precision are the trade.
    #[test]
    fn a_total_method_carries_no_guard() {
        let guarded = Clause::Effect {
            guard: Some(Box::new(Expr::Eq(
                Box::new(Expr::Arg(0)),
                Box::new(Expr::Config(0)),
            ))),
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        };
        assert_eq!(
            check_declarations(&MethodSignature {
                totality: Totality::Total,
                effects: vec![guarded],
                ..MethodSignature::default()
            }),
            Err(DeclarationError::GuardedTotality)
        );

        // The binding alone is enough: it is the parameter an absent
        // capability travels beside.
        assert_eq!(
            check_declarations(&MethodSignature {
                totality: Totality::Total,
                abi: vec![AbiParam::Guard(0)],
                effects: vec![Clause::Effect {
                    guard: None,
                    target: TargetExpr::Point(Expr::SelfAddr),
                    mode: ModeExpr::Read,
                    denomination: None,
                }],
                ..MethodSignature::default()
            }),
            Err(DeclarationError::GuardedTotality)
        );
    }

    /// Metadata can be authored rather than derived, so the
    /// contradiction the macro refuses at the second call site is
    /// refused here too — against the target expressions, since publish
    /// has no arguments to evaluate them with.
    #[test]
    fn opposite_presence_requirements_on_one_target_do_not_publish() {
        let cell = |material| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                slot: SlotId(PACKAGE_SLOT_BASE),
                material,
            })
        };
        let write = |requires| Clause::Effect {
            guard: None,
            target: cell(vec![]),
            mode: ModeExpr::Write { requires },
            denomination: None,
        };
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };

        assert_eq!(
            declared(vec![write(Presence::Absent), write(Presence::Present)]),
            Err(DeclarationError::PresenceConflict)
        );
        assert_eq!(
            declared(vec![write(Presence::Present), write(Presence::Absent)]),
            Err(DeclarationError::PresenceConflict)
        );

        // The indifferent clause concedes rather than absorbing, so a
        // requirement still meets its opposite across one written
        // between them — in either order, and whichever side it sits.
        for opposed in [
            vec![
                write(Presence::Either),
                write(Presence::Absent),
                write(Presence::Present),
            ],
            vec![
                write(Presence::Present),
                write(Presence::Either),
                write(Presence::Absent),
            ],
            vec![
                write(Presence::Absent),
                write(Presence::Either),
                write(Presence::Either),
                write(Presence::Present),
            ],
        ] {
            assert_eq!(declared(opposed), Err(DeclarationError::PresenceConflict));
        }

        // What is not a contradiction: a named requirement beside the
        // indifferent one, the same requirement twice, and two named
        // requirements on targets that are not the same expression.
        assert_eq!(
            declared(vec![write(Presence::Either), write(Presence::Absent)]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                write(Presence::Either),
                write(Presence::Absent),
                write(Presence::Absent),
            ]),
            Ok(())
        );
        assert_eq!(
            declared(vec![write(Presence::Absent), write(Presence::Absent)]),
            Ok(())
        );
        assert_eq!(
            declared(vec![
                write(Presence::Absent),
                Clause::Effect {
                    guard: None,
                    target: cell(vec![Expr::Config(0)]),
                    mode: ModeExpr::Write {
                        requires: Presence::Present,
                    },
                    denomination: None,
                },
            ]),
            Ok(())
        );
    }

    /// A denomination list is read at the positions it indexes, so the
    /// two ways it can fail to index anything are refused at publish.
    ///
    /// A published package could carry a hand-written metadata section,
    /// so neither is a fact about what the tracer emits: what admission
    /// reads has to line up with the parameters whatever wrote it.
    #[test]
    fn a_denomination_names_a_parameter_that_carries_value() {
        let denominating = |params: Vec<ParamType>, denominations: Vec<Option<Expr>>| {
            check_declarations(&MethodSignature {
                params,
                denominations,
                ..MethodSignature::default()
            })
        };

        // No list at all is the method that fixes nothing, which is most
        // of them.
        assert_eq!(denominating(vec![ParamType::Bucket], vec![]), Ok(()));
        // A list covering the parameters, fixing the one that carries
        // value and leaving the other open.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![Some(Expr::Config(0)), None]
            ),
            Ok(())
        );

        // A list that does not cover them indexes positions nobody agrees
        // on.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![Some(Expr::Config(0))]
            ),
            Err(DeclarationError::DenominationArity {
                expected: 2,
                found: 1
            })
        );
        // A denomination on a position that carries no value denominates
        // nothing.
        assert_eq!(
            denominating(
                vec![ParamType::Bucket, ParamType::U128],
                vec![None, Some(Expr::Config(0))]
            ),
            Err(DeclarationError::DenominationKind {
                param: 1,
                kind: "u128"
            })
        );
        // Both edge kinds carry value, so both take one.
        assert_eq!(
            denominating(vec![ParamType::NfBucket], vec![Some(Expr::Config(0))]),
            Ok(())
        );
    }

    /// A resource address, for a value cell to be keyed by.
    fn a_resource() -> Expr {
        Expr::Literal(Value::Address(Address::new(
            [7; 31],
            AddressClass::Resource,
        )))
    }

    /// A leaf under the declaring instance, at `slot` and keyed by
    /// `material`.
    fn own_point(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
        TargetExpr::Point(Expr::ChildKey {
            owner: Box::new(Expr::SelfAddr),
            slot,
            material,
        })
    }

    /// The whole order-key space of a collection under the declaring
    /// instance, at a cap no test reaches.
    fn own_interval(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
        TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: slot,
            material,
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(u128::MAX)),
            cap: 4,
        }
    }

    /// A signature declaring exactly one clause.
    fn one_clause(
        target: TargetExpr,
        mode: ModeExpr,
        denomination: Option<Expr>,
    ) -> MethodSignature {
        MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target,
                mode,
                denomination: denomination.map(Box::new),
            }],
            ..MethodSignature::default()
        }
    }

    /// Whether a signature is refused for naming a protocol cell in a
    /// shape that cell does not have.
    fn misshapen(signature: &MethodSignature) -> bool {
        matches!(
            check_declarations(signature),
            Err(DeclarationError::ProtocolSlotShape { .. })
        )
    }

    /// The protocol's value cells, and the shape each one has.
    ///
    /// Exhaustive over the three on purpose. The corpus declares a vault
    /// in two of its four modes and reaches the claims cell without ever
    /// opening it, so a rule about the rest would be a rule nothing
    /// holds.
    #[test]
    fn a_value_cell_is_keyed_by_what_it_holds() {
        let moves = [
            ModeExpr::Write {
                requires: Presence::Either,
            },
            ModeExpr::Delta,
            ModeExpr::Reserve(Expr::Arg(0)),
        ];
        // A vault and the delivery cell beside it are keyed by the
        // resource they hold and say so wherever any of it can move. A
        // read moves none, and the custody gate's possession read is
        // exactly that.
        for slot in [VAULT, CLAIMS] {
            for mode in moves.clone() {
                let keyed = || own_point(slot, vec![a_resource()]);
                assert_eq!(
                    check_declarations(&one_clause(keyed(), mode.clone(), Some(a_resource()))),
                    Ok(()),
                    "{slot:?} {mode:?}"
                );
                // Keyed by one resource and denominated in another: two
                // answers to what one leaf holds.
                assert!(misshapen(&one_clause(
                    keyed(),
                    mode.clone(),
                    Some(Expr::Arg(0))
                )));
                // And no answer at all, where value moves.
                assert!(misshapen(&one_clause(keyed(), mode, None)));
            }
            let read = |target| one_clause(target, ModeExpr::Read, None);
            assert_eq!(
                check_declarations(&read(own_point(slot, vec![a_resource()]))),
                Ok(())
            );
            // Value is never locked, never keyed by nothing, and never a
            // collection.
            assert!(misshapen(&one_clause(
                own_point(slot, vec![a_resource()]),
                ModeExpr::Locked,
                None
            )));
            assert!(misshapen(&read(own_point(slot, vec![]))));
            assert!(misshapen(&read(own_interval(slot, vec![a_resource()]))));
        }

        // Holdings are the same statement in collection form: one
        // resource's instances, in the interval narrowed by it.
        let holdings = || own_interval(NF_VAULT, vec![a_resource()]);
        let write = || ModeExpr::Write {
            requires: Presence::Either,
        };
        assert_eq!(
            check_declarations(&one_clause(holdings(), write(), Some(a_resource()))),
            Ok(())
        );
        assert!(misshapen(&one_clause(
            own_point(NF_VAULT, vec![a_resource()]),
            write(),
            Some(a_resource())
        )));
        assert!(misshapen(&one_clause(
            holdings(),
            ModeExpr::Delta,
            Some(a_resource())
        )));
    }

    /// The protocol's cells that hold no value, and the shape each one
    /// has.
    ///
    /// Exhaustive over the rest of the vocabulary, on the same terms as
    /// the value cells beside it.
    #[test]
    fn a_protocol_cell_holding_no_value_is_declared_in_its_own_shape() {
        let write = || ModeExpr::Write {
            requires: Presence::Either,
        };
        let creates = || ModeExpr::Write {
            requires: Presence::Absent,
        };
        let plain = |target, mode| one_clause(target, mode, None);

        // A configuration leaf is read and never rewritten; a stored
        // authority cell is read or rewritten whole. Neither is keyed by
        // anything and neither holds value.
        for mode in [ModeExpr::Locked, ModeExpr::Read] {
            assert_eq!(
                check_declarations(&plain(own_point(CONFIG, vec![]), mode)),
                Ok(())
            );
        }
        assert!(misshapen(&plain(own_point(CONFIG, vec![]), write())));
        for mode in [ModeExpr::Read, write(), creates()] {
            assert_eq!(
                check_declarations(&plain(own_point(AUTH, vec![]), mode)),
                Ok(())
            );
        }
        assert!(misshapen(&plain(own_point(AUTH, vec![]), ModeExpr::Delta)));
        assert!(misshapen(&plain(
            own_point(AUTH, vec![a_resource()]),
            write()
        )));

        // A record and an instance's data are written where the thing
        // they describe is not there yet, and not again.
        for (slot, material) in [
            (RESOURCE, vec![a_resource()]),
            (INSTANCE, vec![a_resource(), Expr::Arg(0)]),
        ] {
            let keyed = || own_point(slot, material.clone());
            assert_eq!(
                check_declarations(&plain(keyed(), creates())),
                Ok(()),
                "{slot:?}"
            );
            assert_eq!(
                check_declarations(&plain(keyed(), ModeExpr::Read)),
                Ok(()),
                "{slot:?}"
            );
            assert!(misshapen(&plain(keyed(), write())));
            // Nothing here holds value, so nothing here denominates.
            assert!(misshapen(&one_clause(
                keyed(),
                creates(),
                Some(a_resource())
            )));
        }
        // Keyed by the wrong number of terms: an instance is a resource
        // and an id, and a record is a resource.
        assert!(misshapen(&plain(own_point(RESOURCE, vec![]), creates())));
        assert!(misshapen(&plain(
            own_point(INSTANCE, vec![a_resource()]),
            creates()
        )));
    }

    /// A value cell is keyed by what it holds, so no leaf holds two
    /// resources.
    ///
    /// The property this buys is not the comparison itself but what
    /// follows from it: the denomination is in the material, the
    /// material is in the key, so two clauses reaching one leaf name one
    /// resource however differently they spell it. A cell that could be
    /// filled under one name and emptied under another would convert
    /// value by holding it.
    #[test]
    fn a_value_cell_is_reached_by_the_name_of_what_it_holds() {
        let other = || {
            Expr::Literal(Value::Address(Address::new(
                [8; 31],
                AddressClass::Resource,
            )))
        };
        let own = |material: Vec<Expr>| own_point(package_slot(0), material);

        // Keyed by what it holds, in the modes that move it.
        for mode in [
            ModeExpr::Delta,
            ModeExpr::Reserve(Expr::Arg(0)),
            ModeExpr::Write {
                requires: Presence::Either,
            },
        ] {
            assert_eq!(
                check_declarations(&one_clause(
                    own(vec![a_resource()]),
                    mode.clone(),
                    Some(a_resource())
                )),
                Ok(()),
                "{mode:?}"
            );
            // Named as something the key does not.
            assert_eq!(
                check_declarations(&one_clause(
                    own(vec![a_resource()]),
                    mode.clone(),
                    Some(other())
                )),
                Err(DeclarationError::DenominationNotKeyed { clause: 0 }),
                "{mode:?}"
            );
            // Or keyed by nothing at all, which names no cell to hold it.
            assert_eq!(
                check_declarations(&one_clause(own(vec![]), mode, Some(a_resource()))),
                Err(DeclarationError::DenominationNotKeyed { clause: 0 })
            );
        }

        // A collection is the same statement: the resource is the term
        // its entries hang under.
        let interval = |material| own_interval(package_slot(1), material);
        assert_eq!(
            check_declarations(&one_clause(
                interval(vec![a_resource()]),
                ModeExpr::Write {
                    requires: Presence::Either
                },
                Some(a_resource())
            )),
            Ok(())
        );
        assert_eq!(
            check_declarations(&one_clause(
                interval(vec![other()]),
                ModeExpr::Write {
                    requires: Presence::Either
                },
                Some(a_resource())
            )),
            Err(DeclarationError::DenominationNotKeyed { clause: 0 })
        );

        // A fresh key carries no material, so nothing could find it
        // again to take value out of it.
        assert_eq!(
            check_declarations(&one_clause(
                TargetExpr::Point(Expr::FreshKey { slot: 0 }),
                ModeExpr::Write {
                    requires: Presence::Either
                },
                Some(a_resource())
            )),
            Err(DeclarationError::DenominationNotKeyed { clause: 0 })
        );
    }

    /// A commutative movement says what it moves.
    ///
    /// `Delta` and `Reserve` move value and do nothing else, so the cell
    /// is one that holds value whether or not the declaration says which.
    /// Refused at materialization too, which has the evaluated key to
    /// name; this is the same verdict where an author hears it.
    #[test]
    fn a_movement_that_names_no_resource_does_not_publish() {
        let own = |material: Vec<Expr>| own_point(package_slot(0), material);
        for mode in [ModeExpr::Delta, ModeExpr::Reserve(Expr::Arg(0))] {
            assert_eq!(
                check_declarations(&one_clause(own(vec![a_resource()]), mode.clone(), None)),
                Err(DeclarationError::UndenominatedMovement { clause: 0 }),
                "{mode:?}"
            );
        }
        // A write is the mode a byte cell takes too, so it says nothing
        // by saying nothing — which is what makes it a byte cell.
        assert_eq!(
            check_declarations(&one_clause(
                own(vec![]),
                ModeExpr::Write {
                    requires: Presence::Either
                },
                None
            )),
            Ok(())
        );
        assert_eq!(
            check_declarations(&one_clause(own(vec![]), ModeExpr::Read, None)),
            Ok(())
        );
    }

    /// One cell holds one thing, and a signature says so once.
    ///
    /// The denomination chooses which handle a clause materializes, so a
    /// leaf denominated by one clause and not by another is a leaf a body
    /// holds as a vault and as a byte cell at once — and a balance
    /// written through the byte handle and debited through the value one
    /// is value from nowhere. What makes this the whole of the property
    /// is that the two clauses need not agree on anything else: a mode, a
    /// presence and a guard are all free.
    #[test]
    fn one_cell_is_not_a_vault_and_a_byte_cell_at_once() {
        let held = || Some(a_resource());
        let declared = |clauses: Vec<Clause>| {
            check_declarations(&MethodSignature {
                effects: clauses,
                ..MethodSignature::default()
            })
        };
        let write = || ModeExpr::Write {
            requires: Presence::Either,
        };
        let effect = |target, mode, denomination: Option<Expr>| Clause::Effect {
            guard: None,
            target,
            mode,
            denomination: denomination.map(Box::new),
        };

        // One leaf, two answers — the shape that would mint.
        let leaf = || own_point(package_slot(0), vec![a_resource()]);
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(leaf(), write(), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // The reading modes are no exception: a read of a vault and a
        // byte read of the same leaf still disagree about what came out.
        assert_eq!(
            declared(vec![
                effect(leaf(), ModeExpr::Delta, held()),
                effect(leaf(), ModeExpr::Read, None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // Nor does a guard make them arms of one answer: what a cell
        // holds is not a question an execution answers.
        let guarded = |cond, denomination| Clause::Effect {
            guard: Some(Box::new(cond)),
            target: leaf(),
            mode: write(),
            denomination,
        };
        let cond = Expr::Eq(Box::new(Expr::Arg(0)), Box::new(Expr::Config(0)));
        assert_eq!(
            declared(vec![
                guarded(cond.clone(), Some(Box::new(a_resource()))),
                guarded(Expr::Not(Box::new(cond)), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );

        // Two intervals of one collection are two targets over one set of
        // entries, so the disagreement is about the entries and comparing
        // targets would let it through. Overlapping or not: what the
        // collection holds is the collection's.
        let interval = |hi| TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: package_slot(1),
            material: vec![a_resource()],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(hi)),
            cap: 4,
        };
        assert_eq!(
            declared(vec![
                effect(interval(u128::MAX), write(), held()),
                effect(interval(10), write(), None),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );
        // And an entry of it is the same statement at width one.
        assert_eq!(
            declared(vec![
                effect(interval(u128::MAX), write(), held()),
                effect(
                    TargetExpr::Entry {
                        owner: Expr::SelfAddr,
                        collection: package_slot(1),
                        material: vec![a_resource()],
                        order: Expr::Literal(Value::U128(3)),
                    },
                    write(),
                    None,
                ),
            ]),
            Err(DeclarationError::MixedContents { clause: 1 })
        );

        // Agreeing clauses are what a body that reads and writes one cell
        // declares, and they stand — in both directions.
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(leaf(), ModeExpr::Read, held()),
            ]),
            Ok(())
        );
        let bytes = || own_point(package_slot(2), vec![]);
        assert_eq!(
            declared(vec![
                effect(bytes(), write(), None),
                effect(bytes(), ModeExpr::Read, None),
            ]),
            Ok(())
        );
        // Two different cells answer for themselves.
        assert_eq!(
            declared(vec![
                effect(leaf(), write(), held()),
                effect(bytes(), write(), None),
            ]),
            Ok(())
        );
    }

    /// A slot naming no cell has no shape to be held to, so it is not a
    /// slot a signature may name at all: the unassigned part of the
    /// vocabulary's band, and the kernel's own at the top.
    #[test]
    fn a_slot_the_protocol_assigns_no_cell_is_not_a_signature_to_name() {
        let declaring = |slot| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    slot,
                    material: vec![],
                }),
                mode: ModeExpr::Read,
                denomination: None,
            }],
            ..MethodSignature::default()
        };
        // Everything below the base the vocabulary has not spoken for.
        let assigned = [VAULT, CLAIMS, CONFIG, AUTH, RESOURCE, NF_VAULT, INSTANCE];
        for slot in (0..PACKAGE_SLOT_BASE).map(SlotId) {
            if assigned.contains(&slot) {
                continue;
            }
            assert_eq!(
                check_declarations(&declaring(slot)),
                Err(DeclarationError::ReservedSlot {
                    clause: 0,
                    slot: slot.0
                }),
                "{slot:?}"
            );
        }
        // The kernel's own band: the publish path's cell and the
        // envelope's, neither of which any signature declares.
        for slot in [PACKAGE_SLOT, NULLIFIER_SLOT] {
            assert_eq!(
                check_declarations(&declaring(slot)),
                Err(DeclarationError::ReservedSlot {
                    clause: 0,
                    slot: slot.0
                }),
                "{slot:?}"
            );
        }
        // And the band between them is a package's own, where the
        // vocabulary has nothing to say.
        assert_eq!(check_declarations(&declaring(package_slot(0))), Ok(()));
        assert_eq!(
            check_declarations(&declaring(SlotId(KERNEL_SLOT_BASE - 1))),
            Ok(())
        );
    }

    /// Every way a signature can write somebody else's prefix, refused
    /// where its author can see it.
    #[test]
    fn a_signature_reaching_another_prefix_is_refused() {
        // Each target in a mode it has a handle for: value moves through
        // a leaf, and an entry of a collection is rewritten.
        let declaring = |target: TargetExpr, mode: ModeExpr| MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::Effect {
                guard: None,
                target,
                mode,
                denomination: Some(Box::new(a_resource())),
            }],
            ..MethodSignature::default()
        };
        let child_of = |owner: Expr| {
            TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(owner),
                slot: SlotId(PACKAGE_SLOT_BASE),
                material: vec![a_resource()],
            })
        };
        let entry_of = |slot: u16, order: u128| TargetExpr::Entry {
            owner: Expr::SelfAddr,
            collection: SlotId(slot),
            material: vec![a_resource()],
            order: Expr::Literal(Value::U128(order)),
        };
        let write = || ModeExpr::Write {
            requires: Presence::Either,
        };

        // Its own prefix, however the key under it is derived.
        assert_eq!(
            check_declarations(&declaring(child_of(Expr::SelfAddr), ModeExpr::Delta)),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(entry_of(PACKAGE_SLOT_BASE + 2, 1), write())),
            Ok(())
        );
        assert_eq!(
            check_declarations(&declaring(entry_of(PACKAGE_SLOT_BASE + 1, 0), write())),
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
                check_declarations(&declaring(child_of(owner), ModeExpr::Delta)),
                Err(DeclarationError::ForeignPrefix { clause: 0 })
            );
        }

        // And inside a `for-each` body, where the element is the owner.
        let looped = MethodSignature {
            totality: Totality::Fallible,
            effects: vec![Clause::ForEach {
                guard: None,
                list: Expr::Arg(0),
                body: vec![Clause::Effect {
                    guard: None,
                    target: child_of(Expr::Binding(0)),
                    mode: ModeExpr::Delta,
                    denomination: Some(Box::new(a_resource())),
                }],
            }],
            ..MethodSignature::default()
        };
        assert_eq!(
            check_declarations(&looped),
            Err(DeclarationError::ForeignPrefix { clause: 1 })
        );
    }
}

//! The effect-signature vocabulary: what a published method declares
//! about its parameters, its accessibility, and its ABI binding.

use hyperscale_hbor::Hbor;

use crate::auth::{AuthRole, RoleSet};
use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::invoke::EdgeKind;
use crate::resource::holdings_entry;
use crate::rule::{RuleExpr, StoredRule};
use crate::types::{MAX_IDS_PER_EDGE, Value};
use crate::vocabulary::VAULT;

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

/// Why a signature's accessibility names no gate: the declaration is
/// not the shape that accessibility pins.
///
/// Its own vocabulary rather than a slice of
/// [`AbiError`](crate::publish::AbiError), so the one consumer that
/// classifies these refusals matches them exhaustively — a new refusal
/// here is a compile error there, never a silent fall-through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum GateError {
    /// An authorizing method whose declaration is not exactly one point
    /// read — the cell its stored rule lives in.
    #[error("an authorizing method declares exactly one point read: its rule cell")]
    AuthorizingShape,
    /// A role-gated method whose declaration is not exactly one point
    /// write — the same cell, rewritten whole.
    #[error("a role-gated method declares exactly one point write: its rule cell")]
    RoleGatedShape,
    /// A custodial method whose declaration is not the pinned custody
    /// shape.
    #[error("a custodial method declares the custody shape: its rule cell and one possession read")]
    CustodialShape,
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
    pub fn gate(&self) -> Result<GateShape<'_>, GateError> {
        match &self.accessibility {
            Accessibility::Public => Ok(GateShape::Open),
            Accessibility::Guarded(rule) => Ok(GateShape::Guarded(rule)),
            Accessibility::Authorizing => self
                .rule_point(&|mode| matches!(mode, ModeExpr::Read))
                .map(|cell| GateShape::Rule {
                    cell,
                    role: AuthRole::Primary,
                })
                .ok_or(GateError::AuthorizingShape),
            Accessibility::RoleGated(role) => self
                .rule_point(&|mode| matches!(mode, ModeExpr::Write { .. }))
                .map(|cell| GateShape::Rule { cell, role: *role })
                .ok_or(GateError::RoleGatedShape),
            Accessibility::Custodial(claim) => self.custody(claim).ok_or(GateError::CustodialShape),
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

#[cfg(test)]
mod tests {
    use super::*;

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
}

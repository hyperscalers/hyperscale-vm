//! The fungible account: the package every principal answers.
//!
//! The package in one place: the effect signatures its guest executes,
//! the roles it stores under where it has any of its own, and the
//! wrappers a client calls it through. A signature and the wrapper
//! mirroring it drift the moment they live apart.

use hyperscale_vm_effects::dsl::{Clause, ModeExpr, TargetExpr};
use hyperscale_vm_effects::vocabulary::{AUTH, CLAIMS, NF_MOVE_CAP, VAULT};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, AuthRole, Expr, MethodSignature, PackageMetadata, ParamType,
    PrincipalAddr, ResourceRef, RoleSet, Rule, Totality, Value, holdings_range, self_child,
};
use hyperscale_vm_manifest_builder::{Bucket, BucketArg, Proof, TypedBuilder, TypedError};

/// The fungible account.
///
/// `withdraw(resource, amount)`: reserve `amount` on the caller's vault
/// for `resource`. `deposit(bucket)`: delta on the recipient's vault plus
/// the claims-area fallback cell, both keyed by the bucket's resource.
/// `authorize()`: nothing but its own gate — naming it mints the
/// account's identity as evidence for later nodes of the intent, which
/// is how an account acts through calls its own signature proof would
/// not open. `securify(roles, delay)`: create the stored-authority cell
/// `authorize` reads, refusing one that already exists — the transition
/// off the address-derived rule, one-way. `propose(roles, delay)`, `cancel()`, `confirm()`: the timed
/// recovery surface, each judged against the stored role its
/// accessibility names — recovery proposes a full replacement that
/// matures after the stored delay, primary cancels one that has not,
/// confirmation enacts one early.
///
/// Spending and writing require the account's own authority; being paid
/// does not. Anyone may credit you, and a transfer therefore still
/// composes under the sender's single signature — the recipient is not
/// asked for one, because nothing about a deposit is theirs to refuse.
/// A method writing a leaf under the target's prefix is gated for the
/// same reason a withdrawal is, though it moves nothing.
///
/// No method reads another account's balance. A precondition on mutable
/// state is a fresh [`ModeExpr::Read`], which makes the read's owner a
/// participant — the account surface has no shape that wants one yet.
#[must_use]
pub fn metadata() -> PackageMetadata {
    let mut methods = PackageMetadata::default();
    funds_methods(&mut methods);
    holdings_methods(&mut methods);
    authority_methods(&mut methods);
    // Index order is the contract: the guest emits 0 and 1, and these are
    // what those indexes mean.
    methods.events = vec!["withdrawn".into(), "deposited".into()];
    methods
}

/// `withdraw` and `deposit`: the account moving funds, the spending side
/// gated by the identity its sign-in mints.
fn funds_methods(methods: &mut PackageMetadata) {
    methods.methods.insert(
        "withdraw".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(Expr::SelfAddr),
            mints: None,
            issues: None,
            params: vec![ParamType::Address, ParamType::U128],
            // The grant is the bucket, so the amount the manifest asked
            // for reaches the declaration and not the body: what the
            // kernel judged is what it hands over.
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![Expr::Arg(0)],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(VAULT, vec![Expr::Arg(0)])),
                mode: ModeExpr::Reserve(Expr::Arg(1)),
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "deposit".into(),
        MethodSignature {
            // What the composite below earns: a deposit that cannot reach
            // the vault lands in the claims cell instead, so the two
            // refusals it would otherwise carry — no such target, a rule
            // that declines — become a different destination rather than
            // an error. Both effects are commutative, nothing gates the
            // call, and no call leaves the body, so there is neither
            // anything to refuse nor a callee's totality to fold in.
            //
            // Claimed here rather than checked: the publish-time checker
            // that grants this does not exist yet, and when it does the
            // stdlib's own marks are things it validates, not things it
            // takes on trust.
            totality: Totality::Total,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        VAULT,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(0)))],
                    )),
                    mode: ModeExpr::Delta,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(
                        CLAIMS,
                        vec![Expr::ResourceOf(Box::new(Expr::Arg(0)))],
                    )),
                    mode: ModeExpr::Delta,
                },
            ],
            calls: vec![],
        },
    );
}

/// `deposit-nf` and `withdraw-nf`: the account holding instances — the
/// entries of its per-resource holdings interval, created at deposit and
/// removed at withdrawal, gated exactly as the fungible pair is.
fn holdings_methods(methods: &mut PackageMetadata) {
    methods.methods.insert(
        "deposit-nf".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Public,
            mints: None,
            issues: None,
            params: vec![ParamType::NfBucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: holdings_range(Expr::ResourceOf(Box::new(Expr::Arg(0))), NF_MOVE_CAP),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "withdraw-nf".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(Expr::SelfAddr),
            mints: None,
            issues: None,
            params: vec![ParamType::Address, ParamType::Ids],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(1))],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(Expr::Arg(0)),
                ids: Box::new(Expr::Arg(1)),
            }],
            effects: vec![Clause::Effect {
                target: holdings_range(Expr::Arg(0), NF_MOVE_CAP),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    // The custody gate: the holder's own rule — the holder acts, nobody
    // else presents its badges — plus possession of the named badge,
    // fungible or not, minting the badge's address as evidence.
    methods.methods.insert(
        "present-badge".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Custodial,
            mints: Some(Expr::Arg(0)),
            issues: None,
            params: vec![ParamType::Address],
            abi: vec![],
            outputs: vec![],
            effects: vec![
                Clause::Effect {
                    target: TargetExpr::Point(self_child(AUTH, vec![])),
                    mode: ModeExpr::Read,
                },
                Clause::Effect {
                    target: TargetExpr::Point(self_child(VAULT, vec![Expr::Arg(0)])),
                    mode: ModeExpr::Read,
                },
                Clause::Effect {
                    target: holdings_range(Expr::Arg(0), 1),
                    mode: ModeExpr::Read,
                },
            ],
            calls: vec![],
        },
    );
}

/// The authority surface: the sign-in, the one-way door, and timed
/// recovery — every method whose gate reads the stored rule cell.
fn authority_methods(methods: &mut PackageMetadata) {
    methods.methods.insert(
        "authorize".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Authorizing,
            mints: None,
            issues: None,
            params: vec![],
            abi: vec![],
            outputs: vec![],
            // The one clause an authorizing method declares: the cell its
            // stored rule lives in. The read is what provisions the cell
            // — or its absence — to every participant, and reads share,
            // so concurrent sign-ins as one account never conflict.
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(AUTH, vec![])),
                mode: ModeExpr::Read,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "securify".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::Guarded(Expr::SelfAddr),
            mints: None,
            issues: None,
            params: vec![ParamType::RoleSet, ParamType::U64],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::Arg(1)),
            ],
            outputs: vec![],
            // An exclusive read-modify-write: the body refuses a cell
            // that already exists, and the write conflicts with every
            // concurrent sign-in's read — retiring a rule and acting
            // under it never share a wave.
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(AUTH, vec![])),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    // The recovery surface: each method's whole declaration is the same
    // exclusive write on the rule cell, which is where its gate's cell
    // comes from and what keeps a role rewrite out of any wave that
    // signs in under the roles it replaces.
    methods.methods.insert(
        "propose".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::RoleGated(AuthRole::Recovery),
            mints: None,
            issues: None,
            params: vec![ParamType::RoleSet, ParamType::U64],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Derived(Expr::Arg(0)),
                AbiParam::Derived(Expr::Arg(1)),
            ],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(AUTH, vec![])),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "cancel".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::RoleGated(AuthRole::Primary),
            mints: None,
            issues: None,
            params: vec![],
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(AUTH, vec![])),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
    methods.methods.insert(
        "confirm".into(),
        MethodSignature {
            totality: Totality::Infallible,
            accessibility: Accessibility::RoleGated(AuthRole::Confirmation),
            mints: None,
            issues: None,
            params: vec![],
            abi: vec![AbiParam::Handle(0)],
            outputs: vec![],
            effects: vec![Clause::Effect {
                target: TargetExpr::Point(self_child(AUTH, vec![])),
                mode: ModeExpr::Write,
            }],
            calls: vec![],
        },
    );
}

// ─── calls ─────────────────────────────────────────────────────────────

/// Reserve `amount` of `resource` on the proof holder's vault,
/// producing it as an edge typed by the resource named here. The
/// proof is the actor: the withdrawal is from whoever authorized.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw`.
pub fn withdraw(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    resource: impl Into<ResourceRef>,
    amount: u128,
) -> Result<Bucket, TypedError> {
    builder
        .call_as(proof, proof.target(), "withdraw", (resource.into(), amount))?
        .one()
}

/// Credit `funds` to `who`'s vault. Anyone may.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit`.
pub fn deposit(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(who, "deposit", (funds,))?.none()
}

/// Sign in as `who`: mint the account's identity as a proof later
/// calls of the same graph present.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `authorize`.
pub fn authorize(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<Proof, TypedError> {
    builder.call_minting(who, "authorize")
}

/// Sign in as `who` through an identity minted earlier — the way in
/// when `who`'s stored rule names another account rather than a key
/// the intent could carry.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `authorize`.
pub fn authorize_as(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    who: PrincipalAddr,
) -> Result<Proof, TypedError> {
    builder.call_minting_as(proof, who, "authorize")
}

/// Create the proof holder's stored-authority cell — three roles
/// and the recovery delay.
///
/// The one-way transition off the rule the account's address
/// derives. Refused at execution if the cell already exists.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `securify`.
pub fn securify(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    roles: RoleSet,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    builder
        .call_as(
            proof,
            proof.target(),
            "securify",
            (roles, recovery_delay_ms),
        )?
        .none()
}

/// Securify with one rule as all three roles.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `securify`.
pub fn securify_uniform(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    rule: Rule,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    securify(builder, proof, RoleSet::uniform(rule), recovery_delay_ms)
}

/// Propose a full replacement for `who`'s roles and delay, judged by
/// the governing recovery rule against the intent's own signature.
/// The proposal matures after the delay the cell currently stores.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `propose`.
pub fn propose(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    roles: RoleSet,
    recovery_delay_ms: u64,
) -> Result<(), TypedError> {
    builder
        .call(who, "propose", (roles, recovery_delay_ms))?
        .none()
}

/// Drop `who`'s unmatured proposal, judged by the governing primary
/// rule against the intent's own signature.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `cancel`.
pub fn cancel(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<(), TypedError> {
    builder.call(who, "cancel", ())?.none()
}

/// Enact `who`'s pending proposal now, judged by the governing
/// confirmation rule against the intent's own signature.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `confirm`.
pub fn confirm(builder: &mut TypedBuilder<'_>, who: PrincipalAddr) -> Result<(), TypedError> {
    builder.call(who, "confirm", ())?.none()
}

/// File `funds`' instances as entries of `who`'s holdings. Anyone
/// may, exactly as with the fungible deposit.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `deposit-nf`.
pub fn deposit_nf(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    funds: impl BucketArg,
) -> Result<(), TypedError> {
    builder.call(who, "deposit-nf", (funds,))?.none()
}

/// Remove the named `ids` of `resource` from the proof holder's
/// holdings, producing their edge; an id not held traps at
/// execution.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `withdraw-nf`.
pub fn withdraw_nf(
    builder: &mut TypedBuilder<'_>,
    proof: Proof,
    resource: impl Into<ResourceRef>,
    ids: &[u64],
) -> Result<Bucket, TypedError> {
    let ids = Value::List(ids.iter().copied().map(Value::U64).collect());
    builder
        .call_as(proof, proof.target(), "withdraw-nf", (resource.into(), ids))?
        .one()
}

/// Present `who`'s custody of `badge`: the holder's own rule plus
/// possession, minting the badge's address as evidence for later
/// nodes of the same intent.
///
/// # Errors
///
/// Any [`TypedError`] the call does not type against `present-badge`.
pub fn present_badge(
    builder: &mut TypedBuilder<'_>,
    who: PrincipalAddr,
    badge: impl Into<ResourceRef>,
) -> Result<Proof, TypedError> {
    builder.call_minting_args(who, "present-badge", (badge.into(),))
}

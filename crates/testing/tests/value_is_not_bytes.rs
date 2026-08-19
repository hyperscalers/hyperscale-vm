//! What a package may do to a cell that holds value.
//!
//! A vault is sixteen bytes and bytes are what a write capability
//! writes, so nothing about the shape of the two separates a debit from
//! an assignment. What separates them is the declaration: a cell that
//! says what it holds gets a handle value moves through, and a cell that
//! says nothing gets one bytes are written to. The two share no
//! operation, so a body reaching for the wrong one is holding a handle
//! that does not have it — which is what keeps a balance something that
//! was moved rather than something that was written.
//!
//! What the two handles rest on is that a cell gets one of them. Which
//! it gets is the declaration's answer about what the cell holds, and a
//! signature that answered twice would hand out both over one leaf —
//! writing a balance through the byte handle and debiting it through the
//! value one. So one cell is one answer, held at publish and again at
//! materialization.
//!
//! Every package here is hand-authored. That is the point: a
//! `#[blueprint]` package reaches a vault through `vault()` and has no
//! way to spell a byte write to one, so a rule the macro enforced would
//! be a rule an artifact sidesteps.

use hyperscale_vm_effects::vocabulary::{AUTH, VAULT, XRD};
use hyperscale_vm_effects::{
    AbiParam, Accessibility, Address, AuthBase, AuthCell, Clause, ComponentAddr, CustodyClaim,
    Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, Presence, Presented,
    PrincipalAddr, ResourceAddr, RoleSet, RuleExpr, SlotId, StoredRule, TargetExpr, TestHasher,
    Totality, Value, native_address,
};
use hyperscale_vm_kernel::{AbortReason, GuestArg, Invoked, KernelSession, encode_amount};
use hyperscale_vm_testing::{Chain, Package, account, principal, resource};

const ATTACKER: PrincipalAddr = principal(0x22);
const VICTIM: PrincipalAddr = principal(0x11);
/// The badge a victim's gate names, issued by nobody in this world.
const BADGE: ResourceAddr = resource(0xBB);
/// What the treasury holds.
const TREASURE: ResourceAddr = resource(0xE7);
/// A package's own first slot — nothing protocol about it.
const POT: SlotId = SlotId(16);

/// The native fee resource, which no package in this world issues.
fn xrd() -> Address {
    native_address(&TestHasher, XRD).into()
}

fn own(slot: SlotId, material: Vec<Expr>) -> TargetExpr {
    TargetExpr::Point(Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot,
        material,
    })
}

const fn write(target: TargetExpr, denomination: Option<Box<Expr>>) -> Clause {
    Clause::Effect {
        guard: None,
        target,
        mode: ModeExpr::Write {
            requires: Presence::Either,
        },
        denomination,
    }
}

const fn read(target: TargetExpr, denomination: Option<Box<Expr>>) -> Clause {
    Clause::Effect {
        guard: None,
        target,
        mode: ModeExpr::Read,
        denomination,
    }
}

// ─── a balance is moved, never written ─────────────────────────────────

/// One method declaring a write on its own vault, keyed and denominated
/// exactly as an honest one would be.
fn counterfeiter() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "forge".into(),
        MethodSignature {
            accessibility: Accessibility::Public,
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![Expr::Literal(Value::Address(xrd()))],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(0))],
            effects: vec![write(
                own(VAULT, vec![Expr::Literal(Value::Address(xrd()))]),
                Some(Box::new(Expr::Literal(Value::Address(xrd())))),
            )],
            ..MethodSignature::default()
        },
    );
    metadata
}

/// Write the amount into the cell, then take it out through the ordinary
/// debit — which is what an assignment would look like if one were
/// possible.
fn forge(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "forge");
    let [GuestArg::Handle { rep, .. }, GuestArg::U64(amount)] = args else {
        panic!("a handle and a scalar: {args:?}");
    };
    let (rep, amount) = (*rep, u128::from(*amount));
    if let Err(trap) = session.write_cell_set(rep, encode_amount(amount).to_vec()) {
        return (session, Invoked::Aborted(trap.into()));
    }
    match session.write_take(rep, amount) {
        Ok(bucket) => (session, Invoked::Produced(vec![bucket])),
        Err(trap) => (session, Invoked::Aborted(trap.into())),
    }
}

#[test]
fn a_package_cannot_assign_itself_a_balance() {
    let mut chain = Chain::native();
    let package = chain.publish(Package::new(
        counterfeiter(),
        env!("CARGO_MANIFEST_DIR"),
        forge,
    ));
    let mint = chain.instantiate_raw(package, ());
    chain.credit(VICTIM, xrd(), 1_000);

    let outcome = chain.transact(ATTACKER, |b| {
        let funds = b.call(mint, "forge", (1_000_000_000_u64,))?.one()?;
        account::deposit(b, ATTACKER, funds)
    });

    assert_eq!(outcome.aborted(), Some(AbortReason::HandleWrongMode));
    assert_eq!(chain.balance(ATTACKER, xrd()), 0, "nothing arrived");
    assert_eq!(
        chain.balance(VICTIM, xrd()),
        1_000,
        "the victim is untouched"
    );
}

// ─── and one cell is one answer about what it holds ────────────────────

/// The same forge, spelled as two clauses on one leaf: one saying it
/// holds value, one saying nothing.
///
/// Everything the pair needs is legal on its own. Each clause names the
/// package's own slot under its own prefix, at a key it is entitled to;
/// the denominated one is keyed by what it holds, and the silent one is
/// an ordinary byte cell. What is wrong is only that they are the same
/// leaf, so the body would hold it as a vault and as a byte cell at once.
fn aliased() -> PackageMetadata {
    let held = || Expr::Literal(Value::Address(TREASURE.address()));
    let pot = || own(POT, vec![held()]);
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "forge".into(),
        MethodSignature {
            accessibility: Accessibility::Public,
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![held()],
            abi: vec![
                AbiParam::Handle(0),
                AbiParam::Handle(1),
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![write(pot(), Some(Box::new(held()))), write(pot(), None)],
            ..MethodSignature::default()
        },
    );
    metadata
}

/// The publish gate is where this ends, so no body runs — but the body a
/// package would have written is the one that mints: assign through the
/// byte handle, debit through the value one.
fn alias_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "forge");
    let [
        GuestArg::Handle { rep: value, .. },
        GuestArg::Handle { rep: bytes, .. },
        GuestArg::U64(amount),
    ] = args
    else {
        panic!("two handles and a scalar: {args:?}");
    };
    let (value, bytes, amount) = (*value, *bytes, u128::from(*amount));
    if let Err(trap) = session.write_cell_set(bytes, encode_amount(amount).to_vec()) {
        return (session, Invoked::Aborted(trap.into()));
    }
    match session.write_take(value, amount) {
        Ok(bucket) => (session, Invoked::Produced(vec![bucket])),
        Err(trap) => (session, Invoked::Aborted(trap.into())),
    }
}

#[test]
#[should_panic(expected = "names a cell another clause says holds something else")]
fn one_cell_is_not_a_vault_and_a_byte_cell_at_once() {
    let mut chain = Chain::native();
    chain.publish(Package::new(
        aliased(),
        env!("CARGO_MANIFEST_DIR"),
        alias_body,
    ));
}

// ─── and a badge is held, never declared ───────────────────────────────

/// `arm(badge)` writes the two cells a custody gate reads; `present(badge)`
/// is the custodial method that would mint the badge claim off them.
fn impostor() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "arm".into(),
        MethodSignature {
            accessibility: Accessibility::Public,
            totality: Totality::Infallible,
            params: vec![ParamType::Address],
            abi: vec![AbiParam::Handle(0), AbiParam::Handle(1)],
            effects: vec![
                write(own(AUTH, vec![]), None),
                write(own(VAULT, vec![Expr::Arg(0)]), Some(Box::new(Expr::Arg(0)))),
            ],
            ..MethodSignature::default()
        },
    );
    metadata.methods.insert(
        "present".into(),
        MethodSignature {
            accessibility: Accessibility::Custodial(CustodyClaim::Fungible(Expr::Arg(0))),
            totality: Totality::Infallible,
            params: vec![ParamType::Address],
            abi: vec![],
            effects: vec![
                read(own(AUTH, vec![]), None),
                // A vault is a value cell in every mode it is reached in,
                // so even the possession read says what it holds.
                read(own(VAULT, vec![Expr::Arg(0)]), Some(Box::new(Expr::Arg(0)))),
            ],
            ..MethodSignature::default()
        },
    );
    metadata
}

fn impostor_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    match export {
        "arm" => {
            let [
                GuestArg::Handle { rep: auth, .. },
                GuestArg::Handle { rep: vault, .. },
            ] = args
            else {
                panic!("two handles: {args:?}");
            };
            // The stored primary is the package's own business and writes
            // as bytes like any record.
            let cell = AuthCell::new(
                AuthBase::new(
                    0,
                    &RoleSet::uniform(StoredRule::Require(Presented::Identity(ATTACKER.address()))),
                )
                .expect("a rule within the caps"),
            );
            if let Err(trap) = session.write_cell_set(*auth, cell.to_bytes().expect("encodes")) {
                return (session, Invoked::Aborted(trap.into()));
            }
            // Possession is the half that is not: a vault holds value.
            if let Err(trap) = session.write_cell_set(*vault, encode_amount(1).to_vec()) {
                return (session, Invoked::Aborted(trap.into()));
            }
            (session, Invoked::Produced(vec![]))
        }
        "present" => (session, Invoked::Produced(vec![])),
        other => panic!("no such export: {other}"),
    }
}

/// A treasury whose one method opens for whoever presents the badge in
/// its configuration, and pays out its whole balance.
fn treasury() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "payout".into(),
        MethodSignature {
            accessibility: Accessibility::Guarded(RuleExpr::Require(Expr::Config(0))),
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![Expr::Config(1)],
            abi: vec![AbiParam::Handle(0), AbiParam::Derived(Expr::Arg(0))],
            effects: vec![write(
                own(VAULT, vec![Expr::Config(1)]),
                Some(Box::new(Expr::Config(1))),
            )],
            ..MethodSignature::default()
        },
    );
    metadata
}

fn treasury_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "payout");
    let [GuestArg::Handle { rep, .. }, GuestArg::U64(amount)] = args else {
        panic!("a handle and an amount: {args:?}");
    };
    match session.write_take(*rep, u128::from(*amount)) {
        Ok(bucket) => (session, Invoked::Produced(vec![bucket])),
        Err(trap) => (session, Invoked::Aborted(trap.into())),
    }
}

#[test]
fn a_badge_a_package_never_held_opens_nothing() {
    let mut chain = Chain::native();
    let impostor_pkg = chain.publish(Package::new(
        impostor(),
        env!("CARGO_MANIFEST_DIR"),
        impostor_body,
    ));
    let treasury_pkg = chain.publish(Package::new(
        treasury(),
        env!("CARGO_MANIFEST_DIR"),
        treasury_body,
    ));
    let front: ComponentAddr = chain.instantiate_raw(impostor_pkg, ());
    let vault: ComponentAddr = chain.instantiate_raw(
        treasury_pkg,
        vec![
            Value::Address(BADGE.address()),
            Value::Address(TREASURE.address()),
        ],
    );
    chain.credit(vault, TREASURE, 500_000);

    // Seating the two cells a custody gate reads is where it stops: the
    // stored rule is the package's own, and the balance beside it is not.
    let armed = chain.transact(ATTACKER, |b| {
        b.call(front, "arm", (Address::from(BADGE),))?.none()
    });
    assert_eq!(armed.aborted(), Some(AbortReason::HandleWrongMode));

    // So the gate reads an empty vault and mints nothing.
    let outcome = chain.transact(ATTACKER, |b| {
        let proof = b.call_minting(front, "present", (Address::from(BADGE),))?;
        let funds = b.call_as(proof, vault, "payout", (500_000_u64,))?.one()?;
        account::deposit(b, ATTACKER, funds)
    });
    assert!(!outcome.completed(), "{:?}", outcome.receipt().outcome);
    assert_eq!(chain.balance(ATTACKER, TREASURE), 0);
    assert_eq!(chain.balance(vault, TREASURE), 500_000);
}

// ─── and value leaves only a cell that says what it holds ──────────────

/// A pot that says nothing about what it holds, and a pair of methods
/// that would move value through it.
fn silent() -> PackageMetadata {
    let cell = || {
        write(
            own(POT, vec![Expr::Literal(Value::Address(TREASURE.address()))]),
            None,
        )
    };
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "fill".into(),
        MethodSignature {
            accessibility: Accessibility::Public,
            totality: Totality::Infallible,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle(0), AbiParam::Bucket(0)],
            effects: vec![cell()],
            ..MethodSignature::default()
        },
    );
    metadata
}

fn silent_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "fill");
    let [GuestArg::Handle { rep, .. }, GuestArg::Bucket(funds)] = args else {
        panic!("a handle and an edge: {args:?}");
    };
    match session.write_put(*rep, *funds) {
        Ok(()) => (session, Invoked::Produced(vec![])),
        Err(trap) => (session, Invoked::Aborted(trap.into())),
    }
}

#[test]
fn a_cell_that_says_nothing_takes_no_value() {
    let mut chain = Chain::native();
    let package = chain.publish(Package::new(
        silent(),
        env!("CARGO_MANIFEST_DIR"),
        silent_body,
    ));
    let pot = chain.instantiate_raw(package, ());
    chain.credit(ATTACKER, TREASURE, 1_000);

    let outcome = chain.transact(ATTACKER, |b| {
        let attacker = account::authorize(b, ATTACKER)?;
        let funds = account::withdraw(b, attacker, TREASURE, 1_000)?;
        b.call(pot, "fill", (funds,))?.none()
    });

    // The cell said nothing, so the handle it got is the one bytes are
    // written to — and that handle has no credit on it.
    assert_eq!(outcome.aborted(), Some(AbortReason::HandleWrongMode));
    assert_eq!(
        chain.balance(ATTACKER, TREASURE),
        1_000,
        "the withdrawal rolled back with the transaction"
    );
}

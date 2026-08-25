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
//! declaration that answered twice would hand out both over one leaf —
//! writing a balance through the byte handle and debiting it through the
//! value one. So one cell is one answer: held over a signature's clauses
//! and over a transaction's, and held per slot over a package's methods,
//! because two of those calls need not arrive together.
//!
//! Every package here is hand-authored. That is the point: a
//! `#[blueprint]` package reaches a vault through `vault()` and has no
//! way to spell a byte write to one, so a rule the macro enforced would
//! be a rule an artifact sidesteps.

use hyperscale_vm_effects::vocabulary::{AUTH, VAULT};
use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, Presented,
    RuleBytes, RuleExpr, RuleLeaf, SlotId, StoredRule, TargetExpr, TestHasher, Totality, Value,
    xrd as protocol_xrd,
};
use hyperscale_vm_kernel::{GuestArg, Invoked, KernelSession};
use hyperscale_vm_testing::{Chain, Package, account, principal, resource};
use hyperscale_vm_types::{
    AbortReason, Address, ComponentAddr, Presence, PrincipalAddr, ResourceAddr, encode_amount,
};

const ATTACKER: PrincipalAddr = principal(0x22);
const VICTIM: PrincipalAddr = principal(0x11);
/// The badge a victim's gate names, issued by nobody in this world.
const BADGE: ResourceAddr = resource(0xBB);
/// What the treasury holds.
const TREASURE: ResourceAddr = resource(0xE7);
/// A package's own first slot — nothing protocol about it.
const POT: SlotId = SlotId(16);

/// The protocol fee resource, which no package in this world issues.
fn xrd() -> Address {
    protocol_xrd(&TestHasher).into()
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
        mode: ModeExpr::Write,
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
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![Expr::Literal(Value::Address(xrd()))],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
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
    let [GuestArg::Site { site }, GuestArg::U64(amount)] = args else {
        panic!("a handle and a scalar: {args:?}");
    };
    let (site, amount) = (*site, u128::from(*amount));
    if let Err(trap) = session.write_cell_set(site, 0, encode_amount(amount).to_vec()) {
        return (session, Invoked::Aborted(trap.into()));
    }
    match session.cell_take(site, 0, amount) {
        Ok(bucket) => (
            session,
            Invoked::Produced {
                edges: vec![bucket],
                answer: None,
            },
        ),
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
    let mint = chain.instantiate_raw(ATTACKER, package, ());
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
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![held()],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Handle { clause: 1, site: 0 },
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
        GuestArg::Site { site: value, .. },
        GuestArg::Site { site: bytes, .. },
        GuestArg::U64(amount),
    ] = args
    else {
        panic!("two handles and a scalar: {args:?}");
    };
    let (value, bytes, amount) = (*value, *bytes, u128::from(*amount));
    if let Err(trap) = session.write_cell_set(bytes, 0, encode_amount(amount).to_vec()) {
        return (session, Invoked::Aborted(trap.into()));
    }
    match session.cell_take(value, 0, amount) {
        Ok(bucket) => (
            session,
            Invoked::Produced {
                edges: vec![bucket],
                answer: None,
            },
        ),
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

/// The same pair, split across two methods — which is where nothing
/// below the package would see it.
///
/// `fill` reaches the pot as bytes and `drain` reaches it as a vault.
/// Each signature is sound read on its own, and a signature is what the
/// clause fold judges; the transaction fold sees only the clauses one
/// call declares, and nothing obliges an attacker to make one call. So
/// the two are held together where the whole package is: a slot holds
/// one thing, for every method that names it.
fn two_faced() -> PackageMetadata {
    let held = || Expr::Literal(Value::Address(TREASURE.address()));
    let pot = || own(POT, vec![held()]);
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "fill".into(),
        MethodSignature {
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![write(pot(), None)],
            ..MethodSignature::default()
        },
    );
    metadata.methods.insert(
        "drain".into(),
        MethodSignature {
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![held()],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![write(pot(), Some(Box::new(held())))],
            ..MethodSignature::default()
        },
    );
    metadata
}

/// What the two bodies would have been: one assigns the balance, the
/// other debits it a transaction later.
fn two_faced_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    let [GuestArg::Site { site }, GuestArg::U64(amount)] = args else {
        panic!("a handle and a scalar: {args:?}");
    };
    let (site, amount) = (*site, u128::from(*amount));
    match export {
        "fill" => match session.write_cell_set(site, 0, encode_amount(amount).to_vec()) {
            Ok(()) => (
                session,
                Invoked::Produced {
                    edges: vec![],
                    answer: None,
                },
            ),
            Err(trap) => (session, Invoked::Aborted(trap.into())),
        },
        "drain" => match session.cell_take(site, 0, amount) {
            Ok(bucket) => (
                session,
                Invoked::Produced {
                    edges: vec![bucket],
                    answer: None,
                },
            ),
            Err(trap) => (session, Invoked::Aborted(trap.into())),
        },
        other => panic!("no such export: {other}"),
    }
}

#[test]
#[should_panic(expected = "declares it and bytes where")]
fn one_slot_is_not_a_vault_in_one_method_and_a_byte_cell_in_another() {
    let mut chain = Chain::native();
    chain.publish(Package::new(
        two_faced(),
        env!("CARGO_MANIFEST_DIR"),
        two_faced_body,
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
            totality: Totality::Infallible,
            params: vec![ParamType::Address],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Handle { clause: 1, site: 0 },
            ],
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
            totality: Totality::Infallible,
            params: vec![ParamType::Address],
            abi: vec![],
            effects: vec![
                read(own(AUTH, vec![]), None),
                // A vault is a value cell in every mode it is reached in,
                // so even the possession read says what it holds.
                read(own(VAULT, vec![Expr::Arg(0)]), Some(Box::new(Expr::Arg(0)))),
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Stored {
                        cell: Expr::ChildKey {
                            owner: Box::new(Expr::SelfAddr),
                            slot: AUTH,
                            material: vec![],
                        },
                    }),
                },
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::Require(RuleLeaf::Presence {
                        target: Box::new(own(VAULT, vec![Expr::Arg(0)])),
                        expect: Presence::Present,
                    }),
                },
                Clause::Mints {
                    guard: None,
                    claim: Expr::Arg(0),
                },
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
                GuestArg::Site { site: auth, .. },
                GuestArg::Site { site: vault, .. },
            ] = args
            else {
                panic!("two handles: {args:?}");
            };
            // The stored rule is the package's own business and writes
            // as bytes like any record.
            let rule = RuleBytes::try_from(&StoredRule::claim(Presented::of_subject(ATTACKER)))
                .expect("a rule within the caps");
            if let Err(trap) = session.write_cell_set(*auth, 0, rule.0) {
                return (session, Invoked::Aborted(trap.into()));
            }
            // Possession is the half that is not: a vault holds value.
            if let Err(trap) = session.write_cell_set(*vault, 0, encode_amount(1).to_vec()) {
                return (session, Invoked::Aborted(trap.into()));
            }
            (
                session,
                Invoked::Produced {
                    edges: vec![],
                    answer: None,
                },
            )
        }
        "present" => (
            session,
            Invoked::Produced {
                edges: vec![],
                answer: None,
            },
        ),
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
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![Expr::Config(1)],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![
                write(
                    own(VAULT, vec![Expr::Config(1)]),
                    Some(Box::new(Expr::Config(1))),
                ),
                Clause::Requires {
                    guard: None,
                    rule: RuleExpr::claim(Expr::Config(0)),
                },
            ],
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
    let [GuestArg::Site { site }, GuestArg::U64(amount)] = args else {
        panic!("a handle and an amount: {args:?}");
    };
    match session.cell_take(*site, 0, u128::from(*amount)) {
        Ok(bucket) => (
            session,
            Invoked::Produced {
                edges: vec![bucket],
                answer: None,
            },
        ),
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
    let front: ComponentAddr = chain.instantiate_raw(ATTACKER, impostor_pkg, ());
    let vault: ComponentAddr = chain.instantiate_raw(
        ATTACKER,
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
    assert!(
        outcome.refused().is_some(),
        "{:?}",
        outcome.receipt().outcome
    );
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
            totality: Totality::Infallible,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle { clause: 0, site: 0 }, AbiParam::Bucket(0)],
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
    let [GuestArg::Site { site }, GuestArg::Bucket(funds)] = args else {
        panic!("a handle and an edge: {args:?}");
    };
    match session.cell_put(*site, 0, *funds) {
        Ok(()) => (
            session,
            Invoked::Produced {
                edges: vec![],
                answer: None,
            },
        ),
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
    let pot = chain.instantiate_raw(ATTACKER, package, ());
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

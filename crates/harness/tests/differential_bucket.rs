//! Differential lane 3, owned handles: the bucket guest runs under the
//! blessed engine and the reference interpreter against the *same kernel
//! session*, and the two must agree on what a handle is numbered, on
//! where ownership sits after each call, and on the drop reaching the
//! host.
//!
//! The lane exists because ownership widens what the engines have to
//! agree about. Handle numbering was already differentially tested for
//! borrows; transfer and drop ordering were not, and a divergence in
//! either is a divergence in what value a transaction moved.

use std::sync::LazyLock;

use hyperscale_vm_effects::{
    Hash32, IssuanceGrant, Issued, ResourceKind, SlotId, TestHasher, child_key,
};
use hyperscale_vm_harness::dual::{DualGuest, DualOutcome, materialize, rep_where};
use hyperscale_vm_harness::fixtures::BUCKET_GUEST_WAT;
use hyperscale_vm_kernel::{Capability, EnvInputs, Held, KernelSession, MemoryStore};
use hyperscale_vm_ref::{CVal, HandleKind};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, CollectionId, Effect, EffectSet, EffectTarget, Mode, Moves,
    Outcome, ResourceAddr, SubstateKey, TxHash, encode_amount,
};
use wasmtime::Result;
use wasmtime::error::{bail, format_err};
use wat::parse_str;

/// A bucket of `amount`, minted rather than conjured.
///
/// Value entering a transaction comes from a mint; a fixture opening a
/// bucket from nothing hands the session value no supply accounts for,
/// which is the thing the conservation check exists to refuse.
fn minted(session: &mut KernelSession, amount: u128) -> u32 {
    session.grant_issuance(vec![IssuanceGrant {
        resource: RESOURCE,
        kind: ResourceKind::Fungible,
        direction: Issued::Either,
    }]);
    session.mint(0, amount).expect("the grant mints")
}

const FUEL: u64 = 1_000_000_000;
/// What the held bucket carries; the guest never learns it, which is the
/// point of the handle.
const HELD: u128 = 40;
/// What the discarded bucket carries: nothing, because a bucket that
/// carries anything cannot be discarded at all.
const SPENT: u128 = 0;

const fn tx() -> TxHash {
    TxHash(Hash32([0x55; 32]))
}

const fn env() -> EnvInputs {
    EnvInputs::unsealed(909_090)
}

/// What a reserve clause grants, and what the vault behind it holds.
const RESERVED: u128 = 75;
/// What the absolute vault holds before a take.
const BALANCE: u128 = 100;
/// The instance whose invocation the take lane runs inside, and the
/// resource it issues.
const ISSUER: Address = Address::new([0x80; 31], AddressClass::Component);
/// What the issuer's grant names: the one resource the lane moves.
const ISSUED: ResourceAddr = ResourceAddr::new([0x80; 31]);
/// What every value cell in the fixture holds.
///
/// One resource across the fixture, because what this lane is about is
/// ownership and numbering rather than denomination: a second would make
/// every credit a resource comparison as well as a transfer.
const RESOURCE: ResourceAddr = ISSUED;

/// The collection whose entries the instance lane moves.
const HOLDINGS: CollectionId = CollectionId([9; 16]);
/// The orders the fixture files instances at.
const INSTANCES: [u128; 3] = [10, 20, 30];

/// The bucket guest in both engines' forms, compiled once per binary.
static GUEST: LazyLock<DualGuest> = LazyLock::new(|| {
    DualGuest::compile(&parse_str(BUCKET_GUEST_WAT).expect("the fixture parses"))
        .expect("the fixture compiles")
});

struct Fixture {
    declared: EffectSet,
    store: MemoryStore,
    readable: SubstateKey,
    vault: SubstateKey,
    ledger: SubstateKey,
    opaque: SubstateKey,
    reserved: SubstateKey,
}

fn fixture() -> Fixture {
    let key = |slot: u16| {
        child_key(
            &TestHasher,
            Address::new([0x60; 31], AddressClass::Component),
            SlotId(slot),
            &[],
        )
    };
    let (readable, vault, ledger, opaque, reserved) = (key(1), key(2), key(3), key(4), key(5));

    let mut store = MemoryStore::new();
    store.write(readable, vec![5]);
    store.write(vault, encode_amount(BALANCE).to_vec());
    store.write(ledger, encode_amount(BALANCE).to_vec());
    store.write(reserved, encode_amount(BALANCE).to_vec());
    // A write cell holding something that is not an amount: state a
    // movement can only refuse, which is the narrow reading the class has.
    store.write(opaque, vec![1, 2, 3]);
    let holder = Address::new([0x90; 31], AddressClass::Component);
    for order in INSTANCES {
        store.entry_write(holder, HOLDINGS, order, vec![1]);
    }

    let mut declared = EffectSet::new();
    for effect in [
        Effect {
            target: EffectTarget::Point(readable),
            mode: Mode::Read,
        },
        Effect {
            target: EffectTarget::Point(vault),
            mode: Mode::Write { moves: Moves::Both },
        },
        Effect {
            target: EffectTarget::Point(opaque),
            mode: Mode::Write { moves: Moves::Both },
        },
        Effect {
            target: EffectTarget::Point(ledger),
            mode: Mode::Delta,
        },
        Effect {
            target: EffectTarget::Point(reserved),
            mode: Mode::Reserve { amount: RESERVED },
        },
        Effect {
            target: EffectTarget::Range {
                owner: holder,
                collection: HOLDINGS,
                lo: 0,
                hi: 100,
                cap: 8,
            },
            mode: Mode::Write { moves: Moves::Both },
        },
    ] {
        declared.insert(effect).unwrap();
    }

    Fixture {
        declared,
        store,
        readable,
        vault,
        ledger,
        opaque,
        reserved,
    }
}

/// What each declared cell holds, aligned with the order the capability
/// table is built in.
///
/// Everything but the read cell: a cell that denominates nothing is one
/// no value moves through, and every cell here but that one is moved
/// through.
fn denominations(fx: &Fixture) -> Vec<Option<ResourceAddr>> {
    fx.declared
        .iter()
        .map(|effect| match effect.target {
            EffectTarget::Point(key) if key == fx.readable => None,
            _ => Some(RESOURCE),
        })
        .collect()
}

fn session_of(fx: &Fixture) -> KernelSession {
    materialize(&fx.store, &fx.declared, &denominations(fx), tx(), env())
}

/// The capability rep for one declared point, by the mode it carries.
fn rep_of(host: &KernelSession, wanted: SubstateKey, mode: Mode) -> u32 {
    rep_where(host, |c| match (mode, c) {
        (Mode::Read, Capability::Read(key))
        | (Mode::Write { .. }, Capability::Amount(key))
        | (Mode::Delta, Capability::Delta(key))
        | (Mode::Reserve { .. }, Capability::Reserve { key, .. }) => *key == wanted,
        _ => false,
    })
}

/// A session with the fixture's capabilities and two buckets in the
/// kernel's keeping.
///
/// The reps are the table's own order, so both runtimes are handed the
/// same two.
fn session(fx: &Fixture) -> (KernelSession, u32, u32) {
    let mut session = session_of(fx);
    let held = minted(&mut session, HELD);
    let spent = minted(&mut session, SPENT);
    (session, held, spent)
}

/// What one run of the four-call sequence observed — on both engines,
/// since every call already had to agree.
#[derive(Debug, PartialEq, Eq)]
struct Trace {
    /// The handle `hold` was given for the bucket it keeps.
    held_handle: u64,
    /// The handle `peek` was lent while that own is still seated.
    borrow_handle: u64,
    /// The rep `release` handed back.
    released_rep: u32,
    /// The handle `discard` was given, after two slots have freed.
    discard_handle: u64,
    /// Whether the released bucket was still the kernel's to take.
    released_amount: u128,
    /// Whether the discarded bucket's rep names anything afterwards.
    discarded_survives: bool,
}

/// The four-call ownership sequence, agreed call by call.
fn bucket_sequence(fx: &Fixture) -> Result<Trace> {
    let (probe, held, spent) = session(fx);
    let readable = rep_of(&probe, fx.readable, Mode::Read);
    let mut dual = GUEST.instantiate(FUEL, || session(fx).0)?;

    let held_handle = dual.invoke_both("hold", &[CVal::Own(held)])?.scalar()?;
    let borrow_handle = dual
        .invoke_both("peek", &[CVal::Borrow(readable, HandleKind::Site)])?
        .scalar()?;
    let released_rep = dual.invoke_both("release", &[])?.bucket()?;
    let discard_handle = dual.invoke_both("discard", &[CVal::Own(spent)])?.scalar()?;

    let (blessed, reference) = dual.finish()?;
    let (mut blessed, mut reference) = (blessed.session, reference.session);
    let released_amount = blessed.take_bucket(released_rep)?.quantity();
    assert_eq!(
        released_amount,
        reference.take_bucket(released_rep)?.quantity(),
        "the released bucket diverged"
    );
    let discarded_survives = blessed.bucket(spent).is_ok();
    assert_eq!(
        discarded_survives,
        reference.bucket(spent).is_ok(),
        "the discarded rep diverged"
    );
    Ok(Trace {
        held_handle,
        borrow_handle,
        released_rep,
        discard_handle,
        released_amount,
        discarded_survives,
    })
}

/// Which debit to drive, against which of the fixture's cells.
#[derive(Clone, Copy)]
enum Take {
    /// Value created under the invocation's issuance grant.
    Issue(u64),
    /// The same, by an invocation granted none.
    IssueUngranted(u64),
    /// A queued debit of `n` against the delta ledger.
    Delta(u64),
    /// An absolute debit of `n` against the amount vault.
    Vault(u64),
    /// An absolute debit against a cell holding no amount.
    Opaque(u64),
    /// The whole grant.
    Reserve,
    /// The same grant, asked twice.
    ReserveTwice,
}

impl Take {
    const fn export(self) -> &'static str {
        match self {
            Self::Issue(_) | Self::IssueUngranted(_) => "issue",
            Self::Delta(_) => "take-delta",
            Self::Vault(_) | Self::Opaque(_) => "take-write",
            Self::Reserve => "take-reserve",
            Self::ReserveTwice => "take-reserve-twice",
        }
    }

    /// The cell the take debits, and the mode it reaches it through.
    ///
    /// Issuance has none: the grant rides the invocation rather than any
    /// state, which is what makes it the one bucket with nothing behind
    /// it.
    const fn cell(self, fx: &Fixture) -> Option<(SubstateKey, Mode)> {
        match self {
            Self::Issue(_) | Self::IssueUngranted(_) => None,
            Self::Delta(_) => Some((fx.ledger, Mode::Delta)),
            Self::Vault(_) => Some((fx.vault, Mode::Write { moves: Moves::Both })),
            Self::Opaque(_) => Some((fx.opaque, Mode::Write { moves: Moves::Both })),
            Self::Reserve | Self::ReserveTwice => {
                Some((fx.reserved, Mode::Reserve { amount: RESERVED }))
            }
        }
    }

    /// Whether the invocation driving this take was granted issuance.
    const fn granted(self) -> bool {
        matches!(self, Self::Issue(_))
    }

    /// The amount the export takes, where the mode has the body name one.
    const fn amount(self) -> Option<u64> {
        match self {
            Self::Issue(n)
            | Self::IssueUngranted(n)
            | Self::Delta(n)
            | Self::Vault(n)
            | Self::Opaque(n) => Some(n),
            Self::Reserve | Self::ReserveTwice => None,
        }
    }
}

/// What a take produced.
#[derive(Debug, PartialEq, Eq)]
enum Took {
    /// The value the bucket carried, once the lane took it back out of
    /// the kernel.
    Value(u128),
    /// The host refused, in the class it assigned.
    Refusal(AbortReason),
}

/// One take on both engines, comparing what it produced, what it touched
/// and what it cost; returns the blessed session for further assertions.
fn both(fx: &Fixture, take: Take) -> Result<(Took, KernelSession)> {
    let build = || {
        let mut host = session_of(fx);
        host.enter_invocation(ISSUER);
        if take.granted() {
            host.grant_issuance(vec![IssuanceGrant {
                resource: ISSUED,
                kind: ResourceKind::Fungible,
                direction: Issued::Either,
            }]);
        }
        host
    };
    let probe = build();
    // Every capability crosses as one resource, whichever mode it
    // carries; what the mode still decides is which table position the
    // fixture is naming. A mint names none — the grant is the
    // invocation's, so nothing crosses to stand for it.
    let mut args: Vec<CVal> = take
        .cell(fx)
        .map(|(key, mode)| CVal::Borrow(rep_of(&probe, key, mode), HandleKind::Site))
        .into_iter()
        .collect();
    args.extend(take.amount().map(CVal::U64));

    let mut dual = GUEST.instantiate(FUEL, build)?;
    let produced = dual.invoke_both(take.export(), &args)?;
    let (blessed, reference) = dual.finish()?;
    let (mut blessed, mut reference) = (blessed.session, reference.session);
    let took = match produced {
        DualOutcome::Values(_) => {
            let rep = produced.bucket()?;
            let value = blessed.bucket(rep)?.quantity();
            assert_eq!(
                value,
                reference.bucket(rep)?.quantity(),
                "{} diverged on the taken value",
                take.export()
            );
            // Burned rather than lifted out of the table: a debit
            // nothing accounts for is value the transaction lost, and
            // what this fixture is about is where the value went.
            for session in [&mut blessed, &mut reference] {
                session.grant_issuance(vec![IssuanceGrant {
                    resource: RESOURCE,
                    kind: ResourceKind::Fungible,
                    direction: Issued::Either,
                }]);
                session.burn(rep)?;
            }
            Took::Value(value)
        }
        DualOutcome::Refused(reason) => Took::Refusal(reason),
        DualOutcome::Trapped(reason) => bail!("{} trapped: {reason:?}", take.export()),
    };
    Ok((took, blessed))
}

#[test]
fn each_take_yields_the_value_it_debits() -> Result<()> {
    let fx = fixture();

    let (delta, host) = both(&fx, Take::Delta(30))?;
    assert_eq!(delta, Took::Value(30));
    let (receipt, _) = host.finish(vec![], 0).expect("the oracle is clean");
    assert_eq!(
        receipt.delta.movements.get(&fx.ledger).map(|m| m.debit),
        Some(30),
        "the debit the take performed is the movement the receipt carries"
    );

    // An exclusive debit reports the movement it made, like a commutative
    // one: the balance it leaves behind depends on what else settles, so
    // the receipt states the change and not the total.
    let (vault, host) = both(&fx, Take::Vault(30))?;
    assert_eq!(vault, Took::Value(30));
    let (receipt, _) = host.finish(vec![], 0).expect("the oracle is clean");
    assert_eq!(
        receipt.delta.movements.get(&fx.vault).map(|m| m.debit),
        Some(30)
    );
    assert!(!receipt.delta.cells.contains_key(&fx.vault));

    // The grant is the bucket: no amount is named and none can be missed.
    let (reserve, _) = both(&fx, Take::Reserve)?;
    assert_eq!(reserve, Took::Value(RESERVED));
    Ok(())
}

#[test]
fn an_over_take_refuses_in_each_modes_own_terms() -> Result<()> {
    let fx = fixture();

    // Absolute: the read-modify-write resolves at the call, so the
    // refusal is the call's.
    let (vault, _) = both(&fx, Take::Vault(500))?;
    assert_eq!(vault, Took::Refusal(AbortReason::CellUnderflow));

    // Commutative: the debit is queued, so the take succeeds and the
    // movement fold is what refuses — the transaction aborts and no value
    // leaves.
    let (delta, host) = both(&fx, Take::Delta(500))?;
    assert_eq!(delta, Took::Value(500));
    let (receipt, _) = host.finish(vec![], 0).expect("the oracle is clean");
    assert_eq!(
        receipt.outcome,
        Outcome::Infeasible {
            key: fx.ledger,
            amount: 500,
        }
    );
    Ok(())
}

#[test]
fn a_stored_cell_that_is_not_an_amount_is_the_states_defect() -> Result<()> {
    let fx = fixture();
    let (opaque, _) = both(&fx, Take::Opaque(1))?;
    assert_eq!(opaque, Took::Refusal(AbortReason::MalformedAmountCell));
    Ok(())
}

/// A credit driven on both engines, with the bucket the lane opened for
/// it: what the cell holds afterwards, and whether the handle survived.
#[derive(Debug, PartialEq, Eq)]
struct Credited {
    /// What the credited cell reads as once the receipt settles.
    cell: Option<Vec<u8>>,
    /// The movement the receipt carries, where the mode has one.
    credit: Option<u128>,
    /// Whether the consumed bucket's rep still names anything.
    funds_survive: bool,
    /// The class the host assigned, where the credit was refused.
    refusal: Option<AbortReason>,
}

/// What the session says about a credit once it settles.
fn settled(
    host: KernelSession,
    key: SubstateKey,
    funds: u32,
    refusal: Option<AbortReason>,
) -> Credited {
    let funds_survive = host.bucket(funds).is_ok();
    let (receipt, _) = host.finish(vec![], 0).expect("the oracle is clean");
    Credited {
        cell: receipt.delta.cells.get(&key).cloned().flatten(),
        credit: receipt.delta.movements.get(&key).map(|m| m.credit),
        funds_survive,
        refusal,
    }
}

/// One credit on both engines, comparing what settled and what it cost.
fn credited(fx: &Fixture, export: &str, held: u128, delta: bool) -> Result<Credited> {
    let build = || {
        let mut host = session_of(fx);
        minted(&mut host, held);
        host
    };
    let mut probe = session_of(fx);
    let funds = minted(&mut probe, held);
    let (key, mode, kind) = if delta {
        (fx.ledger, Mode::Delta, HandleKind::Site)
    } else {
        (
            fx.vault,
            Mode::Write { moves: Moves::Both },
            HandleKind::Site,
        )
    };
    let args = vec![
        CVal::Borrow(rep_of(&probe, key, mode), kind),
        CVal::Own(funds),
    ];
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let refusal = match dual.invoke_both(export, &args)? {
        DualOutcome::Values(_) => None,
        DualOutcome::Refused(reason) => Some(reason),
        DualOutcome::Trapped(reason) => bail!("{export} trapped: {reason:?}"),
    };
    let (blessed, reference) = dual.finish()?;
    let blessed = settled(blessed.session, key, funds, refusal);
    let reference = settled(reference.session, key, funds, refusal);
    assert_eq!(blessed, reference, "{export} settled differently");
    Ok(blessed)
}

#[test]
fn a_credit_is_what_the_bucket_carried() -> Result<()> {
    let fx = fixture();

    // Both modes record the same credit. What separates them is when
    // they may run, not what the receipt says they did — an exclusive
    // value cell reports a movement and no absolute, because the value
    // it ends at is the settling shard's answer rather than this
    // transaction's.
    let exclusive = credited(&fx, "put-write", 30, false)?;
    assert_eq!(exclusive.credit, Some(30));
    assert_eq!(exclusive.cell, None, "a value cell reports no absolute");

    let commutative = credited(&fx, "put-delta", 30, true)?;
    assert_eq!(commutative.credit, Some(30));
    Ok(())
}

#[test]
fn a_put_consumes_the_handle_it_was_given() -> Result<()> {
    let fx = fixture();
    // The canonical ABI lifts an owned argument out of the guest's table,
    // so the value is the kernel's again and the rep names nothing.
    let credited = credited(&fx, "put-write", 30, false)?;
    assert!(!credited.funds_survive);
    Ok(())
}

/// And the handle is gone on the guest's side too: dropping it after
/// the put reaches for a slot the table no longer holds, which both
/// engines refuse as the canonical ABI's own violation.
#[test]
fn a_consumed_handle_cannot_be_dropped_again() -> Result<()> {
    let fx = fixture();
    let build = || {
        let mut host = session_of(&fx);
        minted(&mut host, 30);
        host
    };
    let mut probe = session_of(&fx);
    let funds = minted(&mut probe, 30);
    let rep = rep_of(&probe, fx.vault, Mode::Write { moves: Moves::Both });
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let refused = dual.invoke_both(
        "put-write-then-drop",
        &[CVal::Borrow(rep, HandleKind::Site), CVal::Own(funds)],
    )?;
    assert_eq!(refused, DualOutcome::Trapped(AbortReason::AbiViolation));
    Ok(())
}

#[test]
fn a_credit_past_the_cells_width_refuses_at_the_call() -> Result<()> {
    let fx = fixture();
    let overflowed = credited(&fx, "put-write", u128::MAX, false)?;
    assert_eq!(overflowed.refusal, Some(AbortReason::CellOverflow));
    // Refused, so nothing moved and the value is still the kernel's to
    // account for.
    assert_eq!(overflowed.cell, None);
    assert!(overflowed.funds_survive);
    Ok(())
}

/// Two debits handed back together: the reps, in the slots they landed
/// in, and what each carried.
#[derive(Debug, PartialEq, Eq)]
struct Pair {
    reps: (u32, u32),
    values: (u128, u128),
}

/// What both edges came to, agreed on both engines.
fn paired(fx: &Fixture, a: u64, b: u64) -> Result<Pair> {
    let probe = session_of(fx);
    let ledger = rep_of(&probe, fx.ledger, Mode::Delta);
    let vault = rep_of(&probe, fx.vault, Mode::Write { moves: Moves::Both });
    let mut dual = GUEST.instantiate(FUEL, || session_of(fx))?;
    let produced = dual.invoke_both(
        "take-two",
        &[
            CVal::Borrow(ledger, HandleKind::Site),
            CVal::Borrow(vault, HandleKind::Site),
            CVal::U64(a),
            CVal::U64(b),
        ],
    )?;
    let DualOutcome::Values(values) = produced else {
        bail!("take-two did not produce: {produced:?}");
    };
    let [CVal::Own(one), CVal::Own(two)] = values.as_slice() else {
        bail!("take-two returned {values:?}");
    };
    let (one, two) = (*one, *two);
    let (blessed, reference) = dual.finish()?;
    let (mut blessed, mut reference) = (blessed.session, reference.session);
    let pair = Pair {
        reps: (one, two),
        values: (
            blessed.take_bucket(one)?.quantity(),
            blessed.take_bucket(two)?.quantity(),
        ),
    };
    assert_eq!(
        pair.values,
        (
            reference.take_bucket(one)?.quantity(),
            reference.take_bucket(two)?.quantity(),
        ),
        "the paired values diverged"
    );
    Ok(pair)
}

/// What a bucket weighs, read through a borrow on both engines.
fn weighed(fx: &Fixture, held: u128) -> Result<u64> {
    let build = || {
        let mut host = session_of(fx);
        minted(&mut host, held);
        host
    };
    let mut probe = session_of(fx);
    let funds = minted(&mut probe, held);
    let ledger = rep_of(&probe, fx.ledger, Mode::Delta);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    dual.invoke_both(
        "weigh",
        &[CVal::Own(funds), CVal::Borrow(ledger, HandleKind::Site)],
    )?
    .scalar()
}

/// One split, driven on both engines: what came off, and what was left.
fn split_on_both(fx: &Fixture, held: u128, off: u64) -> Result<(u128, u128)> {
    let build = || {
        let mut host = session_of(fx);
        minted(&mut host, held);
        host
    };
    let mut probe = session_of(fx);
    let funds = minted(&mut probe, held);
    let ledger = rep_of(&probe, fx.ledger, Mode::Delta);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let came_off = dual
        .invoke_both(
            "split",
            &[
                CVal::Own(funds),
                CVal::U64(off),
                CVal::Borrow(ledger, HandleKind::Site),
            ],
        )?
        .bucket()?;
    let (blessed, reference) = dual.finish()?;
    let (mut blessed, mut reference) = (blessed.session, reference.session);
    let taken = blessed.bucket(came_off)?.quantity();
    assert_eq!(
        taken,
        reference.bucket(came_off)?.quantity(),
        "the split diverged"
    );
    // The half that came off is burned rather than lifted away, so what
    // the split divided is still accounted for on both sides of it.
    for session in [&mut blessed, &mut reference] {
        session.grant_issuance(vec![IssuanceGrant {
            resource: RESOURCE,
            kind: ResourceKind::Fungible,
            direction: Issued::Either,
        }]);
        session.burn(came_off)?;
    }
    let (receipt, _) = blessed.finish(vec![], 0).expect("the oracle is clean");
    let left = receipt
        .delta
        .movements
        .get(&fx.ledger)
        .map_or(0, |m| m.credit);
    Ok((taken, left))
}

/// The value a successful lift produced, taken back out beforehand.
fn lifted_value(fx: &Fixture, ids: &[u64]) -> Result<u128> {
    let probe = session_of(fx);
    let held = rep_where(&probe, |c| matches!(c, Capability::Instances { .. }));
    let mut dual = GUEST.instantiate(FUEL, || session_of(fx))?;
    let rep = dual
        .invoke_both(
            "lift",
            &[
                CVal::Borrow(held, HandleKind::Site),
                CVal::Ids(ids.to_vec()),
            ],
        )?
        .bucket()?;
    let (mut blessed, mut reference) = dual.finish().map(|(b, r)| (b.session, r.session))?;
    let value = blessed.take_bucket(rep)?.quantity();
    assert_eq!(
        value,
        reference.take_bucket(rep)?.quantity(),
        "the lift diverged"
    );
    Ok(value)
}

#[test]
fn taking_instances_out_of_a_collection_is_what_produces_them() -> Result<()> {
    let fx = fixture();
    // The removal and the edge are one operation, so what crosses is
    // exactly what left.
    assert_eq!(lifted_value(&fx, &[10, 20])?, 2);

    // And filing them straight back leaves the collection as it was.
    let probe = session_of(&fx);
    let held = rep_where(&probe, |c| matches!(c, Capability::Instances { .. }));
    let mut dual = GUEST.instantiate(FUEL, || session_of(&fx))?;
    let round_trip = dual
        .invoke_both(
            "relift",
            &[
                CVal::Borrow(held, HandleKind::Site),
                CVal::Ids(vec![10, 20]),
            ],
        )?
        .scalar()?;
    assert_eq!(round_trip, 3);

    // Naming none yields an empty bucket, which is how a method that
    // moves nothing gets one.
    assert_eq!(lifted_value(&fx, &[])?, 0);
    Ok(())
}

#[test]
fn an_instance_a_body_does_not_hold_is_refused() -> Result<()> {
    let fx = fixture();
    // The one thing a take can be wrong about: a body naming what the
    // collection does not hold. An interval take could only have answered
    // with silence.
    let probe = session_of(&fx);
    let held = rep_where(&probe, |c| matches!(c, Capability::Instances { .. }));
    let mut dual = GUEST.instantiate(FUEL, || session_of(&fx))?;
    let refused = dual.invoke_both(
        "lift",
        &[
            CVal::Borrow(held, HandleKind::Site),
            CVal::Ids(vec![10, 99]),
        ],
    )?;
    assert_eq!(
        refused,
        DualOutcome::Refused(AbortReason::InstanceNotHeld),
        "an unheld instance is refused"
    );
    Ok(())
}

#[test]
fn a_split_divides_a_bucket_and_loses_nothing() -> Result<()> {
    let fx = fixture();
    let (came_off, left) = split_on_both(&fx, 100, 30)?;
    // Neither half is a number the body wrote down, and together they are
    // what the bucket carried.
    assert_eq!(came_off, 30);
    assert_eq!(left, 70);
    Ok(())
}

#[test]
fn a_bucket_survives_a_split_and_a_merge_whole() -> Result<()> {
    let fx = fixture();
    let build = || {
        let mut host = session_of(&fx);
        minted(&mut host, 100);
        host
    };
    let mut probe = session_of(&fx);
    let funds = minted(&mut probe, 100);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let whole = dual
        .invoke_both("halve", &[CVal::Own(funds), CVal::U64(30)])?
        .bucket()?;
    let (blessed, _) = dual.finish()?;
    let mut blessed = blessed.session;
    assert_eq!(blessed.take_bucket(whole)?.quantity(), 100);
    Ok(())
}

/// A merge of a bucket into itself is refused, identically, by both.
///
/// The lane the divergence would have hidden in. A merge reads its
/// target through a borrow and consumes its source as an own, so naming
/// one bucket twice asks the boundary to take a slot out from under a
/// lend it is holding. The blessed engine refuses that; an interpreter
/// that did not model the lend would hand the kernel one rep twice and
/// have it add a quantity to itself — a doubling on one runtime and a
/// refusal on the other, which is a fork rather than a bug.
///
/// What the kernel does if it is ever reached anyway is its own test.
#[test]
fn a_merge_of_a_bucket_into_itself_is_refused_by_both_engines() -> Result<()> {
    let fx = fixture();
    let build = || {
        let mut host = session_of(&fx);
        minted(&mut host, 100);
        host
    };
    let mut probe = session_of(&fx);
    let funds = minted(&mut probe, 100);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let refused = dual.invoke_both("self-merge", &[CVal::Own(funds)])?;
    assert_eq!(refused, DualOutcome::Trapped(AbortReason::AbiViolation));
    // And neither runtime moved value: the bucket carries what it did.
    let (blessed, reference) = dual.finish()?;
    assert_eq!(blessed.session.bucket(funds)?, Held::Amount(100));
    assert_eq!(reference.session.bucket(funds)?, Held::Amount(100));
    Ok(())
}

#[test]
fn a_body_can_read_what_it_was_paid_without_moving_it() -> Result<()> {
    let fx = fixture();
    assert_eq!(weighed(&fx, 4242)?, 4242);
    Ok(())
}

#[test]
fn a_method_with_two_edges_hands_back_two_buckets() -> Result<()> {
    let fx = fixture();
    let pair = paired(&fx, 30, 40)?;

    // Distinct buckets, in the order the body took them: which slot an
    // edge lands in is what a consumer routes on, so the two engines
    // agreeing on it is the whole of what the tuple has to promise.
    assert_eq!(pair.values, (30, 40));
    assert_ne!(pair.reps.0, pair.reps.1);
    Ok(())
}

#[test]
fn issuance_is_the_one_bucket_with_no_cell_behind_it() -> Result<()> {
    let fx = fixture();
    let (issued, _) = both(&fx, Take::Issue(9))?;
    assert_eq!(issued, Took::Value(9));
    Ok(())
}

#[test]
fn an_invocation_granted_nothing_issues_nothing() -> Result<()> {
    let fx = fixture();
    let (refused, _) = both(&fx, Take::IssueUngranted(9))?;
    // The handle is what a declaration grants, so a body that declared no
    // issued output has nothing to name — and reaching for one anyway is
    // the same refusal on both engines.
    assert_eq!(refused, Took::Refusal(AbortReason::IssuanceUngranted));
    Ok(())
}

#[test]
fn a_reservation_answers_once() -> Result<()> {
    let fx = fixture();
    let (twice, _) = both(&fx, Take::ReserveTwice)?;
    // The read this replaces answered every time it was asked, so a body
    // asking twice held two edges against one hold.
    assert_eq!(twice, Took::Refusal(AbortReason::ReservationAlreadyTaken));
    Ok(())
}

#[test]
fn ownership_transfer_and_the_drop_agree_across_the_engines() -> Result<()> {
    let fx = fixture();
    let trace = bucket_sequence(&fx)?;

    // The component model reserves index 0, so the kept bucket takes the
    // first allocatable slot — and keeps it, which is what the borrow
    // lands one past.
    assert_eq!(trace.held_handle, 1);
    assert_eq!(trace.borrow_handle, 2);
    // Returning the bucket frees slot 1 after the borrow freed slot 2, so
    // the next lowered handle takes the more recently freed of the two.
    assert_eq!(trace.discard_handle, 1);
    Ok(())
}

#[test]
fn a_returned_bucket_comes_back_to_the_kernel_whole() -> Result<()> {
    let fx = fixture();
    let trace = bucket_sequence(&fx)?;
    // The guest held a handle and gave back the same rep; the amount was
    // never anywhere it could be rewritten.
    assert_eq!(trace.released_amount, HELD);
    Ok(())
}

#[test]
fn an_empty_bucket_drops_and_reaches_the_host() -> Result<()> {
    let fx = fixture();
    let trace = bucket_sequence(&fx)?;
    // Nothing but the destructor could have emptied the slot: the lane
    // takes the released bucket by hand and never touches this one.
    assert!(!trace.discarded_survives);
    Ok(())
}

#[test]
fn letting_go_of_value_keeps_it_the_tables_to_answer_for() -> Result<()> {
    let fx = fixture();
    // The property the handle exists for, and where it is settled. The
    // canonical ABI routes a discarded owned handle to the host, so the
    // host learns of the discard where a record could not have noticed
    // being forgotten — and what the host does with it is hold on to the
    // value rather than judge it. A body that keeps a full bucket to the
    // end delivers no drop at all, so a verdict here would answer for one
    // of the two ways of losing value and be silent about the other.
    let (outcome, held) = discarded(&fx, 40)?;
    assert!(matches!(outcome, DualOutcome::Values(_)));
    assert_eq!(held, Some(40), "the value is still the transaction's");

    // Nothing to lose is nothing to hold on to, so the slot goes.
    let (outcome, held) = discarded(&fx, 0)?;
    assert!(matches!(outcome, DualOutcome::Values(_)));
    assert_eq!(held, None, "an empty bucket leaves the table");
    Ok(())
}

#[test]
fn a_transaction_that_let_value_go_does_not_commit_on_either_engine() -> Result<()> {
    let fx = fixture();
    // The other half of the same fact. The discard itself judges nothing,
    // so what says the value was lost is the close — and it has to say it
    // on both engines, because the receipt is what every participant of a
    // cross-shard transaction derives for itself.
    for (held, expected) in [(40u128, Some(AbortReason::ValueDropped)), (0, None)] {
        let (blessed, reference) = closed_after_discarding(&fx, held)?;
        assert_eq!(blessed, expected, "the blessed lane at {held}");
        assert_eq!(reference, expected, "the reference lane at {held}");
    }
    Ok(())
}

/// One discard on both engines, carried through to the close: the abort
/// each lane's receipt names, or `None` where it committed.
fn closed_after_discarding(
    fx: &Fixture,
    held: u128,
) -> Result<(Option<AbortReason>, Option<AbortReason>)> {
    let build = || {
        let mut host = session_of(fx);
        minted(&mut host, held);
        host
    };
    let mut probe = session_of(fx);
    let funds = minted(&mut probe, held);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    dual.invoke_both("discard", &[CVal::Own(funds)])?;

    let (blessed, reference) = dual.finish()?;
    let closed = |session: KernelSession| {
        let (receipt, _) = session.finish(vec![], 0).expect("the close receipts");
        match receipt.outcome {
            Outcome::UserError { reason } => Some(reason),
            _ => None,
        }
    };
    Ok((closed(blessed.session), closed(reference.session)))
}

/// One discard on both engines: how the drop ended, and what the rep
/// still names afterwards — which the two lanes have to agree on for
/// `finish` to reach one verdict.
fn discarded(fx: &Fixture, held: u128) -> Result<(DualOutcome, Option<u128>)> {
    let build = || {
        let mut host = session_of(fx);
        minted(&mut host, held);
        host
    };
    let mut probe = session_of(fx);
    let funds = minted(&mut probe, held);
    let mut dual = GUEST.instantiate(FUEL, build)?;
    let outcome = dual.invoke_both("discard", &[CVal::Own(funds)])?;

    let (blessed, reference) = dual.finish()?;
    let survives = |session: KernelSession| session.bucket(funds).ok().map(|h| h.quantity());
    let blessed = survives(blessed.session);
    assert_eq!(blessed, survives(reference.session), "the discard diverged");
    Ok((outcome, blessed))
}

// ─── and the read that moves none of it ────────────────────────────────

/// A component whose one export asks a balance and hands back the figure.
///
/// Its own component rather than a fixture export, because what it needs
/// is a capability the fixture does not carry: a fresh read of a cell
/// that holds value, which excludes no other reader.
const PEEK_WAT: &str = r#"
(component
  (import "hyperscale:kernel/state" (instance $state
    (export "site" (type $ar (sub resource)))
    (type $amt_decl (record (field "low" u64) (field "high" u64)))
    (export "amount" (type $amt (eq $amt_decl)))
    (export "site-balance" (func (param "c" (borrow $ar)) (param "element" u32) (result $amt)))))
  (alias export $state "site" (type $aread))
  (alias export $state "site-balance" (func $balance))

  (core module $alloc
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) i32.const 1024))
  (core instance $a (instantiate $alloc))
  (core func $balance_l (canon lower (func $balance) (memory $a "mem")))
  (core func $drop_r (canon resource.drop $aread))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "balance" (func $balance (param i32 i32 i32)))
    (import "k" "drop" (func $drop (param i32)))
    (func (export "peek") (param i32) (result i64)
      (local $held i64)
      local.get 0
      i32.const 0
      i32.const 96
      call $balance
      i32.const 96
      i64.load
      local.set $held
      local.get 0
      call $drop
      local.get $held))

  (core instance $i (instantiate $m
    (with "env" (instance (export "mem" (memory $a "mem"))))
    (with "k" (instance (export "balance" (func $balance_l)) (export "drop" (func $drop_r))))))

  (func (export "peek")
    (param "c" (borrow $aread)) (result u64)
    (canon lift (core func $i "peek"))))
"#;

/// A session over one vault, declared read and denominated — the shape a
/// method that only asks what a pool holds declares.
fn peeking() -> KernelSession {
    let key = child_key(&TestHasher, ISSUER, SlotId(1), &[]);
    let mut store = MemoryStore::new();
    store.write(key, encode_amount(BALANCE).to_vec());
    let read = Effect {
        target: EffectTarget::Point(key),
        mode: Mode::Read,
    };
    let mut declared = EffectSet::default();
    declared.insert(read).expect("the set takes it");
    materialize(&store, &declared, &[Some(RESOURCE)], tx(), env())
}

/// Asking a balance is the one thing a body does with value that moves
/// none of it, and the two engines answer the same figure through the
/// same handle.
#[test]
fn a_balance_read_agrees_between_the_engines() -> Result<()> {
    let guest = DualGuest::compile(&parse_str(PEEK_WAT)?)?;
    let mut dual = guest.instantiate(FUEL, peeking)?;
    let held = dual
        .invoke_both("peek", &[CVal::Borrow(0, HandleKind::Site)])?
        .scalar()
        .map_err(|other| format_err!("peek: {other}"))?;
    assert_eq!(u128::from(held), BALANCE);
    Ok(())
}

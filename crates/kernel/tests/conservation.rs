//! Conservation through the session that performs it: a receipt reports
//! what its transaction brought into and out of existence, and each
//! execution balances on its own.
//!
//! Nothing here keeps a running total. Chain-wide supply is a fold over
//! receipts, which is what makes it survive a reshape: a sum does not
//! live at a prefix, and two children's totals adding to their parent's
//! would pin nothing about which resource went to which side.

use hyperscale_vm_effects::{
    Hash32, IntentHash, IntentRecord, Nullifier, ResourceKind, SlotId, TestHasher, Value, child_key,
};

/// Any expiry; these tests never reach one.
const TEST_EXPIRY_MS: u64 = 1_000_000;
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_types::{
    Address, AddressClass, PrincipalAddr, SubstateKey, TxHash, encode_amount,
};

const VAULT: SlotId = SlotId(1);

fn vault(owner: u8, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([owner; 31], AddressClass::Component),
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

/// The two operations that move supply, through the session that performs
/// them.
///
/// Above the accumulator is arithmetic anyone can do; what these pin is
/// that a receipt reports what its transaction actually brought into and
/// out of existence, which is what a shard has to add to its own total.
mod through_the_session {
    use std::sync::Arc;

    use hyperscale_vm_effects::{Declaration, Hasher, IssuanceGrant, Issued};
    use hyperscale_vm_kernel::{EnvInputs, FeeBurn, KernelSession, OverlayStore, SupplyDelta};
    use hyperscale_vm_types::{
        AbortReason, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome, ResourceAddr,
    };

    use super::{Hash32, MemoryStore, ResourceKind, TestHasher, TxHash, encode_amount, vault};

    const UNIT: ResourceAddr = ResourceAddr::new([0xA1; 31]);

    fn hash(data: &[u8]) -> [u8; 32] {
        TestHasher.hash(b"crypto", &[data]).0
    }

    /// A session over one vault holding the resource the grant issues.
    fn session() -> KernelSession {
        session_over(MemoryStore::new())
    }

    /// The same, over a store that already holds something.
    fn session_over(store: MemoryStore) -> KernelSession {
        let moving = Effect {
            target: EffectTarget::Point(vault(1, UNIT.address())),
            mode: Mode::Delta { moves: Moves::Both },
        };
        let mut set = EffectSet::new();
        set.insert_at_cap(moving).expect("one cell");
        let declaration = Declaration::from_set(set).denominated(|_| Some(UNIT));
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &declaration,
            TxHash(Hash32([9; 32])),
            EnvInputs::unsealed(0),
            hash,
        )
        .expect("one unheld delta cell materializes");
        session.grant_issuance(vec![IssuanceGrant {
            resource: UNIT,
            kind: ResourceKind::Fungible,
            direction: Issued::Either,
        }]);
        session
    }

    fn completed(session: KernelSession) -> SupplyDelta {
        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the oracle stands");
        receipt.supply
    }

    /// A queued movement answers a presence question the way it will
    /// answer at commit: a credited cell is present to the gate that
    /// asks, and a drained one is not.
    #[test]
    fn presence_follows_the_queued_movements() {
        let key = vault(1, UNIT.address());
        let target = EffectTarget::Point(key);

        let mut crediting = session();
        assert!(!crediting.declared_present(target).expect("declared"));
        let minted = crediting.mint(0, 500).expect("the grant mints");
        crediting.cell_put(0, 0, minted).expect("the credit queues");
        assert!(crediting.declared_present(target).expect("declared"));

        let mut held = MemoryStore::new();
        held.write(key, encode_amount(500).to_vec());
        let mut draining = session_over(held);
        assert!(draining.declared_present(target).expect("declared"));
        let taken = draining.cell_take(0, 0, 500).expect("the debit queues");
        draining.burn(taken).expect("the grant burns");
        assert!(!draining.declared_present(target).expect("declared"));
    }

    /// A mint reports what it created, which is what a fold over
    /// receipts adds up.
    #[test]
    fn a_mint_is_what_the_receipt_reports() {
        let mut session = session();
        let minted = session.mint(0, 500).expect("the grant mints");
        session.cell_put(0, 0, minted).expect("into its own vault");

        let supply = completed(session);
        assert_eq!(supply.minted(UNIT), 500);
        assert_eq!(supply.burned(UNIT), 0);
    }

    /// A burn reports what it destroyed, and the round trip nets to
    /// nothing — which is the whole of what a kept accumulator would
    /// have said, read off the two receipts instead.
    /// The fee the shard states is a debit on the payer's vault and a
    /// burn of the same amount: the receipt reports both, the vault's
    /// movement carries the debit beside whatever else moved it, and
    /// the fold balances them.
    #[test]
    fn a_fee_is_a_burn_the_fold_sees() {
        let payer = vault(2, UNIT.address());
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT.address()), encode_amount(500).to_vec());
        held.write(payer, encode_amount(100).to_vec());
        let session = session_over(held).with_fee(Some(FeeBurn {
            vault: payer,
            resource: UNIT,
            amount: 21,
        }));
        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the oracle stands");
        assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
        assert_eq!(receipt.supply.burned(UNIT), 21);
        assert_eq!(receipt.supply.minted(UNIT), 0);
        let movement = receipt
            .delta
            .movements
            .get(&payer)
            .expect("the fee is a movement on the payer's vault");
        assert_eq!((movement.credit, movement.debit), (0, 21));
    }

    /// A payer that cannot cover the price loses the transaction, not a
    /// balance: the fee is judged against the vault like any debit.
    #[test]
    fn a_fee_the_payer_cannot_cover_refuses_the_transaction() {
        let payer = vault(2, UNIT.address());
        let mut held = MemoryStore::new();
        held.write(payer, encode_amount(20).to_vec());
        let session = session_over(held).with_fee(Some(FeeBurn {
            vault: payer,
            resource: UNIT,
            amount: 21,
        }));
        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the oracle stands");
        assert_eq!(
            receipt.outcome,
            Outcome::Infeasible {
                key: payer,
                amount: 21
            }
        );
        assert_eq!(receipt.supply, SupplyDelta::default());
    }

    #[test]
    fn a_burn_returns_what_a_mint_added() {
        let mut minting = session();
        let minted = minting.mint(0, 500).expect("the grant mints");
        minting.cell_put(0, 0, minted).expect("into its own vault");
        let created = completed(minting);

        // The burn needs value to destroy, which is the mint's — held in
        // the cell rather than threaded through, because what is under
        // test is the reporting and not the store.
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT.address()), encode_amount(500).to_vec());
        let mut burning = session_over(held);
        let taken = burning.cell_take(0, 0, 500).expect("the debit is queued");
        burning.burn(taken).expect("the grant burns");
        let destroyed = completed(burning);

        assert_eq!(destroyed.burned(UNIT), 500);
        assert_eq!(created.minted(UNIT), destroyed.burned(UNIT));
    }

    /// Both halves are reported, because they are two facts.
    ///
    /// A net of zero would read as a transaction that touched nothing,
    /// where this one created value and destroyed value — and a shard
    /// auditing its own trajectory needs to see both.
    #[test]
    fn a_mint_and_a_burn_in_one_transaction_are_both_recorded() {
        let mut session = session();
        let minted = session.mint(0, 500).expect("the grant mints");
        session.burn(minted).expect("the grant burns");

        let supply = completed(session);
        assert_eq!((supply.minted(UNIT), supply.burned(UNIT)), (500, 500));
        assert!(!supply.is_empty(), "two movements, not a net of nothing");
    }

    /// An abort brings nothing into existence, whatever it ran: a body
    /// that dropped value flips inside `finish`, and the flip discards
    /// the supply it claimed along with everything else.
    #[test]
    fn an_aborted_mint_moves_no_supply() {
        let mut session = session();
        // Minted, and never landed in a cell: the account cannot balance.
        let minted = session.mint(0, 500).expect("the grant mints");
        let _ = minted;

        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the flip still produces a receipt");
        assert!(matches!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::ValueDropped
            }
        ));
        assert!(receipt.supply.is_empty());
    }

    /// A credit no mint stands behind does not commit.
    ///
    /// The one thing a package cannot express and the kernel must never
    /// do: value appearing in a cell with nothing accounting for it.
    /// Reached here through the unmediated primitive, which is the only
    /// way to write down what a defect would look like — every path a
    /// body can take goes through a bucket, and the table has to balance
    /// before any of it commits.
    #[test]
    fn value_from_nowhere_does_not_commit() {
        let mut session = session();
        session.delta_add(0, 0, 500).expect("the queue takes it");

        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the fold produces a receipt rather than failing the batch");
        assert_eq!(
            receipt.outcome,
            Outcome::ProtocolError {
                reason: AbortReason::ValueNotConserved,
            },
            "the kernel lost the value, so the kernel is what the abort names"
        );
        assert!(receipt.delta.is_empty(), "nothing it wrote survives");
        assert!(receipt.supply.is_empty(), "and nothing it claimed does");
    }

    /// A nullifier key that also materialized as a value cell aborts the
    /// transaction rather than crashing the batch.
    ///
    /// The spend is raw bytes — the transaction hash — which a cell
    /// denominated in a resource would decode back as an amount at apply,
    /// failing the whole batch. The nullifier is declared as the
    /// `Write { Both }` its screen demands and denominated all the same, so
    /// it materializes as a value cell; `finish` states the invariant
    /// instead of writing the spend: a nullifier cell is not a value cell.
    #[test]
    fn a_nullifier_that_is_a_value_cell_aborts_the_transaction() {
        let key = vault(1, UNIT.address());
        let writing = Effect {
            target: EffectTarget::Point(key),
            mode: Mode::Write { moves: Moves::Both },
        };
        let mut set = EffectSet::new();
        set.insert_at_cap(writing).expect("one cell");
        let declaration = Declaration::from_set(set).denominated(|_| Some(UNIT));
        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(MemoryStore::new())),
            &declaration,
            TxHash(Hash32([9; 32])),
            EnvInputs::unsealed(0),
            hash,
        )
        .expect("one denominated write cell materializes")
        .with_nullifiers(vec![super::nullifier_record(
            super::IntentHash(Hash32([9; 32])),
            key,
        )]);

        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the guard produces a receipt rather than failing the batch");
        assert_eq!(
            receipt.outcome,
            Outcome::ProtocolError {
                reason: AbortReason::MalformedAmountCell,
            },
            "a nullifier cell is not a value cell"
        );
        assert!(receipt.delta.is_empty(), "nothing it wrote survives");
    }

    /// The same in the other direction: a debit that reached no bucket.
    #[test]
    fn value_into_nowhere_does_not_commit_either() {
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT.address()), encode_amount(500).to_vec());
        let mut session = session_over(held);
        session.delta_sub(0, 0, 500).expect("the queue takes it");

        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("a receipt either way");
        assert_eq!(
            receipt.outcome,
            Outcome::ProtocolError {
                reason: AbortReason::ValueNotConserved,
            }
        );
    }

    /// A total the fold cannot weigh is one it does not pass.
    ///
    /// One cell's balance cannot overflow a side of the sum, but a
    /// transaction reaching enough of them can. Totalling to a ceiling
    /// instead would pin both sides there and read the arithmetic it
    /// could not do as agreement — here, a unit appearing out of nothing
    /// beside a debit large enough to hide it.
    #[test]
    fn a_total_past_the_accumulator_does_not_commit() {
        let drained = vault(2, UNIT.address());
        let mut held = MemoryStore::new();
        held.write(drained, encode_amount(u128::MAX).to_vec());

        let cells = [vault(1, UNIT.address()), drained, vault(3, UNIT.address())];
        let mut set = EffectSet::new();
        for cell in cells {
            set.insert_at_cap(Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Delta { moves: Moves::Both },
            })
            .expect("three distinct cells");
        }
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(held)),
            &Declaration::from_set(set).denominated(|_| Some(UNIT)),
            TxHash(Hash32([9; 32])),
            EnvInputs::unsealed(0),
            hash,
        )
        .expect("three unheld delta cells materialize");

        // The clause list orders by the set, so each cell's rep is its
        // position among the three keys ascending.
        let rep = |cell| {
            u32::try_from(cells.iter().filter(|other| **other < cell).count()).expect("of three")
        };
        session
            .delta_sub(rep(drained), 0, u128::MAX)
            .expect("the cell covers it");
        session
            .delta_add(rep(cells[0]), 0, u128::MAX)
            .expect("the queue takes it");
        session
            .delta_add(rep(cells[2]), 0, 1)
            .expect("and the unit that overflows the side");

        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("a receipt either way");
        assert_eq!(
            receipt.outcome,
            Outcome::ProtocolError {
                reason: AbortReason::ValueNotConserved,
            },
            "a side that left u128 is unweighed, and unweighed is unconserved"
        );
    }

    /// A transfer moves no supply, which is what makes same-shard
    /// movement conserve the accumulator without counting anything.
    #[test]
    fn value_moving_between_cells_moves_no_supply() {
        let mut session = session();
        let minted = session.mint(0, 500).expect("the grant mints");
        session.cell_put(0, 0, minted).expect("into its own vault");
        let moved = session.cell_take(0, 0, 200).expect("out again");
        session.cell_put(0, 0, moved).expect("and back");

        // The mint is the only movement; the two cell operations cancel.
        let supply = completed(session);
        assert_eq!((supply.minted(UNIT), supply.burned(UNIT)), (500, 0));
    }
}

/// What a vault has promised to fees, through the session that judges
/// under it and the replay that applies what the session produced.
mod under_fee_holds {
    use std::sync::{Arc, Mutex};

    use hyperscale_vm_effects::{Declaration, DeclaredAccess, Hasher};
    use hyperscale_vm_kernel::{
        Baseline, BatchOutcome, BatchTx, EnvInputs, ExecutionMode, FeeBurn, FeeHolds,
        KernelSession, OverlayStore, OwnerSet, Receipt, RunResult, Substates, decode_amount,
        execute_batch,
    };
    use hyperscale_vm_types::{
        AbortReason, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome, ResourceAddr,
        SubstateKey,
    };
    use proptest::prelude::{prop_assert_eq, proptest};

    use super::{Hash32, MemoryStore, TestHasher, TxHash, encode_amount, vault};

    pub const UNIT: ResourceAddr = ResourceAddr::new([0xA1; 31]);

    fn hash(data: &[u8]) -> [u8; 32] {
        TestHasher.hash(b"crypto", &[data]).0
    }

    pub const fn tx(byte: u8) -> TxHash {
        TxHash(Hash32([byte; 32]))
    }

    /// The payer's vault, which every fee here burns from.
    pub fn payer() -> SubstateKey {
        vault(2, UNIT.address())
    }

    /// Where a body files what it took.
    pub fn sink() -> SubstateKey {
        vault(3, UNIT.address())
    }

    /// A store whose payer holds `balance`.
    pub fn funded(balance: u128) -> MemoryStore {
        let mut store = MemoryStore::new();
        store.write(payer(), encode_amount(balance).to_vec());
        store
    }

    /// `store` with fee holds standing on the payer's vault: one per
    /// member named, and `rest` no member ends.
    fn holding(mut store: MemoryStore, members: &[(TxHash, u128)], rest: u128) -> MemoryStore {
        store.hold_fees(payer(), standing(members, rest));
        store
    }

    fn standing(members: &[(TxHash, u128)], rest: u128) -> FeeHolds {
        FeeHolds {
            members: members.iter().copied().collect(),
            rest,
        }
    }

    pub fn fee(amount: u128) -> FeeBurn {
        FeeBurn {
            vault: payer(),
            resource: UNIT,
            amount,
        }
    }

    /// A member that may move the payer's vault into the sink, burning
    /// `burn` from the vault.
    fn member(tx: TxHash, burn: FeeBurn) -> BatchTx {
        let declaration = declaring(&[
            (payer(), Mode::Delta { moves: Moves::Both }),
            (sink(), Mode::Delta { moves: Moves::Both }),
        ]);
        BatchTx::new(tx, declaration, EnvInputs::unsealed(0)).with_fee(Some(burn))
    }

    pub const fn completed(session: KernelSession) -> RunResult {
        RunResult::Completed {
            session,
            answers: vec![],
            spent: vec![],
        }
    }

    /// A [`member`]'s body: what `amount` names for it out of the vault
    /// and into the sink, or nothing at all where that is zero.
    fn spend(
        amount: impl Fn(TxHash) -> u128 + Sync,
    ) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
        move |entry, mut session| {
            let amount = amount(entry.tx);
            if amount > 0 {
                let taken = session.cell_take(0, 0, amount).expect("the debit queues");
                session.cell_put(1, 0, taken).expect("into the sink");
            }
            completed(session)
        }
    }

    /// A declaration of value cells in clause order, folded to its set.
    pub fn declaring(clauses: &[(SubstateKey, Mode)]) -> Declaration {
        let ordered: Vec<DeclaredAccess> = clauses
            .iter()
            .map(|(key, mode)| DeclaredAccess {
                reach: None,
                effect: Effect {
                    target: EffectTarget::Point(*key),
                    mode: *mode,
                },
                holds: Some(UNIT),
                clause: None,
            })
            .collect();
        let mut set = EffectSet::new();
        for declared in &ordered {
            set.insert_at_cap(declared.effect)
                .expect("the clauses fold");
        }
        Declaration {
            set,
            ordered,
            ..Declaration::default()
        }
    }

    /// What the store holds at `key`, an absent cell being zero.
    pub fn amount_at(store: &impl Substates, key: SubstateKey) -> u128 {
        store
            .cell(key)
            .map_or(0, |cell| decode_amount(&cell).expect("an amount cell"))
    }

    pub fn run(
        base: MemoryStore,
        batch: &[BatchTx],
        body: impl Fn(&BatchTx, KernelSession) -> RunResult + Sync,
    ) -> BatchOutcome {
        execute_batch(Arc::new(base), batch, &body, hash, ExecutionMode::Serial)
            .expect("no member fails the batch")
    }

    /// One member through a session of its own over `store`: its receipt
    /// and the store the session threads on.
    pub fn in_session(
        store: MemoryStore,
        entry: &BatchTx,
        body: &impl Fn(&BatchTx, KernelSession) -> RunResult,
    ) -> (Receipt, OverlayStore) {
        let session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &entry.declaration,
            entry.tx,
            entry.env.clone(),
            hash,
        )
        .expect("the store covers what the member reserves")
        .with_fee(entry.fee)
        .with_credits_withheld(entry.credits_withheld);
        let RunResult::Completed {
            session,
            answers,
            spent,
        } = body(entry, session)
        else {
            unreachable!("a body that declines has no session to finish");
        };
        session.finish(answers, spent).expect("the oracle stands")
    }

    /// One member alone over `base`, through a session and through a
    /// batch, which agree: its outcome, what the payer's vault holds
    /// after it, and the fee holds left standing there.
    fn alone(
        base: MemoryStore,
        entry: BatchTx,
        body: impl Fn(&BatchTx, KernelSession) -> RunResult + Sync,
    ) -> (Outcome, u128, FeeHolds) {
        let tx = entry.tx;
        let (receipt, threaded) = in_session(base.clone(), &entry, &body);
        let outcome = run(base, &[entry], body);
        assert_eq!(
            outcome.receipts[&tx], receipt,
            "the replay applies what the session judged"
        );
        let left = amount_at(&threaded, payer());
        let holds = threaded.fee_holds(payer());
        assert_eq!(amount_at(&outcome.store, payer()), left);
        assert_eq!(outcome.store.fee_holds(payer()), holds);
        (receipt.outcome, left, holds)
    }

    /// The burn comes out of the hold it was held for: a vault holding
    /// exactly its member's hold covers the burn only because judging
    /// the burn ends that hold first.
    #[test]
    fn a_fee_burn_ends_its_members_hold() {
        let base = holding(funded(21), &[(tx(1), 21)], 0);
        let (outcome, left, holds) = alone(base, member(tx(1), fee(21)), spend(|_| 0));
        assert!(matches!(outcome, Outcome::Completed { .. }), "{outcome:?}");
        assert_eq!(left, 0);
        assert_eq!(holds, FeeHolds::default());
    }

    /// A fee of nothing is still the judgement its hold was waiting on.
    #[test]
    fn a_burn_of_nothing_ends_its_members_hold() {
        let base = holding(funded(10), &[(tx(1), 10)], 0);
        let entry = member(tx(1), fee(0));
        let (receipt, _) = in_session(base.clone(), &entry, &spend(|_| 0));
        assert!(
            !receipt.delta.movements.contains_key(&payer()),
            "nothing moved, so the receipt carries no movement"
        );
        assert!(receipt.supply.is_empty());

        let (outcome, left, holds) = alone(base, entry, spend(|_| 0));
        assert!(matches!(outcome, Outcome::Completed { .. }), "{outcome:?}");
        assert_eq!(left, 10);
        assert_eq!(holds, FeeHolds::default());
    }

    /// The shard that applies the vault judges the burn, so it is the
    /// one that ends the hold: anywhere else the fee is neither burned
    /// nor answered.
    #[test]
    fn a_fee_on_a_vault_held_elsewhere_ends_nothing() {
        let elsewhere = payer().owner;
        let base = holding(funded(10), &[(tx(1), 10)], 0);
        let entry =
            member(tx(1), fee(5)).with_applies(OwnerSet::of(move |owner| owner != elsewhere));
        let outcome = run(base, &[entry], spend(|_| 0));

        let receipt = &outcome.receipts[&tx(1)];
        assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
        assert!(!receipt.delta.movements.contains_key(&payer()));
        assert!(receipt.supply.is_empty());
        assert_eq!(amount_at(&outcome.store, payer()), 10);
        assert_eq!(
            outcome.store.fee_holds(payer()),
            standing(&[(tx(1), 10)], 0)
        );
    }

    /// Ending its own hold frees the burn nothing else: what stands for
    /// another member and what stands for nobody in the batch both stay
    /// under it, and both are standing afterwards.
    #[test]
    fn a_fee_burn_leaves_every_other_hold() {
        for (balance, other, rest) in [(100, 40, 30), (99, 39, 30), (99, 40, 29)] {
            let base = holding(funded(balance), &[(tx(1), 30), (tx(2), other)], rest);
            let (outcome, left, holds) = alone(base, member(tx(1), fee(30)), spend(|_| 0));
            assert!(matches!(outcome, Outcome::Completed { .. }), "{outcome:?}");
            assert_eq!(left, balance - 30);
            assert_eq!(holds, standing(&[(tx(2), other)], rest));
        }

        // One short of the burn above the other two, and the member
        // loses: its own hold is back with everything else it did.
        let base = holding(funded(99), &[(tx(1), 30), (tx(2), 40)], 30);
        let (outcome, left, holds) = alone(base, member(tx(1), fee(30)), spend(|_| 0));
        assert_eq!(
            outcome,
            Outcome::Infeasible {
                key: payer(),
                amount: 30
            }
        );
        assert_eq!(left, 99);
        assert_eq!(holds, standing(&[(tx(1), 30), (tx(2), 40)], 30));
    }

    /// A member's hold stands under its own body at what it was held
    /// for, whatever the burn turns out to take of it.
    #[test]
    fn a_members_body_leaves_its_own_hold() {
        let base = holding(funded(100), &[(tx(1), 30)], 0);

        let (outcome, left, holds) = alone(base.clone(), member(tx(1), fee(10)), spend(|_| 71));
        assert_eq!(
            outcome,
            Outcome::Infeasible {
                key: payer(),
                amount: 71
            },
            "a debit into the hold is a debit past the floor"
        );
        assert_eq!(left, 100);
        assert_eq!(holds, standing(&[(tx(1), 30)], 0));

        let (outcome, left, holds) = alone(base, member(tx(1), fee(10)), spend(|_| 70));
        assert!(matches!(outcome, Outcome::Completed { .. }), "{outcome:?}");
        assert_eq!(
            left, 20,
            "the body down to the hold, then the burn out of it"
        );
        assert_eq!(holds, FeeHolds::default());
    }

    /// A member that does not complete was not charged here, so the hold
    /// its charge will come out of stands; the reservation it declared
    /// was its own and goes.
    #[test]
    fn an_aborted_member_keeps_its_fee_hold() {
        let declaration = declaring(&[
            (payer(), Mode::Reserve { amount: 20 }),
            (sink(), Mode::Delta { moves: Moves::Both }),
        ]);
        let entry = BatchTx::new(tx(1), declaration, EnvInputs::unsealed(0)).with_fee(Some(fee(5)));
        let declining = |_: &BatchTx, session: KernelSession| RunResult::Aborted {
            session,
            outcome: Outcome::UserError {
                reason: AbortReason::Unreachable,
            },
            spent: vec![],
        };
        let outcome = run(holding(funded(100), &[(tx(1), 30)], 0), &[entry], declining);

        assert!(matches!(
            outcome.receipts[&tx(1)].outcome,
            Outcome::UserError { .. }
        ));
        assert_eq!(amount_at(&outcome.store, payer()), 100);
        assert_eq!(
            outcome.store.fee_holds(payer()),
            standing(&[(tx(1), 30)], 0)
        );
        assert_eq!(outcome.store.held_reservation(payer(), tx(1)), None);
    }

    /// Two members of one payer whose holds are the whole vault: each
    /// burns out of its own, in its own conflict group, under the
    /// other's.
    #[test]
    fn two_members_of_one_payer_both_burn() {
        let base = holding(funded(70), &[(tx(1), 30), (tx(2), 40)], 0);
        let batch = [member(tx(1), fee(30)), member(tx(2), fee(40))];
        let outcome = run(base, &batch, spend(|_| 0));

        for entry in &batch {
            let receipt = &outcome.receipts[&entry.tx];
            assert!(
                matches!(receipt.outcome, Outcome::Completed { .. }),
                "{:?}",
                receipt.outcome
            );
        }
        assert_eq!(amount_at(&outcome.store, payer()), 0);
        assert_eq!(outcome.store.fee_holds(payer()), FeeHolds::default());
    }

    /// The store a session threads on carries its burn, so a later
    /// member of the payer's conflict group reads the vault the
    /// canonical state will hold.
    #[test]
    fn a_group_mate_reads_the_vault_less_the_burn() {
        let reader = BatchTx::new(
            tx(2),
            declaring(&[(payer(), Mode::Read)]),
            EnvInputs::unsealed(0),
        );
        let read = Mutex::new(None);
        let body = |entry: &BatchTx, mut session: KernelSession| {
            if entry.tx == tx(2) {
                let balance = session
                    .amount_cell_balance(0, 0)
                    .expect("the vault is declared");
                *read.lock().expect("one reader") = Some(balance);
            }
            completed(session)
        };
        let outcome = run(funded(100), &[member(tx(1), fee(21)), reader], body);

        for receipt in outcome.receipts.values() {
            assert!(matches!(receipt.outcome, Outcome::Completed { .. }));
        }
        assert_eq!(*read.lock().expect("one reader"), Some(79));
    }

    /// A reservation settles what its body took, and what it held beyond
    /// that is free again by the time the burn is judged: the session
    /// settles before it burns, and the replay applies in that order.
    #[test]
    fn a_reservation_taken_short_frees_the_rest_for_the_burn() {
        // Two grants fold to one hold of 70 and the body takes the 30,
        // so the burn of 50 needs 20 of the 40 the hold lets go.
        let declaration = declaring(&[
            (payer(), Mode::Reserve { amount: 30 }),
            (payer(), Mode::Reserve { amount: 40 }),
            (sink(), Mode::Delta { moves: Moves::Both }),
        ]);
        let body = |_: &BatchTx, mut session: KernelSession| {
            let funds = session.reserve_take(0, 0).expect("the first grant is held");
            session.cell_put(2, 0, funds).expect("into the sink");
            completed(session)
        };
        let entry =
            BatchTx::new(tx(1), declaration, EnvInputs::unsealed(0)).with_fee(Some(fee(50)));

        let (receipt, _) = in_session(funded(100), &entry, &body);
        assert!(
            matches!(receipt.outcome, Outcome::Completed { .. }),
            "the session burns out of what the settle freed: {:?}",
            receipt.outcome
        );

        let outcome = run(funded(100), &[entry], body);
        assert!(
            matches!(outcome.receipts[&tx(1)].outcome, Outcome::Completed { .. }),
            "and the replay agrees: {:?}",
            outcome.receipts[&tx(1)].outcome
        );
        assert_eq!(amount_at(&outcome.store, payer()), 20);
        assert_eq!(amount_at(&outcome.store, sink()), 30);
    }

    /// A member whose credit a counterpart's verdict can still discard
    /// funds no other member of its batch: the debits the batch
    /// completes on a vault stay within what the vault holds without
    /// that credit, wherever the crediting member falls in canonical
    /// order.
    #[test]
    fn a_debit_does_not_spend_a_provisional_credit_of_its_batch() {
        let source = vault(4, UNIT.address());
        let mut base = funded(100);
        base.write(source, encode_amount(50).to_vec());

        let provisional = tx(1);
        let crediting = BatchTx::new(
            provisional,
            declaring(&[
                (source, Mode::Delta { moves: Moves::Both }),
                (payer(), Mode::Delta { moves: Moves::Both }),
            ]),
            EnvInputs::unsealed(0),
        )
        .with_credits_withheld(true);
        let batch = [
            crediting,
            member(tx(2), fee(0)).with_fee(None),
            member(tx(3), fee(0)).with_fee(None),
        ];
        let body = |entry: &BatchTx, mut session: KernelSession| {
            let amount = if entry.tx == provisional { 50 } else { 60 };
            let taken = session.cell_take(0, 0, amount).expect("the debit queues");
            session.cell_put(1, 0, taken).expect("the credit queues");
            completed(session)
        };
        let outcome = run(base, &batch, body);

        assert!(
            matches!(
                outcome.receipts[&provisional].outcome,
                Outcome::Completed { .. }
            ),
            "the crediting member completes: {:?}",
            outcome.receipts[&provisional].outcome
        );
        let debited: u128 = [tx(2), tx(3)]
            .iter()
            .map(|member| &outcome.receipts[member])
            .filter(|receipt| matches!(receipt.outcome, Outcome::Completed { .. }))
            .filter_map(|receipt| receipt.delta.movements.get(&payer()))
            .map(|movement| movement.debit)
            .sum();
        assert!(
            debited <= 100,
            "the batch completes debits of {debited} on a vault holding 100 without the provisional credit"
        );
    }

    proptest! {
        /// Two members in separate conflict groups debit and burn from
        /// one vault. Each group runs over the batch's base, so the
        /// second's session never saw the first; the replay judges it
        /// after the first landed, and reaches the verdict a session
        /// started over the store the first left would have.
        ///
        /// A member its own group refused is not replayed, and keeps
        /// that refusal.
        #[test]
        fn session_and_replay_agree_behind_a_cross_group_mate(
            balance in 0u128..200,
            rest in 0u128..60,
            first in (0u128..120, 0u128..40, 0u128..60),
            second in (0u128..120, 0u128..40, 0u128..60),
        ) {
            let base = holding(funded(balance), &[(tx(1), first.2), (tx(2), second.2)], rest);
            let debits = move |member: TxHash| if member == tx(1) { first.0 } else { second.0 };
            let batch = [member(tx(1), fee(first.1)), member(tx(2), fee(second.1))];

            let together = run(base.clone(), &batch, spend(debits));
            let before = run(base.clone(), &batch[..1], spend(debits));
            prop_assert_eq!(&together.receipts[&tx(1)], &before.receipts[&tx(1)]);

            let left = before.store.collapse_onto(base.clone());
            let (grouped, _) = in_session(base, &batch[1], &spend(debits));
            let expected = if matches!(grouped.outcome, Outcome::Completed { .. }) {
                in_session(left, &batch[1], &spend(debits)).0
            } else {
                grouped
            };
            prop_assert_eq!(&together.receipts[&tx(2)], &expected);
        }
    }
}

/// The credits a member may not spend, through the session that judges
/// under them and the replay that applies what the session produced.
mod under_withheld_credits {
    use hyperscale_vm_kernel::{
        Baseline, BatchTx, EnvInputs, KernelSession, OwnerSet, RunResult, WithheldCredits,
    };
    use hyperscale_vm_types::{Mode, Moves, Outcome, SubstateKey};
    use proptest::collection::vec as prop_vec;
    use proptest::prelude::{any, prop_assert, prop_assert_eq, proptest};

    use super::under_fee_holds::{
        UNIT, amount_at, completed, declaring, fee, funded, in_session, payer, run, sink, tx,
    };
    use super::{MemoryStore, TxHash, encode_amount, vault};

    /// What a body moves into the payer's vault, which holds plenty.
    fn source() -> SubstateKey {
        vault(4, UNIT.address())
    }

    /// A cell every member of a batch may declare an exclusive write on,
    /// which puts them in one conflict group.
    fn latch() -> SubstateKey {
        vault(5, UNIT.address())
    }

    /// A store whose payer holds `balance`, beside a source that covers
    /// every credit a body makes.
    fn supplied(balance: u128) -> MemoryStore {
        let mut store = funded(balance);
        store.write(source(), encode_amount(1_000_000).to_vec());
        store
    }

    /// What one member does: the credit it moves into the payer's vault,
    /// the debit it moves out of it, the fee it burns from it, and
    /// whether its credits are withheld.
    type Moving = (u128, u128, u128, bool);

    /// A member that may credit the payer's vault from the source and
    /// debit it into the sink.
    fn mover(tx: TxHash, (_, _, burn, withheld): Moving, grouped: bool) -> BatchTx {
        let mut clauses = vec![
            (payer(), Mode::Delta { moves: Moves::Both }),
            (sink(), Mode::Delta { moves: Moves::Both }),
            (source(), Mode::Delta { moves: Moves::Both }),
        ];
        if grouped {
            clauses.push((latch(), Mode::Write { moves: Moves::Both }));
        }
        BatchTx::new(tx, declaring(&clauses), EnvInputs::unsealed(0))
            .with_fee(Some(fee(burn)))
            .with_credits_withheld(withheld)
    }

    /// A [`mover`]'s body: its credit into the vault, then its debit out.
    fn moving(
        of: impl Fn(TxHash) -> Moving + Sync,
    ) -> impl Fn(&BatchTx, KernelSession) -> RunResult + Sync {
        move |entry, mut session| {
            let (credit, debit, _, _) = of(entry.tx);
            if credit > 0 {
                let taken = session.cell_take(2, 0, credit).expect("the debit queues");
                session.cell_put(0, 0, taken).expect("into the vault");
            }
            if debit > 0 {
                let taken = session.cell_take(0, 0, debit).expect("the debit queues");
                session.cell_put(1, 0, taken).expect("into the sink");
            }
            completed(session)
        }
    }

    /// A member's debits and its burn come out of its own credit: the
    /// credit is withheld from everyone else, and the member that made
    /// it settles or is discarded with it.
    #[test]
    fn a_member_spends_its_own_withheld_credit() {
        let does = (50, 30, 20, true);
        let entry = mover(tx(1), does, false);
        let (receipt, threaded) = in_session(supplied(0), &entry, &moving(|_| does));
        assert!(
            matches!(receipt.outcome, Outcome::Completed { .. }),
            "{:?}",
            receipt.outcome
        );
        assert_eq!(amount_at(&threaded, payer()), 0);

        let outcome = run(supplied(0), &[entry], moving(|_| does));
        assert_eq!(outcome.receipts[&tx(1)], receipt, "and the replay agrees");
        assert_eq!(amount_at(&outcome.store, payer()), 0);
        assert_eq!(
            outcome.store.withheld_credits(payer()),
            threaded.withheld_credits(payer())
        );
        assert_eq!(
            outcome.store.withheld_credits(payer()).members,
            [(tx(1), 20)].into(),
            "what its body raised the vault by, which its burn then took",
        );
    }

    /// The outcome of a mate debiting `debit` from a vault holding 100,
    /// applied behind a member whose credits are withheld and that moves
    /// `through` in and out of the vault.
    fn debiting_behind(through: (u128, u128), debit: u128) -> Outcome {
        let of = move |member: TxHash| {
            if member == tx(1) {
                (through.0, through.1, 0, true)
            } else {
                (0, debit, 0, false)
            }
        };
        let batch = [
            mover(tx(1), of(tx(1)), false),
            mover(tx(2), of(tx(2)), false),
        ];
        let outcome = run(supplied(100), &batch, moving(of));
        assert!(
            matches!(outcome.receipts[&tx(1)].outcome, Outcome::Completed { .. }),
            "the member moving value through completes: {:?}",
            outcome.receipts[&tx(1)].outcome
        );
        outcome.receipts[&tx(2)].outcome.clone()
    }

    /// A member that moves value into a vault and the same value out
    /// leaves it holding what it held whether the member stands or is
    /// discarded, so nothing of the vault is withheld from its mates.
    #[test]
    fn a_round_trip_through_a_vault_withholds_nothing() {
        for debit in [10, 100] {
            assert!(
                matches!(
                    debiting_behind((100, 100), debit),
                    Outcome::Completed { .. }
                ),
                "the vault covers {debit} with the member or without it",
            );
        }
        assert_eq!(
            debiting_behind((100, 100), 101),
            Outcome::Infeasible {
                key: payer(),
                amount: 101
            }
        );
    }

    /// A member that leaves a vault holding more than it found withholds
    /// what it raised it by and no more: its mates spend what the vault
    /// held below the batch.
    #[test]
    fn only_what_a_member_raised_a_vault_by_is_withheld() {
        assert!(matches!(
            debiting_behind((80, 30), 100),
            Outcome::Completed { .. }
        ));
        assert_eq!(
            debiting_behind((80, 30), 101),
            Outcome::Infeasible {
                key: payer(),
                amount: 101
            }
        );
    }

    /// A member that leaves a vault holding less than it found withholds
    /// nothing, and its mates spend what it left: the vault holds no
    /// more than that while the member stands.
    #[test]
    fn a_member_drawing_a_vault_down_leaves_its_mates_the_rest() {
        assert!(matches!(
            debiting_behind((30, 80), 50),
            Outcome::Completed { .. }
        ));
        assert_eq!(
            debiting_behind((30, 80), 51),
            Outcome::Infeasible {
                key: payer(),
                amount: 51
            }
        );
    }

    /// A member refused after its credit folded loses the credit and the
    /// record of it at once, in the session and in the replay.
    #[test]
    fn a_flip_removes_a_withheld_credit_and_its_record_together() {
        // The burn is past what the credit leaves, so the member is
        // refused at the last judgement it gets.
        let does = (50, 0, 60, true);
        let entry = mover(tx(1), does, false);
        let (receipt, threaded) = in_session(supplied(0), &entry, &moving(|_| does));
        assert_eq!(
            receipt.outcome,
            Outcome::Infeasible {
                key: payer(),
                amount: 60
            }
        );
        assert_eq!(amount_at(&threaded, payer()), 0);
        assert_eq!(
            threaded.withheld_credits(payer()),
            WithheldCredits::default()
        );

        // In the replay it is a mate in another group that takes the
        // floor: the second member's session completed over the base, and
        // by the time it is applied the first has burned what it needed.
        let batch = [
            mover(tx(1), (0, 0, 40, false), false),
            mover(tx(2), does, false),
        ];
        let of = move |member: TxHash| {
            if member == tx(1) {
                (0, 0, 40, false)
            } else {
                does
            }
        };
        let outcome = run(supplied(40), &batch, moving(of));
        assert_eq!(
            outcome.receipts[&tx(2)].outcome,
            Outcome::Infeasible {
                key: payer(),
                amount: 60
            }
        );
        assert_eq!(amount_at(&outcome.store, payer()), 0);
        assert_eq!(
            outcome.store.withheld_credits(payer()),
            WithheldCredits::default()
        );
    }

    proptest! {
        /// Two members in separate conflict groups credit, debit and burn
        /// on one vault, either with its credits withheld. The second's
        /// session never saw the first; the replay judges it after the
        /// first landed, under the credit the first is recorded with, and
        /// reaches the verdict a session started over the store the first
        /// left, that record carried, would have.
        ///
        /// A member its own group refused is not replayed, and keeps
        /// that refusal.
        #[test]
        fn session_and_replay_agree_behind_a_withheld_credit(
            balance in 0u128..150,
            first in (0u128..80, 0u128..120, 0u128..30, any::<bool>()),
            second in (0u128..80, 0u128..120, 0u128..30, any::<bool>()),
        ) {
            let base = supplied(balance);
            let of = move |member: TxHash| if member == tx(1) { first } else { second };
            let batch = [mover(tx(1), first, false), mover(tx(2), second, false)];

            let together = run(base.clone(), &batch, moving(of));
            let before = run(base.clone(), &batch[..1], moving(of));
            prop_assert_eq!(&together.receipts[&tx(1)], &before.receipts[&tx(1)]);

            let left = before.store.collapse_onto(base.clone());
            let (grouped, _) = in_session(base, &batch[1], &moving(of));
            let expected = if matches!(grouped.outcome, Outcome::Completed { .. }) {
                in_session(left, &batch[1], &moving(of)).0
            } else {
                grouped
            };
            prop_assert_eq!(&together.receipts[&tx(2)], &expected);
        }

        /// Whichever of the members whose credits are withheld go on to
        /// settle, no cell is overdrawn: the members nothing withholds
        /// settle with any subset of the rest, each cell taking every
        /// survivor's movement over what it held below the batch.
        ///
        /// In separate groups the replay alone judges one member behind
        /// another; in one group each session does, over the store the
        /// members before it threaded.
        #[test]
        fn no_surviving_subset_of_withheld_members_overdraws_a_cell(
            balance in 0u128..150,
            members in prop_vec((0u128..80, 0u128..120, 0u128..20, any::<bool>()), 1..5),
            grouped in any::<bool>(),
        ) {
            let base = supplied(balance);
            let named: Vec<(TxHash, Moving)> = members
                .iter()
                .enumerate()
                .map(|(index, does)| (tx(u8::try_from(index + 1).expect("a handful")), *does))
                .collect();
            let batch: Vec<BatchTx> = named
                .iter()
                .map(|(member, does)| mover(*member, *does, grouped))
                .collect();
            let of = |member: TxHash| {
                named
                    .iter()
                    .find(|(named, _)| *named == member)
                    .map_or((0, 0, 0, false), |(_, does)| *does)
            };
            let outcome = run(base.clone(), &batch, moving(of));

            let (withheld, settled): (Vec<&BatchTx>, Vec<&BatchTx>) = batch
                .iter()
                .filter(|entry| {
                    matches!(outcome.receipts[&entry.tx].outcome, Outcome::Completed { .. })
                })
                .partition(|entry| entry.credits_withheld);
            let whole = OwnerSet::whole();
            for surviving in 0u32..1 << withheld.len() {
                let survivors = settled.iter().chain(
                    withheld
                        .iter()
                        .enumerate()
                        .filter(|(index, _)| surviving & (1 << index) != 0)
                        .map(|(_, entry)| entry),
                );
                let mut credited = std::collections::BTreeMap::<SubstateKey, u128>::new();
                let mut debited = std::collections::BTreeMap::<SubstateKey, u128>::new();
                for entry in survivors {
                    let owned = outcome.receipts[&entry.tx].delta.owned(&whole);
                    for (key, movement) in owned.movements() {
                        *credited.entry(key).or_default() += movement.credit;
                        *debited.entry(key).or_default() += movement.debit;
                    }
                }
                for (key, debit) in debited {
                    let held = amount_at(&base, key) + credited.get(&key).copied().unwrap_or(0);
                    prop_assert!(
                        debit <= held,
                        "{key:?} holds {held} under debits of {debit} with {surviving:b} surviving",
                    );
                }
            }
        }
    }
}

/// The instance term, where an entry changes without a holding moving.
///
/// A non-fungible's quantity is a count of entries, so what the fold
/// weighs is a presence flip. An entry whose bytes change and whose
/// presence does not is the same instance where it was — and reading
/// that as an arrival refuses a transaction for creating what it still
/// holds, for free, since the abort it reaches is priced to nobody.
mod instances {
    use std::sync::Arc;

    use hyperscale_hbor::Capped;
    use hyperscale_vm_effects::{
        Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, Value, collection_id,
    };
    use hyperscale_vm_kernel::{EnvInputs, KernelSession, OverlayStore};
    use hyperscale_vm_types::{
        Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome, ResourceAddr,
        TxHash,
    };

    use super::MemoryStore;

    const HOLDER: Address = Address::new([0x40; 31], AddressClass::Component);
    const TICKET: ResourceAddr = ResourceAddr::new([0xB0; 31]);
    /// The holder's own holdings collection, keyed by what it holds.
    const HOLDINGS: SlotId = SlotId(16);
    /// The order the one instance sits at.
    const ORDER: u64 = 42;

    fn hash(data: &[u8]) -> [u8; 32] {
        TestHasher.hash(b"crypto", &[data]).0
    }

    /// A session over an interval of the holder's instances, with one
    /// already filed at `ORDER` carrying `filed`.
    fn session_holding(filed: &[u8]) -> KernelSession {
        let collection = collection_id(
            &TestHasher,
            HOLDER,
            HOLDINGS,
            &[Value::Address(TICKET.address()).canonical_bytes()],
        );
        let interval = Effect {
            target: EffectTarget::Range {
                owner: HOLDER,
                collection,
                lo: 0,
                hi: u128::MAX,
                cap: 8,
            },
            mode: Mode::Write { moves: Moves::Both },
        };
        let mut set = EffectSet::new();
        set.insert_at_cap(interval).expect("one interval");
        let mut store = MemoryStore::new();
        store.entry_write(HOLDER, collection, u128::from(ORDER), filed.to_vec());

        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: vec![DeclaredAccess {
                    reach: None,
                    effect: interval,
                    holds: Some(TICKET),
                    clause: None,
                }],
                ..Declaration::default()
            },
            TxHash(Hash32([7; 32])),
            EnvInputs::unsealed(0),
            hash,
        )
        .expect("a denominated interval materializes")
    }

    /// Take the instance and file it back where it was, leaving `refiled`
    /// in the entry.
    fn refile(filed: &[u8], refiled: &[u8]) -> Outcome {
        let mut session = session_holding(filed);
        let held = session
            .range_take(0, 0, &[ORDER])
            .expect("the holder has it");
        session
            .range_put(0, 0, held, refiled)
            .expect("back it goes");
        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("a receipt either way");
        receipt.outcome
    }

    #[test]
    fn refiling_an_instance_where_it_was_moves_no_holding() {
        assert_eq!(
            refile(&[1], &[1]),
            Outcome::Completed {
                answers: Capped::empty()
            }
        );
        assert_eq!(
            refile(&[1], &[2]),
            Outcome::Completed {
                answers: Capped::empty()
            },
            "the entry carries something else and the instance is where it was",
        );
    }
}

/// What the cell an escrowed crossing names to be credited back may come
/// to hold between the issue and the return.
///
/// The record names the cell its value was debited from, and only a
/// session's own declaration says what that cell holds: whether a point
/// is an amount, and of which resource, is the clause that names it. So a
/// later transaction holding the cell as bytes, as another resource's
/// amount, or crediting it to the top, is one the kernel completes.
mod a_credit_cell {
    use std::sync::Arc;

    use hyperscale_vm_effects::{Declaration, Hash32, Hasher, IssuanceGrant, Issued};
    use hyperscale_vm_kernel::{EnvInputs, KernelSession, OverlayStore};
    use hyperscale_vm_types::{
        Effect, EffectSet, EffectTarget, Mode, Movement, Moves, Outcome, ResourceAddr, read_amount,
    };

    use super::{MemoryStore, ResourceKind, TestHasher, TxHash, encode_amount, vault};

    const UNIT: ResourceAddr = ResourceAddr::new([0xA1; 31]);
    const OTHER: ResourceAddr = ResourceAddr::new([0xA2; 31]);

    fn hash(data: &[u8]) -> [u8; 32] {
        TestHasher.hash(b"crypto", &[data]).0
    }

    /// The cell an escrow of `UNIT` was debited from, holding `held`.
    fn left(held: u128) -> MemoryStore {
        let mut store = MemoryStore::new();
        store.write(vault(1, UNIT.address()), encode_amount(held).to_vec());
        store
    }

    /// A session over `store` holding the credit cell in `mode`,
    /// denominated in `holds` where it holds an amount at all.
    fn holding(store: MemoryStore, mode: Mode, holds: Option<ResourceAddr>) -> KernelSession {
        let mut set = EffectSet::new();
        set.insert_at_cap(Effect {
            target: EffectTarget::Point(vault(1, UNIT.address())),
            mode,
        })
        .expect("one cell");
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration::from_set(set).denominated(|_| holds),
            TxHash(Hash32([7; 32])),
            EnvInputs::unsealed(0),
            hash,
        )
        .expect("the declaration materializes");
        if let Some(resource) = holds {
            session.grant_issuance(vec![IssuanceGrant {
                resource,
                kind: ResourceKind::Fungible,
                direction: Issued::Either,
            }]);
        }
        session
    }

    /// What the cell holds once `session` completes.
    fn after(session: KernelSession) -> Option<Vec<u8>> {
        let (receipt, _) = session
            .finish(vec![], Vec::new())
            .expect("the oracle stands");
        assert!(
            matches!(receipt.outcome, Outcome::Completed { .. }),
            "{:?}",
            receipt.outcome
        );
        let key = vault(1, UNIT.address());
        let movement = receipt.delta.movements.get(&key).copied();
        receipt.delta.cells.get(&key).cloned().unwrap_or_else(|| {
            movement.map(|movement| {
                encode_amount(movement.apply(400).expect("the credit fits")).to_vec()
            })
        })
    }

    /// A declaration naming the cell as bytes writes bytes over the
    /// amount it held.
    #[test]
    fn a_credit_cell_can_come_to_hold_bytes() {
        let mut session = holding(left(400), Mode::Write { moves: Moves::Both }, None);
        session
            .write_cell_set(0, 0, vec![1, 2, 3])
            .expect("a write handle writes");
        let held = after(session).expect("the cell holds what was written");
        assert_eq!(held, vec![1, 2, 3]);
        assert_eq!(read_amount(&held), None, "the cell holds no amount");
    }

    /// A declaration naming the cell as another resource's amount
    /// credits that resource to it.
    #[test]
    fn a_credit_cell_can_take_a_second_resource() {
        let mut session = holding(left(400), Mode::Delta { moves: Moves::Both }, Some(OTHER));
        let minted = session.mint(0, 50).expect("the grant mints");
        session
            .cell_put(0, 0, minted)
            .expect("the cell takes what its declaration denominates");
        let held = after(session).expect("the cell holds an amount");
        assert_eq!(read_amount(&held), Some(450));
    }

    /// A credit fills the cell to the top of `u128`, where the escrow's
    /// return cannot land.
    #[test]
    fn a_credit_cell_can_be_filled_past_what_its_return_fits() {
        let mut session = holding(left(400), Mode::Delta { moves: Moves::Both }, Some(UNIT));
        let minted = session.mint(0, u128::MAX - 400).expect("the grant mints");
        session.cell_put(0, 0, minted).expect("the credit fits");
        let held = after(session).expect("the cell holds an amount");
        assert_eq!(read_amount(&held), Some(u128::MAX));
    }

    /// A return over a full cell applies to nothing: a credit past
    /// `u128` leaves the producer's fold no amount to write, so the fold
    /// skips the return and the record stands. One that fits lands to
    /// the top.
    #[test]
    fn a_return_past_u128_applies_to_nothing() {
        let returned = Movement {
            credit: 100,
            ..Movement::none(UNIT)
        };
        assert_eq!(returned.apply(u128::MAX), None);
        assert_eq!(returned.apply(u128::MAX - 100), Some(u128::MAX));
    }
}

/// The record a spend carries: the intent, its account's cell, and
/// when the record stops being owed.
fn nullifier_record(intent: IntentHash, nullifier: SubstateKey) -> IntentRecord {
    IntentRecord {
        intent,
        nullifiers: vec![Nullifier {
            account: PrincipalAddr::new([1; 31]),
            key: nullifier,
        }],
        expiry_ms: TEST_EXPIRY_MS,
    }
}

//! Conservation over the amount cells: the shard's supply accumulator
//! equals the sum of its cells through same-shard transfers, and moves
//! only on mint and cross-shard legs.

use std::sync::Arc;

use hyperscale_vm_effects::{Hash32, ResourceKind, SlotId, TestHasher, Value, child_key};
use hyperscale_vm_kernel::{
    AmountLedger, Baseline, DeltaOp, MemoryStore, OverlayStore, Substates, SupplyLedger,
    WorkingStore, decode_amount,
};
use hyperscale_vm_types::{
    Address, AddressClass, ResourceAddr, SubstateKey, TxHash, encode_amount,
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

const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

fn cell_total(store: &impl Substates, cells: &[SubstateKey]) -> u128 {
    cells
        .iter()
        .map(|key| {
            store
                .cell(*key)
                .map_or(0, |cell| decode_amount(&cell).unwrap())
        })
        .sum()
}

#[test]
fn supply_tracks_cells_through_transfers_and_cross_shard_legs() {
    let resource = ResourceAddr::new([0xEE; 31]);
    let alice = vault(1, resource.into());
    let bob = vault(2, resource.into());
    let cells = [alice, bob];

    let mut store = OverlayStore::new(Arc::new(MemoryStore::new()) as Arc<dyn Baseline>);
    let mut supply = SupplyLedger::new();

    // Mint: the only same-shard event that credits supply.
    store.write(alice, encode_amount(100).to_vec()).unwrap();
    supply.credit(resource, 100).unwrap();
    assert_eq!(cell_total(&store, &cells), supply.amount(resource));

    // A same-shard transfer: reserve-settle out of one cell, delta into
    // the other. Supply is untouched and conservation holds.
    let verdicts = store.judge_and_hold(&[(tx(1), alice, 30)]).unwrap();
    assert!(verdicts[&(tx(1), alice)].is_feasible());
    store.settle(alice, tx(1)).unwrap();
    store.queue_delta(bob, DeltaOp::Add(30)).unwrap();
    store.commit_deltas().unwrap();
    assert_eq!(cell_total(&store, &cells), 100);
    assert_eq!(supply.amount(resource), 100);

    // An outbound cross-shard leg: the settled amount leaves the shard,
    // and the ledger debits with it.
    let verdicts = store.judge_and_hold(&[(tx(2), alice, 20)]).unwrap();
    assert!(verdicts[&(tx(2), alice)].is_feasible());
    let outbound = store.settle(alice, tx(2)).unwrap();
    supply.debit(resource, outbound).unwrap();
    assert_eq!(cell_total(&store, &cells), 80);
    assert_eq!(supply.amount(resource), 80);

    // The matching inbound leg on another shard would credit 20 there:
    // composing the two ledgers restores the original total.
    let mut remote = SupplyLedger::new();
    remote.credit(resource, outbound).unwrap();
    assert_eq!(supply.compose(&remote).unwrap().amount(resource), 100);
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
    use hyperscale_vm_kernel::{EnvInputs, KernelSession, OverlayStore, SupplyDelta, SupplyLedger};
    use hyperscale_vm_types::{
        AbortReason, Effect, EffectSet, EffectTarget, Mode, Outcome, ResourceAddr,
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
            mode: Mode::Delta,
        };
        let mut set = EffectSet::new();
        set.insert(moving).expect("one cell");
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
        let (receipt, _) = session.finish(vec![], 0).expect("the oracle stands");
        receipt.supply
    }

    /// A mint credits the shard's accumulator by what it created.
    #[test]
    fn a_mint_is_what_the_receipt_reports_and_the_ledger_takes() {
        let mut session = session();
        let minted = session.mint(0, 500).expect("the grant mints");
        session.cell_put(0, 0, minted).expect("into its own vault");

        let supply = completed(session);
        assert_eq!(supply.minted(UNIT), 500);
        assert_eq!(supply.burned(UNIT), 0);

        let mut ledger = SupplyLedger::new();
        supply.apply(&mut ledger).expect("the shard takes it");
        assert_eq!(ledger.amount(UNIT), 500);
    }

    /// A burn debits it by what it destroyed, and the round trip leaves
    /// the shard where it started.
    #[test]
    fn a_burn_returns_what_a_mint_added() {
        let mut ledger = SupplyLedger::new();

        let mut minting = session();
        let minted = minting.mint(0, 500).expect("the grant mints");
        minting.cell_put(0, 0, minted).expect("into its own vault");
        completed(minting).apply(&mut ledger).expect("credited");

        // The burn needs value to destroy, which is the mint's — held in
        // the cell rather than threaded through, because what is under
        // test is the accumulator and not the store.
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT.address()), encode_amount(500).to_vec());
        let mut burning = session_over(held);
        let taken = burning.cell_take(0, 0, 500).expect("the debit is queued");
        burning.burn(taken).expect("the grant burns");
        let supply = completed(burning);
        assert_eq!(supply.burned(UNIT), 500);
        supply.apply(&mut ledger).expect("debited");

        assert_eq!(ledger.amount(UNIT), 0);
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

        let mut ledger = SupplyLedger::new();
        supply.apply(&mut ledger).expect("both applied");
        assert_eq!(ledger.amount(UNIT), 0);
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
            .finish(vec![], 0)
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
            .finish(vec![], 0)
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

    /// The same in the other direction: a debit that reached no bucket.
    #[test]
    fn value_into_nowhere_does_not_commit_either() {
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT.address()), encode_amount(500).to_vec());
        let mut session = session_over(held);
        session.delta_sub(0, 0, 500).expect("the queue takes it");

        let (receipt, _) = session.finish(vec![], 0).expect("a receipt either way");
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
            set.insert(Effect {
                target: EffectTarget::Point(cell),
                mode: Mode::Delta,
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

        let (receipt, _) = session.finish(vec![], 0).expect("a receipt either way");
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

/// The instance term, where an entry changes without a holding moving.
///
/// A non-fungible's quantity is a count of entries, so what the fold
/// weighs is a presence flip. An entry whose bytes change and whose
/// presence does not is the same instance where it was — and reading
/// that as an arrival refuses a transaction for creating what it still
/// holds, for free, since the abort it reaches is priced to nobody.
mod instances {
    use std::sync::Arc;

    use hyperscale_vm_effects::{
        Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, Value, collection_id,
    };
    use hyperscale_vm_kernel::{EnvInputs, KernelSession, OverlayStore};
    use hyperscale_vm_types::{
        Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Outcome, ResourceAddr, TxHash,
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
            mode: Mode::Write,
        };
        let mut set = EffectSet::new();
        set.insert(interval).expect("one interval");
        let mut store = MemoryStore::new();
        store.entry_write(HOLDER, collection, u128::from(ORDER), filed.to_vec());

        KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &Declaration {
                set,
                ordered: vec![DeclaredAccess {
                    effect: interval,
                    holds: Some(TICKET),
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
        // The metered lane drains what a scan lifted after every call
        // that can reach one; nothing meters this session, so what the
        // two probes lifted is settled before finishing.
        let _ = session.take_scan_debt();
        let (receipt, _) = session.finish(vec![], 0).expect("a receipt either way");
        receipt.outcome
    }

    #[test]
    fn refiling_an_instance_where_it_was_moves_no_holding() {
        assert_eq!(refile(&[1], &[1]), Outcome::Completed { answers: vec![] });
        assert_eq!(
            refile(&[1], &[2]),
            Outcome::Completed { answers: vec![] },
            "the entry carries something else and the instance is where it was",
        );
    }
}

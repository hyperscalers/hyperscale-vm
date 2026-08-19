//! Conservation over the amount cells: the shard's supply accumulator
//! equals the sum of its cells through same-shard transfers, and moves
//! only on mint and cross-shard legs.

use std::sync::Arc;

use hyperscale_vm_effects::{Hash32, SlotId, TestHasher, Value, child_key};
use hyperscale_vm_kernel::{
    AmountLedger, Baseline, DeltaOp, MemoryStore, OverlayStore, Substates, SupplyLedger,
    WorkingStore, decode_amount,
};
use hyperscale_vm_types::{
    Address, AddressClass, Denomination, ResourceAddr, SubstateKey, TxHash, encode_amount,
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
    let resource = Denomination::Resource(ResourceAddr::new([0xEE; 31]));
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

    use hyperscale_vm_effects::{Declaration, Hasher};
    use hyperscale_vm_kernel::{EnvInputs, KernelSession, OverlayStore, SupplyDelta, SupplyLedger};
    use hyperscale_vm_types::{
        AbortReason, Effect, EffectSet, EffectTarget, ISSUER_REP, Mode, Outcome, ResourceAddr,
    };

    use super::{
        Address, AddressClass, Hash32, MemoryStore, TestHasher, TxHash, encode_amount, vault,
    };

    const UNIT: Address = Address::new([0xA1; 31], AddressClass::Resource);

    /// The grant's own view of the fixture: what has a minter.
    fn unit() -> ResourceAddr {
        ResourceAddr::try_from(UNIT).expect("a resource-class address")
    }

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
            target: EffectTarget::Point(vault(1, UNIT)),
            mode: Mode::Delta,
        };
        let mut set = EffectSet::new();
        set.insert(moving).expect("one cell");
        let declaration = Declaration::from_set(set).denominated(|_| Some(unit().into()));
        let mut session = KernelSession::materialize(
            OverlayStore::new(Arc::new(store)),
            &declaration,
            TxHash(Hash32([9; 32])),
            EnvInputs {
                clock_ms: 0,
                randomness: [0; 32],
            },
            hash,
        )
        .expect("one unheld delta cell materializes");
        session.grant_issuance(unit());
        session
    }

    fn completed(session: KernelSession) -> SupplyDelta {
        let (receipt, _) = session.finish(None, 0).expect("the oracle stands");
        receipt.supply
    }

    /// A mint credits the shard's accumulator by what it created.
    #[test]
    fn a_mint_is_what_the_receipt_reports_and_the_ledger_takes() {
        let mut session = session();
        let minted = session.mint(ISSUER_REP, 500).expect("the grant mints");
        session.delta_put(0, minted).expect("into its own vault");

        let supply = completed(session);
        assert_eq!(supply.minted(unit()), 500);
        assert_eq!(supply.burned(unit()), 0);

        let mut ledger = SupplyLedger::new();
        supply.apply(&mut ledger).expect("the shard takes it");
        assert_eq!(ledger.amount(unit().into()), 500);
    }

    /// A burn debits it by what it destroyed, and the round trip leaves
    /// the shard where it started.
    #[test]
    fn a_burn_returns_what_a_mint_added() {
        let mut ledger = SupplyLedger::new();

        let mut minting = session();
        let minted = minting.mint(ISSUER_REP, 500).expect("the grant mints");
        minting.delta_put(0, minted).expect("into its own vault");
        completed(minting).apply(&mut ledger).expect("credited");

        // The burn needs value to destroy, which is the mint's — held in
        // the cell rather than threaded through, because what is under
        // test is the accumulator and not the store.
        let mut held = MemoryStore::new();
        held.write(vault(1, UNIT), encode_amount(500).to_vec())
            .expect("seeded");
        let mut burning = session_over(held);
        let taken = burning.delta_take(0, 500).expect("the debit is queued");
        burning.burn(ISSUER_REP, taken).expect("the grant burns");
        let supply = completed(burning);
        assert_eq!(supply.burned(unit()), 500);
        supply.apply(&mut ledger).expect("debited");

        assert_eq!(ledger.amount(unit().into()), 0);
    }

    /// Both halves are reported, because they are two facts.
    ///
    /// A net of zero would read as a transaction that touched nothing,
    /// where this one created value and destroyed value — and a shard
    /// auditing its own trajectory needs to see both.
    #[test]
    fn a_mint_and_a_burn_in_one_transaction_are_both_recorded() {
        let mut session = session();
        let minted = session.mint(ISSUER_REP, 500).expect("the grant mints");
        session.burn(ISSUER_REP, minted).expect("the grant burns");

        let supply = completed(session);
        assert_eq!((supply.minted(unit()), supply.burned(unit())), (500, 500));
        assert!(!supply.is_empty(), "two movements, not a net of nothing");

        let mut ledger = SupplyLedger::new();
        supply.apply(&mut ledger).expect("both applied");
        assert_eq!(ledger.amount(unit().into()), 0);
    }

    /// An abort brings nothing into existence, whatever it ran: a body
    /// that dropped value flips inside `finish`, and the flip discards
    /// the supply it claimed along with everything else.
    #[test]
    fn an_aborted_mint_moves_no_supply() {
        let mut session = session();
        // Minted, and never landed in a cell: the account cannot balance.
        let minted = session.mint(ISSUER_REP, 500).expect("the grant mints");
        let _ = minted;

        let (receipt, _) = session
            .finish(None, 0)
            .expect("the flip still produces a receipt");
        assert!(matches!(
            receipt.outcome,
            Outcome::UserError {
                reason: AbortReason::ValueDropped
            }
        ));
        assert!(receipt.supply.is_empty());
    }

    /// A transfer moves no supply, which is what makes same-shard
    /// movement conserve the accumulator without counting anything.
    #[test]
    fn value_moving_between_cells_moves_no_supply() {
        let mut session = session();
        let minted = session.mint(ISSUER_REP, 500).expect("the grant mints");
        session.delta_put(0, minted).expect("into its own vault");
        let moved = session.delta_take(0, 200).expect("out again");
        session.delta_put(0, moved).expect("and back");

        // The mint is the only movement; the two cell operations cancel.
        let supply = completed(session);
        assert_eq!((supply.minted(unit()), supply.burned(unit())), (500, 0));
    }
}

//! The pool patterns end to end on both runtimes: swaps with real pool
//! math, output floors, and the share vault's rounding.

use hyperscale_vm_effects::{
    AdmissionError, Claim, EnvelopeTree, Hash32, IntentDecl, IntentHeader, ManifestGraph, SlotId,
    TestHasher, Value, child_key, holdings_collection,
};
use hyperscale_vm_fixtures::{amm, shares};
use hyperscale_vm_harness::driver::{amount_of, declared_vault, vault};
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, EnvelopeError, IntentBuilder};
use hyperscale_vm_sdk::client::VaultField;
use hyperscale_vm_sdk::{Declines, DeclinesAs};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    Address, EffectTarget, Mode, Moves, Outcome, Presence, SubstateKey, TxHash, UnmetCondition,
    encode_amount,
};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;
use hyperscale_vm_types::NetworkId;

/// Any network; these tests only need every intent to name the same one.
const TEST_NETWORK: NetworkId = NetworkId(242);

/// Any window; these tests never validate one against a clock.
const TEST_HEADER: IntentHeader = IntentHeader {
    network: TEST_NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
    discriminator: 0,
};

/// The share vault's one declared pool, at its marker's slot.
const SHARES_POOL: SlotId = SlotId(<shares::Pool as VaultField>::SLOT);

/// One of an amm venue's declared reserves.
fn reserve(pool: amm::Amm, resource: impl Into<Address>) -> SubstateKey {
    declared_vault(pool, amm::RESERVES, resource)
}

/// The same trade the other way round, paid in the side the pool sold
/// last time.
fn reverse_swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_Y, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

/// The same trade, paid in a resource the pool does not trade at all.
fn untraded_swap_graph() -> ManifestGraph {
    graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_Z, 500)?;
        let out = pool().swap(b, funds, 0)?;
        account::deposit(b, ALICE, out)
    })
}

/// The pool's pair is its configuration's, and a manifest paying in a
/// third resource never becomes a transaction.
///
/// The declared denomination is a conditional over that pair rather than
/// the resource the edge happens to carry, which is what keeps the cycle
/// total: a resource in neither side selects the side it is not, and the
/// mismatch is the refusal. Were it read off the edge instead, a caller
/// could pay in anything, land it in a vault holding none of it, and have
/// the curve quote a share against an empty reserve. Refused at
/// admission, where the verdict is a function of signed content and costs
/// the sender nothing.
#[test]
fn a_swap_paid_in_a_resource_the_pool_does_not_trade_is_refused() {
    let chain = world();
    let graph = untraded_swap_graph();
    let refused = admit_here(&graph, ALICE, &chain)
        .expect_err("the pool trades a pair and this manifest pays neither side");

    let AdmissionError::WrongDenomination {
        param,
        expected,
        found,
        ..
    } = refused
    else {
        panic!("the refusal names the denomination: {refused:?}");
    };
    assert_eq!(param, 0, "the payment is the swap's first argument");
    assert_eq!(
        expected,
        RES_Y.address(),
        "a resource that is not x selects the side it is not"
    );
    assert_eq!(found, RES_Z.address());
}

/// The control: both sides of the pair admit against one instance.
#[test]
fn a_swap_paid_in_either_side_of_the_pair_admits() {
    let chain = world();
    for graph in [swap_graph(300), reverse_swap_graph(300)] {
        admit_here(&graph, ALICE, &chain)
            .expect("either side of the configured pair is one the declaration asks for");
    }
}

fn swap_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store.write(reserve(pool(), RES_X), encode_amount(1_000).to_vec());
    store.write(reserve(pool(), RES_Y), encode_amount(1_000).to_vec());
    store
}

#[test]
fn swap_profile_and_provision_shape_are_exact() {
    let world = world();
    let routing = sharded_routing(&world, &swap_graph(300));

    let pool_set = &routing.per_shard[&shard_of(pool())];
    assert_eq!(
        *pool_set,
        set(&[
            point(config_leaf(pool()), Mode::Read),
            point(reserve(pool(), RES_X), Mode::Write { moves: Moves::In }),
            point(reserve(pool(), RES_Y), Mode::Write { moves: Moves::Out }),
        ])
    );
    // The pool-shard provision carries the two balance cells and the
    // fence's leaf: the reserves are read-modify-writes, and the
    // configuration read is what every participant judges the
    // component's presence by.
    assert_eq!(
        pool_set.provision_targets(),
        [
            EffectTarget::Point(config_leaf(pool())),
            EffectTarget::Point(reserve(pool(), RES_X)),
            EffectTarget::Point(reserve(pool(), RES_Y)),
        ]
        .into_iter()
        .collect()
    );
    // The user's side provisions the sign-in's rule cell and the flag
    // her deposit reads to pick a destination; her balance movement
    // stays commutative, which is what the credits say and what the
    // reads beside them do not change.
    assert_eq!(
        routing.per_shard[&shard_of(ALICE)].provision_targets(),
        [
            EffectTarget::Point(auth(ALICE)),
            EffectTarget::Point(refused(ALICE, RES_Y)),
        ]
        .into_iter()
        .collect()
    );
}

#[test]
fn swap_executes_with_real_pool_math_on_both_runtimes() {
    let world = world();
    let graph = swap_graph(300);
    let (results, final_store) = run_both(
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x02; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("swap must complete");
    };

    // The constant-product math, computed independently: 30 bps fee on
    // 500 in gives 498 effective; out = 1000 * 498 / 1498 = 332. The
    // pool's own vaults report what moved rather than what they hold:
    // the curve read its reserves here, and the totals they land on are
    // the settling shard's to fold.
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&reserve(pool(), RES_X))
            .map(|moved| (moved.credit, moved.debit)),
        Some((500, 0))
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&reserve(pool(), RES_Y))
            .map(|moved| (moved.credit, moved.debit)),
        Some((0, 332))
    );
    assert_eq!(
        receipt
            .delta
            .settles
            .get(&vault(ALICE, RES_X))
            .map(|moved| moved.debit),
        Some(500)
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(ALICE, RES_Y))
            .unwrap()
            .credit,
        332
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_Y)), 332);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 100);
}

/// The other direction, against the same instance and the same reserves.
///
/// One pool, one curve, both ways round — which is the whole of what a
/// conditional key buys here. A second instance would price the same
/// market off half the liquidity, and the two would drift apart on every
/// trade either one took.
#[test]
fn the_pool_trades_both_directions_off_one_instance() {
    let world = world();
    let mut store = swap_store();
    store.write(vault(ALICE, RES_Y), encode_amount(600).to_vec());
    let (results, final_store) = run_both(
        &world,
        &store,
        &[(&reverse_swap_graph(300), TxHash(Hash32([0x04; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("swap must complete");
    };

    // The mirror of the forward trade, because the reserves are equal:
    // 500 in less 30 bps is 498 effective, and 1000 * 498 / 1498 is 332.
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&reserve(pool(), RES_Y))
            .map(|moved| (moved.credit, moved.debit)),
        Some((500, 0))
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&reserve(pool(), RES_X))
            .map(|moved| (moved.credit, moved.debit)),
        Some((0, 332))
    );
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 932);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_Y)), 100);
}

/// The floor is declined, not trapped, and the two lanes reach the same
/// code.
///
/// The distinction is the whole of A1: 332 out cannot cover a 400 floor,
/// which is a race the sender lost between signing and execution rather
/// than a defect it committed. The abort is still whole-transaction —
/// nothing moves, and the manifest does not branch on the arm — but the
/// receipt records what happened instead of a wasm backtrace, and the
/// fee schedule prices it as the lost race.
#[test]
fn a_violated_output_floor_declines_identically() {
    let world = world();
    let graph = swap_graph(400);
    let (results, final_store) = run_both(
        &world,
        &swap_store(),
        &[(&graph, TxHash(Hash32([0x03; 32])))],
    );
    let slippage = amm::Error::SlippageExceeded;
    assert_eq!(results[0], TxResult::Declined(slippage.code()));
    assert_eq!(
        amm::metadata().errors[slippage.code() as usize],
        slippage.declined_as(),
        "the code is an index into the table the package published",
    );
    assert_eq!(amount_of(&final_store, reserve(pool(), RES_X)), 1_000);
    assert_eq!(amount_of(&final_store, vault(ALICE, RES_X)), 600);
}

/// The share vault seeded so that neither direction divides evenly.
///
/// A thousand assets against seven hundred and seventy-seven shares. The
/// ratio is what makes the test worth running: every step truncates, and
/// which way it truncates is the whole of what the four entry points are
/// for.
fn shares_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(1_000).to_vec());
    store.write(
        declared_vault(shares_vault(), SHARES_POOL, RES_X),
        encode_amount(1_000).to_vec(),
    );
    store.write(supply_leaf(shares_vault()), encode_amount(777).to_vec());
    store
}

/// The vault's circulating-supply leaf.
fn supply_leaf(owner: impl Into<Address>) -> SubstateKey {
    child_key(&TestHasher, owner, shares::SUPPLY, &[])
}

/// A deposit and a redemption of what it bought, on both runtimes, over a
/// ratio that truncates in both directions.
///
/// Here rather than in the guest's own crate because of what it computes.
/// Every step is a rounding decision over the widest arithmetic the
/// vocabulary has, and a subunit's disagreement between two engines is a
/// fork no test running one of them can see. The arithmetic is computed
/// here rather than read off the body, and `run_both` is what asserts the
/// two engines reached it.
///
/// The invariant underneath is that assets per share never falls: a
/// depositor who immediately redeems gets back less than they put in, and
/// the difference stayed with the pool rather than going anywhere.
#[test]
fn the_share_vault_rounds_toward_the_pool_on_both_runtimes() {
    let world = world();

    // 100 assets into 1000 assets against 777 shares mints
    // floor(100 * 777 / 1000) = 77 shares, not 77.7.
    let deposit = graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 100)?;
        let units = shares_vault().deposit(b, funds)?;
        account::deposit(b, ALICE, units)
    });
    let (results, store) = run_both(
        &world,
        &shares_store(),
        &[(&deposit, TxHash(Hash32([0x40; 32])))],
    );
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the deposit must complete: {:?}", results[0]);
    };
    assert_eq!(
        receipt.supply.minted(shares_unit()),
        77,
        "the shares are minted rather than moved, so supply says so"
    );

    // Redeeming all 77 against 1100 assets and 854 shares returns
    // floor(77 * 1100 / 854) = 99 assets, not 99.18 — so the depositor
    // is one subunit down and the pool is one subunit up.
    let redeem = graph(|b| {
        let units = account::withdraw(b, ALICE, shares_unit(), 77)?;
        let assets = shares_vault().redeem(b, units)?;
        account::deposit(b, ALICE, assets)
    });
    let (results, end) = run_both(&world, &store, &[(&redeem, TxHash(Hash32([0x41; 32])))]);
    let TxResult::Completed(receipt) = &results[0] else {
        panic!("the redemption must complete: {:?}", results[0]);
    };
    assert_eq!(
        receipt.supply.burned(shares_unit()),
        77,
        "the shares are destroyed rather than parked"
    );

    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 999);
    assert_eq!(
        amount_of(&end, declared_vault(shares_vault(), SHARES_POOL, RES_X)),
        1_001
    );
    assert_eq!(amount_of(&end, vault(ALICE, shares_unit())), 0);
}

/// A consumer reads an instance's configuration by name: the record is a
/// list of values, and the metadata is what says which field each one is.
///
/// A value carries its own kind, so what the leaf cannot supply is the
/// name — and a positional record with no names is three addresses and a
/// guess about which is which.
#[test]
fn a_configuration_reads_by_name_from_metadata() {
    let metadata = amm::metadata();
    let instance = pool_meta();
    // The table names exactly the fields the record holds, so nothing is
    // paired against a position that is not there.
    assert_eq!(metadata.config.len(), instance.config.len());
    let named: Vec<(&str, &Value)> = metadata
        .config
        .iter()
        .map(String::as_str)
        .zip(instance.config.iter())
        .collect();
    assert_eq!(
        named.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
        ["x", "y", "fee"]
    );
    assert_eq!(named[0].1, &Value::Address(RES_X.address()));
    assert_eq!(named[1].1, &Value::Address(RES_Y.address()));
}

/// The restricted class trades through a real venue, and the venue is
/// bound by the same entry the holder is.
///
/// Which is the whole of what a movement seam buys over a holder-side
/// fence. The pool declares nothing about the register — its author
/// never read the share's rules and could not have been made to — and
/// both of its own movements are judged against them anyway, because
/// the requirement is injected from the resource the edge carries and
/// resolved against the vault's own owner. A design that bound accounts
/// would have stopped at the first deposit into this pool.
#[test]
fn a_registered_venue_trades_the_restricted_class_on_both_runtimes() {
    let world = world();
    let graph = register_swap_graph(300);
    let (results, end) = run_both(
        &world,
        &register_store(true),
        &[(&graph, TxHash(Hash32([0x40; 32])))],
    );
    let TxResult::Completed(_) = &results[0] else {
        panic!(
            "a registered venue and a registered holder trade: {:?}",
            results[0]
        );
    };

    // The same curve the unrestricted pool runs: 30 bps on 500 in gives
    // 498 effective, and 1000 * 498 / 1498 is 332 out. The rules govern
    // who may move it and never how much moves.
    assert_eq!(amount_of(&end, vault(ALICE, share())), 332);
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 100);
    assert_eq!(amount_of(&end, reserve(register_pool(), share())), 668);
    assert_eq!(amount_of(&end, reserve(register_pool(), RES_X)), 1_500);
}

/// The same trade into a venue nobody admitted, refused where the pool's
/// own vault moves.
///
/// The register is a standing fact about the party whose cell moves, so
/// a venue is asked exactly as a holder is: the pool pays out of its own
/// share vault, that debit earns the class's `withdraw` entry, and the
/// entry names a badge the pool does not hold. Nothing about Alice
/// changes between this and the case above — she is on the register in
/// both — which is what pins the refusal on the venue.
#[test]
fn an_unadmitted_venue_cannot_trade_the_restricted_class() {
    let world = world();
    let graph = register_swap_graph(300);
    let (results, end) = run_both(
        &world,
        &register_store(false),
        &[(&graph, TxHash(Hash32([0x41; 32])))],
    );
    // Named node and target and all: the swap call, and the venue's own
    // interval for the register badge, asked to hold anything at all.
    // Nothing about the refusal mentions the pool's code, because the
    // pool's code says nothing about it — and the interval spans the id
    // space, which is what a non-fungible register costs every movement
    // of the class.
    assert_eq!(
        results[0],
        TxResult::Refused(Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Range {
                    owner: Address::from(register_pool()),
                    collection: holdings_collection(&TestHasher, register_pool(), registered()),
                    lo: 0,
                    hi: u128::from(u64::MAX),
                    cap: 1,
                },
                required: Presence::Present,
                node: Some(2),
            },
        }),
        "a venue off the register moves none of the class",
    );
    // And nothing moved: the verdict lands before any body runs.
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 600);
    assert_eq!(amount_of(&end, reserve(register_pool(), share())), 1_000);
}

/// The buyer's own intent: a trade of the approval-mode class, with a
/// socket where the registrar's approval goes.
///
/// The holder signs *which authority they are asking for* and never who
/// supplies it. Two of her nodes present it — the swap, whose debit is
/// the pool's, and her own deposit, whose credit is hers — because a
/// proof is not conserved and one claim answers every socket that asks
/// for it.
fn approval_request(approver: Claim) -> IntentDecl {
    let chain = world();
    let mut decl = IntentBuilder::declaration(&chain, &TestHasher, ALICE, TEST_HEADER);
    let approval = decl.declare_proof(approver);
    let funds = account::withdraw(&mut decl, ALICE, RES_X, 500).expect("withdraw types");
    let out = decl
        .call_presenting([approval], approval_pool(), "swap", (funds, 300u128))
        .expect("the swap types")
        .one()
        .expect("a swap answers with the bought side");
    decl.call_presenting([approval], ALICE, "deposit", (out,))
        .expect("the deposit types")
        .none()
        .expect("a deposit yields nothing");
    decl.into_decl()
        .expect("the request reaches its own socket")
}

/// The composition that fills it: the registrar signs in and offers the
/// claim their own node mints.
fn approved_composition(request: IntentDecl) -> Result<EnvelopeTree, EnvelopeError> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher, REGISTRAR, TEST_HEADER);
    let registrar = account::authorize(&mut root, REGISTRAR)?;
    let offered = root.offer(registrar).expect("the root's own proof offers");
    let wants = env
        .adopt(ALICE, request)?
        .one()
        .expect("the request declares one socket");
    env.seal(root)?.none()?;
    env.bind(wants, offered)?;
    env.build()
}

/// The venue holding no credential at all, and the class it trades
/// stocked on both sides.
fn approval_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store.write(
        reserve(approval_pool(), RES_X),
        encode_amount(1_000).to_vec(),
    );
    store.write(
        reserve(approval_pool(), approved()),
        encode_amount(1_000).to_vec(),
    );
    store
}

/// The other posture, through the same venue: nobody holds a
/// credential, and the trade is admitted because the registrar signed
/// the transaction it happens in.
///
/// What it buys is a venue that never onboards. The register-mode class
/// above needed the pool admitted before it could hold any, so the
/// issuer had to pass on every venue as well as every holder; here the
/// pool holds nothing of the issuer's and is bound just as tightly,
/// because the entry asks about the transaction rather than about the
/// party. One authoring word covers both — the subject is what decides
/// which question is answerable.
#[test]
fn an_approved_trade_settles_through_a_venue_holding_no_credential() {
    let world = world();
    let request = approval_request(Claim::of_subject(REGISTRAR));
    let signed = request.hash(&TestHasher);
    let tree = approved_composition(request).expect("the registrar composes the approval");
    assert_eq!(
        tree.subintents[0].decl.hash(&TestHasher),
        signed,
        "nothing the composition did moved what the buyer signed",
    );

    let (outcome, end) =
        run_both_tree(&world, &approval_store(), &tree, REGISTRAR).expect("the approval admits");
    let tx = TxHash(tree.hash(&TestHasher).0);
    assert!(
        matches!(outcome.receipts[&tx].outcome, Outcome::Completed { .. }),
        "the approved trade settles: {:?}",
        outcome.receipts[&tx].outcome
    );

    // The same curve as the register-mode pool, over the same reserves.
    assert_eq!(amount_of(&end, vault(ALICE, approved())), 332);
    assert_eq!(amount_of(&end, vault(ALICE, RES_X)), 100);
    assert_eq!(amount_of(&end, reserve(approval_pool(), approved())), 668);
}

/// The same trade with nobody's approval in it, refused at admission.
///
/// A claim leaf reads what the call presented and nothing else, so the
/// verdict lands before any leg could have committed on it — and it
/// costs the sender nothing, because a transaction that never becomes
/// one is never included.
#[test]
fn an_unapproved_trade_never_becomes_a_transaction() {
    let world = world();
    let graph = graph(|b| {
        let funds = account::withdraw(b, ALICE, RES_X, 500)?;
        let out = approval_pool().swap(b, funds, 300u128)?;
        account::deposit(b, ALICE, out)
    });
    assert_eq!(
        admit_here(&graph, ALICE, &world),
        Err(AdmissionError::MissingEvidence { node: 2 }),
        "the swap's debit is the pool's, and no claim on the registrar reached it",
    );
}

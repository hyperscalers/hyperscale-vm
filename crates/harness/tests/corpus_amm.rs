//! The pool patterns end to end on both runtimes: swaps with real pool
//! math, output floors, and the share vault's rounding.

use hyperscale_vm_effects::{
    AdmissionError, Hash32, ManifestGraph, TestHasher, Value, admit, child_key,
};
use hyperscale_vm_fixtures::{amm, shares};
use hyperscale_vm_harness::driver::{amount_of, vault};
use hyperscale_vm_kernel::MemoryStore;
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{Address, EffectTarget, Mode, SubstateKey, TxHash, encode_amount};

mod common;
#[allow(clippy::wildcard_imports)] // the shared world is the binary's prelude
use common::world::*;

/// The same trade the other way round, paid in the side the pool sold
/// last time.
fn reverse_swap_graph(min_out: u128) -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_Y, 500)?;
        let out = pool().swap(b, funds, min_out)?;
        account::deposit(b, ALICE, out)
    })
}

/// The same trade, paid in a resource the pool does not trade at all.
fn untraded_swap_graph() -> ManifestGraph {
    graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_Z, 500)?;
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
    let refused = admit(&graph, ALICE, &chain, &TestHasher)
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
        admit(&graph, ALICE, &chain, &TestHasher)
            .expect("either side of the configured pair is one the declaration asks for");
    }
}

fn swap_store() -> MemoryStore {
    let mut store = sealed_store();
    store.write(vault(ALICE, RES_X), encode_amount(600).to_vec());
    store.write(vault(pool(), RES_X), encode_amount(1_000).to_vec());
    store.write(vault(pool(), RES_Y), encode_amount(1_000).to_vec());
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
            point(vault(pool(), RES_X), Mode::Write),
            point(vault(pool(), RES_Y), Mode::Write),
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
            EffectTarget::Point(vault(pool(), RES_X)),
            EffectTarget::Point(vault(pool(), RES_Y)),
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
            .get(&vault(pool(), RES_X))
            .map(|moved| (moved.credit, moved.debit)),
        Some((500, 0))
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(pool(), RES_Y))
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
            .get(&vault(pool(), RES_Y))
            .map(|moved| (moved.credit, moved.debit)),
        Some((500, 0))
    );
    assert_eq!(
        receipt
            .delta
            .movements
            .get(&vault(pool(), RES_X))
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
    assert_eq!(results[0], TxResult::Declined(amm::SLIPPAGE_EXCEEDED));
    assert_eq!(
        amm::metadata().errors[amm::SLIPPAGE_EXCEEDED as usize],
        "slippage-exceeded",
        "the code is an index into the table the package published",
    );
    assert_eq!(amount_of(&final_store, vault(pool(), RES_X)), 1_000);
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
    store.write(vault(shares_vault(), RES_X), encode_amount(1_000).to_vec());
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
        let alice = account::authorize(b, ALICE)?;
        let funds = account::withdraw(b, alice, RES_X, 100)?;
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
        let alice = account::authorize(b, ALICE)?;
        let units = account::withdraw(b, alice, shares_unit(), 77)?;
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
    assert_eq!(amount_of(&end, vault(shares_vault(), RES_X)), 1_001);
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

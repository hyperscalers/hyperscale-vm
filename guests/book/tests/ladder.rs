//! The ladder's own tests, against the real kernel.

use book_guest::book::client::{Book, Pair};
use book_guest::book::{Error, Quote, Tick};
use hyperscale_vm_sdk::state::{Fixed, Wide};
use hyperscale_vm_testing::{
    Chain, PrincipalAddr, ResourceAddr, account, package, principal, resource,
};

const MAKER: PrincipalAddr = principal(1);
const TAKER: PrincipalAddr = principal(2);
const BASE_ASSET: ResourceAddr = resource(0x61);
const QUOTE_ASSET: ResourceAddr = resource(0x62);

/// The stored rate's scale, which is one quote subunit per tick.
const ONE: u128 = 1_000_000_000_000_000_000_000_000_000_000_000_000;

/// A book quoting in whole quote subunits, with both sides funded.
fn ladder(mut chain: Chain) -> (Chain, Book) {
    chain.publish(package!(book_guest::book));
    let ladder = chain.instantiate::<Book>(
        MAKER,
        Pair {
            base: BASE_ASSET,
            quote: QUOTE_ASSET,
            tick: Fixed::<Quote, Tick>::from_scaled(Wide::from_u128(ONE)),
        },
    );
    chain.credit(MAKER, BASE_ASSET, 1_000);
    chain.credit(TAKER, QUOTE_ASSET, 1_000);
    (chain, ladder)
}

fn place(chain: &mut Chain, ladder: Book, ticks: u64, size: u128) {
    chain
        .transact(MAKER, |b| {
            let signed_in = account::authorize(b, MAKER)?;
            let offered = account::withdraw(b, signed_in, BASE_ASSET, size)?;
            ladder.place_ask(b, ticks, offered)
        })
        .expect_completed();
}

fn fill(chain: &mut Chain, ladder: Book, from: u64, to: u64, budget: u128) {
    chain
        .transact(TAKER, |b| {
            let signed_in = account::authorize(b, TAKER)?;
            let payment = account::withdraw(b, signed_in, QUOTE_ASSET, budget)?;
            let [bought, change] = ladder.fill_asks(b, from, to, payment)?;
            account::deposit(b, TAKER, bought)?;
            account::deposit(b, TAKER, change)
        })
        .expect_completed();
}

/// An ask nobody could price never stands.
///
/// The refusal is here rather than at the fill, and the two are not the
/// same check: a zero-priced ask refused where it would be taken would be
/// left standing and unfillable, blocking every ask behind it forever.
#[hyperscale_vm_testing::test]
fn an_unpriced_ask_is_refused_where_it_would_be_placed(chain: Chain) {
    let (mut chain, ladder) = ladder(chain);

    let outcome = chain.transact(MAKER, |b| {
        let signed_in = account::authorize(b, MAKER)?;
        let offered = account::withdraw(b, signed_in, BASE_ASSET, 100)?;
        ladder.place_ask(b, 0, offered)
    });

    outcome.expect_declined(Error::UnpricedAsk);
    assert_eq!(chain.balance(MAKER, BASE_ASSET), 1_000, "and nothing moved");
}

/// A taker walks the ladder cheapest first, whatever order the asks were
/// rested in.
#[hyperscale_vm_testing::test]
fn a_taker_walks_the_ladder_from_the_best_price(chain: Chain) {
    let (mut chain, ladder) = ladder(chain);
    place(&mut chain, ladder, 5, 10);
    place(&mut chain, ladder, 2, 10);

    // Ten base at two ticks is twenty quote; the budget covers that and
    // ten more, which takes two of the ask at five.
    fill(&mut chain, ladder, 1, 9, 30);

    assert_eq!(chain.balance(TAKER, BASE_ASSET), 12, "the cheap ask first");
    assert_eq!(chain.balance(TAKER, QUOTE_ASSET), 970, "and it paid thirty");
}

/// What the budget does not cover stays standing, and what it does not
/// spend comes back.
#[hyperscale_vm_testing::test]
fn a_partial_fill_leaves_the_rest_of_the_ask_standing(chain: Chain) {
    let (mut chain, ladder) = ladder(chain);
    place(&mut chain, ladder, 3, 100);

    fill(&mut chain, ladder, 1, 9, 31);

    // Ten base at three ticks is thirty; the odd subunit buys nothing and
    // walks away with the taker.
    assert_eq!(chain.balance(TAKER, BASE_ASSET), 10);
    assert_eq!(chain.balance(TAKER, QUOTE_ASSET), 970);

    // And the rest of the ask is still there to be taken.
    chain.credit(TAKER, QUOTE_ASSET, 1_000);
    fill(&mut chain, ladder, 1, 9, 270);
    assert_eq!(chain.balance(TAKER, BASE_ASSET), 100, "the whole ask");
}

/// An interval that misses the ask fills nothing and spends nothing.
#[hyperscale_vm_testing::test]
fn a_walk_outside_the_asks_price_takes_none_of_it(chain: Chain) {
    let (mut chain, ladder) = ladder(chain);
    place(&mut chain, ladder, 7, 10);

    fill(&mut chain, ladder, 1, 5, 100);

    assert_eq!(chain.balance(TAKER, BASE_ASSET), 0);
    assert_eq!(chain.balance(TAKER, QUOTE_ASSET), 1_000, "nothing spent");
    assert_eq!(
        chain.balance(ladder, BASE_ASSET),
        10,
        "and the ask is untouched"
    );
}

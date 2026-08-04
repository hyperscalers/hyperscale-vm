//! The stake pool guest: delegation for stake units, and the two events
//! the beacon's control plane folds.
//!
//! Both methods are movement plus the record of it. Nothing reads a pool
//! aggregate, because nothing needs one: the beacon accumulates per-pool
//! totals from the events it consumes, so a total kept here would be a
//! second copy that every delegator contends on.
//!
//! Nothing names the pool either. An event's emitter is stamped by the
//! kernel from the invocation, so the instance that emitted a fact *is*
//! its subject — which is what stops one pool's code from crediting
//! another pool, and what leaves a payload with nothing to carry but an
//! amount.
//!
//! Stake units are minted at par with the delegation. A redemption rate
//! is what makes them interesting and what makes them contended — it is
//! a function of the pool's staked total and the units outstanding, so
//! reading it puts every delegator on one cell. Rewards are what would
//! move that rate, and there are none to move it yet.

wit_bindgen::generate!({
    path: "wit",
    world: "staking",
    generate_all,
});

use hyperscale::kernel::events::emit;
use hyperscale::kernel::state::delta_cell_add;

/// The pool's event table: the indexes a consumer resolves against this
/// package's metadata. The beacon's witness lift reads exactly these two
/// and maps them onto its own stake-deposit and stake-withdraw facts.
const STAKED: u32 = 0;
const UNSTAKED: u32 = 1;

struct Staking;

impl Guest for Staking {
    fn stake(vault: &DeltaCell, amount: Vec<u8>) -> Vec<u8> {
        delta_cell_add(vault, &amount);
        // The amount is the kernel's own 16-byte cell, which is what the
        // handle carries, so neither end reformats a number it was handed.
        emit(STAKED, &amount);
        // Stake units at par: the returned bucket is the caller's position.
        amount
    }

    fn unstake(unbonding: &DeltaCell, amount: Vec<u8>) {
        delta_cell_add(unbonding, &amount);
        emit(UNSTAKED, &amount);
    }
}

export!(Staking);

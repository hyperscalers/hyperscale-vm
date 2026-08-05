//! The stake pool guest: delegation for stake units, the validators the
//! pool operates, and the events the beacon's control plane folds.
//!
//! Every method is movement or a record plus the fact of it. Nothing reads
//! a pool aggregate, because nothing needs one: the beacon accumulates
//! per-pool totals from the events it consumes, so a total kept here would
//! be a second copy that every delegator contends on.
//!
//! Nothing names the pool either. An event's emitter is stamped by the
//! kernel from the invocation, so the instance that emitted a fact *is*
//! its subject — which is what stops one pool's code from crediting
//! another pool, and what leaves a payload carrying only what the emitter
//! cannot already say.
//!
//! Stake units are minted at par with the delegation. A redemption rate
//! is what makes them interesting and what makes them contended — it is
//! a function of the pool's staked total and the units outstanding, so
//! reading it puts every delegator on one cell. Rewards are what would
//! move that rate, and there are none to move it yet.
//!
//! The validator record is per validator rather than a set, so two
//! operator actions on two validators commute. It is written once and
//! never cleared, which is the beacon's own rule for a validator id —
//! once a record exists the id is spent for the life of the chain — held
//! here so the pool cannot speak about a validator it never took on.

wit_bindgen::generate!({
    path: "wit",
    world: "staking",
    generate_all,
});

use hyperscale::kernel::events::emit;
use hyperscale::kernel::state::{delta_cell_add, write_cell_get, write_cell_set};

/// The pool's event table: the indexes a consumer resolves against this
/// package's metadata.
///
/// The order is the package's contract: `staking_metadata` declares the
/// names and the guest emits against them. A package is immutable and
/// content-addressed, so an index can never come to mean something else.
const STAKED: u32 = 0;
const UNSTAKED: u32 = 1;
const VALIDATOR_REGISTERED: u32 = 2;
const VALIDATOR_DEACTIVATED: u32 = 3;
const VALIDATOR_UNJAILED: u32 = 4;

/// The consensus scheme's key and signature widths.
///
/// A general-purpose contract would not know these. This one is the
/// beacon's control plane written as a package, so what a validator is
/// made of is within its subject matter — and checking here is what turns
/// a malformed operator call into a failed transaction rather than a
/// transaction that succeeds and witnesses nothing.
const PUBKEY_BYTES: usize = 48;
const POSSESSION_PROOF_BYTES: usize = 96;

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

    fn register_validator(
        leaf: &WriteCell,
        validator_id: u64,
        pubkey: Vec<u8>,
        possession_proof: Vec<u8>,
    ) {
        assert!(pubkey.len() == PUBKEY_BYTES, "pubkey is not a consensus key");
        assert!(
            possession_proof.len() == POSSESSION_PROOF_BYTES,
            "possession proof is not a consensus signature"
        );
        assert!(
            write_cell_get(leaf).is_empty(),
            "this pool already registered this validator"
        );
        // What the pool keeps is the key it registered, which is the whole
        // of its claim on this validator.
        write_cell_set(leaf, &pubkey);
        let mut payload = validator_id.to_le_bytes().to_vec();
        payload.extend_from_slice(&pubkey);
        payload.extend_from_slice(&possession_proof);
        emit(VALIDATOR_REGISTERED, &payload);
    }

    fn deactivate_validator(leaf: &WriteCell, validator_id: u64) {
        assert!(
            !write_cell_get(leaf).is_empty(),
            "this pool does not operate this validator"
        );
        emit(VALIDATOR_DEACTIVATED, &validator_id.to_le_bytes());
    }

    fn unjail(leaf: &WriteCell, validator_id: u64) {
        assert!(
            !write_cell_get(leaf).is_empty(),
            "this pool does not operate this validator"
        );
        emit(VALIDATOR_UNJAILED, &validator_id.to_le_bytes());
    }
}

export!(Staking);

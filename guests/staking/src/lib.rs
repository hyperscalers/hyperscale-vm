//! The stake pool: delegation for stake units, the validators the pool
//! operates, and the events the beacon's control plane folds.
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
//!
//! The vote leaf is the opposite shape and for the opposite reason: a
//! pool holds one vote, the network counts it once, so one leaf holding
//! the current vote is what a pool's governance position *is*.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod staking {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Keyed, Locked, Vault, issue};

    /// The pool's creation-fixed configuration: what a delegation is
    /// denominated in.
    struct Settings {
        staked_resource: Address,
    }

    /// A delegation arrived.
    #[event]
    struct Staked;
    /// A delegation began unbonding.
    #[event]
    struct Unstaked;
    /// The pool took on a validator.
    #[event]
    struct ValidatorRegistered;
    /// The pool stood a validator down.
    #[event]
    struct ValidatorDeactivated;
    /// The pool asked for a validator to be unjailed.
    #[event]
    struct ValidatorUnjailed;
    /// The pool cast its governance vote.
    #[event]
    struct ParamVoteCast;
    /// The pool withdrew its governance vote.
    #[event]
    struct ParamVoteCleared;

    /// The consensus scheme's key and signature widths.
    ///
    /// A general-purpose contract would not know these. This one is the
    /// beacon's control plane written as a package, so what a validator
    /// is made of is within its subject matter — and checking here is
    /// what turns a malformed operator call into a failed transaction
    /// rather than a transaction that succeeds and witnesses nothing.
    const PUBKEY_BYTES: usize = 48;
    const POSSESSION_PROOF_BYTES: usize = 96;

    #[state]
    struct Staking {
        #[role(3)]
        config: Locked<Settings>,
        /// The delegations under management.
        #[role(1)]
        #[denomination(config.staked_resource)]
        staked: Cell<Vault>,
        /// What a delegation becomes on its way out: the units handed
        /// back, held until their release leg.
        #[role(16)]
        #[denomination(issued(b""))]
        unbonding: Cell<Vault>,
        /// One leaf per validator the pool operates, so two operator
        /// actions on two validators commute.
        #[role(17)]
        validators: Keyed<Vec<u8>>,
        /// The pool's one governance vote: a pool holds one, the network
        /// counts it once, so one leaf is what its position *is*.
        #[role(18)]
        vote: Cell<Vec<u8>>,
    }

    impl Staking {
        /// Delegate `funds`, taking stake units at par.
        pub fn stake(&mut self, funds: Bucket) -> Bucket {
            // The amount is the kernel's own cell width, which is what
            // the handle carries, so neither end reformats a number it
            // was handed.
            let staked = funds.quantity();
            self.staked.vault().put(funds);
            Staked::emit(&staked.subunits().to_le_bytes());
            issue(b"", staked)
        }

        /// Return stake units, beginning the unbonding period.
        pub fn unstake(&mut self, units: Bucket) {
            let returned = units.quantity();
            self.unbonding.vault().put(units);
            Unstaked::emit(&returned.subunits().to_le_bytes());
        }

        /// Take on a validator, recording the key the pool registered.
        #[name("register-validator")]
        #[guarded(issued(b"owner-badge"))]
        #[allow(clippy::needless_pass_by_value)] // the contract consumes what it stores
        pub fn register_validator(
            &mut self,
            validator_id: u64,
            pubkey: Vec<u8>,
            possession_proof: Vec<u8>,
        ) {
            // The payload opens with the validator it concerns, which is
            // also the first thing this method is about.
            let mut payload = validator_id.to_le_bytes().to_vec();
            assert!(
                pubkey.len() == PUBKEY_BYTES,
                "pubkey is not a consensus key"
            );
            assert!(
                possession_proof.len() == POSSESSION_PROOF_BYTES,
                "possession proof is not a consensus signature"
            );
            let mut leaf = self.validators.at(validator_id);
            assert!(
                leaf.get().is_empty(),
                "this pool already registered this validator"
            );
            // What the pool keeps is the key it registered, which is the
            // whole of its claim on this validator.
            leaf.set(pubkey.clone());
            payload.extend_from_slice(&pubkey);
            payload.extend_from_slice(&possession_proof);
            ValidatorRegistered::emit(&payload);
        }

        /// Stand a validator down.
        #[name("deactivate-validator")]
        #[guarded(issued(b"owner-badge"))]
        pub fn deactivate_validator(&mut self, validator_id: u64) {
            let mut leaf = self.validators.at(validator_id);
            let held = leaf.get();
            assert!(
                !held.is_empty(),
                "this pool does not operate this validator"
            );
            // The leaf is held exclusively either way, and writing back
            // what it holds is what makes the declaration say so.
            leaf.set(held);
            ValidatorDeactivated::emit(&validator_id.to_le_bytes());
        }

        /// Ask for a validator to be unjailed.
        #[guarded(issued(b"owner-badge"))]
        pub fn unjail(&mut self, validator_id: u64) {
            let mut leaf = self.validators.at(validator_id);
            let held = leaf.get();
            assert!(
                !held.is_empty(),
                "this pool does not operate this validator"
            );
            // The leaf is held exclusively either way, and writing back
            // what it holds is what makes the declaration say so.
            leaf.set(held);
            ValidatorUnjailed::emit(&validator_id.to_le_bytes());
        }

        /// Cast the pool's governance vote, replacing any it held.
        #[name("cast-param-vote")]
        #[guarded(issued(b"owner-badge"))]
        pub fn cast_param_vote(&mut self, split_bytes: u64, impound_epochs: u64, activate_at: u64) {
            // The pool holds one vote, so a cast replaces rather than
            // adds. What it keeps is what it voted for, which is the only
            // copy the pool itself can read back.
            let mut payload = split_bytes.to_le_bytes().to_vec();
            payload.extend_from_slice(&impound_epochs.to_le_bytes());
            payload.extend_from_slice(&activate_at.to_le_bytes());
            self.vote.set(payload.clone());
            ParamVoteCast::emit(&payload);
        }

        /// Withdraw the pool's governance vote.
        #[name("clear-param-vote")]
        #[guarded(issued(b"owner-badge"))]
        pub fn clear_param_vote(&mut self) {
            self.vote.set(Vec::new());
            ParamVoteCleared::emit(&[]);
        }
    }
}

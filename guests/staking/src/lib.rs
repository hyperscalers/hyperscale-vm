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
    use hyperscale_vm_sdk::state::{Bucket, Cell, Keyed, Quantity};
    use hyperscale_vm_sdk::{Address, ResourceAddr};

    /// The identity the pool's operator surface admits: a badge this
    /// instance issues, so holding it is operating the pool and selling
    /// the pool is transferring it.
    ///
    /// The pool comes up holding its one instance, which leaves as the
    /// edge the bring-up yields — so a pool that exists has an operator
    /// and there is no window in which it does not.
    #[resource(non_fungible, initial(0))]
    struct OwnerBadge;

    /// A delegation's receipt: the resource the pool issues against what
    /// is staked with it, so a holder's units name the pool that owes
    /// them and two pools can never share one stake unit.
    #[resource(grants(mint = self, burn = self))]
    struct StakeUnit;

    /// The pool's creation-fixed configuration: what a delegation is
    /// denominated in, and who may bring the pool up.
    ///
    /// A pool's address is derivable by anyone, and the badge is what
    /// confers the operator surface — so without the gate the race to
    /// seal an address is the race to own the pool it names.
    #[config]
    #[requires(config.founder)]
    struct Settings {
        staked_resource: ResourceAddr,
        /// Who may bring the pool up: fixed where the address is
        /// derived, so whoever names an address names its founder, and
        /// the race an open bring-up would be is decided before any
        /// transaction exists.
        founder: Address,
    }

    /// A delegation arrived.
    #[event]
    struct Staked {
        amount: Quantity,
    }
    /// A delegation began unbonding.
    #[event]
    struct Unstaked {
        amount: Quantity,
    }
    /// The pool took on a validator.
    ///
    /// What the beacon's control plane reads. The key and the proof are
    /// stated at the widths the scheme fixes, which is the same check
    /// the body would otherwise write as an assert.
    #[event]
    struct ValidatorRegistered {
        validator_id: u64,
        pubkey: [u8; PUBKEY_BYTES],
        possession_proof: [u8; POSSESSION_PROOF_BYTES],
    }
    /// The pool stood a validator down.
    #[event]
    struct ValidatorDeactivated {
        validator_id: u64,
    }
    /// The pool asked for a validator to be unjailed.
    #[event]
    struct ValidatorUnjailed {
        validator_id: u64,
    }
    /// The pool cast its governance vote.
    #[event]
    struct ParamVoteCast(ParamVote);
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

    /// A validator the pool operates: the consensus key it registered,
    /// which is the whole of its claim on that validator.
    #[record]
    #[derive(Clone)]
    struct Validator {
        pubkey: [u8; PUBKEY_BYTES],
    }

    /// The pool's position on the network's parameters.
    #[record]
    #[derive(Clone)]
    struct ParamVote {
        split_bytes: u64,
        impound_epochs: u64,
        activate_at: u64,
    }

    #[state]
    struct Staking {
        /// One leaf per validator the pool operates, so two operator
        /// actions on two validators commute.
        #[slot(17)]
        validators: Keyed<Option<Validator>>,
        /// The pool's one governance vote: a pool holds one, the network
        /// counts it once, so one leaf is what its position *is*.
        #[slot(18)]
        vote: Cell<Option<ParamVote>>,
    }

    impl Staking {
        /// Delegate `funds`, taking stake units at par.
        pub fn stake(&mut self, funds: Bucket) -> Bucket {
            // The amount is the kernel's own cell width, which is what
            // the handle carries, so neither end reformats a number it
            // was handed.
            let staked = funds.quantity();
            self.vault(self.config().staked_resource).put(funds);
            Staked { amount: staked }.emit();
            StakeUnit::mint(staked)
        }

        /// Return stake units, beginning the unbonding period.
        ///
        /// The units are destroyed rather than parked: a delegator who
        /// has asked to leave no longer holds a claim on the pool, and
        /// the supply should say so. What replaces the claim is the
        /// event — the same answer this pool gives to every aggregate,
        /// and the one that keeps two delegators leaving at once from
        /// contending on a total neither of them reads.
        pub fn unstake(&mut self, units: Bucket) {
            let returned = units.quantity();
            StakeUnit::burn(units);
            Unstaked { amount: returned }.emit();
        }

        /// Take on a validator, recording the key the pool registered.
        #[requires(issued(OwnerBadge))]
        pub fn register_validator(
            &mut self,
            validator_id: u64,
            pubkey: Vec<u8>,
            possession_proof: Vec<u8>,
        ) {
            // The payload opens with the validator it concerns, which is
            // also the first thing this method is about. The widths are
            // the event's own, so what checks them is the conversion into
            // it rather than an assert beside it.
            let pubkey: [u8; PUBKEY_BYTES] =
                pubkey.try_into().expect("pubkey is not a consensus key");
            let possession_proof: [u8; POSSESSION_PROOF_BYTES] = possession_proof
                .try_into()
                .expect("possession proof is not a consensus signature");
            // Registering twice is refused by the shard holding the leaf,
            // against committed state, before this runs.
            self.validators
                .at(validator_id)
                .create(Validator { pubkey });
            ValidatorRegistered {
                validator_id,
                pubkey,
                possession_proof,
            }
            .emit();
        }

        /// Stand a validator down.
        #[requires(issued(OwnerBadge))]
        pub fn deactivate_validator(&mut self, validator_id: u64) {
            // Holding the leaf is the whole of the access: the
            // declaration says the pool operates this validator, and the
            // shard judges that before the body runs.
            self.validators.at(validator_id).exclusive();
            ValidatorDeactivated { validator_id }.emit();
        }

        /// Ask for a validator to be unjailed.
        #[requires(issued(OwnerBadge))]
        pub fn unjail(&mut self, validator_id: u64) {
            self.validators.at(validator_id).exclusive();
            ValidatorUnjailed { validator_id }.emit();
        }

        /// Cast the pool's governance vote, replacing any it held.
        #[requires(issued(OwnerBadge))]
        pub fn cast_param_vote(&mut self, split_bytes: u64, impound_epochs: u64, activate_at: u64) {
            // The pool holds one vote, so a cast replaces rather than
            // adds. What it keeps is what it voted for, which is the only
            // copy the pool itself can read back.
            let vote = ParamVote {
                split_bytes,
                impound_epochs,
                activate_at,
            };
            self.vote.set(Some(vote.clone()));
            ParamVoteCast(vote).emit();
        }

        /// Withdraw the pool's governance vote.
        #[requires(issued(OwnerBadge))]
        pub fn clear_param_vote(&mut self) {
            self.vote.set(None);
            ParamVoteCleared.emit();
        }
    }
}

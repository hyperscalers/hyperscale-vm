//! The fungible account, as one module: the funds pair, the instances a
//! holder keeps, and the authority surface every principal answers.
//!
//! Spending and writing require the account's own authority; being paid
//! does not. Anyone may credit you, and a transfer therefore still
//! composes under the sender's single signature — the recipient is not
//! asked for one, because nothing about a deposit is theirs to refuse.
//!
//! The stored-authority cell is a frame this package splices without a
//! codec: `[u32 LE base_len][base]`, optionally followed by
//! `[u64 LE effective_at_ms][base']` running to the cell's end, where
//! `base = [u64 LE recovery_delay_ms][role-set bytes]`. The role-set
//! bytes are opaque here — admission validated them, the kernel's gate
//! decodes them — so every operation below is concatenation, integer
//! reads at fixed offsets, and one saturating add.

use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
pub mod account {
    use hyperscale_vm_sdk::state::{
        AuthBase, AuthCell, Bucket, Ids, NfBucket, Proposal, Quantity, RoleTable, clock_ms,
    };
    use hyperscale_vm_sdk::{Address, Denomination, PRIMARY};

    /// Funds left the account.
    #[event]
    struct Withdrawn {
        amount: Quantity,
    }

    /// Funds arrived.
    #[event]
    struct Deposited {
        amount: Quantity,
    }

    /// The account stores nothing of its own. Every cell it uses —
    /// balances, the delivery fallback, the stored authority, the
    /// instances held — is one the protocol gives every owner.
    #[state]
    struct Account {}

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        ///
        /// The grant is the bucket: the kernel judged and held the
        /// reservation against this method's own declaration before the
        /// body ran, so there is no requested amount left to check it
        /// against and no way for the two to differ.
        #[requires(self)]
        pub fn withdraw(&mut self, resource: Denomination, amount: Quantity) -> Bucket {
            let funds = self.vault(resource).reserve(amount);
            Withdrawn {
                amount: funds.quantity(),
            }
            .emit();
            funds
        }

        /// Credit the vault and the guaranteed-delivery cell beside it.
        ///
        /// The mark the composite earns: a deposit that cannot reach the
        /// vault lands in the claims cell instead, so the two refusals it
        /// would otherwise carry — no such target, a rule that declines —
        /// become a different destination rather than an error. Both
        /// effects are commutative, nothing gates the call, and no call
        /// leaves the body, so there is neither anything to refuse nor a
        /// callee's totality to fold in.
        #[total]
        pub fn deposit(&mut self, funds: Bucket) {
            // The credit comes last because it is what consumes the edge:
            // value is linear, so every read of what crossed — the amount
            // the event carries, the resource both cells are keyed by —
            // happens while there is still a bucket to read it from.
            let credited = funds.quantity();
            self.claims(funds.resource()).declared();
            self.vault(funds.resource()).put(funds);
            Deposited { amount: credited }.emit();
        }

        /// Nothing but its own gate: the kernel judges the stored rule
        /// before the export runs, so the body has nothing to say and
        /// the read the gate performs is the gate's to declare.
        #[proves(self)]
        pub fn authorize(&mut self) {}

        /// File the instances the edge carries as holdings entries.
        ///
        /// The filing is the kernel's: each instance lands at the order
        /// it was taken under, so the body names no id at all.
        pub fn deposit_nf(&mut self, instances: NfBucket) {
            self.holdings(instances.resource()).all(64).file(instances);
        }

        /// Take the named instances out of the holdings interval,
        /// trapping on one not held. The removal and the edge are one
        /// operation, so a body cannot hand on what it left where it was.
        #[requires(self)]
        pub fn withdraw_nf(&mut self, resource: Denomination, ids: Ids) -> NfBucket {
            self.holdings(resource).all(64).take(ids)
        }

        /// Nothing but its own gate, like `authorize`: the kernel judges
        /// the holder's rule and the badge-keyed vault before the export
        /// runs, and what the call mints is the badge's address.
        ///
        /// For a fungible badge, where holding any of it is the whole
        /// claim. One instance of a non-fungible one is `present-instance`.
        #[proves(badge)]
        pub fn present_badge(&mut self, badge: Address) {}

        /// The same gate over one instance: the kernel judges the
        /// holder's rule and the holdings entry at `id` before the
        /// export runs, and the call mints that instance and the badge
        /// it is an instance of.
        ///
        /// Both, because a holder of an instance holds the badge — so a
        /// rule naming the resource admits any holder, and one naming
        /// the instance admits its holder alone. Which is what makes one
        /// badge resource with one instance per admin expressible:
        /// rotate by issuing, revoke by burning.
        #[proves(badge[id])]
        pub fn present_instance(&mut self, badge: Address, id: u64) {}

        /// Create the stored-authority cell: the caller's roles and
        /// recovery delay, with nothing pending. The cell existing is
        /// this body's own refusal, which is what makes the transition
        /// off the address-derived rule one-way.
        #[requires(self)]
        pub fn securify(&mut self, roles: RoleTable, delay_ms: u64) {
            // The one-way door is the declaration's, judged against
            // committed state before this runs: the write requires the
            // cell to be absent, so a second securify is refused by the
            // shard holding it rather than trapped here.
            self.auth().create(AuthCell::new(AuthBase {
                recovery_delay_ms: delay_ms,
                roles,
            }));
        }

        /// Append a pending replacement for the whole cell, maturing
        /// after the stored recovery delay; an unmatured proposal is
        /// replaced, a matured one first promoted.
        #[requires(auth[recovery])]
        pub fn propose(&mut self, roles: RoleTable, delay_ms: u64) {
            let stored = self.auth().existing();
            // The wait comes from the delay that governs now, never from
            // the proposer: the proposal's own delay only starts
            // governing when the proposal does.
            let current = stored.governing(clock_ms()).clone();
            let effective_at_ms = clock_ms().saturating_add(current.recovery_delay_ms);
            self.auth().set(Some(AuthCell {
                base: current,
                proposal: Some(Proposal {
                    effective_at_ms,
                    base: AuthBase {
                        recovery_delay_ms: delay_ms,
                        roles,
                    },
                }),
            }));
        }

        /// Drop an unmatured proposal; a matured one is promoted instead
        /// — cancelling what already governs would be a rewrite, not a
        /// cancel.
        ///
        /// Withdrawn by the role that made it: a proposal is recovery's,
        /// so a compromised primary cannot veto its own replacement, and
        /// there is no cancel war for it to win.
        #[requires(auth[recovery])]
        pub fn cancel(&mut self) {
            let stored = self.auth().existing();
            let governing = stored.governing(clock_ms()).clone();
            self.auth().set(Some(AuthCell::new(governing)));
        }

        /// Promote the pending proposal now, matured or not: early
        /// enactment and compaction are one operation.
        #[requires(auth[confirmation])]
        pub fn confirm(&mut self) {
            let stored = self.auth().existing();
            let proposal = stored.proposal.expect("nothing is pending");
            self.auth().set(Some(AuthCell::new(proposal.base)));
        }

        /// Strip the primary's acting power, now, keeping whatever
        /// proposal is pending: what stops a compromised key draining
        /// the account while its replacement matures. An absent entry
        /// denies, so the freeze is a removal rather than a rule nobody
        /// can write — and unfreezing is the rotation itself, since the
        /// matured or confirmed proposal writes a table with a primary
        /// in it.
        #[requires(auth[recovery])]
        pub fn freeze(&mut self) {
            let stored = self.auth().existing();
            let mut base = stored.governing(clock_ms()).clone();
            // A matured proposal was promoted by the governing read;
            // only one still waiting stays pending.
            let pending = match stored.proposal {
                Some(proposal) if proposal.effective_at_ms > clock_ms() => Some(proposal),
                _ => None,
            };
            base.roles.remove(PRIMARY);
            self.auth().set(Some(AuthCell {
                base,
                proposal: pending,
            }));
        }
    }
}

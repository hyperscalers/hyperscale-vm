//! The fungible account, as one module: the funds pair, the instances a
//! holder keeps, and the authority surface every principal answers.
//!
//! Spending and writing require the account's own authority; being paid
//! does not. Anyone may credit you, and a transfer therefore still
//! composes under the sender's single signature — the recipient is not
//! asked for one, because nothing about a deposit is theirs to refuse.
//!
//! Every address has one governing rule, in the cell the protocol keeps
//! for it, and while nothing is stored there the address governs itself —
//! which is the rule's own second branch rather than anything the kernel
//! supplies. Everything past that is this package's policy and lives in
//! this package's cells: the two further rules a recovery surface needs,
//! the replacement waiting on a delay, and what it takes to enact one.
//!
//! Rule bytes stay opaque here. The kernel decodes them where it judges a
//! call against them, and a body that stores what it was handed converts
//! nothing.

use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
pub mod account {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Ids, NfBucket, Quantity, RuleBytes, clock_ms};
    use hyperscale_vm_sdk::{Address, ResourceAddr, nobody};

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

    /// A replacement for all three rules, waiting on the delay that
    /// governed when it was made.
    #[record]
    struct Pending {
        /// When it may be enacted without a confirmation.
        effective_at_ms: u64,
        /// What each cell becomes.
        primary: RuleBytes,
        recovery: RuleBytes,
        confirmation: RuleBytes,
    }

    /// What the account keeps beyond the governing rule every address
    /// already has: the surface that can replace it.
    ///
    /// A recovery rule and a confirmation rule are two more of the same
    /// thing, so they are two more cells rather than a table with a
    /// vocabulary of its own — and each gate reads the one rule it needs
    /// instead of every rule the account holds.
    #[state]
    struct Account {
        /// Who may propose a replacement, and who may cancel one.
        recovery: Cell<Option<RuleBytes>>,
        /// Who may enact one before its delay runs out.
        confirmation: Cell<Option<RuleBytes>>,
        /// The replacement waiting, where one is.
        pending: Cell<Option<Pending>>,
        /// How long a proposal waits when nothing confirms it.
        delay_ms: Cell<u64>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        ///
        /// The grant is the bucket: the kernel judged and held the
        /// reservation against this method's own declaration before the
        /// body ran, so there is no requested amount left to check it
        /// against and no way for the two to differ.
        #[requires(self)]
        pub fn withdraw(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
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
            self.claims(funds.resource()).declared_credit();
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
        /// it was taken under, so the body names no id at all — and the
        /// interval's cap is the edge's own count, derived from the
        /// move, so a deposit declares exactly the walk it performs and
        /// pays for nothing wider.
        pub fn deposit_nf(&mut self, instances: NfBucket) {
            self.holdings(instances.resource()).all().file(instances);
        }

        /// Take the named instances out of the holdings interval,
        /// trapping on one not held. The removal and the edge are one
        /// operation, so a body cannot hand on what it left where it
        /// was. The cap is the count of ids named, on `deposit_nf`'s
        /// terms.
        #[requires(self)]
        pub fn withdraw_nf(&mut self, resource: ResourceAddr, ids: Ids) -> NfBucket {
            self.holdings(resource).all().take(ids)
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

        /// Hand `amount` of `resource` out of this account, to whoever
        /// the resource's own granted recall rule admits.
        ///
        /// The one way a recall reaches a holder's vault: the holder's
        /// own method, declared under the holder's own prefix, gated on
        /// a rule the resource's address commits to — so ownership
        /// holds, the kernel gains nothing, and a holder sees the power
        /// before accepting the asset.
        #[requires(recalls(resource))]
        pub fn recall(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            self.vault(resource).take(amount)
        }

        /// Store the three rules that govern from here on.
        ///
        /// The governing cell being absent is this body's own refusal,
        /// judged against committed state before it runs — and it is what
        /// makes the transition off the address's own key one-way, since
        /// the branch admitting that key is the one the cell's absence
        /// meets.
        #[requires(self)]
        pub fn securify(
            &mut self,
            primary: RuleBytes,
            recovery: RuleBytes,
            confirmation: RuleBytes,
            delay_ms: u64,
        ) {
            self.auth().create(primary);
            self.recovery.set(Some(recovery));
            self.confirmation.set(Some(confirmation));
            self.delay_ms.set(delay_ms);
        }

        /// Wait out a replacement's delay, or replace one still waiting.
        ///
        /// The wait comes from the delay that governs now, never from the
        /// proposer: a proposal's own delay starts governing when the
        /// proposal does.
        #[requires(governs(recovery))]
        pub fn propose(
            &mut self,
            primary: RuleBytes,
            recovery: RuleBytes,
            confirmation: RuleBytes,
        ) {
            let effective_at_ms = clock_ms().saturating_add(self.delay_ms.get());
            self.pending.set(Some(Pending {
                effective_at_ms,
                primary,
                recovery,
                confirmation,
            }));
        }

        /// Enact a replacement whose delay has run out.
        ///
        /// Open to anyone, because it does only what the clock already
        /// licensed: the party who wants it is whoever proposed it, and
        /// it is a node in their own transaction. Nothing happens before
        /// the instant the proposal named.
        pub fn promote(&mut self) {
            if let Some(pending) = self.pending.get()
                && pending.effective_at_ms <= clock_ms()
            {
                self.auth().set(Some(pending.primary));
                self.recovery.set(Some(pending.recovery));
                self.confirmation.set(Some(pending.confirmation));
                self.pending.set(None);
            }
        }

        /// Drop the replacement waiting, whatever its instant.
        ///
        /// Withdrawn by whoever may propose one: a replacement is the
        /// recovery rule's, so a compromised governing key cannot veto
        /// its own replacement and there is no cancel war for it to win.
        /// Cancelling one whose instant has passed is no different —
        /// whoever wanted it enacted could have enacted it, in the same
        /// transaction they proposed it or any since.
        #[requires(governs(recovery))]
        pub fn cancel(&mut self) {
            self.pending.set(None);
        }

        /// Enact a replacement now, matured or not.
        #[requires(governs(confirmation))]
        pub fn confirm(&mut self) {
            if let Some(pending) = self.pending.get() {
                self.auth().set(Some(pending.primary));
                self.recovery.set(Some(pending.recovery));
                self.confirmation.set(Some(pending.confirmation));
                self.pending.set(None);
            }
        }

        /// Strip the primary's acting power, now, keeping whatever
        /// replacement is waiting: what stops a compromised key draining
        /// the account while its replacement matures.
        ///
        /// A write of the rule nobody satisfies rather than a removal,
        /// and the difference is the whole of the freeze: an absent cell
        /// is what the address's own key still governs, so removing the
        /// rule would hand the account back to the key being frozen out.
        ///
        /// Unfreezing is the replacement itself, and only that. Nothing
        /// here requires one to be waiting, so a freeze is immediate and
        /// one-way, and the delay governs takeover rather than this. A
        /// recovery factor in the wrong hands can therefore lock the
        /// account for good; the dial against that is the confirmation
        /// rule, which every replacement must satisfy once the delay is
        /// long enough not to arrive.
        #[requires(governs(recovery))]
        pub fn freeze(&mut self) {
            self.auth().set(Some(nobody()));
        }
    }
}

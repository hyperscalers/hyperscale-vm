//! The fungible account, as one module: the funds pair, the instances a
//! holder keeps, and the authority surface every principal answers.
//!
//! Spending and writing require the account's own authority; being paid
//! does not. Anyone may credit you, and a transfer therefore still
//! composes under the sender's single signature — the recipient is not
//! asked for one, because nothing about a deposit is theirs to refuse.
//!
//! Every address has one governing rule, in the cell the protocol keeps
//! for it, and while nothing is stored there the address governs itself.
//! No method here reads it: the account's shard judges the attesting keys
//! of every intent against that cell before any body runs, so a method
//! naming `self` is naming a sign-in already made. Everything past that
//! is this package's policy and lives in this package's cells: the two
//! further rules a recovery surface needs, the replacement waiting on a
//! delay, and what it takes to enact one — each read by the gate that
//! needs it and judged against the claims the call presents.
//!
//! Rule bytes stay opaque here. The kernel decodes them where it judges a
//! call against them, and a body that stores what it was handed converts
//! nothing.

use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
pub mod account {
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Ids, Keyed, NfBucket, PrincipalRule, Quantity, RuleBytes, Vault, clock_ms,
        destroy, destroy_nf,
    };
    use hyperscale_vm_sdk::{Address, Authority, ResourceAddr, nobody};

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

    /// A verdict on a proposal that is not there to answer, or an
    /// enactment the clock has not licensed.
    #[error]
    enum Error {
        /// No proposal waits under the serial named.
        NoSuchProposal,
        /// The proposal named has not reached its instant.
        Unmatured,
    }

    /// A replacement for the account's factors, waiting on the delay
    /// that governed when it was made.
    ///
    /// A recovery replaces what the account acts with and nothing
    /// about who may recover it: the roles are the primary's to amend,
    /// under the same delay, once it can act again. That is also what
    /// keeps this record inside one leaf — a leaf holds fewer than four
    /// rules at the argument cap.
    #[record]
    struct Pending {
        /// Which proposal this is, so a verdict names the one its signer
        /// saw: a proposal landed between the signing and the inclusion
        /// of a confirmation is refused rather than enacted in its place.
        serial: u64,
        /// When it may be enacted without a confirmation.
        effective_at_ms: u64,
        /// The factors the governing record takes, at the narrowed kind
        /// that record holds.
        primary: PrincipalRule,
        confirmation: PrincipalRule,
        /// The primary a freeze displaced, where the account is frozen.
        ///
        /// In the proposal rather than in a cell of its own, so a frozen
        /// account has a proposal waiting by construction: the freeze
        /// ends when the proposal does, enacted or cancelled, and a
        /// proposal that replaces a frozen one carries this forward, so
        /// re-proposing never loses the rule a cancel gives back.
        frozen: Option<RuleBytes>,
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
        /// The resources this account does not want in its vault.
        ///
        /// A flag rather than a record, and set rather than cleared, so
        /// that saying nothing is accepting: an account that has never
        /// thought about a resource takes it, which is what every
        /// account does today and what a deposit into a fresh address
        /// has to keep doing.
        refused: Keyed<bool>,
        /// Where a refused resource lands instead.
        ///
        /// The whole reason `deposit` can stay total: a recipient who
        /// does not want something is answered by a different
        /// destination rather than by a refusal, so a sender composing
        /// a transfer never has to know the recipient's mind. What the
        /// *issuer* forbids is a different question and a different
        /// answer — a `Deposit` entry aborts the transfer at admission,
        /// before there is anything here to sweep.
        quarantine: Keyed<Vault>,
        /// Who may propose a replacement, and who may cancel one.
        ///
        /// A rule reaches the account as an argument, and an argument's
        /// bytes are capped at four kibibytes; the cell is sized to
        /// hold any rule that can be handed to it. The record and not
        /// the bare bytes: a byte string sits behind its own length, and
        /// an absent rule behind a tag, so the width is the argument cap
        /// and three bytes — sized at the cap alone, the widest rule an
        /// account can be handed is the one it refuses.
        #[width(4099)]
        recovery: Cell<Option<RuleBytes>>,
        /// Who may stop a replacement before its delay runs out, giving
        /// a frozen primary back: the holder's defence against a
        /// recovery role in the wrong hands. Cold, and never a factor the
        /// sign-in reads — a thief holding every everyday factor must
        /// not hold this.
        #[width(4099)]
        veto: Cell<Option<RuleBytes>>,
        /// The replacement waiting, where one is: three rules at the
        /// argument cap, their lengths and the tag on the optional one,
        /// and two words.
        #[width(12311)]
        pending: Cell<Option<Pending>>,
        /// How long a proposal waits when nothing confirms it.
        ///
        /// A cell rather than a constant of the account, because a
        /// replacement replaces this too — `securify` sets the first one
        /// and every enacted proposal sets the next.
        delay_ms: Cell<u64>,
        /// How many proposals this account has had, which is the serial
        /// the next one takes.
        serials: Cell<u64>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        ///
        /// The grant is the bucket: the kernel judged and held the
        /// reservation against this method's own declaration before the
        /// body ran, so there is no requested amount left to check it
        /// against and no way for the two to differ.
        #[requires(self)]
        #[emits(Withdrawn)]
        pub fn withdraw(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            let funds = self.vault(resource).reserve(amount);
            Withdrawn {
                amount: funds.quantity(),
            }
            .emit();
            funds
        }

        /// Credit the vault, or the quarantine beside it where this
        /// account has refused the resource.
        ///
        /// The mark the composite earns: a recipient who does not want
        /// something is answered by a different destination rather than
        /// by an error, so the one refusal a deposit could otherwise
        /// carry becomes a place for the value to sit. Both destinations
        /// are declared whichever the body picks — a total method's
        /// handles are all materialized or none are — so what the choice
        /// changes is where the value goes and never what the
        /// declaration says.
        ///
        /// What the issuer forbids is not this question. A `Deposit`
        /// entry that declines aborts the transfer at admission, before
        /// anything lands here to be swept, so the two never meet.
        #[total]
        #[emits(Deposited)]
        pub fn deposit(&mut self, funds: Bucket) {
            // The credits come last because one of them consumes the
            // edge: value is linear, so every read of what crossed — the
            // amount the event carries, the resource both cells are keyed
            // by — happens while there is still a bucket to read it from.
            let credited = funds.quantity();
            let resource = funds.resource();
            let refused = self.refused.at(resource).get();
            if refused {
                self.quarantine.at(resource).put(funds);
            } else {
                self.vault(resource).put(funds);
            }
            Deposited { amount: credited }.emit();
        }

        /// Send `resource` to the quarantine from here on.
        ///
        /// What is already in the vault stays there: this says where the
        /// next deposit lands, not where the last one went.
        #[requires(self)]
        pub fn refuse(&mut self, resource: ResourceAddr) {
            self.refused.at(resource).set(true);
        }

        /// Take it back into the vault from here on.
        #[requires(self)]
        pub fn accept(&mut self, resource: ResourceAddr) {
            self.refused.at(resource).set(false);
        }

        /// Take `amount` of a quarantined resource out.
        ///
        /// The way anything leaves the quarantine, and it is the
        /// holder's alone — the same gate `withdraw` carries, because
        /// what sits here is theirs and was only ever put aside.
        #[requires(self)]
        pub fn sweep(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            self.quarantine.at(resource).reserve(amount)
        }

        /// Retire what the caller hands over.
        ///
        /// Not the issuer's burn and not this account's authority: what
        /// leaves existence is the edge's own resource, so the rule that
        /// admits it is that resource's own `Burn` entry, injected at
        /// admission and answered by whoever the issuer named. A
        /// resource granting none is one this method cannot destroy,
        /// which is every resource until its issuer says otherwise.
        ///
        /// Ungated here for the same reason `deposit` is: what may
        /// happen is the resource's answer rather than this package's,
        /// and a gate written here would be a second opinion that could
        /// disagree with it.
        pub fn burn(&mut self, funds: Bucket) {
            destroy(funds);
        }

        /// The same, over instances.
        pub fn burn_nf(&mut self, instances: NfBucket) {
            destroy_nf(instances);
        }

        /// File the instances the edge carries as holdings entries.
        ///
        /// The filing is the kernel's: each instance lands at the order
        /// it was taken under, so the body names no id at all — and the
        /// interval's cap is the edge's own count, derived from the
        /// move, so a deposit declares exactly the walk it performs and
        /// pays for nothing wider.
        pub fn deposit_nf(&mut self, instances: NfBucket) {
            self.holdings(instances.resource()).whole().file(instances);
        }

        /// Take the named instances out of the holdings interval,
        /// trapping on one not held. The removal and the edge are one
        /// operation, so a body cannot hand on what it left where it
        /// was. The cap is the count of ids named, on `deposit_nf`'s
        /// terms.
        #[requires(self)]
        pub fn withdraw_nf(&mut self, resource: ResourceAddr, ids: Ids) -> NfBucket {
            self.holdings(resource).whole().take(ids)
        }

        /// Nothing but its own gate: the holder names itself, which
        /// their intent's signature answers, and the kernel judges the
        /// badge-keyed vault before the export runs. What the call
        /// proves is the badge's address.
        ///
        /// For a fungible badge, where holding any of it is the whole
        /// claim. One instance of a non-fungible one is `present-instance`.
        #[proves(badge)]
        pub fn present_badge(&self, badge: Address) {}

        /// The same gate over one instance: the kernel judges the
        /// holdings entry at `id` before the export runs, and the call
        /// proves that instance and the badge it is an instance of.
        ///
        /// Both, because a holder of an instance holds the badge — so a
        /// rule naming the resource admits any holder, and one naming
        /// the instance admits its holder alone. Which is what makes one
        /// badge resource with one instance per admin expressible:
        /// rotate by issuing, revoke by burning.
        #[proves(badge[id])]
        pub fn present_instance(&self, badge: Address, id: u64) {}

        /// Store the factors and the roles that govern from here on, and
        /// the delay a replacement waits.
        ///
        /// The governing cell being absent is this body's own refusal,
        /// judged against committed state before it runs — and it is what
        /// makes the transition off the address's own key one-way, since
        /// the branch admitting that key is the one the cell's absence
        /// meets.
        #[requires(self)]
        pub fn securify(
            &mut self,
            primary: PrincipalRule,
            confirmation: PrincipalRule,
            recovery: RuleBytes,
            veto: RuleBytes,
            delay_ms: u64,
        ) {
            self.auth().create(Authority {
                primary: primary.into_bytes(),
                confirmation: confirmation.into_bytes(),
            });
            self.recovery.set(Some(recovery));
            self.veto.set(Some(veto));
            self.delay_ms.set(delay_ms);
        }

        /// Replace either factor now.
        ///
        /// No delay, because the intent passed the sign-in over both
        /// factors: whoever can call this already holds every everyday
        /// factor and gains nothing over the guardians by rotating,
        /// while a holder retiring a key or replacing a worn card gets
        /// it done at once. Dropping the second factor is rotating it
        /// to the rule anyone satisfies.
        #[requires(self)]
        pub fn rotate(&mut self, primary: PrincipalRule, confirmation: PrincipalRule) {
            let mut authority = self.auth().existing();
            authority.primary = primary.into_bytes();
            authority.confirmation = confirmation.into_bytes();
            self.auth().set(Some(authority));
        }

        /// Wait out a replacement's delay, or replace one still waiting.
        ///
        /// The wait is the delay that governs now: a proposal cannot
        /// shorten its own takeover, because the delay is not a
        /// proposal's to name.
        #[requires(governs(recovery))]
        pub fn propose(&mut self, primary: PrincipalRule, confirmation: PrincipalRule) {
            let frozen = self.pending.get().and_then(|waiting| waiting.frozen);
            self.file(primary, confirmation, frozen);
        }

        /// Propose a replacement and strip the primary's acting power
        /// now, the confirmation standing: what stops a compromised key
        /// draining the account while its replacement matures.
        ///
        /// A freeze is a proposal with the primary closed, never a state
        /// of its own. It ends when the proposal does — enacted, which
        /// writes the primary the proposal names, or cancelled, which
        /// gives the displaced one back — so a frozen account always has
        /// a clock running on it. A freeze or a proposal while frozen
        /// replaces the proposal and carries the displaced primary
        /// forward, so re-proposing never loses it.
        ///
        /// Written as the rule nobody satisfies rather than as a removal,
        /// and the difference is the whole of the freeze: an absent cell
        /// is what the address's own key still governs, so removing the
        /// rule would hand the account back to the key being frozen out.
        #[requires(governs(recovery))]
        pub fn freeze(&mut self, primary: PrincipalRule, confirmation: PrincipalRule) {
            let mut authority = self.auth().existing();
            let displaced = self
                .pending
                .get()
                .and_then(|waiting| waiting.frozen)
                .unwrap_or_else(|| authority.primary.clone());
            self.file(primary, confirmation, Some(displaced));
            authority.primary = nobody();
            self.auth().set(Some(authority));
        }

        /// File a replacement as the one waiting, under the next serial
        /// and the delay that governs now, carrying the primary a freeze
        /// displaced where there is one.
        fn file(
            &mut self,
            primary: PrincipalRule,
            confirmation: PrincipalRule,
            frozen: Option<RuleBytes>,
        ) {
            let effective_at_ms = clock_ms().saturating_add(self.delay_ms.get());
            let serial = self.serials.get().saturating_add(1);
            self.serials.set(serial);
            self.pending.set(Some(Pending {
                serial,
                effective_at_ms,
                primary,
                confirmation,
                frozen,
            }));
        }

        /// Enact the replacement `serial` names, whose delay has run out.
        ///
        /// Open to anyone: the record was authorized by the gate that
        /// wrote it, and the clock is the only condition left — so the
        /// recovered holder's own new key can finish what a guardian
        /// began, and nobody signs twice. Before the instant the
        /// proposal named this is a refusal rather than nothing, so a
        /// caller is told rather than charged for a no-op.
        pub fn promote(&mut self, serial: u64) -> Result<(), Error> {
            let pending = self.proposal(serial)?;
            if clock_ms() < pending.effective_at_ms {
                return Err(Error::Unmatured);
            }
            self.enact(pending);
            Ok(())
        }

        /// Drop the replacement `serial` names, whatever its instant,
        /// giving back the primary a freeze displaced.
        ///
        /// Withdrawn by whoever may propose one: a replacement is the
        /// recovery rule's, so a compromised governing key cannot veto
        /// its own replacement and there is no cancel war for it to win.
        /// Cancelling one whose instant has passed is no different —
        /// whoever wanted it enacted could have enacted it, in the same
        /// transaction they proposed it or any since.
        #[requires(governs(recovery))]
        pub fn cancel(&mut self, serial: u64) -> Result<(), Error> {
            self.withdraw_proposal(serial)
        }

        /// Stop the replacement `serial` names, whatever its instant,
        /// giving back the primary a freeze displaced.
        ///
        /// The veto role's, and the whole of its power: it enacts
        /// nothing and proposes nothing, so a veto key found by a
        /// stranger can only ever say no. What it is for is a recovery
        /// role in the wrong hands — the freeze it lands is undone by
        /// this, and the account is where it was.
        #[requires(governs(veto))]
        pub fn veto(&mut self, serial: u64) -> Result<(), Error> {
            self.withdraw_proposal(serial)
        }

        /// Drop the replacement `serial` names and give back what a
        /// freeze displaced, where one did.
        fn withdraw_proposal(&mut self, serial: u64) -> Result<(), Error> {
            let pending = self.proposal(serial)?;
            self.pending.set(None);
            if let Some(primary) = pending.frozen {
                let mut authority = self.auth().existing();
                authority.primary = primary;
                self.auth().set(Some(authority));
            }
            Ok(())
        }

        /// The replacement waiting under `serial`, or the refusal that
        /// none is: a verdict answers the proposal its signer saw and no
        /// other.
        fn proposal(&self, serial: u64) -> Result<Pending, Error> {
            let Some(pending) = self.pending.get() else {
                return Err(Error::NoSuchProposal);
            };
            if pending.serial != serial {
                return Err(Error::NoSuchProposal);
            }
            Ok(pending)
        }

        /// File `pending`'s factors as the governing ones and clear the
        /// wait — and with it any freeze, whose displaced primary the
        /// proposal has just replaced.
        ///
        /// A replacement is of the factors and nothing about who may
        /// recover: guardians who pass the card's rule back leave an
        /// account colluding guardians still cannot spend from, and the
        /// roles are the primary's to amend once it can act again.
        fn enact(&mut self, pending: Pending) {
            let mut authority = self.auth().existing();
            authority.primary = pending.primary.into_bytes();
            authority.confirmation = pending.confirmation.into_bytes();
            self.auth().set(Some(authority));
            self.pending.set(None);
        }
    }
}

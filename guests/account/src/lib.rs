//! The fungible account, as one module: the funds pair, the instances a
//! holder keeps, and the authority surface every principal answers.
//!
//! Spending and writing require the account's own authority; being paid
//! does not. Anyone may credit you, and a transfer therefore still
//! composes under the sender's single signature — the recipient is not
//! asked for one, because nothing about a deposit is theirs to refuse.
//!
//! Every address has a governing record, in the cell the protocol keeps
//! for it: the everyday rule and a second factor beside it, judged
//! together at sign-in. While nothing is stored there the address
//! governs itself. No method here reads it as a gate: the account's
//! shard judges the attesting keys of every intent against that cell
//! before any body runs, so a method naming `self` is naming a sign-in
//! already made. Everything past that is this package's policy and lives
//! in this package's cells: the two roles that may recover or stop a
//! recovery, the replacement waiting on a delay, and the count that
//! names it — each read by the gate that needs it and judged against the
//! claims the call presents.
//!
//! Rule bytes stay opaque here. The kernel decodes them where it judges a
//! call against them, and a body that stores what it was handed converts
//! nothing.

use hyperscale_vm_sdk::blueprint;

#[blueprint(principals)]
pub mod account {
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Ids, NfBucket, PrincipalRule, Quantity, RuleBytes, clock_ms, destroy,
        destroy_nf,
    };
    use hyperscale_vm_sdk::{Address, Authority, ResourceAddr, nobody};

    /// Funds left the account.
    #[event]
    struct Withdrawn {
        amount: Quantity,
    }

    /// A replacement was filed — of the factors, or of who may recover
    /// them — and the instant it may be enacted from.
    ///
    /// What makes the delay usable rather than merely anxious: a wallet
    /// watching the account's prefix sees every filing and can put the
    /// verdict on the notification.
    #[event]
    struct Proposed {
        serial: u64,
        effective_at_ms: u64,
    }

    /// The replacement `serial` names was enacted.
    #[event]
    struct Enacted {
        serial: u64,
    }

    /// The replacement `serial` names was dropped, cancelled or vetoed,
    /// and whatever it would have replaced stands.
    #[event]
    struct Cancelled {
        serial: u64,
    }

    /// A verdict on a proposal that is not there to answer, or an
    /// enactment the clock has not licensed.
    #[error]
    enum Error {
        /// No proposal waits under the serial named.
        NoSuchProposal,
        /// The proposal named has not reached its instant.
        Unmatured,
        /// A recovery proposal waits, and it outranks an amendment.
        Outranked,
    }

    /// A replacement waiting on the delay that governed when it was
    /// filed: of the factors, or of who may recover them.
    ///
    /// One cell for both kinds because they never coexist — a recovery
    /// filing retires a waiting amendment, and an amendment is refused
    /// while a recovery waits — and one count names them, so a verdict's
    /// serial names one record or none.
    #[record]
    struct Proposal {
        /// Which proposal this is, so a verdict names the one its signer
        /// saw: a proposal landed between the signing and the inclusion
        /// of a verdict is refused rather than answered in its place.
        serial: u64,
        /// When it may be enacted.
        effective_at_ms: u64,
        replaces: Replacement,
    }

    /// What a proposal replaces.
    ///
    /// Split by what it replaces, which is also who may file it: the
    /// factors are the recovery role's to propose, the roles are the
    /// primary's to amend. Each arm holds fewer than four rules at the
    /// argument cap, which is what keeps the record inside one leaf.
    #[record]
    enum Replacement {
        /// The factors the governing record takes, at the narrowed kind
        /// that record holds.
        ///
        /// A recovery replaces what the account acts with and nothing
        /// about who may recover it: guardians who pass the card's rule
        /// back leave an account colluding guardians still cannot spend
        /// from, and the roles are the primary's to amend once it can
        /// act again.
        Factors {
            primary: PrincipalRule,
            confirmation: PrincipalRule,
            /// The primary a freeze displaced, where the account is
            /// frozen.
            ///
            /// In the proposal rather than in a cell of its own, so a
            /// frozen account has a proposal waiting by construction:
            /// the freeze ends when the proposal does, enacted or
            /// cancelled, and a proposal that replaces a frozen one
            /// carries this forward, so re-proposing never loses the
            /// rule a cancel gives back.
            frozen: Option<RuleBytes>,
        },
        /// What the three role cells become.
        ///
        /// The primary's to file and the recovery role's to cancel,
        /// which is the one asymmetry a stolen key requires: a thief
        /// evicting the guardians is stopped by the guardians, and an
        /// owner replacing a guardian who has gone quiet succeeds after
        /// the wait.
        Roles {
            recovery: RuleBytes,
            veto: RuleBytes,
            delay_ms: u64,
        },
    }

    /// What the account keeps beyond the governing record every address
    /// already has: the surface that can replace it.
    ///
    /// A recovery rule and a veto rule are two more of the same thing,
    /// so they are two more cells rather than a table with a vocabulary
    /// of its own — and each gate reads the one rule it needs instead of
    /// every rule the account holds.
    #[state]
    struct Account {
        /// Who may propose a replacement of the factors, and who may
        /// cancel any proposal.
        ///
        /// A rule reaches the account as an argument, so the cell holds
        /// any rule that can be handed to it: the width is the argument
        /// cap its type states and the length a byte string sits behind.
        recovery: Cell<Option<RuleBytes>>,
        /// Who may stop a proposal before its delay runs out, giving a
        /// frozen primary back: the holder's defence against a recovery
        /// role in the wrong hands. Cold, and never a factor the sign-in
        /// reads — a thief holding every everyday factor must not hold
        /// this.
        veto: Cell<Option<RuleBytes>>,
        /// The replacement waiting, where one is.
        proposal: Cell<Option<Proposal>>,
        /// How long a proposal waits before it may be enacted.
        ///
        /// A cell rather than a constant of the account, because an
        /// amendment replaces this too — `securify` sets the first one
        /// and every enacted amendment sets the next.
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
        pub fn withdraw(&mut self, resource: ResourceAddr, amount: Quantity) -> Bucket {
            let funds = self.vault(resource).reserve(amount);
            Withdrawn {
                amount: funds.quantity(),
            }
            .emit();
            funds
        }

        /// Credit the vault for what crossed.
        ///
        /// One destination and one delta, which is what lets the credit
        /// be completed from the crossing's own leaf: the cell is the
        /// holder's vault for the resource the record names, and both
        /// are terms a reader of the leaf already holds. A recipient who
        /// does not want a resource is answered by not showing it, which
        /// is a wallet's question rather than a ledger's.
        ///
        /// What the issuer forbids is not this question either. A
        /// `Deposit` entry that declines aborts the transfer at
        /// admission, before anything lands here.
        ///
        /// The body is the declaration's source and nothing else: its
        /// shape is a vault deposit, which the kernel performs itself.
        pub fn deposit(&mut self, funds: Bucket) {
            let resource = funds.resource();
            self.vault(resource).put(funds);
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
        /// to the rule anyone satisfies. Through the door that requires
        /// presence, so an account that has not securified is refused
        /// rather than securified without its roles.
        #[requires(self)]
        pub fn rotate(&mut self, primary: PrincipalRule, confirmation: PrincipalRule) {
            self.auth().rewrite(Authority {
                primary: primary.into_bytes(),
                confirmation: confirmation.into_bytes(),
            });
        }

        /// Change who may recover the account, after the delay.
        ///
        /// The roles are the primary's to amend and never a recovery's
        /// to rewrite, and the amendment waits the delay the guardians
        /// serve so that a thief evicting them is stopped by them: it is
        /// theirs to cancel throughout. A recovery proposal outranks it —
        /// refused while one waits, retired when one is filed — so the
        /// primary can never stall the guardians. Withdrawing one is
        /// amending to the current values.
        #[requires(self)]
        pub fn amend(
            &mut self,
            recovery: RuleBytes,
            veto: RuleBytes,
            delay_ms: u64,
        ) -> Result<(), Error> {
            if let Some(waiting) = self.proposal.get()
                && matches!(waiting.replaces, Replacement::Factors { .. })
            {
                return Err(Error::Outranked);
            }
            self.file(Replacement::Roles {
                recovery,
                veto,
                delay_ms,
            });
            Ok(())
        }

        /// File a replacement of the factors, or replace one still
        /// waiting.
        ///
        /// The wait is the delay that governs now: a proposal cannot
        /// shorten its own takeover, because the delay is not a
        /// proposal's to name.
        #[requires(governs(recovery))]
        pub fn propose(&mut self, primary: PrincipalRule, confirmation: PrincipalRule) {
            let frozen = self.displaced();
            self.file(Replacement::Factors {
                primary,
                confirmation,
                frozen,
            });
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
                .displaced()
                .unwrap_or_else(|| authority.primary.clone());
            self.file(Replacement::Factors {
                primary,
                confirmation,
                frozen: Some(displaced),
            });
            authority.primary = nobody();
            self.auth().rewrite(authority);
        }

        /// The primary a waiting freeze displaced, where the account is
        /// frozen.
        fn displaced(&self) -> Option<RuleBytes> {
            match self.proposal.get()?.replaces {
                Replacement::Factors { frozen, .. } => frozen,
                Replacement::Roles { .. } => None,
            }
        }

        /// File `replaces` as the proposal waiting, under the next serial
        /// and the delay that governs now — retiring whatever waited,
        /// which is a recovery outranking an amendment or a filing
        /// superseding its own.
        ///
        /// Through the door that requires the governing cell: the
        /// recovery surface exists only once the account has securified,
        /// so an address still governed by its own key cannot file a
        /// record no verdict could reach.
        fn file(&mut self, replaces: Replacement) {
            self.auth().present();
            let effective_at_ms = clock_ms().saturating_add(self.delay_ms.get());
            let serial = self.serials.get().saturating_add(1);
            self.serials.set(serial);
            self.proposal.set(Some(Proposal {
                serial,
                effective_at_ms,
                replaces,
            }));
            Proposed {
                serial,
                effective_at_ms,
            }
            .emit();
        }

        /// Enact the proposal `serial` names, whose delay has run out.
        ///
        /// Open to anyone: the record was authorized by the gate that
        /// wrote it, and the clock is the only condition left — so the
        /// recovered holder's own new key can finish what a guardian
        /// began, and nobody signs twice. Before the instant the
        /// proposal named this is a refusal rather than nothing, so a
        /// caller is told rather than charged for a no-op.
        ///
        /// Enacting the factors ends any freeze with them, the displaced
        /// primary having just been replaced; enacting the roles touches
        /// no factor.
        pub fn promote(&mut self, serial: u64) -> Result<(), Error> {
            let proposal = self.named(serial)?;
            if clock_ms() < proposal.effective_at_ms {
                return Err(Error::Unmatured);
            }
            match proposal.replaces {
                Replacement::Factors {
                    primary,
                    confirmation,
                    ..
                } => self.auth().rewrite(Authority {
                    primary: primary.into_bytes(),
                    confirmation: confirmation.into_bytes(),
                }),
                Replacement::Roles {
                    recovery,
                    veto,
                    delay_ms,
                } => {
                    self.recovery.set(Some(recovery));
                    self.veto.set(Some(veto));
                    self.delay_ms.set(delay_ms);
                }
            }
            self.proposal.set(None);
            Enacted { serial }.emit();
            Ok(())
        }

        /// Drop the proposal `serial` names, whatever its instant,
        /// giving back the primary a freeze displaced.
        ///
        /// Withdrawn by whoever may propose a replacement: a proposal is
        /// the recovery rule's, so a compromised governing key cannot
        /// cancel its own replacement and there is no cancel war for it
        /// to win. Cancelling one whose instant has passed is no
        /// different — whoever wanted it enacted could have enacted it,
        /// in the same transaction they proposed it or any since.
        #[requires(governs(recovery))]
        pub fn cancel(&mut self, serial: u64) -> Result<(), Error> {
            self.retract(serial)
        }

        /// Stop the proposal `serial` names, whatever its instant,
        /// giving back the primary a freeze displaced.
        ///
        /// The veto role's, and the whole of its power: it enacts
        /// nothing and proposes nothing, so a veto key found by a
        /// stranger can only ever say no. What it is for is a recovery
        /// role in the wrong hands — the freeze it lands is undone by
        /// this, and the account is where it was.
        #[requires(governs(veto))]
        pub fn veto(&mut self, serial: u64) -> Result<(), Error> {
            self.retract(serial)
        }

        /// Drop whatever `serial` names, giving back what a freeze
        /// displaced where one did — or refuse: a verdict answers the
        /// proposal its signer saw and no other.
        fn retract(&mut self, serial: u64) -> Result<(), Error> {
            let proposal = self.named(serial)?;
            if let Replacement::Factors {
                frozen: Some(primary),
                ..
            } = proposal.replaces
            {
                let mut authority = self.auth().existing();
                authority.primary = primary;
                self.auth().rewrite(authority);
            }
            self.proposal.set(None);
            Cancelled { serial }.emit();
            Ok(())
        }

        /// The proposal `serial` names, which is the one waiting or none.
        fn named(&self, serial: u64) -> Result<Proposal, Error> {
            self.proposal
                .get()
                .filter(|waiting| waiting.serial == serial)
                .ok_or(Error::NoSuchProposal)
        }
    }
}

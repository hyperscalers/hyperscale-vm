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

#[blueprint]
pub mod account {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{
        Bucket, Cell, Ids, Keyed, NfBucket, Ordered, Quantity, RoleSet, clock_ms,
    };

    /// Funds left the account.
    #[event]
    struct Withdrawn;

    /// Funds arrived.
    #[event]
    struct Deposited;

    /// What a holdings entry holds: presence, and nothing else. Which
    /// instance it is, is the entry's own order key.
    const HELD: [u8; 1] = [1];

    #[state]
    struct Account {
        #[role(1)]
        vaults: Keyed<Quantity>,
        #[role(2)]
        claims: Keyed<Quantity>,
        /// The stored authority: the cell `authorize` reads and
        /// `securify` creates. Absent for a virtual account.
        #[role(4)]
        auth: Cell<Vec<u8>>,
        /// One sub-collection per resource, its entries the instances
        /// held at their own ids.
        #[role(6)]
        holdings: Ordered<Vec<u8>>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        ///
        /// The grant is the bucket: the kernel judged and held the
        /// reservation against this method's own declaration before the
        /// body ran, so there is no requested amount left to check it
        /// against and no way for the two to differ.
        #[guarded(self)]
        pub fn withdraw(&mut self, resource: Address, amount: Quantity) -> Bucket {
            let funds = self.vaults.at(resource).reserve(amount);
            Withdrawn::emit(&funds.quantity().subunits().to_le_bytes());
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
            self.claims.at(funds.resource()).declared();
            self.vaults.at(funds.resource()).put(funds);
            Deposited::emit(&credited.subunits().to_le_bytes());
        }

        /// Nothing but its own gate: the kernel judges the stored rule
        /// before the export runs, so the body has nothing to say and
        /// the read the gate performs is the gate's to declare.
        #[authorizing(auth)]
        #[allow(clippy::unused_self, clippy::missing_const_for_fn)] // a gate, not a body
        pub fn authorize(&mut self) {}

        /// File the instances the edge carries as holdings entries.
        ///
        /// The filing is the kernel's: each instance lands at the order
        /// it was taken under, so the body names no id at all.
        #[name("deposit-nf")]
        pub fn deposit_nf(&mut self, funds: NfBucket) {
            self.holdings.of(funds.resource()).all(64).put(funds, &HELD);
        }

        /// Take the named instances out of the holdings interval,
        /// trapping on one not held. The removal and the edge are one
        /// operation, so a body cannot hand on what it left where it was.
        #[name("withdraw-nf")]
        #[guarded(self)]
        pub fn withdraw_nf(&mut self, resource: Address, ids: Ids) -> Bucket {
            self.holdings.of(resource).all(64).take(ids)
        }

        /// Nothing but its own gate, like `authorize`: the kernel judges
        /// the holder's rule and the badge-keyed possession reads before
        /// the export runs, and what the call mints is the badge's
        /// address.
        #[name("present-badge")]
        #[custodial(auth, badge)]
        #[allow(clippy::unused_self, clippy::missing_const_for_fn)] // a gate, not a body
        #[allow(unused_variables)] // the badge is the gate's; the body never sees it
        pub fn present_badge(&mut self, badge: Address) {}

        /// Create the stored-authority cell: the caller's roles and
        /// recovery delay, with nothing pending. The cell existing is
        /// this body's own refusal, which is what makes the transition
        /// off the address-derived rule one-way.
        #[guarded(self)]
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn securify(&mut self, roles: RoleSet, delay_ms: u64) {
            // The admission gate decoded the roles under the vocabulary
            // caps; what is left to judge here is the one-way door.
            let stored = self.auth.get();
            assert!(stored.is_empty(), "the account is already securified");
            self.auth.set(frame(&base(roles.bytes(), delay_ms), None));
        }

        /// Append a pending replacement for the whole cell, maturing
        /// after the stored recovery delay; an unmatured proposal is
        /// replaced, a matured one first promoted.
        #[role_gated(recovery)]
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn propose(&mut self, roles: RoleSet, delay_ms: u64) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            // The wait comes from the delay that governs now, never from
            // the proposer: the proposal's own delay only starts
            // governing when the proposal does.
            let current = governing(&stored);
            let wait = u64::from_le_bytes(current[0..8].try_into().unwrap());
            let effective_at_ms = clock_ms().saturating_add(wait);
            let proposed = base(roles.bytes(), delay_ms);
            self.auth
                .set(frame(current, Some((effective_at_ms, &proposed))));
        }

        /// Drop an unmatured proposal; a matured one is promoted instead
        /// — cancelling what already governs would be a rewrite, not a
        /// cancel.
        #[role_gated(primary)]
        pub fn cancel(&mut self) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            self.auth.set(frame(governing(&stored), None));
        }

        /// Promote the pending proposal now, matured or not: early
        /// enactment and compaction are one operation.
        #[role_gated(confirmation)]
        pub fn confirm(&mut self) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            let (_, proposal) = split(&stored);
            let (_, proposed) = proposal.expect("nothing is pending");
            self.auth.set(frame(proposed, None));
        }
    }

    /// One base's frame bytes: the delay, then the opaque role set.
    fn base(roles: &[u8], delay_ms: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + roles.len());
        out.extend_from_slice(&delay_ms.to_le_bytes());
        out.extend_from_slice(roles);
        out
    }

    /// One whole cell from its parts.
    fn frame(base: &[u8], proposal: Option<(u64, &[u8])>) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + base.len());
        out.extend_from_slice(&u32::try_from(base.len()).unwrap().to_le_bytes());
        out.extend_from_slice(base);
        if let Some((effective_at_ms, proposed)) = proposal {
            out.extend_from_slice(&effective_at_ms.to_le_bytes());
            out.extend_from_slice(proposed);
        }
        out
    }

    /// A stored cell split into its base and, if present, its proposal.
    /// Only this package writes the cell, so a frame that does not split
    /// is unreachable and the indexing panic is the trap it deserves.
    fn split(cell: &[u8]) -> (&[u8], Option<(u64, &[u8])>) {
        let base_len = u32::from_le_bytes(cell[0..4].try_into().unwrap()) as usize;
        let base = &cell[4..4 + base_len];
        let tail = &cell[4 + base_len..];
        let proposal = if tail.is_empty() {
            None
        } else {
            let effective_at_ms = u64::from_le_bytes(tail[0..8].try_into().unwrap());
            Some((effective_at_ms, &tail[8..]))
        };
        (base, proposal)
    }

    /// The base that governs now: the proposal's once its instant has
    /// arrived, the stored one until then. The write-side twin of the
    /// gate's own comparison — promoting here is compaction of what reads
    /// already answer, never a change of verdict.
    fn governing(cell: &[u8]) -> &[u8] {
        let (base, proposal) = split(cell);
        match proposal {
            Some((effective_at_ms, proposed)) if effective_at_ms <= clock_ms() => proposed,
            _ => base,
        }
    }
}

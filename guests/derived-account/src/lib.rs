//! The fungible account, as one module: the funds pair and the authority
//! surface every principal answers.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod account {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Cell, Keyed, RoleSet};

    /// Funds left the account.
    #[event]
    struct Withdrawn;

    /// Funds arrived.
    #[event]
    struct Deposited;

    #[state]
    struct Account {
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(2)]
        claims: Keyed<Amount>,
        #[role(4)]
        auth: Cell<Vec<u8>>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        #[guarded(self)]
        pub fn withdraw(&mut self, resource: Address, amount: u128) -> Bucket {
            self.vaults.at(resource).reserve(amount)
        }

        /// Credit the vault and the guaranteed-delivery cell beside it.
        pub fn deposit(&mut self, funds: Bucket) {
            let resource = funds.resource();
            self.vaults.at(resource).put(funds);
            self.claims.at(resource).declared();
        }

        /// Nothing but its own gate: the kernel judges the stored rule
        /// before the export runs, so the body has nothing to say and
        /// the read the gate performs is the gate's to declare.
        #[authorizing(auth)]
        #[allow(clippy::unused_self, clippy::missing_const_for_fn)] // a gate, not a body
        pub fn authorize(&mut self) {}

        /// Create the stored-authority cell; an existing one is the
        /// body's own refusal, which is what makes the transition off
        /// the address-derived rule one-way.
        #[guarded(self)]
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn securify(&mut self, roles: RoleSet, delay_ms: u64) {
            let stored = self.auth.get();
            assert!(stored.is_empty(), "the account is already securified");
            let mut cell = roles.bytes().to_vec();
            cell.extend_from_slice(&delay_ms.to_le_bytes());
            self.auth.set(cell);
        }

        /// Append a pending replacement for the whole cell.
        #[role_gated(recovery)]
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn propose(&mut self, roles: RoleSet, delay_ms: u64) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            let mut cell = roles.bytes().to_vec();
            cell.extend_from_slice(&delay_ms.to_le_bytes());
            self.auth.set(cell);
        }

        /// Drop an unmatured proposal.
        #[role_gated(primary)]
        pub fn cancel(&mut self) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            self.auth.set(stored);
        }

        /// Promote the pending proposal now.
        #[role_gated(confirmation)]
        pub fn confirm(&mut self) {
            let stored = self.auth.get();
            assert!(!stored.is_empty(), "the account is not securified");
            self.auth.set(stored);
        }
    }
}

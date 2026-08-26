//! A component that holds other people's value and cooperates with
//! nothing.
//!
//! Written hostile rather than naive. Every method here is one a real
//! lending pool, order book or escrow already has — twenty lines nobody
//! has to be talked into writing — and none of them declares a rule, a
//! halt leaf, or anything else an issuer could hold them to. There is no
//! method a governance action could call to make this component behave,
//! because a component that offered one would not be the case worth
//! testing.
//!
//! What it exists to establish is that binding value held here takes
//! nothing from its author. A holder-side fence reaches an account and
//! stops at the first deposit into any application, so a design that
//! only fenced accounts would leave every one of these methods open. The
//! requirement is admission's, resolved against the vault's own owner,
//! so this package is bound by declaring exactly what it wanted to
//! declare anyway.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod custodian {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Ids, NfBucket, Quantity};

    /// Which resources this custodian keeps, fixed at creation.
    #[config]
    struct Terms {
        /// The asset it takes in and pays out.
        asset: ResourceAddr,
        /// A second asset, so value can move between two of its own
        /// vaults with no account anywhere in the transaction.
        other: ResourceAddr,
        /// A non-fungible it also custodies.
        instances: ResourceAddr,
    }

    impl Custodian {
        /// Take value in and hold it. No gate, no rule, nothing declared
        /// about who may.
        pub fn deposit(&mut self, funds: Bucket) {
            self.vault(self.config().asset).put(funds);
        }

        /// Hand value back out to whoever asked. This is the method a
        /// holder-side fence cannot reach: it declares no halt leaf and
        /// there is no way to make it declare one.
        pub fn withdraw(&mut self, amount: Quantity) -> Bucket {
            self.vault(self.config().asset).take(amount)
        }

        /// An exchange across its own two vaults: one credited, one
        /// debited, in a transaction no account is a party to.
        ///
        /// The case that matters because the requirement is resolved
        /// against the *access owner* rather than against whoever
        /// signed. Both vaults are this component's, so both movements
        /// are judged against what this component holds — and a design
        /// that looked at the caller would find a stranger and bind
        /// nothing.
        pub fn swap(&mut self, incoming: Bucket, amount: Quantity) -> Bucket {
            self.vault(self.config().asset).put(incoming);
            self.vault(self.config().other).take(amount)
        }

        /// Instances in, on the same terms: an interval admits a read
        /// and a write and says nothing about which way value went.
        ///
        /// Keyed on the configured resource rather than on whatever the
        /// edge carries, exactly as the fungible half is — a collection
        /// is keyed by what it holds, so filing under the edge's own
        /// resource would open a collection nothing takes from, and what
        /// went into it could never come out. An edge of any other
        /// resource traps at the write instead.
        pub fn file(&mut self, instances: NfBucket) {
            self.holdings(self.config().instances).all().file(instances);
        }

        /// And instances back out, from the one collection `file` fills.
        pub fn release(&mut self, ids: Ids) -> NfBucket {
            self.holdings(self.config().instances).all().take(ids)
        }
    }
}

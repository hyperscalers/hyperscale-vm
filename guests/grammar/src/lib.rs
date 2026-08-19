//! The shapes a contract body may take, as a package that has to execute
//! them.
//!
//! What a body *declares* is settled on a host build, where nothing runs.
//! That says nothing about whether the emission has a rewriting for it,
//! because that only shows up when the guest half is compiled — and a
//! shape the declaration admits but the emission cannot write is a
//! package that traces cleanly and will not build.
//!
//! So this crate is the emission's side of the same question: every shape
//! below is here because it is one the grammar admits, and the check is
//! that `cargo hyperscale` gets an artifact out of it.

use hyperscale_vm_sdk::blueprint;

#[blueprint]
pub mod grammar {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Ids, Keyed, Ordered, Quantity, Vault, pack};

    #[state]
    struct Grammar {
        entries: Ordered<Quantity>,
    }

    impl Grammar {
        /// A loop over a computed list, ending the body. Both halves
        /// matter: the loop is not a `for-each` because what it ranges
        /// over is not a term, and it is not a returned value because the
        /// method yields nothing however the tail is spelled.
        pub fn file(&mut self, ids: Ids) {
            let mut held = self.entries.range(pack(0, 0), pack(u64::MAX, u64::MAX), 64);
            for id in ids.named().iter().copied() {
                held.insert(u128::from(id), Quantity::from_subunits(1));
            }
        }

        /// A `while` walking an interval by index, and a conditional in
        /// tail position — the other two ways a unit body ends.
        pub fn sweep(&mut self, holder: Address) {
            let mut held = self.entries.range(pack(0, 0), pack(u64::MAX, u64::MAX), 64);
            let vault = self.vault(holder);
            let mut index = 0;
            let mut total = vault.balance();
            while index < held.count() {
                total += held.entry(index);
                index += 1;
            }
            if !total.is_zero() {
                held.set(0, total);
            }
        }

        /// A branch the declaration can read, over a cell the code around
        /// it also reaches.
        ///
        /// The guard is a fact about the collection rather than about the
        /// line that first named it, so the clause is declared always and
        /// the guest takes no verdict — it branches on the condition it
        /// wrote. What the emission has to get right is that the handle
        /// is there on both arms: a body writing an entry conditionally
        /// and another unconditionally reaches one handle twice.
        pub fn settle(&mut self, seed: u64) {
            if seed == 1 {
                self.entries
                    .range(pack(0, 0), pack(u64::MAX, u64::MAX), 64)
                    .insert(1, Quantity::from_subunits(1));
            }
            self.entries
                .range(pack(0, 0), pack(u64::MAX, u64::MAX), 64)
                .insert(2, Quantity::from_subunits(2));
        }

        /// A branch whose arm alone declares its clause, so the export
        /// takes the declaration's verdict as a `bool` and the guest
        /// branches on that rather than on a second copy of the
        /// condition. The guarded shape `settle` deliberately avoids:
        /// nothing outside the arm reaches the handle, so the clause is
        /// conditional and the verdict crosses the boundary.
        pub fn stash(&mut self, seed: u64) {
            if seed == 1 {
                self.entries
                    .range(pack(0, 0), pack(u64::MAX, u64::MAX), 64)
                    .insert(3, Quantity::from_subunits(3));
            }
        }

        /// A produced edge out of a conditional body, so the value path
        /// is exercised beside the statement ones.
        pub fn take(&mut self, resource: Address, amount: Quantity) -> Bucket {
            self.vault(resource).reserve(amount)
        }
    }
}

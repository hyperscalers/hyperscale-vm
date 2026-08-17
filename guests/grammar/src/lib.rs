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
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Ordered, Quantity, pack};

    /// The ids a count-prefixed edge cell carries.
    fn cell_ids(cell: &[u8]) -> Vec<u64> {
        let (&count, ids) = cell.split_first().expect("an id cell has a count");
        assert!(ids.len() == usize::from(count) * 8, "malformed id cell");
        ids.chunks_exact(8)
            .map(|id| u64::from_le_bytes(id.try_into().unwrap()))
            .collect()
    }

    #[state]
    struct Grammar {
        #[role(1)]
        vaults: Keyed<Quantity>,
        #[role(5)]
        holdings: Ordered<Quantity>,
    }

    impl Grammar {
        /// A loop over a computed list, ending the body. Both halves
        /// matter: the loop is not a `for-each` because what it ranges
        /// over is not a term, and it is not a returned value because the
        /// method yields nothing however the tail is spelled.
        pub fn file(&mut self, ids: Vec<u8>) {
            let mut held = self.holdings.range(pack(0, 0), pack(u64::MAX, u64::MAX), 64);
            for id in cell_ids(&ids) {
                held.insert(u128::from(id), Quantity::from_subunits(1));
            }
        }

        /// A `while` walking an interval by index, and a conditional in
        /// tail position — the other two ways a unit body ends.
        pub fn sweep(&mut self, holder: Address) {
            let mut held = self.holdings.range(pack(0, 0), pack(u64::MAX, u64::MAX), 64);
            let vault = self.vaults.at(holder);
            let mut index = 0;
            let mut total = vault.get();
            while index < held.count() {
                total += held.entry(index);
                index += 1;
            }
            if !total.is_zero() {
                held.set(0, total);
            }
        }

        /// A produced edge out of a conditional body, so the value path
        /// is exercised beside the statement ones.
        pub fn take(&mut self, resource: Address, amount: Quantity) -> Bucket {
            self.vaults.at(resource).reserve(amount)
        }
    }
}

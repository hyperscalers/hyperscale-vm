//! What a stored struct may name, and where the width bound applies.
//!
//! A cell is written through an allocating encode whatever it holds, so
//! a record that never reaches an emit is held to what the encoding
//! carries and not to what a buffer on the stack could. The bound the
//! emit path does need travels with the payload — an event, and every
//! declaration one names — which is checked as a refusal beside the
//! lowering's others.

use hyperscale_vm_effects::{PACKAGE_SLOT_BASE, SlotId, TestHasher, child_key};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::hbor::to_vec;
use hyperscale_vm_testing::{Chain, PrincipalAddr, package, principal};

const CALLER: PrincipalAddr = principal(0x71);

#[blueprint]
mod ledger {
    use hyperscale_vm_sdk::state::Cell;

    /// A record no event names, so its fields are the encoding's to
    /// carry rather than a stack buffer's to hold.
    #[record]
    struct Entry {
        memo: Vec<u8>,
        amount: u64,
    }

    #[state]
    struct Ledger {
        latest: Cell<Option<Entry>>,
    }

    impl Ledger {
        /// File an entry whose width the caller chose.
        pub fn file(&mut self, memo: Vec<u8>, amount: u64) {
            self.latest.set(Some(Entry { memo, amount }));
        }
    }
}

/// A record the emit path never reaches carries a caller-sized field,
/// and its cell holds the encoding of what was filed.
#[test]
fn a_record_no_event_names_carries_a_length() {
    let mut chain = Chain::native();
    chain.publish(package!(ledger));
    let ledger = chain.instantiate::<ledger::client::Ledger>(());

    let memo = vec![0xAB; 300];
    chain
        .transact(CALLER, |b| ledger.file(b, memo.clone(), 7))
        .expect_completed();

    assert_eq!(
        chain.cell(child_key(
            &TestHasher,
            ledger,
            SlotId(PACKAGE_SLOT_BASE),
            &[]
        )),
        Some(to_vec(&ledger::Entry { memo, amount: 7 }).expect("the record encodes")),
        "the cell holds the record's own encoding, at whatever width it came to",
    );
}

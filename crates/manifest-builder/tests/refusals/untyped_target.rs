//! An address whose class was forgotten is not a target: whether it
//! answers calls is exactly what the forgotten class said.

use hyperscale_vm_effects::{Address, AddressClass};
use hyperscale_vm_manifest_builder::GraphBuilder;

const SOMEBODY: Address = Address::new([0x10; 31], AddressClass::Principal);

fn main() {
    let mut b = GraphBuilder::new();
    let [] = b.call(SOMEBODY, "deposit", ());
    let _ = b.build();
}

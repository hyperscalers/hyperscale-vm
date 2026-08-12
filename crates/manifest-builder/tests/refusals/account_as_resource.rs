//! An account holds resources; it is not one. Constraining an edge to
//! carry "an account" is the misaddressing the classes exist to catch.

use hyperscale_vm_effects::{PrincipalAddr, ResourceAddr};
use hyperscale_vm_manifest_builder::GraphBuilder;

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);

fn main() {
    let mut b = GraphBuilder::new();
    let [funds] = b.call(ALICE, "withdraw", (RES, 100u128));
    let [] = b.call(BOB, "deposit", (funds.resource_is(ALICE),));
    let _ = b.build();
}

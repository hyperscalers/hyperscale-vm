//! A package address names code, which answers no calls.

use hyperscale_vm_types::PackageAddr;
use hyperscale_vm_manifest_builder::GraphBuilder;

const CODE: PackageAddr = PackageAddr::new([0x30; 31]);

fn main() {
    let mut b = GraphBuilder::new();
    let [] = b.call(CODE, "withdraw", ());
    let _ = b.build();
}

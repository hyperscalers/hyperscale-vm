//! Print this package's declaration as its canonical section bytes.
//! `cargo hyperscale build` runs this and attaches what it prints to the
//! code beside it.

use std::io::Write as _;

fn main() {
    let metadata = derived_account::account::blueprint().metadata();
    let bytes = hyperscale_vm_sdk::encode_metadata(&metadata).expect("a traced declaration encodes");
    std::io::stdout()
        .write_all(&bytes)
        .expect("write the declaration");
}

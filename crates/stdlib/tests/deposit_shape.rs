//! The genesis vault deposits, by name.
//!
//! What an owed crossing's consumer fold stands on. The kernel performs a
//! vault deposit and the fold credits the consumer's vault from the
//! record, so the account's `deposit` has to keep the shape — a genesis
//! deposit of any other would be run by its body locally and credited by
//! the fold when owed, two different credits for one call. And a genesis
//! method gaining the shape is one more method no body runs for, which
//! deserves a reviewer's eye rather than arriving unnoticed.

use hyperscale_vm_stdlib::{account, staking};

#[test]
fn the_genesis_vault_deposits_are_the_accounts_deposit() {
    let mut deposits: Vec<String> = Vec::new();
    for (name, metadata) in [
        ("account", account::metadata()),
        ("staking", staking::metadata()),
    ] {
        for (method, signature) in &metadata.methods {
            if signature.is_vault_deposit() {
                deposits.push(format!("{name}::{method}"));
            }
        }
    }
    assert_eq!(deposits, ["account::deposit"]);
}

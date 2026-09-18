//! The account's rule-bearing slots, at the widths their elements derive.
//!
//! These three figures were written beside the fields once, with the
//! arithmetic explained in prose above each: the argument cap, the length
//! a byte string encodes behind itself, and a proposal's widest arm. They
//! are now read off the types, and what makes that safe to have done is
//! that the derivation lands on the same numbers.
//!
//! Kept afterwards because they are protocol figures rather than an
//! implementation detail. A rule cell that stopped fitting the widest
//! rule an account can be handed is an account whose owner cannot replace
//! its own gate, and nothing else in the workspace would say so.

use hyperscale_vm_stdlib::account;

/// The widest byte argument a rule can arrive as, and the two bytes of
/// length its cell writes in front of it.
const RULE: u32 = 4098;

/// A proposal: two words, a byte for which arm, and the wider arm — three
/// rules at the argument cap behind their lengths, and the tag on the
/// optional one.
const PROPOSAL: u32 = 12312;

#[test]
fn the_accounts_rule_cells_derive_the_widths_they_once_declared() {
    let metadata = account::metadata();
    let width = |name: &str| {
        metadata
            .state
            .values()
            .find(|slot| slot.name == name)
            .unwrap_or_else(|| panic!("the account declares `{name}`"))
            .width
    };
    assert_eq!(width("recovery"), RULE);
    assert_eq!(width("veto"), RULE);
    assert_eq!(width("proposal"), PROPOSAL);
}

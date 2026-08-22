//! What a body declares, held to what a differently-spelled body does.
//!
//! A value crossing to the guest is the ABI's business and never the
//! declaration's: what a caller routes on is the cells a method reaches,
//! and how the body came by a number it writes there changes nothing
//! about them. Two spellings that reach one cell therefore declare one
//! thing, and the place they may differ is the binding.

use hyperscale_vm_effects::AbiParam;
use hyperscale_vm_fixtures::grammar;

#[test]
fn a_bare_lookup_declares_what_the_guarded_spelling_does() {
    // The guarded spelling exists so a miss answers rather than refuses,
    // which is a fact about the value and not about the leaf: `charge`
    // reads the table outright and `charge-or` reads it under the
    // question a miss answers, and both write the same cell.
    let metadata = grammar::metadata();
    let bare = &metadata.methods["charge"];
    let guarded = &metadata.methods["charge-or"];

    assert_eq!(
        bare.effects, guarded.effects,
        "the same cell, however the value reaching it was chosen",
    );

    // And the binding is where they part: one lookup against a selection
    // over the same table.
    assert!(
        matches!(bare.abi.last(), Some(AbiParam::Derived(_)))
            && bare.abi.last() != guarded.abi.last(),
        "the value is the ABI's business: {:?} against {:?}",
        bare.abi,
        guarded.abi,
    );
}

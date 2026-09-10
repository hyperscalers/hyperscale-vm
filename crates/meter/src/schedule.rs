//! The schedule: what each operator costs.
//!
//! Stated here in the pass's own vocabulary, and stated a second time in
//! the reference interpreter's, sharing no constant with it; a harness
//! lane decodes an instrumented module and holds every block's charge to
//! the interpreter's sum over the same operators. Moving a price is an
//! edit to this file, visible in review, and never something an engine
//! upgrade carries in.

use wasmparser::Operator;

/// What an operator costs when the work it stands for is fixed.
pub const FLAT: u64 = 1;

/// What an operator costs when it lowers to no code of its own: `nop`,
/// `drop`, and the pure control structure, none of which survive
/// translation as anything a machine executes.
pub const FREE: u64 = 0;

/// The price of one operator.
///
/// The bulk memory operators are priced here at [`FLAT`] for the
/// instruction itself; the bytes they move are charged at run time, one
/// per byte, by the check the pass emits in front of them.
#[must_use]
pub const fn cost(op: &Operator<'_>) -> u64 {
    match op {
        Operator::Block { .. }
        | Operator::Loop { .. }
        | Operator::Else
        | Operator::End
        | Operator::Nop
        | Operator::Drop
        | Operator::Return
        | Operator::Unreachable => FREE,
        _ => FLAT,
    }
}

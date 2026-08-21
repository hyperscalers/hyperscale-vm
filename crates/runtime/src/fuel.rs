//! The canonical fuel schedule.
//!
//! Fuel is a receipt field, so what an operator costs is protocol rather
//! than an engine implementation detail. The table here states the
//! schedule and [`crate::engine::blessed_config`] configures the engine
//! from it, so moving a price is an edit to this file — visible in review
//! — and never something an engine upgrade can carry in unannounced.
//!
//! vm-ref states the same schedule independently, in its own operator
//! vocabulary, and shares no constant with this table. The harness holds
//! the two against each other, so a wrong entry here fails a test instead
//! of pricing a receipt.

use wasmtime::{OperatorCost, VariableOperatorCost};

/// What an operator costs when the work it stands for is fixed.
pub const FLAT: u8 = 1;

/// What an operator costs when it lowers to no code of its own: `nop`,
/// `drop`, and the pure control structure, none of which survive
/// translation as anything a machine executes.
pub const FREE: u8 = 0;

/// The operators priced at [`FREE`]; every other operator costs [`FLAT`].
pub const FREE_OPERATORS: &[&str] = &[
    "Block",
    "Drop",
    "Else",
    "End",
    "Loop",
    "Nop",
    "Return",
    "Unreachable",
];

/// The canonical operator cost table.
#[must_use]
pub const fn blessed_operator_cost() -> OperatorCost {
    OperatorCost {
        variable: blessed_variable_cost(),
        ..OperatorCost::new()
    }
}

/// Prices for the operators whose work is a runtime operand rather than a
/// property of the instruction, charged on top of the flat cost.
///
/// Only the memory entries are reachable: the profile admits `memory.copy`,
/// `memory.fill`, and `memory.grow` and rejects every table and array
/// operator at the deploy validator, so the rest price work no admitted
/// module can ask for.
///
/// `memory.grow` prices at nothing per page only because
/// [`crate::engine::blessed_config`] reserves
/// [`MAX_MEMORY_PAGES`](crate::profile::MAX_MEMORY_PAGES) up front: a grow
/// moves a bound inside a mapping that already exists, and the pages it
/// admits arrive zeroed from the host, so the work is constant and the
/// stores that reach those pages are what carry the cost. A reservation
/// below the profile's ceiling would make a grow map, and this price would
/// have to move with it.
const fn blessed_variable_cost() -> VariableOperatorCost {
    VariableOperatorCost {
        memory_copy_per_byte: 1,
        memory_fill_per_byte: 1,
        memory_init_per_byte: 1,
        memory_grow_per_page: 0,

        table_copy_per_element: 1,
        table_fill_per_element: 1,
        table_init_per_element: 1,
        table_grow_per_element: 1,

        array_copy_per_element: 1,
        array_fill_per_element: 1,
        array_new_data_per_element: 1,
        array_init_data_per_element: 1,
        array_new_elem_per_element: 1,
        array_init_elem_per_element: 1,
        array_new_default_per_element: 1,
        array_new_per_element: 1,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::to_value;

    use super::{FLAT, FREE, FREE_OPERATORS, blessed_operator_cost};

    /// Every operator in the table is priced by the schedule's own rule.
    ///
    /// The sweep is what makes the table canonical rather than inherited:
    /// it reads every field the engine's operator set defines, so a price
    /// that moves underneath us fails here, naming the operator, instead
    /// of reaching a receipt.
    #[test]
    fn the_schedule_prices_every_operator_by_its_own_rule() {
        let table = to_value(blessed_operator_cost()).expect("the table serializes");
        let fields = table.as_object().expect("the table is a struct");

        let mut operators = 0;
        for (name, price) in fields {
            if name == "variable" {
                continue;
            }
            operators += 1;
            let price = price.as_u64().expect("an operator price is a number");
            let expected = u64::from(if FREE_OPERATORS.contains(&name.as_str()) {
                FREE
            } else {
                FLAT
            });
            assert_eq!(
                price, expected,
                "{name} is priced at {price}, not {expected}"
            );
        }

        assert!(
            operators > 100,
            "the table covers {operators} operators, too few to be the whole set"
        );
    }

    /// Every operator the schedule prices at [`FREE`] exists in the table.
    ///
    /// Without this the sweep above stays green when an entry in
    /// [`FREE_OPERATORS`] is misspelled or an operator is renamed: the
    /// name would simply never match, and the operator would quietly
    /// price at [`FLAT`].
    #[test]
    fn every_free_operator_is_one_the_table_defines() {
        let table = to_value(blessed_operator_cost()).expect("the table serializes");
        let fields = table.as_object().expect("the table is a struct");

        for name in FREE_OPERATORS {
            assert!(
                fields.contains_key(*name),
                "{name} is priced free but is not an operator the table defines"
            );
        }
    }
}

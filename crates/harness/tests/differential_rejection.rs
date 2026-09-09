//! Identical rejection: profile *feature-class* violations must be refused
//! by both implementations — the validator rejects them at deploy, and the
//! reference interpreter cannot represent them at decode (defense in
//! depth). One set of bytes faces both, so the refusals are of the same
//! module rather than of two renderings of it.
//!
//! Structural limits (sizes, counts) are deliberately validator-only
//! policy: the interpreter executes any validated shape, so those fixtures
//! make no vm-ref claim.

use hyperscale_vm_ref::RefModule;
use hyperscale_vm_runtime::validate_core_module;
use wat::parse_str;

/// Feature-class fixtures: (name, module body).
const FEATURE_FIXTURES: [(&str, &str); 8] = [
    (
        "floats",
        "(func (param f64) (result f64) local.get 0 local.get 0 f64.add)",
    ),
    ("simd", "(func (result v128) v128.const i64x2 0 0)"),
    ("shared_memory", "(memory 1 1 shared)"),
    ("tail_call", "(func $a) (func return_call $a)"),
    ("multi_memory", "(memory 1 1) (memory 1 1)"),
    ("two_tables", "(table 1 1 funcref) (table 1 1 funcref)"),
    (
        "extended_const",
        "(global i32 (i32.add (i32.const 1) (i32.const 2)))",
    ),
    (
        "table_copy",
        "(table 1 1 funcref) \
         (func i32.const 0 i32.const 0 i32.const 0 table.copy)",
    ),
];

#[test]
fn feature_violations_are_rejected_by_both_implementations() {
    for (name, body) in FEATURE_FIXTURES {
        let module = parse_str(format!("(module {body})")).expect("fixture must parse");
        validate_core_module(&module).expect_err(&format!("validator must reject {name}"));
        RefModule::decode(&module).expect_err(&format!("vm-ref must reject {name}"));
    }
}

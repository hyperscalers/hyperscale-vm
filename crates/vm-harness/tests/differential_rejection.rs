//! Identical rejection: profile *feature-class* violations must be refused by
//! both implementations — the validator rejects them at deploy, and the
//! reference interpreter cannot represent them at decode (defense in depth).
//!
//! Structural limits (sizes, counts) are deliberately validator-only policy:
//! the interpreter executes any validated shape, so those fixtures make no
//! vm-ref claim.

use hyperscale_vm_ref::RefModule;
use hyperscale_vm_runtime::validate_component;
use wat::parse_str;

/// Feature-class fixtures: (name, core module body).
const FEATURE_FIXTURES: [(&str, &str); 4] = [
    (
        "floats",
        "(func (param f64) (result f64) local.get 0 local.get 0 f64.add)",
    ),
    ("simd", "(func (result v128) v128.const i64x2 0 0)"),
    ("shared_memory", "(memory 1 1 shared)"),
    ("tail_call", "(func $a) (func return_call $a)"),
];

#[test]
fn feature_violations_are_rejected_by_both_implementations() {
    for (name, core) in FEATURE_FIXTURES {
        let component =
            parse_str(format!("(component (core module {core}))")).expect("fixture must parse");
        validate_component(&component).expect_err(&format!("validator must reject {name}"));

        let module = parse_str(format!("(module {core})")).expect("fixture must parse");
        RefModule::decode(&module).expect_err(&format!("vm-ref must reject {name}"));
    }
}

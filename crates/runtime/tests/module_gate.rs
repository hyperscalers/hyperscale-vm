//! The core-module gate: what `validate_module` admits and refuses, and
//! how `module_exports` reads what it admits.

mod common;

use common::{every_import, import_wat, module};
use hyperscale_vm_embed::abi::{CoreType, STATE};
use hyperscale_vm_runtime::{ModuleExport, ProfileError, module_exports, validate_module};
use wat::parse_str;

fn refused(wat: &str) -> ProfileError {
    let bytes = parse_str(wat).expect("the fixture parses");
    validate_module(&bytes).expect_err("the fixture is refused")
}

fn boundary(wat: &str) -> String {
    match refused(wat) {
        ProfileError::Boundary(reason) => reason,
        other => panic!("refused for another reason: {other}"),
    }
}

/// A module that imports the whole kernel at the kernel's own types,
/// exports its memory, and exports methods of every admitted shape.
#[test]
fn a_conforming_module_is_admitted_and_its_exports_read() {
    let wat = module(
        r#"
  (func (export "silent") (param i32 i32) i32.const 0 i32.const 0 call $reply)
  (func (export "scalar") (param i64) (result i32) i32.const 0)
  (func (export "nothing"))"#,
    );
    let bytes = parse_str(&wat).expect("parses");
    validate_module(&bytes).expect("admitted");
    let exports = module_exports(&bytes).expect("reads");
    assert_eq!(
        exports.get("silent"),
        Some(&ModuleExport {
            params: vec![CoreType::I32, CoreType::I32],
            declines: false,
        })
    );
    assert_eq!(
        exports.get("scalar"),
        Some(&ModuleExport {
            params: vec![CoreType::I64],
            declines: true,
        })
    );
    assert_eq!(
        exports.get("nothing"),
        Some(&ModuleExport {
            params: vec![],
            declines: false,
        })
    );
    assert_eq!(exports.len(), 3, "the memory is not an export shape");
}

/// An import the kernel does not define is outside the kernel table, whatever
/// its module; one the kernel defines at another type is refused by
/// name.
#[test]
fn imports_are_held_to_the_kernel_table() {
    let unknown_module = "(module\n  (import \"wasi:io/streams\" \"read\" (func))\n  \
         (memory (export \"memory\") 1 1))";
    assert!(matches!(
        refused(unknown_module),
        ProfileError::ForbiddenImport(name) if name == "wasi:io/streams/read"
    ));

    let unknown_name = format!(
        "(module\n  (import \"{STATE}\" \"site_forget\" (func (param i32)))\n  \
         (memory (export \"memory\") 1 1))"
    );
    assert!(matches!(
        refused(&unknown_name),
        ProfileError::ForbiddenImport(name) if name == format!("{STATE}/site_forget")
    ));

    let retyped = format!(
        "(module\n  (import \"{STATE}\" \"site_get\" (func (param i32 i32) (result i64)))\n  \
         (memory (export \"memory\") 1 1))"
    );
    assert!(boundary(&retyped).contains("site_get"));

    let extra_param = format!(
        "(module\n  (import \"{STATE}\" \"site_len\" (func (param i32 i32) (result i32)))\n  \
         (memory (export \"memory\") 1 1))"
    );
    assert!(boundary(&extra_param).contains("site_len"));

    let not_a_function = format!(
        "(module\n  (import \"{STATE}\" \"table\" (table 1 1 funcref))\n  \
         (memory (export \"memory\") 1 1))"
    );
    assert!(boundary(&not_a_function).contains("nothing but functions"));

    let one_import = format!(
        "(module\n{}  (memory (export \"memory\") 1 1))",
        import_wat(STATE, "site_len", &[CoreType::I32], &[CoreType::I32])
    );
    validate_module(&parse_str(one_import).expect("parses")).expect("a subset is admitted");
}

/// The kernel reads one memory, by name, and nothing else but methods.
#[test]
fn exports_are_one_memory_and_methods() {
    assert!(boundary("(module (func (export \"f\")))").contains("0 memories"));
    assert!(boundary("(module (memory (export \"mem\") 1 1))").contains("`mem`"));
    assert!(
        boundary(
            "(module (memory (export \"memory\") 1 1) (global (export \"g\") i32 (i32.const 0)))"
        )
        .contains("Global")
    );
    assert!(
        boundary("(module (memory (export \"memory\") 1 1) (table (export \"t\") 1 1 funcref))")
            .contains("Table")
    );
    assert!(
        boundary(
            "(module (memory (export \"memory\") 1 1) (func (export \"f\") (result i64) i64.const 0))"
        )
        .contains("returns"),
    );
    assert!(
        boundary(
            "(module (memory (export \"memory\") 1 1) \
             (func (export \"f\") (result i32 i32) i32.const 0 i32.const 0))"
        )
        .contains("returns"),
    );
    let re_export = format!(
        "(module\n{}  (memory (export \"memory\") 1 1)\n  (export \"clock\" (func $clock)))",
        every_import()
    );
    assert!(boundary(&re_export).contains("re-exports"));
}

/// What the profile refuses of a bare module, it still refuses: a
/// start section, a float, and a memory without a maximum.
#[test]
fn the_profile_still_holds() {
    assert!(matches!(
        refused("(module (memory (export \"memory\") 1 1) (func $s) (start $s))"),
        ProfileError::StartSection
    ));
    assert!(matches!(
        refused("(module (memory (export \"memory\") 1 1) (func (export \"f\") (param f32)))"),
        ProfileError::Feature(_)
    ));
    assert!(matches!(
        refused("(module (memory (export \"memory\") 1))"),
        ProfileError::Structural(_)
    ));
    assert!(matches!(
        refused("(module (memory (export \"memory\") 1 1) (func $r (export \"r\") call $r))"),
        ProfileError::Structural(_)
    ));
}

/// The chain budget is the whole reserve: one chain stands at a time,
/// so frames as heavy as the locals limit allows chain until the reserve
/// itself runs out.
#[test]
fn the_chain_budget_is_the_whole_reserve() {
    use std::fmt::Write as _;

    use hyperscale_vm_runtime::profile::{
        HOST_FRAME_RESERVE_BYTES, MAX_CALL_CHAIN_BYTES, MAX_LOCALS_PER_FUNCTION,
        MAX_WASM_STACK_BYTES, STACK_BYTES_PER_SLOT, STACK_FRAME_OVERHEAD_BYTES,
    };
    assert_eq!(
        MAX_CALL_CHAIN_BYTES,
        MAX_WASM_STACK_BYTES - HOST_FRAME_RESERVE_BYTES
    );
    let frame = MAX_LOCALS_PER_FUNCTION * STACK_BYTES_PER_SLOT + STACK_FRAME_OVERHEAD_BYTES;
    let chain = |depth: usize| {
        let locals = format!("(local {})", "i32 ".repeat(MAX_LOCALS_PER_FUNCTION));
        let mut wat = String::from("(module (memory (export \"memory\") 1 1)\n");
        for index in 0..depth {
            let callee = if index + 1 < depth {
                format!(" call $f{}", index + 1)
            } else {
                String::new()
            };
            let export = if index == 0 { " (export \"run\")" } else { "" };
            let _ = writeln!(wat, "  (func $f{index}{export} {locals}{callee})");
        }
        wat.push(')');
        parse_str(&wat).expect("parses")
    };
    // The deepest chain of such frames that fits, and one more.
    let fits = MAX_CALL_CHAIN_BYTES / frame;
    validate_module(&chain(fits)).expect("the chain fits the whole reserve");
    assert!(matches!(
        validate_module(&chain(fits + 1)),
        Err(ProfileError::Structural(reason)) if reason.contains("call chain")
    ));
}

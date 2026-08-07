//! The export-parameter shapes an ABI binding is judged against.

use hyperscale_vm_runtime::{ExportParam, component_export_params};
use wat::parse_str;

#[test]
fn every_world_shape_classifies_and_nested_exports_stay_invisible() {
    let bytes = parse_str(
        r#"(component
             (import "hyperscale:kernel/state" (instance $state
               (export "reserve-cell" (type $rc (sub resource)))
               (export "delta-cell" (type $dc (sub resource)))))
             (alias export $state "reserve-cell" (type $reserve))
             (alias export $state "delta-cell" (type $delta))

             (core module $m
               (func (export "withdraw") (param i32 i32 i32) (result i32)
                 i32.const 0)
               (func (export "tick") (param i64) (result i64)
                 local.get 0)
               (memory (export "mem") 1 1)
               (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                 i32.const 1024))
             (core instance $i (instantiate $m))

             (func (export "withdraw")
               (param "vault" (borrow $reserve)) (param "amount" (list u8))
               (result (list u8))
               (canon lift (core func $i "withdraw")
                 (memory $i "mem") (realloc (func $i "realloc"))))
             (func (export "tick") (param "clock" u64) (result u64)
               (canon lift (core func $i "tick"))))"#,
    )
    .expect("fixture must parse");

    let params = component_export_params(&bytes).expect("the fixture validates");
    assert_eq!(
        params["withdraw"],
        vec![
            ExportParam::Handle("reserve-cell".to_string()),
            ExportParam::Bytes,
        ],
    );
    assert_eq!(params["tick"], vec![ExportParam::U64]);
    assert_eq!(params.len(), 2, "only function exports classify");
}

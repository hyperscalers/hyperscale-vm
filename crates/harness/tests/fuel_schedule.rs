//! The schedule, stated twice.
//!
//! The blessed engine is configured from a canonical operator cost table;
//! vm-ref states the same schedule independently, in its own operator
//! vocabulary, sharing no constant with it. Two statements of one intent
//! are only worth having if something holds them together, and that is
//! this lane: every operator the profile admits is priced from both sides
//! and the two prices must agree.
//!
//! The differential fuel lane checks the other half — that the two charge
//! at the same points and in the same counts. Together they pin the whole
//! schedule: the prices here, the accounting there.

use hyperscale_vm_ref::{fuel_cost, translate};
use hyperscale_vm_runtime::blessed_operator_cost;
use wasmparser::{Operator, Parser, Payload};
use wat::parse_str;

/// Every operator the deterministic profile admits, in one module.
///
/// Blocks carry no type: block arity is not something the schedule prices,
/// so an empty block type keeps the fixture readable without narrowing
/// what it covers.
const EVERY_OPERATOR: &str = r"(module
  (type $void (func))
  (table 1 1 funcref)
  (memory 1)
  (global $g (mut i32) (i32.const 0))
  (func $callee (type $void))

  (func $control (param i32) (result i32)
    block
      loop
        local.get 0
        if
          nop
        else
          unreachable
        end
        local.get 0
        br_if 0
        local.get 0
        br_table 0 1 2
      end
    end
    call $callee
    i32.const 0
    call_indirect (type $void)
    local.get 0
    local.get 0
    i32.const 1
    select
    drop
    local.tee 0
    local.set 0
    global.get $g
    global.set $g
    memory.size
    drop
    i32.const 1
    memory.grow
    drop
    i32.const 0
    i32.const 0
    i32.const 0
    memory.fill
    i32.const 0
    i32.const 0
    i32.const 0
    memory.copy
    local.get 0
    return
  )

  (func $loads (result i64)
    i32.const 0 i32.load       drop
    i32.const 0 i32.load8_s    drop
    i32.const 0 i32.load8_u    drop
    i32.const 0 i32.load16_s   drop
    i32.const 0 i32.load16_u   drop
    i32.const 0 i64.load8_s    drop
    i32.const 0 i64.load8_u    drop
    i32.const 0 i64.load16_s   drop
    i32.const 0 i64.load16_u   drop
    i32.const 0 i64.load32_s   drop
    i32.const 0 i64.load32_u   drop
    i32.const 0 i32.const 0 i32.store
    i32.const 0 i32.const 0 i32.store8
    i32.const 0 i32.const 0 i32.store16
    i32.const 0 i64.const 0 i64.store
    i32.const 0 i64.const 0 i64.store8
    i32.const 0 i64.const 0 i64.store16
    i32.const 0 i64.const 0 i64.store32
    i32.const 0 i64.load
  )

  (func $unary (param i32) (param i64) (result i64)
    local.get 0 i32.eqz    drop
    local.get 1 i64.eqz    drop
    local.get 0 i32.clz    drop
    local.get 0 i32.ctz    drop
    local.get 0 i32.popcnt drop
    local.get 1 i64.clz    drop
    local.get 1 i64.ctz    drop
    local.get 1 i64.popcnt drop
    local.get 0 i32.extend8_s  drop
    local.get 0 i32.extend16_s drop
    local.get 1 i64.extend8_s  drop
    local.get 1 i64.extend16_s drop
    local.get 1 i64.extend32_s drop
    local.get 1 i32.wrap_i64   drop
    local.get 0 i64.extend_i32_s drop
    local.get 0 i64.extend_i32_u
  )

  (func $binary (param i32) (param i32) (result i32)
    local.get 0 local.get 1 i32.add   drop
    local.get 0 local.get 1 i32.sub   drop
    local.get 0 local.get 1 i32.mul   drop
    local.get 0 local.get 1 i32.div_s drop
    local.get 0 local.get 1 i32.div_u drop
    local.get 0 local.get 1 i32.rem_s drop
    local.get 0 local.get 1 i32.rem_u drop
    local.get 0 local.get 1 i32.and   drop
    local.get 0 local.get 1 i32.or    drop
    local.get 0 local.get 1 i32.xor   drop
    local.get 0 local.get 1 i32.shl   drop
    local.get 0 local.get 1 i32.shr_s drop
    local.get 0 local.get 1 i32.shr_u drop
    local.get 0 local.get 1 i32.rotl  drop
    local.get 0 local.get 1 i32.rotr  drop
    local.get 0 local.get 1 i32.eq    drop
    local.get 0 local.get 1 i32.ne    drop
    local.get 0 local.get 1 i32.lt_s  drop
    local.get 0 local.get 1 i32.lt_u  drop
    local.get 0 local.get 1 i32.gt_s  drop
    local.get 0 local.get 1 i32.gt_u  drop
    local.get 0 local.get 1 i32.le_s  drop
    local.get 0 local.get 1 i32.le_u  drop
    local.get 0 local.get 1 i32.ge_s  drop
    local.get 0 local.get 1 i32.ge_u
  )

  (func $binary64 (param i64) (param i64) (result i32)
    local.get 0 local.get 1 i64.add   drop
    local.get 0 local.get 1 i64.sub   drop
    local.get 0 local.get 1 i64.mul   drop
    local.get 0 local.get 1 i64.div_s drop
    local.get 0 local.get 1 i64.div_u drop
    local.get 0 local.get 1 i64.rem_s drop
    local.get 0 local.get 1 i64.rem_u drop
    local.get 0 local.get 1 i64.and   drop
    local.get 0 local.get 1 i64.or    drop
    local.get 0 local.get 1 i64.xor   drop
    local.get 0 local.get 1 i64.shl   drop
    local.get 0 local.get 1 i64.shr_s drop
    local.get 0 local.get 1 i64.shr_u drop
    local.get 0 local.get 1 i64.rotl  drop
    local.get 0 local.get 1 i64.rotr  drop
    local.get 0 local.get 1 i64.eq    drop
    local.get 0 local.get 1 i64.ne    drop
    local.get 0 local.get 1 i64.lt_s  drop
    local.get 0 local.get 1 i64.lt_u  drop
    local.get 0 local.get 1 i64.gt_s  drop
    local.get 0 local.get 1 i64.gt_u  drop
    local.get 0 local.get 1 i64.le_s  drop
    local.get 0 local.get 1 i64.le_u  drop
    local.get 0 local.get 1 i64.ge_s  drop
    local.get 0 local.get 1 i64.ge_u
  )
)";

/// Every operator in every function body of a module, in encounter order.
fn operators(bytes: &[u8]) -> Vec<Operator<'_>> {
    let mut ops = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("the fixture parses") {
            let reader = body
                .get_operators_reader()
                .expect("a function body reads as operators");
            for op in reader {
                ops.push(op.expect("an operator decodes"));
            }
        }
    }
    ops
}

/// The engine's table and the spec charge the same fuel for every operator
/// the profile admits.
#[test]
fn the_table_and_the_spec_price_every_operator_alike() {
    let bytes = parse_str(EVERY_OPERATOR).expect("the fixture assembles");
    let table = blessed_operator_cost();

    let mut priced = 0;
    for op in operators(&bytes) {
        let spec = fuel_cost(&translate(&[], &op).expect("the fixture stays inside the profile"));
        let engine = table.cost(&op);
        assert_eq!(
            i64::try_from(spec).expect("a price fits"),
            engine,
            "{op:?}: the spec charges {spec}, the table charges {engine}"
        );
        priced += 1;
    }

    assert!(
        priced > 150,
        "the fixture priced only {priced} operators, too few to stand for the profile"
    );
}

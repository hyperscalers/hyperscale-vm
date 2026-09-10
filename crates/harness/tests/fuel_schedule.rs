//! The schedule, stated twice.
//!
//! The meter's pass charges each metering block by its own table; vm-ref
//! states the same schedule independently, in its own operator
//! vocabulary, sharing no constant with it. Two statements of one intent
//! are only worth having if something holds them together, and that is
//! this lane: a module carrying every operator the profile admits is
//! instrumented, the instrumented body is read back, and every block's
//! charge must equal the spec's price summed over the block's own
//! operators.
//!
//! Reading the body back restates the pass's block rule a second time,
//! which is the point — the charge the pass wrote and the sum this lane
//! computes come from two descriptions of where a block starts and ends.
//! The differential fuel lane checks the other half: that both engines
//! run the instrumented module to the same exhaustion.

use hyperscale_vm_meter::instrument;
use hyperscale_vm_ref::{PAGE_COST, fuel_cost, translate};
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

/// Every operator in every function body of a module, per body.
fn bodies(bytes: &[u8]) -> Vec<Vec<Operator<'_>>> {
    let mut bodies = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Payload::CodeSectionEntry(body) = payload.expect("the fixture parses") {
            let reader = body
                .get_operators_reader()
                .expect("a function body reads as operators");
            bodies.push(
                reader
                    .into_iter()
                    .map(|op| op.expect("an operator decodes"))
                    .collect(),
            );
        }
    }
    bodies
}

/// What one instruction of an instrumented body is: a charge the pass
/// wrote at a block's head, the run-time check in front of a bulk
/// operator, the same check scaled by the page price in front of a
/// grow, or one of the author's own operators.
enum Read<'a> {
    Charge(u64),
    ByteCheck,
    PageCheck(u64),
    Author(Operator<'a>),
}

/// The static check the pass writes: ten instructions naming the same
/// counter and the same charge twice.
fn charge_at(ops: &[Operator<'_>]) -> Option<u64> {
    let [
        Operator::GlobalGet { global_index: g1 },
        Operator::I64Const { value: c1 },
        Operator::I64LtU,
        Operator::If { .. },
        Operator::Call { .. },
        Operator::End,
        Operator::GlobalGet { global_index: g2 },
        Operator::I64Const { value: c2 },
        Operator::I64Sub,
        Operator::GlobalSet { global_index: g3 },
    ] = ops
    else {
        return None;
    };
    (g1 == g2 && g2 == g3 && c1 == c2).then(|| u64::try_from(*c1).expect("a charge is unsigned"))
}

/// The run-time check the pass writes in front of a bulk operator:
/// thirteen instructions over the scratch local.
const fn byte_check_at(ops: &[Operator<'_>]) -> bool {
    matches!(
        ops,
        [
            Operator::LocalTee { .. },
            Operator::GlobalGet { .. },
            Operator::LocalGet { .. },
            Operator::I64ExtendI32U,
            Operator::I64LtU,
            Operator::If { .. },
            Operator::Call { .. },
            Operator::End,
            Operator::GlobalGet { .. },
            Operator::LocalGet { .. },
            Operator::I64ExtendI32U,
            Operator::I64Sub,
            Operator::GlobalSet { .. },
        ]
    )
}

/// The run-time check the pass writes in front of `memory.grow`: the
/// byte check with the count scaled by one price, named twice.
fn page_check_at(ops: &[Operator<'_>]) -> Option<u64> {
    let [
        Operator::LocalTee { .. },
        Operator::GlobalGet { .. },
        Operator::LocalGet { .. },
        Operator::I64ExtendI32U,
        Operator::I64Const { value: p1 },
        Operator::I64Mul,
        Operator::I64LtU,
        Operator::If { .. },
        Operator::Call { .. },
        Operator::End,
        Operator::GlobalGet { .. },
        Operator::LocalGet { .. },
        Operator::I64ExtendI32U,
        Operator::I64Const { value: p2 },
        Operator::I64Mul,
        Operator::I64Sub,
        Operator::GlobalSet { .. },
    ] = ops
    else {
        return None;
    };
    (p1 == p2).then(|| u64::try_from(*p1).expect("a price is unsigned"))
}

/// An instrumented body read back as charges and author operators.
fn read_back<'a>(ops: &[Operator<'a>]) -> Vec<Read<'a>> {
    let mut read = Vec::new();
    let mut at = 0;
    while at < ops.len() {
        if let Some(charge) = ops.get(at..at + 10).and_then(charge_at) {
            read.push(Read::Charge(charge));
            at += 10;
        } else if ops.get(at..at + 13).is_some_and(byte_check_at) {
            read.push(Read::ByteCheck);
            at += 13;
        } else if let Some(price) = ops.get(at..at + 17).and_then(page_check_at) {
            read.push(Read::PageCheck(price));
            at += 17;
        } else {
            read.push(Read::Author(ops[at].clone()));
            at += 1;
        }
    }
    read
}

/// The spec's price for the author's operators of every block, beside
/// the charge the pass wrote for it: `(charged, priced)` per block, with
/// no charge written where nothing is priced.
///
/// The block rule restated: a block starts at entry and after a label
/// or a conditional branch, ends at an unconditional one, and what
/// follows an unconditional branch is dead until the label at its own
/// depth — so it is priced at nothing, and the pass must have written
/// no charge for it.
fn blocks(read: &[Read<'_>]) -> Vec<(u64, u64)> {
    let mut blocks = Vec::new();
    let mut charged = 0u64;
    let mut priced = 0u64;
    let mut open = false;
    let mut depth = 0u32;
    let mut dead: Option<u32> = None;
    for item in read {
        match item {
            Read::Charge(charge) => {
                assert!(!open, "a charge landed inside a block");
                assert!(dead.is_none(), "a charge landed in dead code");
                charged = *charge;
                open = true;
            }
            Read::ByteCheck | Read::PageCheck(_) => {}
            Read::Author(op) => {
                if dead.is_none() {
                    open = true;
                    let spec = translate(&[], op).expect("the fixture stays inside the profile");
                    priced += fuel_cost(&spec);
                }
                let closes = match op {
                    Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                        depth += 1;
                        true
                    }
                    Operator::Else => {
                        if dead == Some(depth) {
                            dead = None;
                        }
                        true
                    }
                    Operator::End => {
                        if dead == Some(depth) {
                            dead = None;
                        }
                        depth = depth.saturating_sub(1);
                        true
                    }
                    Operator::BrIf { .. } => true,
                    Operator::Br { .. }
                    | Operator::BrTable { .. }
                    | Operator::Return
                    | Operator::Unreachable => {
                        if dead.is_none() {
                            dead = Some(depth);
                        }
                        true
                    }
                    _ => false,
                };
                if closes && open {
                    blocks.push((charged, priced));
                    charged = 0;
                    priced = 0;
                    open = false;
                }
            }
        }
    }
    assert!(!open, "a block did not close");
    blocks
}

/// The pass and the spec price every block alike, over a module
/// carrying every operator the profile admits.
#[test]
fn the_pass_and_the_spec_price_every_block_alike() {
    let author = parse_str(EVERY_OPERATOR).expect("the fixture assembles");
    let instrumented = instrument(&author).expect("the fixture instruments");

    let mut priced = 0usize;
    let mut checked = 0usize;
    for body in bodies(&instrumented) {
        let read = read_back(&body);
        priced += read
            .iter()
            .filter(|item| matches!(item, Read::Author(_)))
            .count();
        for (charged, spec) in blocks(&read) {
            assert_eq!(
                charged, spec,
                "the pass charged {charged} for a block the spec prices at {spec}"
            );
            checked += 1;
        }
    }
    assert!(
        priced > 150,
        "the fixture priced only {priced} operators, too few to stand for the profile"
    );
    assert!(checked > 10, "only {checked} blocks were read back");
}

/// The bulk operators carry their byte check and the grow its page
/// check, and only they do; the page price is the spec's.
#[test]
fn only_the_counted_operators_carry_a_run_time_check() {
    let author = parse_str(EVERY_OPERATOR).expect("the fixture assembles");
    let instrumented = instrument(&author).expect("the fixture instruments");
    let mut byte_checks = 0usize;
    let mut page_checks = 0usize;
    let mut bulk = 0usize;
    let mut grows = 0usize;
    for body in bodies(&instrumented) {
        for item in read_back(&body) {
            match item {
                Read::ByteCheck => byte_checks += 1,
                Read::PageCheck(price) => {
                    assert_eq!(price, PAGE_COST, "the pass and the spec price a page alike");
                    page_checks += 1;
                }
                Read::Author(Operator::MemoryFill { .. } | Operator::MemoryCopy { .. }) => {
                    bulk += 1;
                }
                Read::Author(Operator::MemoryGrow { .. }) => grows += 1,
                _ => {}
            }
        }
    }
    assert_eq!(bulk, 2, "the fixture carries a fill and a copy");
    assert_eq!(byte_checks, bulk, "one byte check per bulk operator");
    assert_eq!(grows, 1, "the fixture carries a grow");
    assert_eq!(page_checks, grows, "one page check per grow");
}

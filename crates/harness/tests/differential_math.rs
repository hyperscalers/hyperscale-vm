//! The `math` interface under both engines.
//!
//! Wide arithmetic is not a place the two runtimes agree — it is a place
//! they share, since both call the same functions in `hyperscale_vm_embed`
//! and neither can word an answer of its own. What this lane covers is
//! everything around that: the canonical ABI's flattening of a 256-bit
//! record into four `i64`s, the return area a result wider than one flat
//! value travels in, the enum discriminants, and the boundary charge.
//!
//! Which makes it a real check on a real risk. A `wide` argument occupies
//! four flattened slots and the reference interpreter reads them by
//! index, so an arity it computed wrongly would read an operand's limb as
//! a return pointer. The blessed engine derives the same layout from the
//! component type rather than from a table, so a disagreement between the
//! two is exactly the mistake this lane exists to catch.

use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_ref::{CVal, CanonError, ExecError, RefComponent, RefComponentInstance};
use hyperscale_vm_runtime::{
    HostRefusal, add_kernel_to_linker, blessed_engine, classify, validate_component,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::component::{Component, Linker};
use wasmtime::{Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

/// The scale a stored rate is quantized to, and the operands the
/// exponentiation case needs, as limbs a promoted slice can hold.
const SCALE: u128 = 10_u128.pow(36);
const ONE_AND_A_HALF: u128 = 15 * 10_u128.pow(35);
const SQUARED: u128 = 225 * 10_u128.pow(34);

#[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
const SCALE_LO: u64 = SCALE as u64;
#[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
const SCALE_HI: u64 = (SCALE >> 64) as u64;
#[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
const HALF_UP_LO: u64 = ONE_AND_A_HALF as u64;
#[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
const HALF_UP_HI: u64 = (ONE_AND_A_HALF >> 64) as u64;
#[allow(clippy::cast_possible_truncation)] // taking a limb is the truncation
const SQUARED_LO: u64 = SQUARED as u64;

/// A guest calling every `math` import, each export returning one `u64`
/// the two lanes can compare.
///
/// The operands are written into the export's own parameters rather than
/// baked in, so one text covers the whole operand space and a case is a
/// call rather than another export.
const MATH_GUEST_WAT: &str = r#"
(component
  (import "hyperscale:kernel/math" (instance $math
    (type (record (field "limb0" u64) (field "limb1" u64)
                  (field "limb2" u64) (field "limb3" u64)))
    (export "wide" (type (eq 0)))
    (type (enum "down" "up"))
    (export "rounding" (type (eq 2)))
    (type (enum "less" "equal" "greater"))
    (export "ordering" (type (eq 4)))
    (export "mul-div" (func (param "a" 1) (param "b" 1) (param "c" 1)
                            (param "r" 3) (result 1)))
    (export "geometric-mean" (func (param "a" 1) (param "b" 1) (result 1)))
    (export "fraction-compose" (func (param "an" 1) (param "ad" 1)
                                     (param "bn" 1) (param "bd" 1)
                                     (result (tuple 1 1))))
    (export "fraction-cmp" (func (param "an" 1) (param "ad" 1)
                                 (param "bn" 1) (param "bd" 1)
                                 (result 5)))
    (export "fixed-pow" (func (param "base" 1) (param "exp" u32)
                              (param "r" 3) (result 1)))))

  (alias export $math "mul-div" (func $mul_div))
  (alias export $math "geometric-mean" (func $gmean))
  (alias export $math "fraction-compose" (func $compose))
  (alias export $math "fraction-cmp" (func $cmp))
  (alias export $math "fixed-pow" (func $pow))

  (core module $alloc
    (memory (export "mem") 1 1)
    (func (export "realloc") (param i32 i32 i32 i32) (result i32) (i32.const 512)))
  (core instance $a (instantiate $alloc))

  (core func $mul_div_l (canon lower (func $mul_div) (memory $a "mem")))
  (core func $gmean_l (canon lower (func $gmean) (memory $a "mem")))
  (core func $compose_l (canon lower (func $compose) (memory $a "mem")))
  (core func $cmp_l (canon lower (func $cmp) (memory $a "mem")))
  (core func $pow_l (canon lower (func $pow) (memory $a "mem")))

  (core module $m
    (import "env" "mem" (memory 1 1))
    (import "k" "mul-div" (func $mul_div
      (param i64 i64 i64 i64  i64 i64 i64 i64  i64 i64 i64 i64  i32  i32)))
    (import "k" "gmean" (func $gmean
      (param i64 i64 i64 i64  i64 i64 i64 i64  i32)))
    (import "k" "compose" (func $compose
      (param i64 i64 i64 i64  i64 i64 i64 i64
             i64 i64 i64 i64  i64 i64 i64 i64  i32)))
    (import "k" "cmp" (func $cmp
      (param i64 i64 i64 i64  i64 i64 i64 i64
             i64 i64 i64 i64  i64 i64 i64 i64) (result i32)))
    (import "k" "pow" (func $pow (param i64 i64 i64 i64 i32 i32 i32)))

    ;; `a * b / c`, every operand a low limb, the result's low limb back.
    (func (export "mul-div") (param $a i64) (param $b i64) (param $c i64)
                             (param $r i32) (result i64)
      (call $mul_div
        (local.get $a) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $b) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $c) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $r) (i32.const 0))
      (i64.load (i32.const 0)))

    ;; The high limb of the same call, so a result past 64 bits is visible.
    (func (export "mul-div-high") (param $a i64) (param $b i64) (param $c i64)
                                  (result i64)
      (call $mul_div
        (local.get $a) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $b) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $c) (i64.const 0) (i64.const 0) (i64.const 0)
        (i32.const 0) (i32.const 0))
      (i64.load (i32.const 8)))

    ;; `floor(sqrt(a * b))` where the product leaves 128 bits.
    (func (export "gmean") (param $a i64) (param $b i64) (result i64)
      (call $gmean
        (local.get $a) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $b) (i64.const 0) (i64.const 0) (i64.const 0)
        (i32.const 0))
      (i64.load (i32.const 0)))

    ;; The composed numerator, with the denominator left at offset 32 —
    ;; which is where a tuple's second field lands and where an arity a
    ;; byte out would not put it.
    (func (export "compose-num") (param $an i64) (param $ad i64)
                                 (param $bn i64) (param $bd i64) (result i64)
      (call $compose
        (local.get $an) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $ad) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $bn) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $bd) (i64.const 0) (i64.const 0) (i64.const 0)
        (i32.const 0))
      (i64.load (i32.const 0)))

    (func (export "compose-den") (param $an i64) (param $ad i64)
                                 (param $bn i64) (param $bd i64) (result i64)
      (call $compose
        (local.get $an) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $ad) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $bn) (i64.const 0) (i64.const 0) (i64.const 0)
        (local.get $bd) (i64.const 0) (i64.const 0) (i64.const 0)
        (i32.const 0))
      (i64.load (i32.const 32)))

    (func (export "cmp") (param $an i64) (param $ad i64)
                         (param $bn i64) (param $bd i64) (result i64)
      (i64.extend_i32_u
        (call $cmp
          (local.get $an) (i64.const 0) (i64.const 0) (i64.const 0)
          (local.get $ad) (i64.const 0) (i64.const 0) (i64.const 0)
          (local.get $bn) (i64.const 0) (i64.const 0) (i64.const 0)
          (local.get $bd) (i64.const 0) (i64.const 0) (i64.const 0))))

    ;; `base^exp` at the fixed scale, the base given as its two low limbs
    ;; so a value past 64 bits is expressible.
    (func (export "pow") (param $lo i64) (param $hi i64) (param $exp i32)
                         (result i64)
      (call $pow
        (local.get $lo) (local.get $hi) (i64.const 0) (i64.const 0)
        (local.get $exp) (i32.const 0) (i32.const 0))
      (i64.load (i32.const 0))))

  (core instance $i (instantiate $m
    (with "env" (instance $a))
    (with "k" (instance
      (export "mul-div" (func $mul_div_l))
      (export "gmean" (func $gmean_l))
      (export "compose" (func $compose_l))
      (export "cmp" (func $cmp_l))
      (export "pow" (func $pow_l))))))

  (func (export "mul-div") (param "a" u64) (param "b" u64) (param "c" u64)
                           (param "r" u32) (result u64)
    (canon lift (core func $i "mul-div")))
  (func (export "mul-div-high") (param "a" u64) (param "b" u64) (param "c" u64)
                                (result u64)
    (canon lift (core func $i "mul-div-high")))
  (func (export "gmean") (param "a" u64) (param "b" u64) (result u64)
    (canon lift (core func $i "gmean")))
  (func (export "compose-num") (param "an" u64) (param "ad" u64)
                               (param "bn" u64) (param "bd" u64) (result u64)
    (canon lift (core func $i "compose-num")))
  (func (export "compose-den") (param "an" u64) (param "ad" u64)
                               (param "bn" u64) (param "bd" u64) (result u64)
    (canon lift (core func $i "compose-den")))
  (func (export "cmp") (param "an" u64) (param "ad" u64)
                       (param "bn" u64) (param "bd" u64) (result u64)
    (canon lift (core func $i "cmp")))
  (func (export "pow") (param "lo" u64) (param "hi" u64) (param "exp" u32)
                       (result u64)
    (canon lift (core func $i "pow"))))
"#;

/// What one call came back with, in terms both lanes can produce.
#[derive(Debug, PartialEq, Eq)]
enum LaneOutcome {
    Value(u64),
    Refusal(AbortReason),
    Other(String),
}

/// One call's arguments: `u64`s and at most one trailing `u32`.
#[derive(Clone, Copy)]
struct Call {
    export: &'static str,
    words: &'static [u64],
    tail: Option<u32>,
}

const fn call(export: &'static str, words: &'static [u64]) -> Call {
    Call {
        export,
        words,
        tail: None,
    }
}

const fn call_with(export: &'static str, words: &'static [u64], tail: u32) -> Call {
    Call {
        export,
        words,
        tail: Some(tail),
    }
}

fn run_blessed(case: Call) -> Result<(LaneOutcome, u64)> {
    let bytes = parse_str(MATH_GUEST_WAT)?;
    validate_component(&bytes)?;
    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<NoHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, NoHost);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;

    let answer = match (case.words, case.tail) {
        ([a, b], None) => instance
            .get_typed_func::<(u64, u64), (u64,)>(&mut store, case.export)?
            .call(&mut store, (*a, *b)),
        ([a, b, c], None) => instance
            .get_typed_func::<(u64, u64, u64), (u64,)>(&mut store, case.export)?
            .call(&mut store, (*a, *b, *c)),
        ([a, b, c, d], None) => instance
            .get_typed_func::<(u64, u64, u64, u64), (u64,)>(&mut store, case.export)?
            .call(&mut store, (*a, *b, *c, *d)),
        ([a, b, c], Some(tail)) => instance
            .get_typed_func::<(u64, u64, u64, u32), (u64,)>(&mut store, case.export)?
            .call(&mut store, (*a, *b, *c, tail)),
        ([a, b], Some(tail)) => instance
            .get_typed_func::<(u64, u64, u32), (u64,)>(&mut store, case.export)?
            .call(&mut store, (*a, *b, tail)),
        other => panic!("no signature for {other:?}"),
    };
    let outcome = match answer {
        Ok((value,)) => LaneOutcome::Value(value),
        Err(error) => error.downcast_ref::<HostRefusal>().map_or_else(
            || LaneOutcome::Other(format!("{error:?}")),
            |refusal| LaneOutcome::Refusal(refusal.0),
        ),
    };
    let spent = FUEL - store.get_fuel()?;
    Ok((outcome, spent))
}

fn run_ref(case: Call) -> Result<(LaneOutcome, u64)> {
    let bytes = parse_str(MATH_GUEST_WAT)?;
    let comp = RefComponent::decode(&bytes)?;
    let mut args: Vec<CVal> = case.words.iter().copied().map(CVal::U64).collect();
    if let Some(tail) = case.tail {
        args.push(CVal::U32(tail));
    }
    let mut instance =
        RefComponentInstance::instantiate(&comp, NoHost, u64::MAX).map_err(|(_, error)| error)?;
    let outcome = match instance.invoke(case.export, &args)? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(value)] => LaneOutcome::Value(*value),
            other => LaneOutcome::Other(format!("unexpected values {other:?}")),
        },
        Err(ExecError::Canon(CanonError::Host(reason))) => LaneOutcome::Refusal(reason),
        Err(error) => LaneOutcome::Other(format!("{error:?}")),
    };
    Ok((outcome, instance.fuel_consumed()))
}

/// Both lanes over one call, asserting they agree on the answer.
fn agreed(case: Call) -> LaneOutcome {
    let (blessed, blessed_fuel) = run_blessed(case).expect("the blessed lane runs");
    let (reference, reference_fuel) = run_ref(case).expect("the reference lane runs");
    assert_eq!(
        blessed, reference,
        "engines disagree on {}{:?}",
        case.export, case.words
    );
    assert!(blessed_fuel > 0 && reference_fuel > 0, "both lanes charge");
    blessed
}

fn value(case: Call) -> u64 {
    match agreed(case) {
        LaneOutcome::Value(value) => value,
        other => panic!("expected a value from {}, got {other:?}", case.export),
    }
}

#[test]
fn a_wide_operand_flattens_to_four_slots_on_both_lanes() {
    // The whole risk this lane covers: if either side counted a `wide`
    // as anything but four flattened arguments, the operands would land
    // in the wrong places and this would not be seven.
    assert_eq!(value(call_with("mul-div", &[21, 2, 6], 0)), 7);
}

#[test]
fn rounding_direction_crosses_as_a_discriminant() {
    assert_eq!(value(call_with("mul-div", &[7, 1, 2], 0)), 3);
    assert_eq!(value(call_with("mul-div", &[7, 1, 2], 1)), 4);
    assert_eq!(value(call_with("mul-div", &[8, 1, 2], 1)), 4);
}

#[test]
fn an_out_of_range_discriminant_aborts_identically() -> Result<()> {
    // The guest export takes the rounding as a raw `u32` and forwards it,
    // so the discriminant space past the enum's declared cases reaches
    // the host boundary from ordinary guest code. Neither lift may
    // resolve it to a case: the engine traps, the interpreter refuses,
    // and both classify as the same violation.
    let bytes = parse_str(MATH_GUEST_WAT)?;

    let engine = blessed_engine()?;
    let component = Component::new(&engine, &bytes)?;
    let mut linker = Linker::<NoHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, NoHost);
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;
    let func = instance.get_typed_func::<(u64, u64, u64, u32), (u64,)>(&mut store, "mul-div")?;
    let blessed = func
        .call(&mut store, (21, 2, 6, 2))
        .expect_err("an invalid discriminant reaches no host body");
    assert_eq!(classify(&blessed), AbortReason::AbiViolation);

    let comp = RefComponent::decode(&bytes)?;
    let mut ref_instance =
        RefComponentInstance::instantiate(&comp, NoHost, u64::MAX).map_err(|(_, error)| error)?;
    let args = [CVal::U64(21), CVal::U64(2), CVal::U64(6), CVal::U32(2)];
    let reference = ref_instance
        .invoke("mul-div", &args)?
        .expect_err("an invalid discriminant reaches no host body");
    assert_eq!(reference.abort_reason(), AbortReason::AbiViolation);
    Ok(())
}

#[test]
fn the_product_is_held_past_the_operand_width() {
    // `(2^64 - 1) * (2^64 - 1) / 1` needs both limbs of the result, so a
    // return area written one limb wide would lose the high half.
    let low = value(call("mul-div-high", &[u64::MAX, u64::MAX, 1]));
    assert_eq!(low, u64::MAX - 1);
}

#[test]
fn a_zero_divisor_refuses_identically() {
    assert_eq!(
        agreed(call_with("mul-div", &[1, 1, 0], 0)),
        LaneOutcome::Refusal(AbortReason::MathDivideByZero)
    );
}

#[test]
fn a_geometric_mean_crosses_the_product_width() {
    // `sqrt(2^64 * 2^64)` is exactly `2^64`, whose low limb is zero and
    // whose value is past what either operand holds.
    assert_eq!(value(call("gmean", &[1 << 62, 1 << 62])), 1 << 62);
    assert_eq!(value(call("gmean", &[9, 1])), 3);
    assert_eq!(value(call("gmean", &[10, 10])), 10);
}

#[test]
fn a_tuple_result_lands_in_two_return_slots() {
    // Composition returns two wide words; the second sits 32 bytes into
    // the return area, which is the layout an arity table cannot guess.
    assert_eq!(value(call("compose-num", &[2, 4, 3, 9])), 6);
    assert_eq!(value(call("compose-den", &[2, 4, 3, 9])), 36);
}

#[test]
fn a_comparison_crosses_as_an_enum() {
    assert_eq!(value(call("cmp", &[1, 3, 2, 6])), 1);
    assert_eq!(value(call("cmp", &[1, 3, 1, 2])), 0);
    assert_eq!(value(call("cmp", &[2, 3, 1, 2])), 2);
}

#[test]
fn a_zero_denominator_refuses_identically() {
    assert_eq!(
        agreed(call("cmp", &[1, 0, 1, 1])),
        LaneOutcome::Refusal(AbortReason::MathDivideByZero)
    );
    assert_eq!(
        agreed(call("compose-num", &[1, 0, 1, 1])),
        LaneOutcome::Refusal(AbortReason::MathDivideByZero)
    );
}

#[test]
fn exponentiation_carries_a_wide_base() {
    // The fixed scale is 10^36, which is past 64 bits, so the base
    // arrives as two limbs. An exponent of one returns it unchanged.
    assert_eq!(value(call_with("pow", &[SCALE_LO, SCALE_HI], 1)), SCALE_LO);
    // 1.5 squared is 2.25, whose low limb the guest reads back.
    assert_eq!(
        value(call_with("pow", &[HALF_UP_LO, HALF_UP_HI], 2)),
        SQUARED_LO
    );
}

#[test]
fn the_wide_record_is_within_the_profile_where_a_guest_declares_it() {
    // A generated guest hoists the interface's types into the component's
    // own type section, which is where the structural walk sees them —
    // and the walk admits a record only where every field is a scalar,
    // because that is what makes it flatten into registers rather than
    // cross through linear memory. A `wide` of two `amount` halves reads
    // naturally and is outside the profile; the import instance type this
    // lane's guest declares would not have caught it, since a type living
    // inside an instance type is never walked.
    let hoisted = r#"(component
      (type $wide (record (field "limb0" u64) (field "limb1" u64)
                          (field "limb2" u64) (field "limb3" u64)))
      (type $f (func (param "a" $wide) (result $wide))))"#;
    let bytes = parse_str(hoisted).expect("the shape parses");
    validate_component(&bytes).expect("four flat limbs are within the profile");

    let nested = r#"(component
      (type $amount (record (field "low" u64) (field "high" u64)))
      (type $wide (record (field "low" $amount) (field "high" $amount)))
      (type $f (func (param "a" $wide) (result $wide))))"#;
    let bytes = parse_str(nested).expect("the shape parses");
    assert!(
        validate_component(&bytes).is_err(),
        "a record of records is outside the profile, and a wide that took \
         that shape would refuse every guest declaring it"
    );
}

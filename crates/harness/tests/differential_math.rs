//! The `math` imports under both engines.
//!
//! Wide arithmetic is not a place the two runtimes agree — it is a place
//! they share, since both dispatch into the same functions in
//! `hyperscale_vm_embed` and neither can word an answer of its own. What
//! this lane covers is everything around that: the operands crossing by
//! pointer at the width the boundary states, the out-pointers a result
//! lands at, the rounding and ordering tags, and the boundary charge.
//!
//! Which makes it a real check on a real risk. A `wide` is thirty-two
//! bytes at a pointer the guest chose, four little-endian limbs, and
//! nothing but the dispatch's slice check holds the guest to that: the
//! bytes the dispatch reads are whatever the guest's stores left there,
//! and an engine whose memory disagreed with the guest's own stores — a
//! stale view, a width read short — would answer a different figure with
//! no refusal to show for it. So every case writes its operands as the
//! boundary states them and asks both engines for the whole ending.

use std::sync::LazyLock;

use hyperscale_vm_embed::abi::{ABI, MATH, MEMORY};
use hyperscale_vm_embed::{GuestArg, Invocation};
use hyperscale_vm_harness::dual::Ended;
use hyperscale_vm_harness::fixtures::NoHost;
use hyperscale_vm_ref::{RefModule, RefModuleInstance};
use hyperscale_vm_runtime::{
    InstantiationCharges, Invoking, add_kernel_imports, blessed_engine, instantiate_charged,
    instantiation_charges, invoke_export, validate_module,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::error::format_err;
use wasmtime::{Engine, Linker, Module, Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

/// The scale a stored rate is quantized to, and the operands the
/// exponentiation case needs, as the limbs a guest writes.
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

/// A guest calling every `math` import, each export answering one `u64`
/// the two lanes can compare.
///
/// The operands are the export's own parameters rather than baked in,
/// so one text covers the whole operand space and a case is a call
/// rather than another export. Every parameter is a `u64`, the tags
/// included: the guest narrows a tag to the `i32` the import takes, so
/// a value past the tag's range reaches the boundary from ordinary
/// guest code.
fn guest() -> String {
    format!(
        r#"
(module
  (import "{MATH}" "mul-div" (func $mul_div (param i32 i32 i32 i32 i32)))
  (import "{MATH}" "geometric-mean" (func $geometric_mean (param i32 i32 i32)))
  (import "{MATH}" "fraction-compose"
    (func $fraction_compose (param i32 i32 i32 i32 i32 i32)))
  (import "{MATH}" "fraction-cmp" (func $fraction_cmp (param i32 i32 i32 i32) (result i32)))
  (import "{MATH}" "fixed-pow" (func $fixed_pow (param i32 i32 i32 i32)))
  (import "{ABI}" "answer" (func $answer (param i32 i32)))
  (import "{ABI}" "reply" (func $reply (param i32 i32)))
  (memory (export "{MEMORY}") 1 1)

  ;; A wide at $at: the low limb, then three zero limbs.
  (func $wide (param $at i32) (param $lo i64)
    (i64.store (local.get $at) (local.get $lo))
    (i64.store offset=8 (local.get $at) (i64.const 0))
    (i64.store offset=16 (local.get $at) (i64.const 0))
    (i64.store offset=24 (local.get $at) (i64.const 0)))

  ;; The eight bytes at $at are the answer; there are no edges.
  (func $done (param $at i32)
    (call $answer (local.get $at) (i32.const 8))
    (call $reply (i32.const 0) (i32.const 0)))

  ;; `a * b / c`, the operands at 0, 32 and 64, the result at 96, its
  ;; low limb answered.
  (func (export "mul-div") (param $a i64) (param $b i64) (param $c i64) (param $r i64)
    (call $wide (i32.const 0) (local.get $a))
    (call $wide (i32.const 32) (local.get $b))
    (call $wide (i32.const 64) (local.get $c))
    (call $mul_div (i32.const 0) (i32.const 32) (i32.const 64)
                   (i32.wrap_i64 (local.get $r)) (i32.const 96))
    (call $done (i32.const 96)))

  ;; The second limb of the same call, so a result past 64 bits is visible.
  (func (export "mul-div-high") (param $a i64) (param $b i64) (param $c i64)
    (call $wide (i32.const 0) (local.get $a))
    (call $wide (i32.const 32) (local.get $b))
    (call $wide (i32.const 64) (local.get $c))
    (call $mul_div (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 0) (i32.const 96))
    (call $done (i32.const 104)))

  ;; `floor(sqrt(a * b))` where the product leaves 64 bits.
  (func (export "gmean") (param $a i64) (param $b i64)
    (call $wide (i32.const 0) (local.get $a))
    (call $wide (i32.const 32) (local.get $b))
    (call $geometric_mean (i32.const 0) (i32.const 32) (i32.const 96))
    (call $done (i32.const 96)))

  ;; Four operands at 0, 32, 64 and 96; the numerator lands at 128 and
  ;; the denominator at 160, each through its own out-pointer.
  (func $compose (param $an i64) (param $ad i64) (param $bn i64) (param $bd i64)
    (call $wide (i32.const 0) (local.get $an))
    (call $wide (i32.const 32) (local.get $ad))
    (call $wide (i32.const 64) (local.get $bn))
    (call $wide (i32.const 96) (local.get $bd))
    (call $fraction_compose (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 96)
                            (i32.const 128) (i32.const 160)))
  (func (export "compose-num") (param $an i64) (param $ad i64) (param $bn i64) (param $bd i64)
    (call $compose (local.get $an) (local.get $ad) (local.get $bn) (local.get $bd))
    (call $done (i32.const 128)))
  (func (export "compose-den") (param $an i64) (param $ad i64) (param $bn i64) (param $bd i64)
    (call $compose (local.get $an) (local.get $ad) (local.get $bn) (local.get $bd))
    (call $done (i32.const 160)))

  ;; The ordering tag, widened to the answer's eight bytes at 128.
  (func (export "cmp") (param $an i64) (param $ad i64) (param $bn i64) (param $bd i64)
    (call $wide (i32.const 0) (local.get $an))
    (call $wide (i32.const 32) (local.get $ad))
    (call $wide (i32.const 64) (local.get $bn))
    (call $wide (i32.const 96) (local.get $bd))
    (i64.store (i32.const 128)
      (i64.extend_i32_u
        (call $fraction_cmp (i32.const 0) (i32.const 32) (i32.const 64) (i32.const 96))))
    (call $done (i32.const 128)))

  ;; `base^exp` at the fixed scale, the base given as its two low limbs
  ;; so a value past 64 bits is expressible; the result at 32.
  (func (export "pow") (param $lo i64) (param $hi i64) (param $exp i64)
    (call $wide (i32.const 0) (local.get $lo))
    (i64.store offset=8 (i32.const 0) (local.get $hi))
    (call $fixed_pow (i32.const 0) (i32.wrap_i64 (local.get $exp)) (i32.const 0) (i32.const 32))
    (call $done (i32.const 32))))
"#
    )
}

/// The guest in both engines' runnable forms, compiled once.
struct Lanes {
    engine: Engine,
    module: Module,
    charges: InstantiationCharges,
    reference: RefModule,
}

static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let bytes = parse_str(guest()).expect("the fixture parses");
    validate_module(&bytes).expect("the fixture is admitted");
    let engine = blessed_engine().expect("the blessed engine configures");
    Lanes {
        module: Module::new(&engine, &bytes).expect("the fixture compiles"),
        charges: instantiation_charges(&bytes).expect("the charges derive"),
        reference: RefModule::decode(&bytes).expect("the fixture decodes"),
        engine,
    }
});

fn run_blessed(export: &str, args: &[GuestArg<'_>]) -> Result<Invocation> {
    let lanes = &*LANES;
    let mut linker = Linker::<Invoking<NoHost>>::new(&lanes.engine);
    add_kernel_imports(&mut linker)?;
    let mut store = Store::new(&lanes.engine, Invoking::new(NoHost));
    let instance = instantiate_charged(&mut store, FUEL, &lanes.charges, |s| {
        linker.instantiate(s, &lanes.module)
    })?;
    Ok(invoke_export(&mut store, &instance, export, args, FUEL))
}

fn run_ref(export: &str, args: &[GuestArg<'_>]) -> Result<Invocation> {
    let mut instance = RefModuleInstance::instantiate(&LANES.reference, NoHost, FUEL)
        .map_err(|(_, error)| format_err!("reference instantiation: {error}"))?;
    Ok(instance.invoke(export, args))
}

/// Both lanes over one call, asserting they agree on the whole ending.
fn agreed(export: &str, words: &[u64]) -> Invocation {
    let args: Vec<GuestArg<'_>> = words.iter().copied().map(GuestArg::U64).collect();
    let blessed = run_blessed(export, &args).expect("the blessed lane runs");
    let reference = run_ref(export, &args).expect("the reference lane runs");
    assert_eq!(blessed, reference, "engines disagree on {export}{words:?}");
    assert!(blessed.fuel > 0, "both lanes charge");
    assert!(!blessed.exhausted);
    blessed
}

fn value(export: &str, words: &[u64]) -> u64 {
    agreed(export, words)
        .scalar()
        .unwrap_or_else(|error| panic!("expected a figure from {export}{words:?}: {error}"))
}

fn refusal(export: &str, words: &[u64]) -> AbortReason {
    agreed(export, words)
        .refusal()
        .unwrap_or_else(|| panic!("expected a refusal from {export}{words:?}"))
}

#[test]
fn operands_cross_at_the_width_the_boundary_states() {
    // The whole risk this lane covers: if either engine read a `wide` at
    // any width but the four limbs the guest wrote, an operand would be
    // read from the bytes beside it and this would not be seven.
    assert_eq!(value("mul-div", &[21, 2, 6, 0]), 7);
}

#[test]
fn rounding_direction_crosses_as_a_tag() {
    assert_eq!(value("mul-div", &[7, 1, 2, 0]), 3);
    assert_eq!(value("mul-div", &[7, 1, 2, 1]), 4);
    assert_eq!(value("mul-div", &[8, 1, 2, 1]), 4);
}

#[test]
fn an_out_of_range_rounding_tag_aborts_identically() {
    // The guest forwards the tag as it was given, so the space past the
    // two the boundary names reaches the dispatch from ordinary guest
    // code. Neither engine may resolve it to a direction: both refuse
    // it as the guest's violation, before any host body runs.
    assert_eq!(
        refusal("mul-div", &[21, 2, 6, 2]),
        AbortReason::AbiViolation
    );
}

#[test]
fn the_product_is_held_past_the_operand_width() {
    // `(2^64 - 1) * (2^64 - 1) / 1` needs both limbs of the result, so a
    // result written one limb wide would lose the high half.
    assert_eq!(
        value("mul-div-high", &[u64::MAX, u64::MAX, 1]),
        u64::MAX - 1
    );
}

#[test]
fn a_zero_divisor_refuses_identically() {
    assert_eq!(
        refusal("mul-div", &[1, 1, 0, 0]),
        AbortReason::MathDivideByZero
    );
}

#[test]
fn a_geometric_mean_crosses_the_product_width() {
    // `sqrt(2^62 * 2^62)` is exactly `2^62`, whose product is past what
    // either operand holds.
    assert_eq!(value("gmean", &[1 << 62, 1 << 62]), 1 << 62);
    assert_eq!(value("gmean", &[9, 1]), 3);
    assert_eq!(value("gmean", &[10, 10]), 10);
}

#[test]
fn a_composition_lands_at_two_out_pointers() {
    // Composition writes two wides, each through its own pointer; the
    // denominator sits where the guest asked for it and nowhere else.
    assert_eq!(value("compose-num", &[2, 4, 3, 9]), 6);
    assert_eq!(value("compose-den", &[2, 4, 3, 9]), 36);
}

#[test]
fn a_comparison_crosses_as_a_tag() {
    assert_eq!(value("cmp", &[1, 3, 2, 6]), 1);
    assert_eq!(value("cmp", &[1, 3, 1, 2]), 0);
    assert_eq!(value("cmp", &[2, 3, 1, 2]), 2);
}

#[test]
fn a_zero_denominator_refuses_identically() {
    assert_eq!(refusal("cmp", &[1, 0, 1, 1]), AbortReason::MathDivideByZero);
    assert_eq!(
        refusal("compose-num", &[1, 0, 1, 1]),
        AbortReason::MathDivideByZero
    );
}

#[test]
fn exponentiation_carries_a_wide_base() {
    // The fixed scale is 10^36, which is past 64 bits, so the base
    // arrives as two limbs. An exponent of one returns it unchanged.
    assert_eq!(value("pow", &[SCALE_LO, SCALE_HI, 1]), SCALE_LO);
    // 1.5 squared is 2.25, whose low limb the guest reads back.
    assert_eq!(value("pow", &[HALF_UP_LO, HALF_UP_HI, 2]), SQUARED_LO);
}

//! The core boundary end to end: hand-written modules under the blessed
//! engine, every import wired, both register paths, the reply rule, and
//! every way a call can end.

mod common;

use common::{CLOCK_MS, Held, Kernel, every_import, ident, module};
use hyperscale_vm_embed::abi::{ABI, CoreType, IMPORTS, MATH, STATE};
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_runtime::{
    Invoking, add_kernel_imports, blessed_engine, invoke_module, validate_module,
};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Engine, Linker, Module, Store};
use wat::parse_str;

const BUDGET: u64 = 1_000_000;

/// Validate, compile, instantiate and invoke one export, handing back
/// how it ended and the kernel it left behind.
fn run(engine: &Engine, wat: &str, export: &str, args: &[GuestArg<'_>]) -> (Invocation, Kernel) {
    run_with(engine, wat, export, args, Kernel::seeded(), BUDGET)
}

fn run_with(
    engine: &Engine,
    wat: &str,
    export: &str,
    args: &[GuestArg<'_>],
    kernel: Kernel,
    budget: u64,
) -> (Invocation, Kernel) {
    let bytes = parse_str(wat).expect("the fixture parses");
    validate_module(&bytes).expect("the fixture is admitted");
    let module = Module::new(engine, &bytes).expect("the fixture compiles");
    let mut linker = Linker::<Invoking<Kernel>>::new(engine);
    add_kernel_imports(&mut linker).expect("the imports register");
    let mut store = Store::new(engine, Invoking::new(kernel));
    store.set_fuel(budget).expect("fuel is on");
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("the fixture instantiates");
    let ended = invoke_module(&mut store, &instance, export, args, budget);
    (ended, store.into_data().into_host())
}

fn engine() -> Engine {
    blessed_engine().expect("the blessed engine configures")
}

fn aborted(ended: &Invocation) -> AbortReason {
    match ended.result {
        Invoked::Aborted(reason) => reason,
        ref other => panic!("expected an abort, got {other:?}"),
    }
}

/// Every import resolves against the linker at the type the kernel
/// defines it, and the ones that reach the host reach it.
///
/// The linker refuses an import whose type disagrees with its wrapper,
/// so instantiating a module that names all forty is what holds the
/// import table to the wrappers; the loop then calls each with zeros
/// and pointers into a zeroed memory, and asks only that the call was
/// admitted — completed or refused on the kernel's own terms — never
/// mis-shaped.
#[test]
fn every_import_resolves_and_reaches_the_host() {
    let engine = engine();
    for (module_name, name, params, results) in IMPORTS {
        if *module_name == ABI {
            continue;
        }
        let pushes: String = params
            .iter()
            .enumerate()
            .map(|(index, param)| match param {
                // Pointers land inside the memory, spaced so an out
                // pointer never overlaps an operand; the math imports
                // take a rounding, so every operand of theirs is zero.
                CoreType::I32 if *module_name != MATH => format!(" i32.const {}", index * 64),
                CoreType::I32 => " i32.const 0".to_owned(),
                CoreType::I64 => " i64.const 0".to_owned(),
            })
            .collect();
        let drop = if results.is_empty() { "" } else { " drop" };
        let body = format!(
            "  (func (export \"run\"){pushes} call {}{drop} i32.const 0 i32.const 0 call $reply)",
            ident(name)
        );
        let (ended, kernel) = run(&engine, &module(&body), "run", &[]);
        match ended.result {
            Invoked::Produced { .. } | Invoked::Aborted(_) => {}
            ref other => panic!("{name}: {other:?}"),
        }
        if *module_name == STATE || *name == "emit" {
            assert!(
                kernel.calls.iter().any(|call| call.starts_with(*name)),
                "{name} never reached the host: {:?}",
                kernel.calls
            );
        }
        assert!(
            !matches!(
                ended.result,
                Invoked::Aborted(AbortReason::AbiViolation | AbortReason::BadReturnShape)
            ),
            "{name} was mis-shaped: {:?}",
            ended.result
        );
    }
}

/// Bytes go in through an input register and come back through the
/// answer register, and what the host sees is what the guest wrote.
#[test]
fn bytes_cross_through_the_registers() {
    let engine = engine();
    let body = r#"
  (func (export "copy") (param $a i32) (param $b i32) (param $payload i32)
    (local $len i32)
    ;; the payload register, collected at 0
    i32.const 2 i32.const 0 call $arg
    ;; site-set(b, 0, payload)
    local.get $b i32.const 0 i32.const 0 local.get $payload call $site_set
    ;; site-get(a, 0), taken at 256
    local.get $a i32.const 0 call $site_get local.set $len
    i32.const 256 call $take
    ;; hash(what was taken) at 512, emitted under type 7
    i32.const 256 local.get $len i32.const 512 call $hash
    i32.const 7 i32.const 512 i32.const 32 call $emit
    ;; answer with the cell, reply with no edges
    i32.const 256 local.get $len call $answer
    i32.const 0 i32.const 0 call $reply)"#;
    let args = [
        GuestArg::Site { site: 0 },
        GuestArg::Site { site: 1 },
        GuestArg::Bytes(b"payload"),
    ];
    let (ended, kernel) = run(&engine, &module(body), "copy", &args);
    assert_eq!(
        ended.result,
        Invoked::Produced {
            edges: vec![],
            answer: Some(b"alpha".to_vec()),
        }
    );
    assert!(!ended.exhausted);
    assert!(ended.fuel > 0);
    assert_eq!(kernel.values[1], b"payload");
    let digest = [b"alpha".iter().fold(0u8, |acc, b| acc.wrapping_add(*b)); 32];
    assert_eq!(kernel.emitted, vec![(7, digest.to_vec())]);
}

/// Value moves through handles: amounts by pointer, buckets by index,
/// and the edge comes back through the reply.
#[test]
fn value_moves_through_handles() {
    let engine = engine();
    let body = r#"
  (func (export "pay") (param $vault i32) (param $funds i32) (result i32)
    (local $b1 i32) (local $b2 i32) (local $b3 i32)
    ;; balance at 0
    local.get $vault i32.const 0 i32.const 0 call $site_balance
    ;; take 30 (written at 16) from the vault
    i32.const 16 i64.const 30 i64.store
    local.get $vault i32.const 0 i32.const 16 call $site_take local.set $b1
    ;; its amount at 32
    local.get $b1 i32.const 32 call $bucket_amount
    ;; split 10 (at 48) off, merge into funds, and put funds back
    i32.const 48 i64.const 10 i64.store
    local.get $b1 i32.const 48 call $bucket_take local.set $b2
    local.get $funds local.get $b2 call $bucket_put
    local.get $vault i32.const 0 local.get $funds call $site_put
    ;; mint 7 (at 64) and burn it; drop what is left of b1
    i32.const 64 i64.const 7 i64.store
    i32.const 0 i32.const 64 call $mint call $burn
    local.get $b1 call $bucket_drop
    ;; the reserve is the edge; reply with it at 80
    local.get $vault i32.const 0 call $site_reserve_take local.set $b3
    i32.const 80 local.get $b3 i32.store
    i32.const 80 i32.const 1 call $reply
    i32.const 0)"#;
    let args = [GuestArg::Site { site: 2 }, GuestArg::Bucket(0)];
    let (ended, kernel) = run(&engine, &module(body), "pay", &args);
    let Invoked::Produced { edges, answer } = ended.result else {
        panic!("{:?}", ended.result);
    };
    assert_eq!(answer, None);
    assert_eq!(edges.len(), 1);
    assert_eq!(kernel.buckets[edges[0] as usize], Held::Amount(5));
    // 300 - 30 + (40 + 10) = 320
    assert_eq!(kernel.balances[2], 320);
    assert_eq!(kernel.buckets[0], Held::Gone, "funds were put");
    assert_eq!(
        kernel.calls,
        [
            "site-balance(2,0)",
            "site-take(2,0,30)",
            "bucket-amount(2)",
            "bucket-take(2,10)",
            "bucket-put(0,3)",
            "site-put(2,0,0)",
            "mint(0,7)",
            "burn(4)",
            "bucket-drop(2)",
            "site-reserve-take(2,0)",
        ]
    );
}

/// A decline is the return value; it needs no reply, and one made before
/// it is discarded.
#[test]
fn a_decline_is_the_return_value() {
    let engine = engine();
    let body = r#"
  (func (export "no") (param $code i64) (result i32)
    local.get $code i32.wrap_i64 i32.const 1 i32.add)
  (func (export "no-after-reply") (param $code i64) (result i32)
    i32.const 0 i32.const 0 call $reply
    local.get $code i32.wrap_i64 i32.const 1 i32.add)
  (func (export "yes") (param $code i64) (result i32)
    i32.const 0 i32.const 0 call $reply
    i32.const 0)"#;
    let wat = module(body);
    for export in ["no", "no-after-reply"] {
        let (ended, _) = run(&engine, &wat, export, &[GuestArg::U64(3)]);
        assert_eq!(ended.result, Invoked::Declined(3), "{export}");
    }
    let (ended, _) = run(&engine, &wat, "yes", &[GuestArg::U64(3)]);
    assert_eq!(
        ended.result,
        Invoked::Produced {
            edges: vec![],
            answer: None
        }
    );
}

/// A completed return without a reply, or with two, is outside the
/// convention.
#[test]
fn a_reply_is_exactly_once() {
    let engine = engine();
    let body = r#"
  (func (export "silent"))
  (func (export "twice")
    i32.const 0 i32.const 0 call $reply
    i32.const 0 i32.const 0 call $reply)
  (func (export "answers-twice")
    i32.const 0 i32.const 0 call $answer
    i32.const 0 i32.const 0 call $answer
    i32.const 0 i32.const 0 call $reply)"#;
    let wat = module(body);
    for export in ["silent", "twice", "answers-twice"] {
        let (ended, _) = run(&engine, &wat, export, &[]);
        assert_eq!(aborted(&ended), AbortReason::BadReturnShape, "{export}");
    }
}

/// Collecting a register that is not filled, or naming memory the
/// module does not have, is the guest's violation.
#[test]
fn register_and_memory_misuse_are_abi_violations() {
    let engine = engine();
    let body = r#"
  (func (export "stale") i32.const 0 call $take)
  (func (export "scalar-arg") (param i64) i32.const 0 i32.const 0 call $arg)
  (func (export "twice-arg") (param i32)
    i32.const 0 i32.const 0 call $arg
    i32.const 0 i32.const 0 call $arg)
  (func (export "wild")
    i32.const 0 i32.const 0 i32.const 65530 i32.const 16 call $site_set)
  (func (export "wild-out")
    i32.const 0 i32.const 0 i32.const 65530 call $site_balance)
  (func (export "bad-rounding")
    i32.const 0 i32.const 0 i32.const 0 i32.const 9 i32.const 64 call $mul_div)"#;
    let wat = module(body);
    let cases: [(&str, &[GuestArg<'_>]); 5] = [
        ("stale", &[]),
        ("scalar-arg", &[GuestArg::U64(1)]),
        ("twice-arg", &[GuestArg::Bytes(b"x")]),
        ("wild", &[]),
        ("bad-rounding", &[]),
    ];
    for (export, args) in cases {
        let (ended, kernel) = run(&engine, &wat, export, args);
        assert_eq!(aborted(&ended), AbortReason::AbiViolation, "{export}");
        assert!(kernel.calls.is_empty(), "{export} reached the host");
    }
    // An out-pointer is judged when the result is written, so the host
    // has answered by then; the violation is the guest's all the same.
    let (ended, _) = run(&engine, &wat, "wild-out", &[]);
    assert_eq!(aborted(&ended), AbortReason::AbiViolation);
}

/// A trap keeps its class, a refusal keeps the kernel's, exhaustion is
/// the engine's, and a name the module does not export is its own.
#[test]
fn every_other_ending_keeps_its_class() {
    let engine = engine();
    let body = r#"
  (func (export "trap") unreachable)
  (func (export "refused") i32.const 99 i32.const 0 call $site_get drop)
  (func (export "spin") (loop br 0))"#;
    let wat = module(body);
    let (ended, _) = run(&engine, &wat, "trap", &[]);
    assert_eq!(aborted(&ended), AbortReason::Unreachable);
    let (ended, _) = run(&engine, &wat, "refused", &[]);
    assert_eq!(aborted(&ended), AbortReason::HandleUnknown);
    let (ended, _) = run_with(&engine, &wat, "spin", &[], Kernel::seeded(), 10_000);
    assert_eq!(aborted(&ended), AbortReason::OutOfGas);
    assert!(ended.exhausted);
    assert_eq!(ended.fuel, 10_000);
    let (ended, _) = run(&engine, &wat, "absent", &[]);
    assert_eq!(aborted(&ended), AbortReason::ExportMissing);
}

/// Fixed-width results land at their out-pointers: wides, a drawn word,
/// and the clock as a plain scalar.
#[test]
fn math_seals_and_the_clock_answer_in_place() {
    let engine = engine();
    let body = r#"
  (func (export "figures") (param $site i32)
    ;; 6 at 0 and 3 at 32, as wides
    i32.const 0 i64.const 6 i64.store
    i32.const 32 i64.const 3 i64.store
    ;; 6 * 3 / 3 -> 64
    i32.const 0 i32.const 32 i32.const 32 i32.const 0 i32.const 64 call $mul_div
    ;; sqrt(6 * 6) -> 96
    i32.const 0 i32.const 0 i32.const 96 call $geometric_mean
    ;; (6/3)*(3/6) -> 128, 160
    i32.const 0 i32.const 32 i32.const 32 i32.const 0 i32.const 128 i32.const 160
    call $fraction_compose
    ;; 3/6 against 6/3 -> the ordering at 192
    i32.const 192
    i32.const 32 i32.const 0 i32.const 0 i32.const 32 call $fraction_cmp
    i32.store
    ;; 6^2 rounding up -> 224 (at the fixed scale, whatever it is)
    i32.const 0 i32.const 2 i32.const 1 i32.const 224 call $fixed_pow
    ;; seal and open: the tag at 256, the word at 260
    local.get $site i32.const 0 call $site_seal
    i32.const 256
    local.get $site i32.const 0 i32.const 260 call $site_open_seal
    i32.store
    ;; the clock at 292
    i32.const 292 call $clock i64.store
    ;; everything from 0 to 300 is the answer
    i32.const 0 i32.const 300 call $answer
    i32.const 0 i32.const 0 call $reply)"#;
    let (ended, kernel) = run(
        &engine,
        &module(body),
        "figures",
        &[GuestArg::Site { site: 1 }],
    );
    let Invoked::Produced {
        answer: Some(answer),
        ..
    } = ended.result
    else {
        panic!("{:?}", ended.result);
    };
    let wide = |at: usize| -> [u64; 4] {
        let mut limbs = [0u64; 4];
        for (limb, chunk) in limbs.iter_mut().zip(answer[at..at + 32].as_chunks::<8>().0) {
            *limb = u64::from_le_bytes(*chunk);
        }
        limbs
    };
    assert_eq!(wide(64), [6, 0, 0, 0], "mul-div");
    assert_eq!(wide(96), [6, 0, 0, 0], "geometric-mean");
    assert_eq!(wide(128), [18, 0, 0, 0], "fraction-compose numerator");
    assert_eq!(wide(160), [18, 0, 0, 0], "fraction-compose denominator");
    assert_eq!(&answer[192..196], &0u32.to_le_bytes(), "3/6 < 6/3");
    assert_ne!(wide(224), [0; 4], "fixed-pow wrote something");
    assert_eq!(&answer[256..260], &1u32.to_le_bytes(), "ready");
    assert_eq!(&answer[260..292], &[0xA5; 32], "the word");
    assert_eq!(&answer[292..300], &CLOCK_MS.to_le_bytes());
    assert!(kernel.sealed[1]);
}

/// Instances are counted ids: minted from an id register, filed into
/// an interval, walked by index, and taken back out as an edge.
#[test]
fn instances_file_into_an_interval_and_come_back_out() {
    let engine = engine();
    let body = r#"
  (func (export "file") (param $site i32) (param $ids i32)
    (local $count i32) (local $b i32) (local $len i32)
    ;; the ids at 0, eight bytes each
    i32.const 1 i32.const 0 call $arg
    local.get $ids i32.const 3 i32.shr_u local.set $count
    ;; mint them and file them under "abc" (at 64)
    i32.const 64 i32.const 0x636261 i32.store
    i32.const 0 i32.const 0 local.get $count call $mint_instances local.set $b
    local.get $site i32.const 0 local.get $b i32.const 64 i32.const 3 call $site_instance_put
    ;; walk: count, covered, order of 0 at 128, entry 0 taken at 160
    local.get $site i32.const 0 call $site_count drop
    local.get $site i32.const 0 call $site_covered drop
    local.get $site i32.const 0 i32.const 0 i32.const 128 call $site_order
    local.get $site i32.const 0 i32.const 0 call $site_entry local.set $len
    i32.const 160 call $take
    ;; rewrite entry 0, insert at order 9 (at 128 rewritten), remove entry 1
    local.get $site i32.const 0 i32.const 0 i32.const 64 i32.const 2 call $site_entry_set
    i32.const 128 i64.const 9 i64.store
    local.get $site i32.const 0 i32.const 128 i32.const 64 i32.const 1 call $site_insert
    local.get $site i32.const 0 i32.const 1 call $site_remove
    ;; the site's own shape
    local.get $site call $site_len drop
    local.get $site i32.const 0 call $site_declared drop
    local.get $site i32.const 0 call $site_clear
    ;; take the first minted id back out, as the edge at 200
    i32.const 200
    local.get $site i32.const 0 i32.const 0 i32.const 1 call $site_instance_take
    i32.store
    i32.const 200 i32.const 1 call $reply)"#;
    let args = [GuestArg::Site { site: 1 }, GuestArg::Ids(&[5, 7])];
    let (ended, kernel) = run(&engine, &module(body), "file", &args);
    let Invoked::Produced {
        edges,
        answer: None,
    } = ended.result
    else {
        panic!("{:?}", ended.result);
    };
    assert_eq!(kernel.buckets[edges[0] as usize], Held::Ids(vec![5]));
    // Filed 5 and 7 under "abc"; entry 0 (5) rewritten to "ab"; 9
    // inserted as "a"; entry 1 (7) removed; then 5 taken back out.
    assert_eq!(kernel.entries[1], vec![(9, b"a".to_vec())]);
    assert!(kernel.values[1].is_empty(), "cleared");
    assert!(
        kernel
            .calls
            .iter()
            .any(|call| call == "mint-instances(0,[5, 7])")
    );
    assert!(
        kernel
            .calls
            .iter()
            .any(|call| call == "site-instance-put(1,0,2,[97, 98, 99])")
    );
}

/// The whole import list is what the linker defines: a module naming
/// one more, or one at another type, does not instantiate.
#[test]
fn an_import_outside_the_table_does_not_link() {
    let engine = engine();
    let mut linker = Linker::<Invoking<Kernel>>::new(&engine);
    add_kernel_imports(&mut linker).expect("the imports register");
    let unknown = format!(
        "(module\n{}  (import \"{STATE}\" \"site-forget\" (func))\n  (memory (export \"memory\") 1 1))",
        every_import()
    );
    let module = Module::new(&engine, parse_str(unknown).expect("parses")).expect("compiles");
    assert!(linker.instantiate_pre(&module).is_err());
    let retyped = format!(
        "(module\n  (import \"{STATE}\" \"site-get\" (func (param i32 i32) (result i64)))\n  \
         (memory (export \"memory\") 1 1))"
    );
    let module = Module::new(&engine, parse_str(retyped).expect("parses")).expect("compiles");
    assert!(linker.instantiate_pre(&module).is_err());
}

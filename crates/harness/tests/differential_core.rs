//! Differential lane 1, core modules: every exported function of every
//! fixture is invoked with an edge-value argument matrix under the blessed
//! engine and the reference interpreter; outcomes — result values or trap
//! kind — must match exactly. Fresh instances per invocation keep the two
//! sides' state histories identical.

use hyperscale_vm_ref::module::Ty;
use hyperscale_vm_ref::{RefInstance, RefModule, Trap as RefTrap, Value};
use hyperscale_vm_runtime::blessed_engine;
use wasmtime::error::Context;
use wasmtime::{Engine, Instance, Module, Result, Store, Trap, Val};
use wat::parse_str;

const I32_EDGES: [i32; 9] = [0, 1, -1, 2, 7, 31, 33, i32::MIN, i32::MAX];
const I64_EDGES: [i64; 9] = [0, 1, -1, 2, 7, 63, 65, i64::MIN, i64::MAX];

/// One observed outcome, comparable across implementations.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Values(Vec<Value>),
    Trap(RefTrap),
    HostError(String),
}

const fn map_trap(trap: Trap) -> Option<RefTrap> {
    match trap {
        Trap::UnreachableCodeReached => Some(RefTrap::Unreachable),
        Trap::IntegerDivisionByZero => Some(RefTrap::IntegerDivisionByZero),
        Trap::IntegerOverflow => Some(RefTrap::IntegerOverflow),
        Trap::MemoryOutOfBounds => Some(RefTrap::MemoryOutOfBounds),
        Trap::TableOutOfBounds => Some(RefTrap::TableOutOfBounds),
        Trap::IndirectCallToNull => Some(RefTrap::IndirectCallToNull),
        Trap::BadSignature => Some(RefTrap::BadSignature),
        _ => None,
    }
}

const FUEL: u64 = 1_000_000_000;

fn wasmtime_outcome(
    engine: &Engine,
    module: &Module,
    export: &str,
    args: &[Value],
) -> (Outcome, Option<u64>) {
    let mut store = Store::new(engine, ());
    store.set_fuel(FUEL).expect("fuel on");
    let instance = match Instance::new(&mut store, module, &[]) {
        Ok(i) => i,
        Err(e) => return (Outcome::HostError(format!("instantiate: {e:#}")), None),
    };
    let func = instance
        .get_func(&mut store, export)
        .expect("export exists");
    let vals: Vec<Val> = args
        .iter()
        .map(|v| match v {
            Value::I32(x) => Val::I32(*x),
            Value::I64(x) => Val::I64(*x),
        })
        .collect();
    let result_len = func.ty(&store).results().len();
    let mut results = vec![Val::I32(0); result_len];
    match func.call(&mut store, &vals, &mut results) {
        Ok(()) => {
            let fuel = FUEL - store.get_fuel().expect("fuel on");
            (
                Outcome::Values(
                    results
                        .iter()
                        .map(|v| match v {
                            Val::I32(x) => Value::I32(*x),
                            Val::I64(x) => Value::I64(*x),
                            other => panic!("non-integer result {other:?}"),
                        })
                        .collect(),
                ),
                Some(fuel),
            )
        }
        Err(e) => (
            e.downcast_ref::<Trap>().map_or_else(
                || Outcome::HostError(format!("{e:#}")),
                |t| {
                    map_trap(*t).map_or_else(
                        || Outcome::HostError(format!("unmapped trap {t:?}")),
                        Outcome::Trap,
                    )
                },
            ),
            None,
        ),
    }
}

fn ref_outcome(module: &RefModule, export: &str, args: &[Value]) -> (Outcome, Option<u64>) {
    let mut instance = match RefInstance::instantiate(module) {
        Ok(i) => i,
        Err(t) => return (Outcome::Trap(t), None),
    };
    match instance.invoke(export, args) {
        Ok(Ok(values)) => {
            let fuel = instance.fuel_consumed();
            (Outcome::Values(values), Some(fuel))
        }
        Ok(Err(trap)) => (Outcome::Trap(trap), None),
        Err(e) => (Outcome::HostError(format!("{e:#}")), None),
    }
}

/// Builds the argument matrix for a signature described by vm-ref's decoded
/// types (`true` = i64 parameter).
fn arg_matrix(params: &[bool]) -> Vec<Vec<Value>> {
    match params {
        [] => vec![vec![]],
        [a] => single(*a).map(|v| vec![v]).collect(),
        [a, b] => {
            let mut out = Vec::new();
            for x in single(*a) {
                for y in single(*b) {
                    out.push(vec![x, y]);
                }
            }
            out
        }
        _ => panic!("fixtures keep to at most two parameters"),
    }
}

fn single(is64: bool) -> Box<dyn Iterator<Item = Value>> {
    if is64 {
        Box::new(I64_EDGES.iter().map(|v| Value::I64(*v)))
    } else {
        Box::new(I32_EDGES.iter().map(|v| Value::I32(*v)))
    }
}

fn compare_fixture(name: &str, wat_text: &str) -> Result<usize> {
    let bytes = parse_str(wat_text).with_context(|| format!("fixture {name}"))?;
    let engine = blessed_engine()?;
    let module = Module::new(&engine, &bytes)?;
    let ref_module = RefModule::decode(&bytes).with_context(|| format!("decode {name}"))?;

    let mut exports: Vec<(String, u32)> = ref_module
        .exports
        .iter()
        .map(|(n, i)| (n.clone(), *i))
        .collect();
    exports.sort();

    let mut invocations = 0usize;
    for (export, func_idx) in exports {
        let func = &ref_module.funcs[func_idx as usize];
        let params: Vec<bool> = ref_module.types[func.ty as usize]
            .params
            .iter()
            .map(|t| matches!(t, Ty::I64))
            .collect();
        for args in arg_matrix(&params) {
            let (blessed, blessed_fuel) = wasmtime_outcome(&engine, &module, &export, &args);
            let (reference, ref_fuel) = ref_outcome(&ref_module, &export, &args);
            assert_eq!(
                blessed, reference,
                "divergence in {name}::{export} with args {args:?}"
            );
            if let (Some(b), Some(r)) = (blessed_fuel, ref_fuel) {
                assert_eq!(b, r, "fuel diverged in {name}::{export} with args {args:?}");
            }
            invocations += 1;
        }
    }
    Ok(invocations)
}

const ARITH32: &str = r#"
(module
  (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add)
  (func (export "sub") (param i32 i32) (result i32) local.get 0 local.get 1 i32.sub)
  (func (export "mul") (param i32 i32) (result i32) local.get 0 local.get 1 i32.mul)
  (func (export "divs") (param i32 i32) (result i32) local.get 0 local.get 1 i32.div_s)
  (func (export "divu") (param i32 i32) (result i32) local.get 0 local.get 1 i32.div_u)
  (func (export "rems") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_s)
  (func (export "remu") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rem_u))
"#;

const ARITH64: &str = r#"
(module
  (func (export "add") (param i64 i64) (result i64) local.get 0 local.get 1 i64.add)
  (func (export "mul") (param i64 i64) (result i64) local.get 0 local.get 1 i64.mul)
  (func (export "divs") (param i64 i64) (result i64) local.get 0 local.get 1 i64.div_s)
  (func (export "divu") (param i64 i64) (result i64) local.get 0 local.get 1 i64.div_u)
  (func (export "rems") (param i64 i64) (result i64) local.get 0 local.get 1 i64.rem_s)
  (func (export "remu") (param i64 i64) (result i64) local.get 0 local.get 1 i64.rem_u))
"#;

const BITS: &str = r#"
(module
  (func (export "shl32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.shl)
  (func (export "shrs32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.shr_s)
  (func (export "shru32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.shr_u)
  (func (export "rotl32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rotl)
  (func (export "rotr32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.rotr)
  (func (export "clz32") (param i32) (result i32) local.get 0 i32.clz)
  (func (export "ctz32") (param i32) (result i32) local.get 0 i32.ctz)
  (func (export "pop32") (param i32) (result i32) local.get 0 i32.popcnt)
  (func (export "ext8") (param i32) (result i32) local.get 0 i32.extend8_s)
  (func (export "ext16") (param i32) (result i32) local.get 0 i32.extend16_s)
  (func (export "shl64") (param i64 i64) (result i64) local.get 0 local.get 1 i64.shl)
  (func (export "shrs64") (param i64 i64) (result i64) local.get 0 local.get 1 i64.shr_s)
  (func (export "rotl64") (param i64 i64) (result i64) local.get 0 local.get 1 i64.rotl)
  (func (export "clz64") (param i64) (result i64) local.get 0 i64.clz)
  (func (export "ext32") (param i64) (result i64) local.get 0 i64.extend32_s)
  (func (export "wrap") (param i64) (result i32) local.get 0 i32.wrap_i64)
  (func (export "extu") (param i32) (result i64) local.get 0 i64.extend_i32_u)
  (func (export "exts") (param i32) (result i64) local.get 0 i64.extend_i32_s))
"#;

const CMP: &str = r#"
(module
  (func (export "lts32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.lt_s)
  (func (export "ltu32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.lt_u)
  (func (export "ges32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.ge_s)
  (func (export "geu32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.ge_u)
  (func (export "eqz32") (param i32) (result i32) local.get 0 i32.eqz)
  (func (export "lts64") (param i64 i64) (result i32) local.get 0 local.get 1 i64.lt_s)
  (func (export "ltu64") (param i64 i64) (result i32) local.get 0 local.get 1 i64.lt_u)
  (func (export "geu64") (param i64 i64) (result i32) local.get 0 local.get 1 i64.ge_u)
  (func (export "eqz64") (param i64) (result i32) local.get 0 i64.eqz))
"#;

const MEMORY: &str = r#"
(module
  (memory 1 2)
  (data (i32.const 16) "\01\02\03\04\05\06\07\08")
  (func (export "load32") (param i32) (result i32) local.get 0 i32.load)
  (func (export "load8u") (param i32) (result i32) local.get 0 i32.load8_u)
  (func (export "load8s") (param i32) (result i32) local.get 0 i32.load8_s)
  (func (export "load16u") (param i32) (result i32) local.get 0 i32.load16_u)
  (func (export "load64") (param i32) (result i64) local.get 0 i64.load)
  (func (export "load32u64") (param i32) (result i64) local.get 0 i64.load32_u)
  (func (export "store_load") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.store
    local.get 0
    i32.load)
  (func (export "store8_load32") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.store8
    local.get 0
    i32.load)
  (func (export "offset_load") (param i32) (result i32) local.get 0 i32.load offset=65528)
  (func (export "grow") (param i32) (result i32) local.get 0 memory.grow)
  (func (export "grow_then_size") (param i32) (result i32)
    local.get 0
    memory.grow
    drop
    memory.size)
  (func (export "fill") (param i32 i32) (result i32)
    local.get 0
    i32.const 9
    local.get 1
    memory.fill
    local.get 0
    i32.load8_u)
  (func (export "copy") (param i32 i32) (result i32)
    local.get 0
    i32.const 16
    local.get 1
    memory.copy
    local.get 0
    i32.load8_u))
"#;

const CONTROL: &str = r#"
(module
  (func (export "sum_loop") (param i64) (result i64)
    (local i64)
    block
      loop
        local.get 0
        i64.eqz
        br_if 1
        local.get 1
        local.get 0
        i64.add
        local.set 1
        local.get 0
        i64.const 1
        i64.sub
        local.set 0
        local.get 0
        i64.const 100000
        i64.gt_u
        br_if 1
        br 0
      end
    end
    local.get 1)
  (func (export "table_pick") (param i32) (result i32)
    block
      block
        block
          local.get 0
          br_table 0 1 2
        end
        i32.const 10
        return
      end
      i32.const 20
      return
    end
    i32.const 30)
  (func (export "if_params") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.const 1
    i32.and
    if (param i32) (result i32)
      i32.const 3
      i32.mul
    else
      i32.const 5
      i32.add
    end)
  (func (export "sel") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    local.get 0
    local.get 1
    i32.lt_s
    select)
  (func (export "early") (param i32) (result i32)
    local.get 0
    i32.eqz
    if
      i32.const -7
      return
    end
    local.get 0))
"#;

const INDIRECT: &str = r#"
(module
  (type $bin (func (param i32) (result i32)))
  (type $other (func (param i64) (result i64)))
  (table 4 4 funcref)
  (elem (i32.const 0) $double $negate $wrong)
  (func $double (type $bin) local.get 0 i32.const 2 i32.mul)
  (func $negate (type $bin) i32.const 0 local.get 0 i32.sub)
  (func $wrong (type $other) local.get 0)
  (func (export "dispatch") (param i32 i32) (result i32)
    local.get 1
    local.get 0
    call_indirect (type $bin))
  (func (export "chain") (param i32) (result i32)
    local.get 0
    call $double
    call $negate))
"#;

const GLOBALS: &str = r#"
(module
  (global $acc (mut i64) (i64.const 5))
  (func (export "bump") (param i64) (result i64)
    global.get $acc
    local.get 0
    i64.add
    global.set $acc
    global.get $acc)
  (func (export "unreach") (param i32) (result i32)
    local.get 0
    i32.eqz
    if
      unreachable
    end
    local.get 0))
"#;

#[test]
fn core_semantics_agree_between_blessed_engine_and_vm_ref() -> Result<()> {
    let fixtures = [
        ("arith32", ARITH32),
        ("arith64", ARITH64),
        ("bits", BITS),
        ("cmp", CMP),
        ("memory", MEMORY),
        ("control", CONTROL),
        ("indirect", INDIRECT),
        ("globals", GLOBALS),
    ];
    let mut total = 0usize;
    for (name, wat_text) in fixtures {
        total += compare_fixture(name, wat_text)?;
    }
    println!("differential lane 1: {total} invocations agreed");
    assert!(total > 1_000, "matrix unexpectedly small: {total}");
    Ok(())
}

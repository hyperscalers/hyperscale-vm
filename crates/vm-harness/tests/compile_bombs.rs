//! The compile-bomb corpus: crafted-but-valid modules at the profile's
//! structural bounds, plus the backend measurement that calibrates them.
//!
//! Two jobs: prove every at-bound shape validates and compiles (the bounds
//! are livable), and measure per-backend compile time at the bounds so the
//! calibration and the blessed-backend pin rest on numbers. The measurement
//! ceiling here is a harness sanity valve — consensus never sees a wall
//! clock; the bounds themselves are the deterministic defense.
//!
//! Run the measurement with
//! `cargo test --release --test compile_bombs -- --ignored --nocapture`.

use std::fmt::Write as _;
use std::time::Instant;

use hyperscale_vm_runtime::{profile, validate_component};
use wasmtime::{Config, Engine, Instance, Module, Result, Store, Strategy};
use wat::parse_str;

/// Sequentially chained blocks at the per-function bound.
fn bomb_blocks() -> String {
    let n = profile::MAX_BLOCKS_PER_FUNCTION;
    let mut body = String::new();
    for _ in 0..n {
        body.push_str("block end\n");
    }
    format!("(func (export \"f\") {body})")
}

/// Deeply nested blocks: the worst case for structured-control bookkeeping.
fn bomb_nesting() -> String {
    let n = profile::MAX_BLOCKS_PER_FUNCTION;
    let mut body = String::new();
    for _ in 0..n {
        body.push_str("block\n");
    }
    for _ in 0..n {
        body.push_str("end\n");
    }
    format!("(func (export \"f\") {body})")
}

/// One function body just under the byte bound: a long dependent add chain,
/// the register-pressure-free worst case for body length.
fn bomb_big_body() -> String {
    // Each `i32.const 1; i32.add` encodes to three bytes.
    let reps = (profile::MAX_FUNCTION_BODY_BYTES - 64) / 3;
    let mut body = String::from("i32.const 0\n");
    for _ in 0..reps {
        body.push_str("i32.const 1 i32.add\n");
    }
    format!("(func (export \"f\") (result i32) {body})")
}

/// The per-module function-count bound.
fn bomb_many_funcs() -> String {
    let n = profile::MAX_FUNCTIONS_PER_MODULE;
    let mut out = String::new();
    for i in 0..n {
        let _ = writeln!(out, "(func (export \"f{i}\") (result i32) i32.const {i})");
    }
    out
}

/// The per-module type-count bound, all distinct shapes.
fn bomb_many_types() -> String {
    let n = profile::MAX_TYPES_PER_MODULE;
    let mut out = String::new();
    for i in 0..n {
        let params = "i32 ".repeat(i % (profile::MAX_PARAMS_PER_FUNCTION + 1));
        let _ = writeln!(out, "(type (func (param {params})))");
    }
    out.push_str("(func (export \"f\"))");
    out
}

/// Max locals, max params, all live across a `br_table` with many targets.
fn bomb_locals_and_table() -> String {
    let locals = "(local i64) ".repeat(profile::MAX_LOCALS_PER_FUNCTION);
    let params = "(param i32) ".repeat(profile::MAX_PARAMS_PER_FUNCTION);
    let targets = (0..1_000).map(|_| "0").collect::<Vec<_>>().join(" ");
    format!(
        "(func (export \"f\") {params} (result i32)\n\
         {locals}\n\
         block\n\
         local.get 0\n\
         br_table {targets} 0\n\
         end\n\
         local.get 31)"
    )
}

/// The per-module global bound.
fn bomb_globals() -> String {
    let n = profile::MAX_GLOBALS_PER_MODULE;
    let mut out = String::new();
    for i in 0..n {
        let _ = writeln!(out, "(global (mut i64) (i64.const {i}))");
    }
    out.push_str("(func (export \"f\") (result i64) global.get 999)");
    out
}

fn bombs() -> Vec<(&'static str, String)> {
    vec![
        ("blocks", bomb_blocks()),
        ("nesting", bomb_nesting()),
        ("big_body", bomb_big_body()),
        ("many_funcs", bomb_many_funcs()),
        ("many_types", bomb_many_types()),
        ("locals_table", bomb_locals_and_table()),
        ("globals", bomb_globals()),
    ]
}

fn engine(strategy: Strategy) -> Result<Engine> {
    let mut config = Config::new();
    config.strategy(strategy);
    config.consume_fuel(true);
    Engine::new(&config)
}

/// Every at-bound bomb must clear the profile validator: the bounds must be
/// livable exactly at their values.
#[test]
fn at_bound_bombs_validate() -> Result<()> {
    for (name, core) in bombs() {
        let component = parse_str(format!("(component (core module {core}))"))?;
        validate_component(&component)
            .unwrap_or_else(|e| panic!("bomb {name} must validate at bound: {e}"));
    }
    Ok(())
}

/// The measurement: per-backend compile time for each at-bound bomb.
#[test]
#[ignore = "measurement; run in release with --ignored --nocapture"]
fn measure_backend_compile_times() -> Result<()> {
    let backends = [
        ("cranelift", engine(Strategy::Cranelift)?),
        ("winch", engine(Strategy::Winch)?),
    ];
    for (name, core) in bombs() {
        let wasm = parse_str(format!("(module {core})"))?;
        for (backend, engine) in &backends {
            let start = Instant::now();
            let result = Module::new(engine, &wasm);
            let elapsed = start.elapsed();
            match result {
                Ok(_) => println!(
                    "{name:14} {backend:10} {:>8.1} ms",
                    elapsed.as_secs_f64() * 1e3
                ),
                Err(e) => {
                    let first = e.to_string();
                    let first = first.lines().next().unwrap_or("").to_string();
                    println!("{name:14} {backend:10} FAILED: {first}");
                }
            }
            // Harness sanity valve only; the deterministic defense is the
            // structural bounds themselves.
            assert!(
                elapsed.as_secs() < 60,
                "{name} on {backend} took {elapsed:?}"
            );
        }
    }

    // Execution speed, the other side of the pin trade: a hot integer loop.
    let loop_wat = parse_str(
        r#"
        (module
          (func (export "work") (param i64) (result i64)
            (local i64)
            block
              loop
                local.get 0
                i64.eqz
                br_if 1
                local.get 1
                local.get 0
                i64.mul
                local.get 0
                i64.xor
                local.set 1
                local.get 0
                i64.const 1
                i64.sub
                local.set 0
                br 0
              end
            end
            local.get 1))
        "#,
    )?;
    for (backend, engine) in &backends {
        let module = Module::new(engine, &loop_wat)?;
        let mut store = Store::new(engine, ());
        store.set_fuel(u64::MAX / 2)?;
        let f = Instance::new(&mut store, &module, &[])?
            .get_typed_func::<i64, i64>(&mut store, "work")?;
        f.call(&mut store, 1_000_000)?; // warm
        let start = Instant::now();
        f.call(&mut store, 50_000_000)?;
        println!(
            "hot_loop 50M   {backend:10} {:>8.1} ms",
            start.elapsed().as_secs_f64() * 1e3
        );
    }
    Ok(())
}

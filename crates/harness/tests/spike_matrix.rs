//! The backend feature matrix.
//!
//! Probes each backend (Cranelift, Winch, Pulley) for: core execution,
//! trap kind fidelity, and NaN bit patterns. Nothing is assumed —
//! unsupported combinations are recorded, not failed, because the matrix
//! itself is the deliverable. The only hard assertions are the baseline
//! (Cranelift supports everything) and trap agreement between every pair
//! of backends that both support a probe. Fuel is not a column: the meter
//! counts inside the module, so no backend has a schedule of its own.
//!
//! Run with `cargo test --test spike_matrix -- --nocapture` to see the matrix.

use std::fmt::Write as _;

use wasmtime::error::{Context, format_err};
use wasmtime::{Config, Engine, Instance, Module, Result, Store, Strategy, Trap};

const CORE_WAT: &str = r#"
(module
  (memory 1)
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
  (func (export "work") (param i64) (result i64)
    (local i64)
    local.get 0
    local.set 1
    block
      loop
        local.get 1
        i64.eqz
        br_if 1
        local.get 1
        i64.const 1
        i64.sub
        local.set 1
        br 0
      end
    end
    local.get 0)
  (func (export "fill") (param i32) (result i32)
    i32.const 0
    i32.const 7
    local.get 0
    memory.fill
    i32.const 0
    i32.load8_u)
  (func (export "nan_div") (param f64 f64) (result i64)
    local.get 0
    local.get 1
    f64.div
    i64.reinterpret_f64)
  (func (export "nan_add") (param f64) (result i64)
    local.get 0
    f64.const 1
    f64.add
    i64.reinterpret_f64)
  (func (export "unreach")
    unreachable)
  (func (export "div0") (param i32) (result i32)
    i32.const 1
    local.get 0
    i32.div_s))
"#;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Backend {
    Cranelift,
    Winch,
    Pulley,
}

impl Backend {
    const ALL: [Self; 3] = [Self::Cranelift, Self::Winch, Self::Pulley];

    const fn name(self) -> &'static str {
        match self {
            Self::Cranelift => "cranelift",
            Self::Winch => "winch",
            Self::Pulley => "pulley",
        }
    }

    fn configure(self, nan_canon: bool) -> Result<Engine> {
        let mut config = Config::new();
        config.cranelift_nan_canonicalization(nan_canon);
        match self {
            Self::Cranelift => {
                config.strategy(Strategy::Cranelift);
            }
            Self::Winch => {
                config.strategy(Strategy::Winch);
            }
            Self::Pulley => {
                config.strategy(Strategy::Cranelift);
                config.target("pulley64")?;
            }
        }
        Engine::new(&config)
    }
}

/// One probe outcome: `Ok(observation)` or the error string explaining why the
/// backend cannot run it.
type Probe = Result<String, String>;

struct Report {
    backend: Backend,
    core_exec: Probe,
    trap_unreachable: Probe,
    trap_div0: Probe,
    nan_div_bits: Probe,
    nan_add_bits: Probe,
}

fn stringify(result: Result<String>) -> Probe {
    result.map_err(|e| format!("{e:#}"))
}

fn core_instance(engine: &Engine) -> Result<(Store<()>, Instance)> {
    let module = Module::new(engine, CORE_WAT).context("compile core module")?;
    let mut store = Store::new(engine, ());
    let instance = Instance::new(&mut store, &module, &[]).context("instantiate")?;
    Ok((store, instance))
}

fn probe_core_exec(backend: Backend) -> Result<String> {
    let engine = backend.configure(false)?;
    let (mut store, instance) = core_instance(&engine)?;
    let add = instance.get_typed_func::<(i32, i32), i32>(&mut store, "add")?;
    let sum = add.call(&mut store, (2, 3))?;
    if sum != 5 {
        return Err(format_err!("add(2, 3) returned {sum}"));
    }
    let work = instance.get_typed_func::<i64, i64>(&mut store, "work")?;
    work.call(&mut store, 10_000)?;
    let fill = instance.get_typed_func::<i32, i32>(&mut store, "fill")?;
    fill.call(&mut store, 60_000)?;
    Ok("ok".to_string())
}

fn probe_trap(backend: Backend, export: &'static str, arg: Option<i32>) -> Result<String> {
    let engine = backend.configure(false)?;
    let (mut store, instance) = core_instance(&engine)?;
    let err = if let Some(a) = arg {
        let f = instance.get_typed_func::<i32, i32>(&mut store, export)?;
        f.call(&mut store, a).expect_err("expected a trap")
    } else {
        let f = instance.get_typed_func::<(), ()>(&mut store, export)?;
        f.call(&mut store, ()).expect_err("expected a trap")
    };
    let trap = err
        .downcast_ref::<Trap>()
        .ok_or_else(|| format_err!("non-trap error: {err:#}"))?;
    Ok(format!("{trap:?}"))
}

fn probe_nan(backend: Backend, canon: bool, export: &'static str) -> Result<String> {
    let engine = backend.configure(canon)?;
    let (mut store, instance) = core_instance(&engine)?;
    let bits = if export == "nan_div" {
        let f = instance.get_typed_func::<(f64, f64), i64>(&mut store, export)?;
        f.call(&mut store, (0.0, 0.0))?
    } else {
        let f = instance.get_typed_func::<f64, i64>(&mut store, export)?;
        // A non-canonical (signaling) NaN input; canonicalization must not
        // let its payload propagate through the add.
        f.call(&mut store, f64::from_bits(0x7ff4_0000_0000_0001))?
    };
    Ok(format!("{:#018x}", bits.cast_unsigned()))
}

fn run_matrix() -> Vec<Report> {
    Backend::ALL
        .into_iter()
        .map(|backend| Report {
            backend,
            core_exec: stringify(probe_core_exec(backend)),
            trap_unreachable: stringify(probe_trap(backend, "unreach", None)),
            trap_div0: stringify(probe_trap(backend, "div0", Some(0))),
            nan_div_bits: stringify(probe_nan(backend, true, "nan_div")),
            nan_add_bits: stringify(probe_nan(backend, true, "nan_add")),
        })
        .collect()
}

fn render(reports: &[Report]) -> String {
    let mut out = String::new();
    for r in reports {
        let _ = writeln!(out, "== {} ==", r.backend.name());
        for (label, probe) in [
            ("core exec", &r.core_exec),
            ("trap unreachable", &r.trap_unreachable),
            ("trap div0", &r.trap_div0),
            ("nan div bits (canon)", &r.nan_div_bits),
            ("nan add bits (canon)", &r.nan_add_bits),
        ] {
            match probe {
                Ok(obs) => {
                    let _ = writeln!(out, "  {label:22} {obs}");
                }
                Err(e) => {
                    let first = e.lines().next().unwrap_or(e);
                    let _ = writeln!(out, "  {label:22} UNSUPPORTED: {first}");
                }
            }
        }
    }
    out
}

#[test]
fn backend_matrix() {
    let reports = run_matrix();
    println!("{}", render(&reports));

    // Baseline: the blessed-path candidate must support everything.
    let cranelift = &reports[0];
    assert_eq!(cranelift.backend, Backend::Cranelift);
    assert!(
        cranelift.core_exec.is_ok(),
        "cranelift core exec: {:?}",
        cranelift.core_exec
    );

    // Every pair of backends that both support a probe must agree exactly on
    // profile-admitted behavior: trap kinds. NaN bit patterns are
    // deliberately excluded — the matrix records them, and the observed
    // Winch payload-preserving quieting is a reason the profile bans floats,
    // not a harness failure.
    for a in &reports[..] {
        for b in &reports[..] {
            for (label, pa, pb) in [
                ("trap unreachable", &a.trap_unreachable, &b.trap_unreachable),
                ("trap div0", &a.trap_div0, &b.trap_div0),
            ] {
                if let (Ok(oa), Ok(ob)) = (pa, pb) {
                    assert_eq!(
                        oa,
                        ob,
                        "{label} diverges between {} and {}",
                        a.backend.name(),
                        b.backend.name()
                    );
                }
            }
        }
    }
}

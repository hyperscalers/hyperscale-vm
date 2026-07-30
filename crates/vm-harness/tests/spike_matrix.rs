//! Milestone 1 spike, questions 1–2: the backend feature matrix and
//! cross-backend fuel determinism.
//!
//! Probes each backend (Cranelift, Winch, Pulley) for: core execution under
//! fuel, component-model execution under fuel, trap kind fidelity, and NaN
//! bit patterns. Nothing is assumed — unsupported combinations are recorded,
//! not failed, because the matrix itself is the deliverable. The only hard
//! assertions are the baseline (Cranelift supports everything) and fuel/output
//! agreement between every pair of backends that both support a probe.
//!
//! Run with `cargo test --test spike_matrix -- --nocapture` to see the matrix.

use std::fmt::Write as _;

use anyhow::{Context, Result, anyhow};
use wasmtime::component::{Component, Linker as ComponentLinker};
use wasmtime::{Config, Engine, Instance, Module, Store, Strategy, Trap};

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

const COMPONENT_WAT: &str = r#"
(component
  (core module $m
    (func (export "add") (param i32 i32) (result i32)
      local.get 0
      local.get 1
      i32.add))
  (core instance $i (instantiate $m))
  (func (export "add") (param "a" u32) (param "b" u32) (result u32)
    (canon lift (core func $i "add"))))
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

    fn configure(self, fuel: bool, nan_canon: bool) -> Result<Engine> {
        let mut config = Config::new();
        config.consume_fuel(fuel);
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
    core_fuel: Probe,
    component_exec: Probe,
    component_fuel: Probe,
    trap_unreachable: Probe,
    trap_div0: Probe,
    nan_div_bits: Probe,
    nan_add_bits: Probe,
}

fn stringify(result: Result<String>) -> Probe {
    result.map_err(|e| format!("{e:#}"))
}

fn core_instance(engine: &Engine, fuel: Option<u64>) -> Result<(Store<()>, Instance)> {
    let module = Module::new(engine, CORE_WAT).context("compile core module")?;
    let mut store = Store::new(engine, ());
    if let Some(f) = fuel {
        store.set_fuel(f).context("set fuel")?;
    }
    let instance = Instance::new(&mut store, &module, &[]).context("instantiate")?;
    Ok((store, instance))
}

fn probe_core_exec(backend: Backend) -> Result<String> {
    let engine = backend.configure(false, false)?;
    let (mut store, instance) = core_instance(&engine, None)?;
    let add = instance.get_typed_func::<(i32, i32), i32>(&mut store, "add")?;
    let sum = add.call(&mut store, (2, 3))?;
    if sum != 5 {
        return Err(anyhow!("add(2, 3) returned {sum}"));
    }
    Ok("ok".to_string())
}

fn probe_core_fuel(backend: Backend) -> Result<String> {
    let engine = backend.configure(true, false)?;
    let (mut store, instance) = core_instance(&engine, Some(1_000_000))?;
    let work = instance.get_typed_func::<i64, i64>(&mut store, "work")?;
    work.call(&mut store, 10_000)?;
    let after_loop = store.get_fuel()?;
    let fill = instance.get_typed_func::<i32, i32>(&mut store, "fill")?;
    fill.call(&mut store, 60_000)?;
    let after_fill = store.get_fuel()?;
    Ok(format!(
        "loop10k={} fill60k={}",
        1_000_000 - after_loop,
        after_loop - after_fill
    ))
}

fn probe_component(backend: Backend, fuel: bool) -> Result<String> {
    let engine = backend.configure(fuel, false)?;
    let component = Component::new(&engine, COMPONENT_WAT).context("compile component")?;
    let linker = ComponentLinker::new(&engine);
    let mut store = Store::new(&engine, ());
    if fuel {
        store.set_fuel(1_000_000)?;
    }
    let instance = linker.instantiate(&mut store, &component)?;
    let add = instance.get_typed_func::<(u32, u32), (u32,)>(&mut store, "add")?;
    let (sum,) = add.call(&mut store, (2, 3))?;
    add.post_return(&mut store)?;
    if sum != 5 {
        return Err(anyhow!("component add(2, 3) returned {sum}"));
    }
    if fuel {
        let consumed = 1_000_000 - store.get_fuel()?;
        return Ok(format!("call={consumed}"));
    }
    Ok("ok".to_string())
}

fn probe_trap(backend: Backend, export: &'static str, arg: Option<i32>) -> Result<String> {
    let engine = backend.configure(false, false)?;
    let (mut store, instance) = core_instance(&engine, None)?;
    let err = if let Some(a) = arg {
        let f = instance.get_typed_func::<i32, i32>(&mut store, export)?;
        f.call(&mut store, a).expect_err("expected a trap")
    } else {
        let f = instance.get_typed_func::<(), ()>(&mut store, export)?;
        f.call(&mut store, ()).expect_err("expected a trap")
    };
    let trap = err
        .downcast_ref::<Trap>()
        .ok_or_else(|| anyhow!("non-trap error: {err:#}"))?;
    Ok(format!("{trap:?}"))
}

fn probe_nan(backend: Backend, canon: bool, export: &'static str) -> Result<String> {
    let engine = backend.configure(false, canon)?;
    let (mut store, instance) = core_instance(&engine, None)?;
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
            core_fuel: stringify(probe_core_fuel(backend)),
            component_exec: stringify(probe_component(backend, false)),
            component_fuel: stringify(probe_component(backend, true)),
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
            ("core fuel", &r.core_fuel),
            ("component exec", &r.component_exec),
            ("component fuel", &r.component_fuel),
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
fn backend_matrix_and_fuel_determinism() {
    let reports = run_matrix();
    println!("{}", render(&reports));

    // Baseline: the blessed-path candidate must support everything.
    let cranelift = &reports[0];
    assert_eq!(cranelift.backend, Backend::Cranelift);
    for (label, probe) in [
        ("core exec", &cranelift.core_exec),
        ("core fuel", &cranelift.core_fuel),
        ("component exec", &cranelift.component_exec),
        ("component fuel", &cranelift.component_fuel),
    ] {
        assert!(probe.is_ok(), "cranelift {label}: {probe:?}");
    }

    // Every pair of backends that both support a probe must agree exactly on
    // profile-admitted behavior: fuel counts and trap kinds. NaN bit patterns
    // are deliberately excluded — the matrix records them, and the observed
    // Winch payload-preserving quieting is a reason the profile bans floats,
    // not a harness failure.
    for a in &reports[..] {
        for b in &reports[..] {
            for (label, pa, pb) in [
                ("core fuel", &a.core_fuel, &b.core_fuel),
                ("component fuel", &a.component_fuel, &b.component_fuel),
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

#[test]
fn fuel_is_deterministic_across_runs() {
    // Ten fresh engine+store runs per backend must consume identical fuel.
    for backend in Backend::ALL {
        let runs: Vec<Probe> = (0..10)
            .map(|_| stringify(probe_core_fuel(backend)))
            .collect();
        let Ok(first) = &runs[0] else {
            continue; // Unsupported backends are recorded by the matrix test.
        };
        for run in &runs[1..] {
            assert_eq!(
                run.as_ref().ok(),
                Some(first),
                "fuel varies across runs on {}",
                backend.name()
            );
        }
    }
}

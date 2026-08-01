//! The component corpus: canon-option wiring as a generated axis.
//!
//! The core-module corpus is generated at volume; the component half of the
//! admission lane was two fixed artifacts, and every component-layer defect
//! found so far was found by hand-authoring a shape that `wit-bindgen`
//! emits or that composes canon options in an ordinary way. This lane
//! generates the wiring instead: which import is lowered, which canonical
//! options the lower carries, and which guest code the ABI runs as its
//! callback — including the shim-and-fixups pattern, where a third module's
//! element segment decides what a trampoline in a second module reaches.
//!
//! Every artifact is held to both implications at once. What the profile
//! admits, the spec must decode; what both runtimes load, they must agree
//! on, byte for byte, down to the fuel.

use std::fmt::Write as _;
use std::sync::Arc;

use hyperscale_vm_effects::{EffectSet, Hash32, Hasher, TestHasher};
use hyperscale_vm_harness::session_host::SessionHost;
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore, TxHash};
use hyperscale_vm_ref::{CVal, CanonError, ExecError, RefComponent, RefComponentInstance};
use hyperscale_vm_runtime::{add_kernel_to_linker, blessed_engine, validate_component};
use wasmtime::component::{Component, Linker};
use wasmtime::{Result, Store};
use wat::parse_str;

const FUEL: u64 = 1_000_000_000;

/// The import the generated component lowers. One per shape the canonical
/// ABI has to move: a scalar result, a list result, and a list in both
/// directions — the last two are the ones that call the guest's realloc.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Import {
    Clock,
    Randomness,
    Hash,
}

/// The canonical options the lower carries. A lowering that moves a list
/// needs both; the corpus generates the artifacts that leave one out so the
/// refusal is exercised rather than assumed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Options {
    Both,
    MemoryOnly,
    Neither,
}

/// What the canonical ABI runs as its own callback, and what that callback
/// can reach.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Wiring {
    /// A realloc that calls nothing.
    Plain,
    /// A realloc that calls through a trampoline whose table a third module
    /// fills with ordinary guest code.
    Shim,
    /// The same shim, with the lowered import in the table: the call cycle
    /// that closes through the canonical-ABI boundary.
    ///
    /// Only a cycle when a canon option names the function as its realloc.
    /// The corpus generates the option sets that do not, where the same
    /// module is ordinary guest code and the artifact is admitted — the
    /// refusal is about the callback position, not about the call.
    ReallocCycle,
    /// A post-return that calls the lowered import directly — it can,
    /// because the module carrying it is instantiated after the lower.
    PostReturnCycle,
}

#[derive(Clone, Copy, Debug)]
struct Spec {
    import: Import,
    options: Options,
    wiring: Wiring,
}

impl Import {
    /// The interface and function name, as the world declares it.
    const fn declaration(self) -> &'static str {
        match self {
            Self::Clock => {
                r#"(import "hyperscale:kernel/env" (instance $i
                     (export "clock" (func (result u64)))))
                   (alias export $i "clock" (func $imp))"#
            }
            Self::Randomness => {
                r#"(import "hyperscale:kernel/env" (instance $i
                     (export "randomness" (func (result (list u8))))))
                   (alias export $i "randomness" (func $imp))"#
            }
            Self::Hash => {
                r#"(import "hyperscale:kernel/crypto" (instance $i
                     (export "hash" (func (param "data" (list u8)) (result (list u8))))))
                   (alias export $i "hash" (func $imp))"#
            }
        }
    }

    /// The lowered function's core signature.
    const fn core_type(self) -> &'static str {
        match self {
            Self::Clock => "(result i64)",
            Self::Randomness => "(param i32)",
            Self::Hash => "(param i32 i32 i32)",
        }
    }

    /// Pushing the call's arguments: a return area, plus a source range for
    /// the lowering that takes a list.
    const fn args(self) -> &'static str {
        match self {
            Self::Clock => "",
            Self::Randomness => "i32.const 32",
            Self::Hash => "i32.const 0 i32.const 4 i32.const 32",
        }
    }

    /// Forwarding a stub's own parameters to the table entry.
    const fn forward(self) -> &'static str {
        match self {
            Self::Clock => "",
            Self::Randomness => "local.get 0",
            Self::Hash => "local.get 0 local.get 1 local.get 2",
        }
    }

    /// Discarding whatever the call left on the stack, for a caller that
    /// wants none of it.
    const fn discard(self) -> &'static str {
        match self {
            Self::Clock => "drop",
            _ => "",
        }
    }

    /// Turning the call's outcome into the export's `u64`: the clock is
    /// already one; a list result is read back through the return area.
    const fn result(self) -> &'static str {
        match self {
            Self::Clock => "",
            _ => "i32.const 32 i32.load i32.load8_u i64.extend_i32_u",
        }
    }

    /// Whether the lowering moves a list, and so calls the guest's realloc.
    const fn moves_a_list(self) -> bool {
        !matches!(self, Self::Clock)
    }
}

impl Options {
    fn text(self) -> String {
        match self {
            Self::Both => r#"(memory $a "mem") (realloc (func $a "realloc"))"#.to_string(),
            Self::MemoryOnly => r#"(memory $a "mem")"#.to_string(),
            Self::Neither => String::new(),
        }
    }
}

impl Spec {
    /// Every wiring, over every import, over every option set.
    fn corpus() -> Vec<Self> {
        let mut specs = Vec::new();
        for import in [Import::Clock, Import::Randomness, Import::Hash] {
            for options in [Options::Both, Options::MemoryOnly, Options::Neither] {
                for wiring in [
                    Wiring::Plain,
                    Wiring::Shim,
                    Wiring::ReallocCycle,
                    Wiring::PostReturnCycle,
                ] {
                    specs.push(Self {
                        import,
                        options,
                        wiring,
                    });
                }
            }
        }
        specs
    }

    const fn has_shim(self) -> bool {
        matches!(self.wiring, Wiring::Shim | Wiring::ReallocCycle)
    }

    /// A name for a failure message.
    fn label(self) -> String {
        format!("{:?}/{:?}/{:?}", self.import, self.options, self.wiring)
    }

    #[allow(clippy::too_many_lines)] // one template, assembled in declaration order
    fn wat(self) -> String {
        let core_type = self.import.core_type();
        let mut out = String::new();
        let _ = writeln!(out, "(component {}", self.import.declaration());

        // The trampoline, and the allocator that calls it. A realloc can
        // only reach a lowered import through a table: the import is
        // defined after the module carrying the realloc it names.
        if self.has_shim() {
            let _ = writeln!(
                out,
                r#"(core module $shim
                     (type $sig (func {core_type}))
                     (table (export "t") 1 1 funcref)
                     (func (export "stub") {core_type}
                       {forward}
                       i32.const 0
                       call_indirect (type $sig)))
                   (core instance $is (instantiate $shim))"#,
                forward = self.import.forward(),
            );
        }
        let (shim_import, reach) = if self.wiring == Wiring::ReallocCycle {
            (
                format!(r#"(import "shim" "stub" (func $stub {core_type}))"#),
                format!(
                    "{} call $stub {}",
                    self.import.args(),
                    self.import.discard()
                ),
            )
        } else {
            (String::new(), String::new())
        };
        let _ = writeln!(
            out,
            r#"(core module $alloc
                 {shim_import}
                 (memory (export "mem") 1 1)
                 (global $next (mut i32) (i32.const 1024))
                 (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                   (local $ret i32)
                   global.get $next
                   local.set $ret
                   global.get $next
                   local.get 3
                   i32.add
                   global.set $next
                   {reach}
                   local.get $ret))
               (core instance $a (instantiate $alloc {shim_arg}))"#,
            shim_arg = if self.wiring == Wiring::ReallocCycle {
                r#"(with "shim" (instance $is))"#
            } else {
                ""
            },
        );

        let _ = writeln!(
            out,
            "(core func $imp_l (canon lower (func $imp) {}))",
            self.options.text()
        );

        // The guest: it calls the import, and carries the two functions the
        // wiring may point at — a benign table entry, and a post-return.
        let post_return_body = if self.wiring == Wiring::PostReturnCycle {
            format!("{} call $imp {}", self.import.args(), self.import.discard())
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            r#"(core module $main
                 (import "env" "mem" (memory 1 1))
                 (import "k" "imp" (func $imp {core_type}))
                 (func (export "noop") {core_type}
                   {noop_body})
                 (func (export "post-return") (param i64)
                   {post_return_body})
                 (func (export "run") (result i64)
                   {args}
                   call $imp
                   {result}))
               (core instance $m (instantiate $main
                 (with "env" (instance $a))
                 (with "k" (instance (export "imp" (func $imp_l))))))"#,
            noop_body = match self.import {
                Import::Clock => "i64.const 0",
                _ => "",
            },
            args = self.import.args(),
            result = self.import.result(),
        );

        if self.has_shim() {
            let target = if self.wiring == Wiring::ReallocCycle {
                r#"(with "k" (instance (export "e" (func $imp_l))))"#
            } else {
                r#"(with "k" (instance (export "e" (func $m "noop"))))"#
            };
            let _ = writeln!(
                out,
                r#"(core module $fixups
                     (import "shim" "t" (table $t 1 1 funcref))
                     (import "k" "e" (func $target {core_type}))
                     (elem (table $t) (i32.const 0) func $target))
                   (core instance (instantiate $fixups
                     (with "shim" (instance $is))
                     {target}))"#,
            );
        }

        let post_return = if self.wiring == Wiring::PostReturnCycle {
            r#"(post-return (func $m "post-return"))"#
        } else {
            ""
        };
        let _ = writeln!(
            out,
            r#"(func (export "run") (result u64)
                 (canon lift (core func $m "run") {post_return})))"#
        );
        out
    }
}

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn session() -> KernelSession {
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &EffectSet::new(),
        TxHash(Hash32([0x55; 32])),
        EnvInputs {
            clock_ms: 424_242,
            randomness: [11; 32],
        },
        test_hash,
    )
    .expect("an empty declaration materializes")
}

/// One comparable outcome. Trap and refusal messages are engine-worded, so
/// the classes are compared rather than the strings — except the value,
/// which must agree exactly.
#[derive(Debug, PartialEq, Eq)]
enum LaneOutcome {
    Value(u64),
    CannotLeave,
    Trapped,
}

fn run_blessed(bytes: &[u8]) -> Result<(LaneOutcome, u64)> {
    let engine = blessed_engine()?;
    let component = Component::new(&engine, bytes)?;
    let mut linker = Linker::<SessionHost>::new(&engine);
    add_kernel_to_linker(&mut linker)?;
    let mut store = Store::new(&engine, SessionHost(session()));
    store.set_fuel(FUEL)?;
    let instance = linker.instantiate(&mut store, &component)?;
    let run = instance.get_typed_func::<(), (u64,)>(&mut store, "run")?;
    let outcome = match run.call(&mut store, ()) {
        Ok((value,)) => LaneOutcome::Value(value),
        Err(e) => {
            let message = format!("{e:#}");
            if message.contains("cannot leave component instance") {
                LaneOutcome::CannotLeave
            } else {
                LaneOutcome::Trapped
            }
        }
    };
    Ok((outcome, FUEL - store.get_fuel()?))
}

fn run_ref(bytes: &[u8]) -> Result<(LaneOutcome, u64)> {
    let comp = RefComponent::decode(bytes)?;
    let mut instance = RefComponentInstance::instantiate(&comp, SessionHost(session()))?;
    instance.set_fuel_limit(FUEL);
    let outcome = match instance.invoke("run", &[])? {
        Ok(values) => match values.as_slice() {
            [CVal::U64(value)] => LaneOutcome::Value(*value),
            other => panic!("the export's declared result is a u64, got {other:?}"),
        },
        Err(ExecError::Canon(CanonError::CannotLeave)) => LaneOutcome::CannotLeave,
        Err(_) => LaneOutcome::Trapped,
    };
    Ok((outcome, instance.fuel_consumed()))
}

#[test]
fn every_generated_wiring_is_admitted_and_agreed_or_refused_by_both() -> Result<()> {
    let mut admitted = 0usize;
    let mut refused = 0usize;
    let mut cycles = 0usize;
    let mut lists = false;

    for spec in Spec::corpus() {
        let label = spec.label();
        let bytes =
            parse_str(spec.wat()).unwrap_or_else(|e| panic!("{label}: generator emits WAT: {e}"));

        if let Err(refusal) = validate_component(&bytes) {
            refused += 1;
            if refusal.to_string().contains("lowered import") {
                cycles += 1;
                assert!(
                    matches!(spec.wiring, Wiring::ReallocCycle | Wiring::PostReturnCycle),
                    "{label}: refused as a callback cycle, and it is not one"
                );
            }
            continue;
        }

        admitted += 1;
        lists |= spec.import.moves_a_list();
        RefComponent::decode(&bytes).unwrap_or_else(|e| {
            panic!("{label}: the profile admits what the spec cannot decode: {e}")
        });

        let (blessed, blessed_fuel) = run_blessed(&bytes).unwrap_or_else(|e| {
            panic!("{label}: the profile admits what the engine will not load: {e:#}")
        });
        let (reference, ref_fuel) = run_ref(&bytes)?;
        assert_eq!(blessed, reference, "{label}: outcome diverged");
        assert_eq!(blessed_fuel, ref_fuel, "{label}: fuel diverged");
    }

    println!("component corpus: {admitted} admitted, {refused} refused, {cycles} callback cycles");
    assert!(admitted >= 8, "corpus yield too low to be evidence");
    assert!(
        lists,
        "no admitted artifact moves a list, so nothing exercised the realloc path"
    );
    assert!(cycles >= 4, "the callback cycles are not being generated");
    Ok(())
}

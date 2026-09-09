//! The host surface, held to the import table that declares it.
//!
//! Adding one kernel import touches several places. Some are compile
//! errors, because the `KernelHost` trait and the `abi` dispatch carry
//! them. The others are the edges between the table and the code that
//! answers it — the blessed engine's linker registration, the reference
//! interpreter's resolution, the meter's charge and its pin — and nothing
//! has been holding those together: an import reaching the table without
//! a `func_wrap` fails only if some fixture imports it.
//!
//! The import table is the source of truth here, and the code is read as
//! text: what is under test is that a name declared there was answered
//! everywhere, and a substring establishes that.

use std::path::Path;

use hyperscale_vm_embed::abi::{ABI, ENV, IMPORTS};
use hyperscale_vm_harness::fixtures::repo_root;

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    std::fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("{}: {error}", Path::new(path).display()))
}

/// The kernel's kebab name as Rust spells it.
fn snake(name: &str) -> String {
    name.replace('-', "_")
}

/// The imports the kernel answers with no charge of their own.
///
/// The register collects move bytes the kernel already priced when it
/// produced or consumed them, and a clock read reaches nothing the guest
/// could make expensive. What each costs is the call, which the engine
/// charges either way.
fn unmetered(module: &str) -> bool {
    module == ABI || module == ENV
}

/// Every name the blessed engine registers, read off the linker file.
fn registered(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for rest in source.split("import!(").skip(1) {
        // `import!(linker, MODULE, "name", ...`: the first literal. The
        // macro's own recursive arm names no import.
        if rest.trim_start().starts_with('$') {
            continue;
        }
        let open = rest.find('"').expect("a registration names its import");
        let close = rest[open + 1..].find('"').expect("the literal closes");
        names.push(rest[open + 1..open + 1 + close].to_owned());
    }
    for rest in source.split("func_wrap(").skip(1) {
        if rest.trim_start().starts_with('$') {
            continue;
        }
        let open = rest.find('"').expect("a wrap names its import");
        let close = rest[open + 1..].find('"').expect("the literal closes");
        names.push(rest[open + 1..open + 1 + close].to_owned());
    }
    names
}

/// Every name the reference interpreter resolves, read off its
/// dispatch table.
fn resolved(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix('(')?;
            let (_, rest) = rest.split_once(", \"")?;
            let (name, _) = rest.split_once("\") =>")?;
            Some(name.to_owned())
        })
        .collect()
}

/// Every import is answered at each of the edges the compiler does not
/// cover.
///
/// One test rather than several, because what fails is an import and
/// the author wants every place it is missing from at once.
#[test]
fn every_import_is_answered_at_every_edge() {
    let dispatch = read("crates/embed/src/abi.rs");
    let registered = registered(&read("crates/runtime/src/imports.rs"));
    let resolved = resolved(&read("crates/ref/src/boundary.rs"));
    let meter = read("crates/embed/src/meter.rs");
    let pins = read("crates/embed/tests/meter.rs");

    let mut missing = Vec::new();
    for (module, name, _, _) in IMPORTS {
        let mut absent = |edge: &str| missing.push(format!("{name}: {edge}"));
        if !dispatch.contains(&format!("pub fn {}<", snake(name))) {
            absent("the boundary states no dispatch of this name");
        }
        if !registered.iter().any(|found| found == name) {
            absent("the blessed engine registers no import of this name");
        }
        if !resolved.iter().any(|found| found == name) {
            absent("the reference interpreter resolves no import of this name");
        }
        // The charge sequence is one function per metered import, named
        // as Rust spells the kernel's kebab. A call the meter does not
        // stand in front of is one that costs nothing beyond the call
        // itself, which is a claim rather than an omission — so it is
        // named, and holding the list to the code is the other half.
        let charged = meter.contains(&format!("pub fn {}", snake(name)));
        if unmetered(module) {
            if charged {
                absent("the meter charges for it after all, so it is not unmetered");
            }
        } else {
            if !charged {
                absent("the meter charges nothing for it");
            }
            // The case's own name, at the indentation a case sits at —
            // the mock port names every function too, and a mock is not
            // a pin.
            if !pins.contains(&format!("\n            \"{name}\",\n")) {
                absent("no pinned charge sequence names it");
            }
        }
    }
    assert!(
        missing.is_empty(),
        "the table declares imports the code does not answer:\n  {}",
        missing.join("\n  ")
    );
}

/// And nothing answers an import the table does not declare.
///
/// The other direction, which is what keeps a retired import from
/// leaving a registration and a resolution behind it — both of which
/// would go on linking.
#[test]
fn nothing_answers_an_import_the_table_does_not_declare() {
    let declared: Vec<&str> = IMPORTS.iter().map(|(_, name, _, _)| *name).collect();
    for (edge, answered) in [
        (
            "the blessed engine registers",
            registered(&read("crates/runtime/src/imports.rs")),
        ),
        (
            "the reference interpreter resolves",
            resolved(&read("crates/ref/src/boundary.rs")),
        ),
    ] {
        assert_eq!(
            answered.len(),
            declared.len(),
            "{edge} {} imports where the table declares {}",
            answered.len(),
            declared.len()
        );
        for name in &answered {
            assert!(
                declared.contains(&name.as_str()),
                "{edge} `{name}`, which the table does not declare"
            );
        }
    }
}

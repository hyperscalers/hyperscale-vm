//! The host surface, held to the world file that declares it.
//!
//! Adding one kernel function touches twelve places. Six are compile
//! errors, because the `KernelHost` trait carries them. The other six
//! are the edges between the world file and the code that implements
//! it, and nothing has been holding those together — a function reaching
//! the world without a `func_wrap` fails only if some fixture imports
//! it, and one reaching the reference interpreter with the wrong arity
//! reads past the end of the call's operands.
//!
//! The world file is the source of truth here, read as text rather than
//! parsed into a model: what is under test is that a name declared there
//! was answered everywhere, and a substring establishes that. The same
//! technique `value_paths.rs` uses on the same file.

use std::collections::BTreeMap;
use std::path::Path;

use hyperscale_vm_harness::fixtures::repo_root;
use hyperscale_vm_ref::HostFn;

/// The canonical ABI's flat-parameter ceiling: past it, the arguments
/// travel through one pointer instead.
const MAX_FLAT_PARAMS: usize = 16;

/// One function the world declares.
struct WorldFn {
    /// The interface it is declared in, which is half its identity.
    interface: String,
    /// Its own name, as the world spells it.
    name: String,
    /// The parameter list, between the parentheses.
    params: String,
    /// What it answers with, where it answers with anything.
    result: Option<String>,
}

fn read(path: &str) -> String {
    let full = repo_root().join(path);
    std::fs::read_to_string(&full)
        .unwrap_or_else(|error| panic!("{}: {error}", Path::new(path).display()))
}

/// Every function the world declares, with the interface it sits in.
fn world_functions(world: &str) -> Vec<WorldFn> {
    let mut found = Vec::new();
    let mut interface = String::new();
    for line in world.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface ")
            && let Some(name) = rest.strip_suffix(" {")
        {
            name.clone_into(&mut interface);
            continue;
        }
        let Some((name, rest)) = line.split_once(": func") else {
            continue;
        };
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_lowercase() || c == '-') {
            continue;
        }
        let rest = rest.trim().trim_end_matches(';');
        let close = rest.rfind(')').expect("a signature closes its parameters");
        let params = rest[1..close].to_owned();
        let result = rest[close + 1..]
            .trim()
            .strip_prefix("->")
            .map(|answer| answer.trim().to_owned());
        found.push(WorldFn {
            interface: interface.clone(),
            name: name.to_owned(),
            params,
            result,
        });
    }
    found
}

/// The named shapes the world declares, as the lines that open them.
///
/// One entry per `record`, `enum` or `variant`, holding the body's own
/// lines — which is all the flattening needs: a record is the sum of its
/// fields and a variant is a discriminant beside the widest of its
/// payloads.
fn shapes(world: &str) -> BTreeMap<String, (String, Vec<String>)> {
    let mut found = BTreeMap::new();
    let lines: Vec<&str> = world.lines().map(str::trim).collect();
    for (index, line) in lines.iter().enumerate() {
        let Some((kind, rest)) = line.split_once(' ') else {
            continue;
        };
        if !matches!(kind, "record" | "enum" | "variant") {
            continue;
        }
        let Some(name) = rest.strip_suffix(" {") else {
            continue;
        };
        let body: Vec<String> = lines[index + 1..]
            .iter()
            .take_while(|line| **line != "}")
            .filter(|line| !line.starts_with("//") && !line.is_empty())
            .map(|line| (*line).trim_end_matches(',').to_owned())
            .collect();
        found.insert(name.to_owned(), (kind.to_owned(), body));
    }
    found
}

/// How many core values a type flattens into.
fn flat(ty: &str, shapes: &BTreeMap<String, (String, Vec<String>)>) -> usize {
    let ty = ty.trim();
    if let Some(inner) = ty.strip_prefix("tuple<").and_then(|t| t.strip_suffix('>')) {
        return split_types(inner).iter().map(|t| flat(t, shapes)).sum();
    }
    if let Some(inner) = ty.strip_prefix("option<").and_then(|t| t.strip_suffix('>')) {
        return 1 + flat(inner, shapes);
    }
    if ty.starts_with("list<") || ty == "string" {
        return 2;
    }
    if ty.starts_with("own<") || ty.starts_with("borrow<") {
        return 1;
    }
    match shapes.get(ty) {
        Some((kind, body)) if kind == "record" => body
            .iter()
            .filter_map(|field| field.split_once(':'))
            .map(|(_, ty)| flat(ty, shapes))
            .sum(),
        Some((kind, _)) if kind == "enum" => 1,
        Some((_, body)) => {
            let widest = body
                .iter()
                .map(|case| {
                    case.split_once('(')
                        .and_then(|(_, rest)| rest.strip_suffix(')'))
                        .map_or(0, |payload| flat(payload, shapes))
                })
                .max()
                .unwrap_or(0);
            1 + widest
        }
        // Every scalar the world uses is one core value wide, and a
        // resource handle is an index, which is one too.
        None => 1,
    }
}

/// Split a comma-separated type list, respecting the angle brackets a
/// generic carries.
fn split_types(list: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut current = String::new();
    for ch in list.chars() {
        match ch {
            '<' => {
                depth += 1;
                current.push(ch);
            }
            '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => parts.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if !current.trim().is_empty() {
        parts.push(current);
    }
    parts
}

/// The world functions the kernel answers with no charge of their own.
///
/// A clock read reaches nothing the guest could make expensive: no
/// substate, no allocation, no scan. What it costs is the call, which
/// the engine charges either way.
const UNMETERED: &[&str] = &["clock"];

/// Every host function the blessed engine wraps, by name.
fn func_wrapped(world: &str) -> Vec<String> {
    world
        .split("func_wrap(")
        .skip(1)
        .filter_map(|rest| {
            let open = rest.find('"')?;
            let close = rest[open + 1..].find('"')?;
            Some(rest[open + 1..open + 1 + close].to_owned())
        })
        .collect()
}

/// The parameter types of a signature, in order.
fn param_types(params: &str) -> Vec<String> {
    split_types(params)
        .iter()
        .filter_map(|param| param.split_once(':'))
        .map(|(_, ty)| ty.trim().to_owned())
        .collect()
}

/// The core parameter count the canonical ABI lowers a signature to.
///
/// The rule `HostFn::params` states in prose, executed: each parameter
/// flattens to its own width, a parameter list past the flat ceiling
/// travels through one pointer instead, and a result wider than one core
/// value costs the caller a return-area pointer appended to the list.
fn flat_arity(function: &WorldFn, shapes: &BTreeMap<String, (String, Vec<String>)>) -> usize {
    let flattened: usize = param_types(&function.params)
        .iter()
        .map(|ty| flat(ty, shapes))
        .sum();
    let params = if flattened > MAX_FLAT_PARAMS {
        1
    } else {
        flattened
    };
    let returns = function
        .result
        .as_ref()
        .is_some_and(|result| flat(result, shapes) > 1);
    params + usize::from(returns)
}

/// Every world function is answered at each of the five edges the
/// compiler does not cover.
///
/// One test rather than five, because what fails is a function and the
/// author wants every place it is missing from at once.
#[test]
fn every_world_function_is_answered_at_every_edge() {
    let world = read("crates/runtime/wit/kernel.wit");
    let shapes = shapes(&world);
    let functions = world_functions(&world);
    assert!(
        functions.len() > 30,
        "the world is the subject; parsing it found only {}",
        functions.len()
    );

    let wrapped = func_wrapped(&read("crates/runtime/src/world.rs"));
    let charges = read("crates/embed/src/meter.rs");
    let pins = read("crates/embed/tests/meter.rs");

    let mut missing = Vec::new();
    for function in &functions {
        let name = &function.name;
        let mut absent = |edge: &str| missing.push(format!("{name}: {edge}"));

        if !wrapped.contains(name) {
            absent("the blessed engine wraps no host function of this name");
        }
        let Some(host) = HostFn::named(&function.interface, name) else {
            absent("the reference interpreter resolves no import of this name");
            continue;
        };
        // The charge sequence is one function per world function, named
        // as Rust spells the world's kebab. A call the meter does not
        // stand in front of is one that costs nothing beyond the call
        // itself, which is a claim rather than an omission — so it is
        // named, and holding the list to the code is the other half.
        if !UNMETERED.contains(&name.as_str()) {
            if !charges.contains(&format!("pub fn {}", name.replace('-', "_"))) {
                absent("the meter charges nothing for it");
            }
            // The case's own name, at the indentation a case sits at —
            // the mock port names every function too, and a mock is not
            // a pin.
            if !pins.contains(&format!("\n            \"{name}\",\n")) {
                absent("no pinned charge sequence names it");
            }
        } else if charges.contains(&format!("pub fn {}", name.replace('-', "_"))) {
            absent("the meter charges for it after all, so it is not unmetered");
        }
        let (declared, computed) = (host.params(), flat_arity(function, &shapes));
        if declared != computed {
            absent(&format!(
                "the reference interpreter takes {declared} core parameters and the world \
                 flattens to {computed}"
            ));
        }
    }
    assert!(
        missing.is_empty(),
        "the world declares functions the code does not answer:\n  {}",
        missing.join("\n  ")
    );
}

/// And nothing answers a function the world does not declare.
///
/// The other direction, which is what keeps a retired function from
/// leaving a charge sequence and a pin behind it — both of which would
/// go on passing.
#[test]
fn nothing_resolves_an_import_the_world_does_not_declare() {
    let world = read("crates/runtime/wit/kernel.wit");
    let declared: Vec<(String, String)> = world_functions(&world)
        .into_iter()
        .map(|function| (function.interface, function.name))
        .collect();
    let reference = read("crates/ref/src/component.rs");

    let resolved: Vec<(String, String)> = reference
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix('(')?;
            let (interface, rest) = rest.split_once(", ")?;
            let (name, _) = rest.split_once(") => Some(Self::")?;
            Some((
                interface.trim_matches('"').to_owned(),
                name.trim_matches('"').to_owned(),
            ))
        })
        .collect();
    assert_eq!(resolved.len(), declared.len());
    for pair in &resolved {
        assert!(
            declared.contains(pair),
            "{}#{} resolves to an import the world does not declare",
            pair.0,
            pair.1
        );
    }
}

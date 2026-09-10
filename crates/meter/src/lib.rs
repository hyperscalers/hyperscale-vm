//! The fuel meter: a module made to count its own fuel, and the
//! schedule it counts by.
//!
//! Fuel is a receipt field, so what a module's execution costs is
//! protocol rather than an engine's accounting. The node instruments a
//! module once, at load: the pass adds one mutable `i64` global exported
//! as [`FUEL`] and one imported function, [`EXHAUST`] under the reserved
//! namespace [`NAMESPACE`], and writes the only instructions that touch
//! either. Every engine then runs the instrumented bytes and the counting
//! is the module's own, identical wherever it runs, and exhaustion is
//! decided in one place — the host answering `exhaust` — rather than by
//! whichever engine happened to trap.
//!
//! **A metering block** starts at function entry and after every
//! instruction whose successor is not certain: `block`, `loop`, `if`,
//! `else` and `end` labels, and the fall-through of `br_if`. `br`,
//! `br_table`, `return` and `unreachable` end one, and what follows them
//! up to the label that makes it reachable again is dead and never
//! charged. Calls do not split a block. At a block's entry the pass
//! emits `if fuel < cost { call exhaust }; fuel -= cost`, with `cost`
//! the schedule summed over the block's operators; a block that costs
//! nothing gets no check, because charging nothing is not an operation.
//! The bulk memory operators charge their byte count at run time through
//! the same check, over a scratch local the pass adds to the function.
//!
//! The counter never goes negative: a block is paid for whole before it
//! runs, so what the global holds at any ending — a return, a trap, an
//! exhaustion — is exact under one rule both engines share.
//!
//! Instantiation is prepaid by the host, off the bytes alone
//! ([`instantiation_cost`]): the global does not exist until the module
//! does, and the segments it applies are the one piece of work that runs
//! before any block.

use wasmparser::{
    BinaryReaderError, CompositeInnerType, DataKind, ExternalKind, Parser, Payload, TypeRef,
};

mod pass;
mod schedule;

pub use schedule::{FLAT, FREE, cost};

/// The import namespace the pass reserves; author bytes may not name it.
pub const NAMESPACE: &str = "hyperscale:meter";

/// The host function the pass imports under [`NAMESPACE`]: called when a
/// block's charge exceeds what the counter holds, it answers the
/// out-of-gas refusal and never returns.
pub const EXHAUST: &str = "exhaust";

/// The name the pass exports the counter under: a mutable `i64` the host
/// sets to the budget before a call and reads after it.
pub const FUEL: &str = "fuel";

/// Why the pass refused a module.
#[derive(Debug, thiserror::Error)]
pub enum PassError {
    /// The bytes do not parse as a core module.
    #[error("the module does not parse: {0}")]
    Malformed(String),
    /// The bytes already carry the meter's own names, which only the
    /// pass may write.
    #[error("the module already {0}")]
    Reserved(&'static str),
}

/// What the pass reads off a module before rewriting it.
#[derive(Debug, Default)]
struct Survey {
    /// Types the module declares, rec groups flattened.
    types: u32,
    /// The parameter count of every type, by type index.
    type_params: Vec<u32>,
    /// Functions the module imports: the low indices of its function
    /// space.
    imported_funcs: u32,
    /// Globals in the module's global space, imported and defined.
    globals: u32,
    /// The parameter count of every defined function, in code order.
    params: Vec<u32>,
    /// What instantiation is prepaid: one per active data segment plus
    /// one per byte it writes.
    data_cost: u64,
}

fn survey(bytes: &[u8]) -> Result<Survey, PassError> {
    let malformed = |error: BinaryReaderError| PassError::Malformed(error.to_string());
    let mut survey = Survey::default();
    let mut function_types: Vec<u32> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(malformed)? {
            Payload::TypeSection(reader) => {
                for group in reader {
                    for subtype in group.map_err(malformed)?.types() {
                        let params = match &subtype.composite_type.inner {
                            CompositeInnerType::Func(func) => func.params().len(),
                            _ => 0,
                        };
                        survey
                            .type_params
                            .push(u32::try_from(params).unwrap_or(u32::MAX));
                        survey.types += 1;
                    }
                }
            }
            Payload::ImportSection(reader) => {
                for import in reader.into_imports() {
                    let import = import.map_err(malformed)?;
                    if import.module == NAMESPACE {
                        return Err(PassError::Reserved("imports the meter's namespace"));
                    }
                    match import.ty {
                        TypeRef::Func(_) | TypeRef::FuncExact(_) => survey.imported_funcs += 1,
                        TypeRef::Global(_) => survey.globals += 1,
                        _ => {}
                    }
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    function_types.push(ty.map_err(malformed)?);
                }
            }
            Payload::GlobalSection(reader) => {
                survey.globals += reader.count();
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.map_err(malformed)?;
                    if export.name == FUEL && export.kind == ExternalKind::Global {
                        return Err(PassError::Reserved("exports the meter's counter"));
                    }
                }
            }
            Payload::DataSection(reader) => {
                for data in reader {
                    let data = data.map_err(malformed)?;
                    if matches!(data.kind, DataKind::Active { .. }) {
                        survey.data_cost = survey
                            .data_cost
                            .saturating_add(1)
                            .saturating_add(data.data.len() as u64);
                    }
                }
            }
            _ => {}
        }
    }
    survey.params = function_types
        .iter()
        .map(|ty| survey.type_params.get(*ty as usize).copied().unwrap_or(0))
        .collect();
    Ok(survey)
}

/// Instrument `bytes`: the same module, counting its own fuel.
///
/// A pure function of its input, so every node holding the same author
/// bytes runs the same instrumented module. The author's indices are
/// preserved where they can be — the meter's type, global and export are
/// appended past the author's — and the one index space that has to
/// move, the function space, moves by exactly the one import the pass
/// adds, applied to every reference the author's bytes make.
///
/// # Errors
///
/// [`PassError`]: the bytes do not parse, or already name the meter's
/// import namespace or export.
pub fn instrument(bytes: &[u8]) -> Result<Vec<u8>, PassError> {
    let survey = survey(bytes)?;
    pass::instrument(bytes, &survey)
}

/// What instantiating `bytes` costs, prepaid off the counter before the
/// module exists: one per active data segment, plus one per byte the
/// segment writes. Element segments cost nothing.
///
/// # Errors
///
/// [`PassError::Malformed`] where the bytes do not parse.
pub fn instantiation_cost(bytes: &[u8]) -> Result<u64, PassError> {
    Ok(survey(bytes)?.data_cost)
}

#[cfg(test)]
mod tests {
    use wasmparser::{ElementItems, ExternalKind, Operator, Parser, Payload, Validator};
    use wat::parse_str;

    use super::{EXHAUST, FUEL, NAMESPACE, PassError, instantiation_cost, instrument};

    /// Every function body of a module as short operator spellings,
    /// which is what an expected instruction sequence is written in.
    fn bodies(bytes: &[u8]) -> Vec<Vec<String>> {
        let mut bodies = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            if let Payload::CodeSectionEntry(body) = payload.expect("the module parses") {
                let mut ops = Vec::new();
                for op in body.get_operators_reader().expect("a body reads") {
                    ops.push(spell(&op.expect("an operator decodes")));
                }
                bodies.push(ops);
            }
        }
        bodies
    }

    fn spell(op: &Operator<'_>) -> String {
        match op {
            Operator::GlobalGet { global_index } => format!("global.get {global_index}"),
            Operator::GlobalSet { global_index } => format!("global.set {global_index}"),
            Operator::LocalGet { local_index } => format!("local.get {local_index}"),
            Operator::LocalSet { local_index } => format!("local.set {local_index}"),
            Operator::LocalTee { local_index } => format!("local.tee {local_index}"),
            Operator::I32Const { value } => format!("i32.const {value}"),
            Operator::I64Const { value } => format!("i64.const {value}"),
            Operator::Call { function_index } => format!("call {function_index}"),
            Operator::Br { relative_depth } => format!("br {relative_depth}"),
            Operator::BrIf { relative_depth } => format!("br_if {relative_depth}"),
            Operator::I64LtU => "i64.lt_u".into(),
            Operator::I64Sub => "i64.sub".into(),
            Operator::I64ExtendI32U => "i64.extend_i32_u".into(),
            Operator::I32Add => "i32.add".into(),
            Operator::If { .. } => "if".into(),
            Operator::Else => "else".into(),
            Operator::End => "end".into(),
            Operator::Block { .. } => "block".into(),
            Operator::Loop { .. } => "loop".into(),
            Operator::Return => "return".into(),
            Operator::Unreachable => "unreachable".into(),
            Operator::Drop => "drop".into(),
            Operator::Nop => "nop".into(),
            Operator::MemoryFill { .. } => "memory.fill".into(),
            Operator::MemoryCopy { .. } => "memory.copy".into(),
            other => format!("{other:?}"),
        }
    }

    /// The check the pass emits at a block charged `cost`, over the
    /// counter at `fuel` and the exhaust import at `exhaust`.
    fn check(cost: u64, fuel: u32, exhaust: u32) -> Vec<String> {
        vec![
            format!("global.get {fuel}"),
            format!("i64.const {cost}"),
            "i64.lt_u".into(),
            "if".into(),
            format!("call {exhaust}"),
            "end".into(),
            format!("global.get {fuel}"),
            format!("i64.const {cost}"),
            "i64.sub".into(),
            format!("global.set {fuel}"),
        ]
    }

    fn seq(parts: &[Vec<String>]) -> Vec<String> {
        parts.iter().flatten().cloned().collect()
    }

    fn ops(spelled: &[&str]) -> Vec<String> {
        spelled.iter().map(|s| (*s).to_owned()).collect()
    }

    fn valid(bytes: &[u8]) {
        Validator::new()
            .validate_all(bytes)
            .expect("the instrumented module validates");
    }

    #[test]
    fn the_pass_is_a_function_of_its_input() {
        let bytes = parse_str(r#"(module (func (export "f") (result i32) i32.const 1))"#).unwrap();
        let once = instrument(&bytes).unwrap();
        let twice = instrument(&bytes).unwrap();
        assert_eq!(once, twice);
        assert_ne!(once, bytes);
        valid(&once);
    }

    #[test]
    fn an_instrumented_module_carries_the_counter_and_the_exhaust_import() {
        let bytes = parse_str(r#"(module (func (export "f")))"#).unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        let mut imports = Vec::new();
        let mut exports = Vec::new();
        for payload in Parser::new(0).parse_all(&out) {
            match payload.unwrap() {
                Payload::ImportSection(reader) => {
                    for import in reader.into_imports() {
                        let import = import.unwrap();
                        imports.push((import.module.to_owned(), import.name.to_owned()));
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.unwrap();
                        exports.push((export.name.to_owned(), export.kind, export.index));
                    }
                }
                _ => {}
            }
        }
        assert_eq!(imports, vec![(NAMESPACE.to_owned(), EXHAUST.to_owned())]);
        assert!(
            exports.contains(&(FUEL.to_owned(), ExternalKind::Global, 0)),
            "{exports:?}"
        );
        // The author's export is still there, its function shifted past
        // the one import the pass added.
        assert!(exports.contains(&("f".to_owned(), ExternalKind::Func, 1)));
    }

    /// One straight-line body is one block, paid for at entry.
    #[test]
    fn a_straight_line_body_is_one_block_charged_at_entry() {
        let bytes = parse_str(
            r#"(module (func (export "f") (param i32) (result i32)
                local.get 0 i32.const 1 i32.add))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        // local.get, i32.const, i32.add cost one each; the function's end
        // is free, so the block charges three.
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                check(3, 0, 0),
                ops(&["local.get 0", "i32.const 1", "i32.add", "end"]),
            ])]
        );
    }

    /// Every label opens a block, and the operator that opened it is
    /// paid for by the block before.
    #[test]
    fn labels_split_blocks_and_a_free_block_gets_no_check() {
        let bytes = parse_str(
            r#"(module (func (export "f") (param i32) (result i32)
                local.get 0
                if (result i32)
                  i32.const 1
                else
                  i32.const 2
                end))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                // local.get and the if: two.
                check(2, 0, 0),
                ops(&["local.get 0", "if"]),
                // The then arm and its else: one.
                check(1, 0, 0),
                ops(&["i32.const 1", "else"]),
                // The else arm and its end: one.
                check(1, 0, 0),
                ops(&["i32.const 2", "end"]),
                // The function's own end costs nothing, so no check.
                ops(&["end"]),
            ])]
        );
    }

    /// A loop body is charged on every entry, including each back edge,
    /// and the fall-through of a conditional branch opens a block.
    #[test]
    fn a_loop_body_is_charged_per_iteration() {
        let bytes = parse_str(
            r#"(module (func (export "f") (param i32)
                block
                  loop
                    local.get 0
                    br_if 1
                    br 0
                  end
                end))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                // block and loop are free: nothing to check at entry.
                ops(&["block", "loop"]),
                // The loop header's block: local.get and br_if.
                check(2, 0, 0),
                ops(&["local.get 0", "br_if 1"]),
                // The fall-through: the br.
                check(1, 0, 0),
                ops(&["br 0"]),
                // Dead until the loop's end, then two free ends.
                ops(&["end", "end", "end"]),
            ])]
        );
    }

    /// Code after an unconditional branch is dead until the label that
    /// makes it reachable again, and is never charged.
    #[test]
    fn dead_code_is_not_charged() {
        let bytes = parse_str(
            r#"(module (func (export "f") (result i32)
                block (result i32)
                  i32.const 1
                  br 0
                  block
                    nop
                  end
                  i32.const 2
                end
                i32.const 3
                i32.add))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                ops(&["block"]),
                check(2, 0, 0),
                ops(&["i32.const 1", "br 0"]),
                // Dead: the nested block and the constant after it.
                ops(&["block", "nop", "end", "i32.const 2", "end"]),
                // Live again after the block's end.
                check(2, 0, 0),
                ops(&["i32.const 3", "i32.add", "end"]),
            ])]
        );
    }

    /// A bulk operator charges its byte count where it runs, through a
    /// scratch local the pass adds past the author's.
    #[test]
    fn bulk_operators_charge_their_bytes_at_run_time() {
        let bytes = parse_str(
            r#"(module (memory 1) (func (export "f") (param i32) (local i32)
                i32.const 0 i32.const 0 local.get 0 memory.fill))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        // One param and one local: the scratch is local 2.
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                check(4, 0, 0),
                ops(&["i32.const 0", "i32.const 0", "local.get 0"]),
                ops(&[
                    "local.tee 2",
                    "global.get 0",
                    "local.get 2",
                    "i64.extend_i32_u",
                    "i64.lt_u",
                    "if",
                    "call 0",
                    "end",
                    "global.get 0",
                    "local.get 2",
                    "i64.extend_i32_u",
                    "i64.sub",
                    "global.set 0",
                ]),
                ops(&["memory.fill", "end"]),
            ])]
        );
    }

    /// The author's function references move past the one import the
    /// pass adds; its own globals and types keep their indices.
    #[test]
    fn author_indices_move_only_where_the_import_forces_them() {
        let bytes = parse_str(
            r#"(module
                (import "host" "h" (func $h))
                (global $g (mut i32) (i32.const 0))
                (table 1 1 funcref)
                (elem (i32.const 0) $f)
                (func $f (export "f") global.get $g global.set $g call $h call $f))"#,
        )
        .unwrap();
        let out = instrument(&bytes).unwrap();
        valid(&out);
        // The author's import keeps index 0; exhaust is 1; $f moves to 2;
        // the author's global keeps 0 and the counter is 1.
        assert_eq!(
            bodies(&out),
            vec![seq(&[
                check(4, 1, 1),
                ops(&["global.get 0", "global.set 0", "call 0", "call 2", "end"]),
            ])]
        );
        let mut elements = Vec::new();
        for payload in Parser::new(0).parse_all(&out) {
            if let Payload::ElementSection(reader) = payload.unwrap() {
                for element in reader {
                    if let ElementItems::Functions(items) = element.unwrap().items {
                        elements.extend(items.into_iter().map(Result::unwrap));
                    }
                }
            }
        }
        assert_eq!(elements, vec![2]);
    }

    #[test]
    fn instantiation_is_priced_per_segment_and_per_byte() {
        let empty = parse_str("(module (memory 1))").unwrap();
        assert_eq!(instantiation_cost(&empty).unwrap(), 0);
        let seeded = parse_str(
            r#"(module (memory 1) (data (i32.const 0) "abc") (data (i32.const 8) "de"))"#,
        )
        .unwrap();
        assert_eq!(instantiation_cost(&seeded).unwrap(), (1 + 3) + (1 + 2));
    }

    #[test]
    fn the_meters_own_names_are_refused_in_author_bytes() {
        let imports = parse_str(format!(
            r#"(module (import "{NAMESPACE}" "{EXHAUST}" (func)))"#
        ))
        .unwrap();
        assert!(matches!(instrument(&imports), Err(PassError::Reserved(_))));
        let exports = parse_str(format!(
            r#"(module (global (export "{FUEL}") (mut i64) (i64.const 0)))"#
        ))
        .unwrap();
        assert!(matches!(instrument(&exports), Err(PassError::Reserved(_))));
        // And so an instrumented module cannot be instrumented again.
        let once = instrument(&parse_str("(module (func))").unwrap()).unwrap();
        assert!(matches!(instrument(&once), Err(PassError::Reserved(_))));
    }

    #[test]
    fn a_module_with_no_sections_still_gains_the_meter() {
        let out = instrument(&parse_str("(module)").unwrap()).unwrap();
        valid(&out);
        assert!(matches!(instrument(&out), Err(PassError::Reserved(_))));
    }
}

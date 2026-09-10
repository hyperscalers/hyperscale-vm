//! The pass: one re-encoding of the author's module with the counter,
//! the exhaust import, and a check at the head of every metering block.
//!
//! Built on the encoder's round trip so every section the pass does not
//! touch comes through byte for byte in meaning, custom sections
//! included, and the one index space the pass has to shift — functions,
//! by the import it adds — is shifted at every reference through one
//! hook rather than at each kind of reference by hand.

use core::convert::Infallible;
use std::collections::BTreeSet;

use wasm_encoder::reencode::{self, Reencode};
use wasm_encoder::{
    BlockType, CodeSection, ConstExpr, EntityType, ExportKind, ExportSection, Function,
    GlobalSection, GlobalType, ImportSection, Instruction, Module, SectionId, TypeSection, ValType,
};
use wasmparser::{
    ExportSectionReader, FunctionBody, GlobalSectionReader, ImportSectionReader, Operator, Parser,
    TypeSectionReader,
};

use crate::schedule::{PAGE, cost};
use crate::{EXHAUST, FUEL, NAMESPACE, PassError, Survey};

struct Pass<'s> {
    survey: &'s Survey,
    /// The exhaust import's function index: past every function the
    /// author imported, before every one the author defined.
    exhaust: u32,
    /// The type the exhaust import is declared at: past the author's.
    exhaust_type: u32,
    /// The counter's global index: past the author's.
    fuel: u32,
    /// Bodies re-encoded so far, which is the index of the next one in
    /// the survey's per-function facts.
    bodies: usize,
    /// The sections the pass adds to, by position, once written — so a
    /// section the author's module lacks is inserted where the binary
    /// format wants it, and one it has is extended in place.
    placed: BTreeSet<u8>,
}

/// Where a section stands in the binary order, so a missing one can be
/// slotted in at the hook between the sections that exist.
const fn position(id: SectionId) -> u8 {
    match id {
        SectionId::Custom => 0,
        SectionId::Type => 1,
        SectionId::Import => 2,
        SectionId::Function => 3,
        SectionId::Table => 4,
        SectionId::Memory => 5,
        SectionId::Tag => 6,
        SectionId::Global => 7,
        SectionId::Export => 8,
        SectionId::Start => 9,
        SectionId::Element => 10,
        SectionId::DataCount => 11,
        SectionId::Code => 12,
        SectionId::Data => 13,
    }
}

/// Whether the operator opens a metering block after itself: a label,
/// or the fall-through of a conditional branch.
const fn opens_block(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::Block { .. }
            | Operator::Loop { .. }
            | Operator::If { .. }
            | Operator::Else
            | Operator::End
            | Operator::BrIf { .. }
    )
}

/// Whether the operator ends a block with nothing reachable after it
/// until the next label.
const fn ends_block(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::Br { .. } | Operator::BrTable { .. } | Operator::Return | Operator::Unreachable
    )
}

/// What an operator charges at run time over the count on top of the
/// stack: one per byte moved, or [`PAGE`] per page grown.
const fn per_unit(op: &Operator<'_>) -> Option<u64> {
    match op {
        Operator::MemoryFill { .. } | Operator::MemoryCopy { .. } | Operator::MemoryInit { .. } => {
            Some(1)
        }
        Operator::MemoryGrow { .. } => Some(PAGE),
        _ => None,
    }
}

/// The charge of the block starting at `ops[0]`: the schedule summed up
/// to and including the operator that closes it.
fn block_charge(ops: &[Operator<'_>]) -> u64 {
    let mut charge = 0u64;
    for op in ops {
        charge = charge.saturating_add(cost(op));
        if opens_block(op) || ends_block(op) {
            break;
        }
    }
    charge
}

impl Pass<'_> {
    const fn new(survey: &Survey) -> Pass<'_> {
        Pass {
            survey,
            exhaust: survey.imported_funcs,
            exhaust_type: survey.types,
            fuel: survey.globals,
            bodies: 0,
            placed: BTreeSet::new(),
        }
    }

    fn exhaust_type(types: &mut TypeSection) {
        types.ty().function([], []);
    }

    fn exhaust_import(&self, imports: &mut ImportSection) {
        imports.import(NAMESPACE, EXHAUST, EntityType::Function(self.exhaust_type));
    }

    fn fuel_global(globals: &mut GlobalSection) {
        globals.global(
            GlobalType {
                val_type: ValType::I64,
                mutable: true,
                shared: false,
            },
            &ConstExpr::i64_const(0),
        );
    }

    fn fuel_export(&self, exports: &mut ExportSection) {
        exports.export(FUEL, ExportKind::Global, self.fuel);
    }

    /// `if fuel < cost { exhaust() }; fuel -= cost`.
    fn check(&self, f: &mut Function, charge: u64) {
        let charge = i64::try_from(charge).unwrap_or(i64::MAX);
        f.instruction(&Instruction::GlobalGet(self.fuel));
        f.instruction(&Instruction::I64Const(charge));
        f.instruction(&Instruction::I64LtU);
        f.instruction(&Instruction::If(BlockType::Empty));
        f.instruction(&Instruction::Call(self.exhaust));
        f.instruction(&Instruction::End);
        f.instruction(&Instruction::GlobalGet(self.fuel));
        f.instruction(&Instruction::I64Const(charge));
        f.instruction(&Instruction::I64Sub);
        f.instruction(&Instruction::GlobalSet(self.fuel));
    }

    /// The same check over the count on top of the stack at `unit` each,
    /// teed into `scratch` so the operator that consumes the count still
    /// finds it there. A unit of one emits no multiply.
    fn check_counted(&self, f: &mut Function, scratch: u32, unit: u64) {
        let unit = i64::try_from(unit).unwrap_or(i64::MAX);
        let scaled = |f: &mut Function| {
            f.instruction(&Instruction::LocalGet(scratch));
            f.instruction(&Instruction::I64ExtendI32U);
            if unit != 1 {
                f.instruction(&Instruction::I64Const(unit));
                f.instruction(&Instruction::I64Mul);
            }
        };
        f.instruction(&Instruction::LocalTee(scratch));
        f.instruction(&Instruction::GlobalGet(self.fuel));
        scaled(f);
        f.instruction(&Instruction::I64LtU);
        f.instruction(&Instruction::If(BlockType::Empty));
        f.instruction(&Instruction::Call(self.exhaust));
        f.instruction(&Instruction::End);
        f.instruction(&Instruction::GlobalGet(self.fuel));
        scaled(f);
        f.instruction(&Instruction::I64Sub);
        f.instruction(&Instruction::GlobalSet(self.fuel));
    }
}

impl Reencode for Pass<'_> {
    type Error = Infallible;

    fn function_index(&mut self, func: u32) -> Result<u32, reencode::Error<Infallible>> {
        Ok(if func >= self.exhaust { func + 1 } else { func })
    }

    fn parse_type_section(
        &mut self,
        types: &mut TypeSection,
        section: TypeSectionReader<'_>,
    ) -> Result<(), reencode::Error<Infallible>> {
        reencode::utils::parse_type_section(self, types, section)?;
        Self::exhaust_type(types);
        self.placed.insert(position(SectionId::Type));
        Ok(())
    }

    fn parse_import_section(
        &mut self,
        imports: &mut ImportSection,
        section: ImportSectionReader<'_>,
    ) -> Result<(), reencode::Error<Infallible>> {
        reencode::utils::parse_import_section(self, imports, section)?;
        self.exhaust_import(imports);
        self.placed.insert(position(SectionId::Import));
        Ok(())
    }

    fn parse_global_section(
        &mut self,
        globals: &mut GlobalSection,
        section: GlobalSectionReader<'_>,
    ) -> Result<(), reencode::Error<Infallible>> {
        reencode::utils::parse_global_section(self, globals, section)?;
        Self::fuel_global(globals);
        self.placed.insert(position(SectionId::Global));
        Ok(())
    }

    fn parse_export_section(
        &mut self,
        exports: &mut ExportSection,
        section: ExportSectionReader<'_>,
    ) -> Result<(), reencode::Error<Infallible>> {
        reencode::utils::parse_export_section(self, exports, section)?;
        self.fuel_export(exports);
        self.placed.insert(position(SectionId::Export));
        Ok(())
    }

    /// A section the author's module lacks is written whole, at the
    /// point in the binary order where the next section present would
    /// otherwise overtake it.
    fn intersperse_section_hook(
        &mut self,
        module: &mut Module,
        _after: Option<SectionId>,
        before: Option<SectionId>,
    ) -> Result<(), reencode::Error<Infallible>> {
        let upto = before.map_or(u8::MAX, position);
        let due = |placed: &BTreeSet<u8>, id: SectionId| {
            !placed.contains(&position(id)) && upto > position(id)
        };
        if due(&self.placed, SectionId::Type) {
            let mut types = TypeSection::new();
            Self::exhaust_type(&mut types);
            module.section(&types);
            self.placed.insert(position(SectionId::Type));
        }
        if due(&self.placed, SectionId::Import) {
            let mut imports = ImportSection::new();
            self.exhaust_import(&mut imports);
            module.section(&imports);
            self.placed.insert(position(SectionId::Import));
        }
        if due(&self.placed, SectionId::Global) {
            let mut globals = GlobalSection::new();
            Self::fuel_global(&mut globals);
            module.section(&globals);
            self.placed.insert(position(SectionId::Global));
        }
        if due(&self.placed, SectionId::Export) {
            let mut exports = ExportSection::new();
            self.fuel_export(&mut exports);
            module.section(&exports);
            self.placed.insert(position(SectionId::Export));
        }
        Ok(())
    }

    fn parse_function_body(
        &mut self,
        code: &mut CodeSection,
        func: FunctionBody<'_>,
    ) -> Result<(), reencode::Error<Infallible>> {
        let params = self.survey.params.get(self.bodies).copied().unwrap_or(0);
        self.bodies += 1;

        let mut locals = Vec::new();
        let mut declared = 0u32;
        for pair in func.get_locals_reader()? {
            let (count, ty) = pair?;
            locals.push((count, self.val_type(ty)?));
            declared = declared.saturating_add(count);
        }
        let mut ops = Vec::new();
        for op in func.get_operators_reader()? {
            ops.push(op?);
        }
        // The scratch a counted operator tees its count into, added only
        // where one is present: a local the module never names would
        // still stand in its frame.
        let scratch = ops.iter().any(|op| per_unit(op).is_some()).then(|| {
            locals.push((1, ValType::I32));
            params.saturating_add(declared)
        });

        let mut f = Function::new(locals);
        // Open frames within the body, and the depth at which an
        // unconditional branch made what follows unreachable.
        let mut depth = 0u32;
        let mut dead: Option<u32> = None;
        let mut opening = true;
        for (index, op) in ops.iter().enumerate() {
            if dead.is_none() && opening {
                let charge = block_charge(&ops[index..]);
                if charge > 0 {
                    self.check(&mut f, charge);
                }
            }
            if let Some(scratch) = scratch
                && dead.is_none()
                && let Some(unit) = per_unit(op)
            {
                self.check_counted(&mut f, scratch, unit);
            }
            f.instruction(&self.instruction(op.clone())?);

            match op {
                Operator::Block { .. } | Operator::Loop { .. } | Operator::If { .. } => {
                    depth += 1;
                }
                Operator::Else => {
                    if dead == Some(depth) {
                        dead = None;
                    }
                }
                Operator::End => {
                    if dead == Some(depth) {
                        dead = None;
                    }
                    depth = depth.saturating_sub(1);
                }
                _ if ends_block(op) && dead.is_none() => dead = Some(depth),
                _ => {}
            }
            opening = dead.is_none() && opens_block(op);
        }
        code.function(&f);
        Ok(())
    }
}

pub fn instrument(bytes: &[u8], survey: &Survey) -> Result<Vec<u8>, PassError> {
    let mut pass = Pass::new(survey);
    let mut module = Module::new();
    pass.parse_core_module(&mut module, Parser::new(0), bytes)
        .map_err(|error| PassError::Malformed(error.to_string()))?;
    Ok(module.finish())
}

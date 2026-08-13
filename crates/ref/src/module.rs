//! Module decoding: wasmparser's borrowed operators translate into the owned
//! instruction set, with structured-control continuations precomputed.

use std::collections::HashMap;

use wasmparser::{
    BlockType, CompositeInnerType, ConstExpr, Data, DataKind, Element, ElementItems, ElementKind,
    ExternalKind, FuncType as WasmFuncType, FunctionBody, Import, MemArg, Operator, Parser,
    Payload, TypeRef, ValType,
};

use crate::error::DecodeError;
use crate::ops::{BrTargets, LoadKind, NumOp, Op, StoreKind, Value};

/// A function signature over the integer subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuncType {
    /// Parameter types.
    pub params: Vec<Ty>,
    /// Result types.
    pub results: Vec<Ty>,
}

/// A value type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ty {
    /// 32-bit integer.
    I32,
    /// 64-bit integer.
    I64,
}

impl Ty {
    pub(crate) const fn zero(self) -> Value {
        match self {
            Self::I32 => Value::I32(0),
            Self::I64 => Value::I64(0),
        }
    }
}

const fn ty(vt: ValType) -> Result<Ty, DecodeError> {
    match vt {
        ValType::I32 => Ok(Ty::I32),
        ValType::I64 => Ok(Ty::I64),
        _ => Err(DecodeError::UnsupportedType),
    }
}

/// One decoded function.
#[derive(Debug)]
pub struct Func {
    /// Type index.
    pub ty: u32,
    /// Declared locals (excluding parameters).
    pub locals: Vec<Ty>,
    /// The instruction sequence, continuations resolved.
    pub ops: Vec<Op>,
}

/// A global definition.
#[derive(Debug)]
pub struct Global {
    /// Initial value.
    pub init: Value,
}

/// An active element or data segment offset plus payload.
#[derive(Debug)]
pub struct Segment<T> {
    /// Offset into the table or memory.
    pub offset: u32,
    /// Segment payload.
    pub items: T,
}

/// One imported item.
#[derive(Debug)]
pub struct CoreImport {
    /// Import module name.
    pub module: String,
    /// Import field name.
    pub name: String,
    /// Item kind.
    pub kind: CoreImportKind,
}

/// The kind of an imported item.
#[derive(Debug, Clone, Copy)]
pub enum CoreImportKind {
    /// A function with its type index.
    Func(u32),
    /// A linear memory.
    Memory,
    /// A table.
    Table,
}

/// The module's import section.
#[derive(Debug, Default)]
pub struct CoreImports {
    /// Imports in declaration order.
    pub entries: Vec<CoreImport>,
}

impl CoreImports {
    /// Number of imported functions (they occupy the low function indices).
    #[must_use]
    pub fn func_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|i| matches!(i.kind, CoreImportKind::Func(_)))
            .count()
    }
}

/// A decoded module over the profile subset.
#[derive(Debug, Default)]
pub struct RefModule {
    /// Imports.
    pub imports: CoreImports,
    /// Function types.
    pub types: Vec<FuncType>,
    /// Functions.
    pub funcs: Vec<Func>,
    /// Linear memory (initial pages, max pages), if declared.
    pub memory: Option<(u64, u64)>,
    /// Globals.
    pub globals: Vec<Global>,
    /// Table 0 (initial, max), if declared.
    pub table: Option<(u64, u64)>,
    /// Active element segments for table 0.
    pub elements: Vec<Segment<Vec<u32>>>,
    /// Active data segments.
    pub datas: Vec<Segment<Vec<u8>>>,
    /// Function exports by name.
    pub exports: HashMap<String, u32>,
    /// Memory export names (a module has at most one memory).
    pub memory_exports: Vec<String>,
    /// Table export names (a module has at most one table).
    pub table_exports: Vec<String>,
}

impl RefModule {
    /// Decodes a core module within the profile subset.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] for malformed binaries or anything outside the
    /// subset the profile validator admits.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut module = Self::default();
        let mut func_types: Vec<u32> = Vec::new();
        let mut bodies: Vec<FunctionBody<'_>> = Vec::new();

        for payload in Parser::new(0).parse_all(bytes) {
            let payload = payload.map_err(|e| DecodeError::Malformed(e.to_string()))?;
            match payload {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        let group = group.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        for sub in group.types() {
                            let CompositeInnerType::Func(f) = &sub.composite_type.inner else {
                                return Err(DecodeError::UnsupportedType);
                            };
                            module.types.push(func_type(f)?);
                        }
                    }
                }
                Payload::ImportSection(reader) => {
                    for import in reader.into_imports() {
                        let import = import.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        module.imports.entries.push(import_entry(&import)?);
                    }
                }
                Payload::FunctionSection(reader) => {
                    for t in reader {
                        func_types.push(t.map_err(|e| DecodeError::Malformed(e.to_string()))?);
                    }
                }
                Payload::MemorySection(reader) => {
                    for memory in reader {
                        let memory = memory.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        if memory.shared {
                            return Err(DecodeError::Unsupported("shared memory".to_string()));
                        }
                        module.memory = Some(sized(module.memory, memory.initial, memory.maximum)?);
                    }
                }
                Payload::TableSection(reader) => {
                    for table in reader {
                        let table = table.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        module.table =
                            Some(sized(module.table, table.ty.initial, table.ty.maximum)?);
                    }
                }
                Payload::GlobalSection(reader) => {
                    for global in reader {
                        let global = global.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        let init = const_expr(&global.init_expr)?;
                        module.globals.push(Global { init });
                    }
                }
                Payload::ExportSection(reader) => {
                    for export in reader {
                        let export = export.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        match export.kind {
                            ExternalKind::Func => {
                                module.exports.insert(export.name.to_string(), export.index);
                            }
                            ExternalKind::Memory => {
                                module.memory_exports.push(export.name.to_string());
                            }
                            ExternalKind::Table => {
                                module.table_exports.push(export.name.to_string());
                            }
                            _ => {}
                        }
                    }
                }
                Payload::ElementSection(reader) => {
                    for element in reader {
                        let element = element.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        module.elements.push(element_segment(element)?);
                    }
                }
                Payload::DataSection(reader) => {
                    for data in reader {
                        let data = data.map_err(|e| DecodeError::Malformed(e.to_string()))?;
                        module.datas.push(data_segment(&data)?);
                    }
                }
                Payload::CodeSectionEntry(body) => bodies.push(body),
                _ => {}
            }
        }

        for (i, body) in bodies.into_iter().enumerate() {
            let ty_idx = *func_types
                .get(i)
                .ok_or_else(|| DecodeError::Malformed("func/code mismatch".to_string()))?;
            module
                .funcs
                .push(decode_function(&module.types, ty_idx, &body)?);
        }
        Ok(module)
    }

    /// The type index of a function by its global index (imports first).
    #[must_use]
    pub fn func_type_index(&self, func: u32) -> u32 {
        let imported = self.imports.func_count();
        if (func as usize) < imported {
            let mut seen = 0usize;
            for import in &self.imports.entries {
                if let CoreImportKind::Func(t) = import.kind {
                    if seen == func as usize {
                        return t;
                    }
                    seen += 1;
                }
            }
            unreachable!("func index within imported range");
        }
        self.funcs[func as usize - imported].ty
    }

    /// The type of a function by its global index.
    #[must_use]
    pub fn func_type(&self, func: u32) -> &FuncType {
        &self.types[self.func_type_index(func) as usize]
    }
}

/// One memory or table declaration: rejects a second declaration and an
/// absent maximum.
fn sized(
    existing: Option<(u64, u64)>,
    initial: u64,
    maximum: Option<u64>,
) -> Result<(u64, u64), DecodeError> {
    if existing.is_some() {
        return Err(DecodeError::Unsupported(
            "second memory or table".to_string(),
        ));
    }
    let max = maximum.ok_or_else(|| DecodeError::Unsupported("no declared maximum".to_string()))?;
    Ok((initial, max))
}

fn import_entry(import: &Import<'_>) -> Result<CoreImport, DecodeError> {
    let kind = match import.ty {
        TypeRef::Func(t) => CoreImportKind::Func(t),
        TypeRef::Memory(_) => CoreImportKind::Memory,
        TypeRef::Table(_) => CoreImportKind::Table,
        _ => return Err(DecodeError::Unsupported("global or tag import".to_string())),
    };
    Ok(CoreImport {
        module: import.module.to_string(),
        name: import.name.to_string(),
        kind,
    })
}

fn func_type(f: &WasmFuncType) -> Result<FuncType, DecodeError> {
    Ok(FuncType {
        params: f
            .params()
            .iter()
            .map(|v| ty(*v))
            .collect::<Result<_, _>>()?,
        results: f
            .results()
            .iter()
            .map(|v| ty(*v))
            .collect::<Result<_, _>>()?,
    })
}

fn element_segment(element: Element<'_>) -> Result<Segment<Vec<u32>>, DecodeError> {
    let ElementKind::Active { offset_expr, .. } = element.kind else {
        return Err(DecodeError::Unsupported("passive element".to_string()));
    };
    let offset = const_expr(&offset_expr)?.as_i32().cast_unsigned();
    let ElementItems::Functions(items) = element.items else {
        return Err(DecodeError::Unsupported("expr elements".to_string()));
    };
    let funcs = items
        .into_iter()
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DecodeError::Malformed(e.to_string()))?;
    Ok(Segment {
        offset,
        items: funcs,
    })
}

fn data_segment(data: &Data<'_>) -> Result<Segment<Vec<u8>>, DecodeError> {
    let DataKind::Active { offset_expr, .. } = &data.kind else {
        return Err(DecodeError::Unsupported("passive data".to_string()));
    };
    let offset = const_expr(offset_expr)?.as_i32().cast_unsigned();
    Ok(Segment {
        offset,
        items: data.data.to_vec(),
    })
}

/// A constant expression is exactly one constant and its `end` — anything
/// longer (an extended-const computation) is unsupported, never silently
/// truncated to its first operand.
fn const_expr(expr: &ConstExpr<'_>) -> Result<Value, DecodeError> {
    let mut reader = expr.get_operators_reader();
    let op = reader
        .read()
        .map_err(|e| DecodeError::Malformed(e.to_string()))?;
    let value = match op {
        Operator::I32Const { value } => Value::I32(value),
        Operator::I64Const { value } => Value::I64(value),
        other => return Err(DecodeError::UnsupportedOp(format!("{other:?} in const"))),
    };
    match reader
        .read()
        .map_err(|e| DecodeError::Malformed(e.to_string()))?
    {
        Operator::End => Ok(value),
        other => Err(DecodeError::UnsupportedOp(format!("{other:?} in const"))),
    }
}

fn block_arity(types: &[FuncType], bt: BlockType) -> Result<(u8, u8), DecodeError> {
    match bt {
        BlockType::Empty => Ok((0, 0)),
        BlockType::Type(_) => Ok((0, 1)),
        BlockType::FuncType(i) => {
            let t = types
                .get(i as usize)
                .ok_or_else(|| DecodeError::Malformed("block type index".to_string()))?;
            Ok((
                u8::try_from(t.params.len()).map_err(|_| DecodeError::UnsupportedType)?,
                u8::try_from(t.results.len()).map_err(|_| DecodeError::UnsupportedType)?,
            ))
        }
    }
}

fn decode_function(
    types: &[FuncType],
    ty_idx: u32,
    body: &FunctionBody<'_>,
) -> Result<Func, DecodeError> {
    let mut locals = Vec::new();
    let locals_reader = body
        .get_locals_reader()
        .map_err(|e| DecodeError::Malformed(e.to_string()))?;
    for entry in locals_reader {
        let (count, vt) = entry.map_err(|e| DecodeError::Malformed(e.to_string()))?;
        let t = ty(vt)?;
        locals.extend(std::iter::repeat_n(t, count as usize));
    }

    let mut ops = Vec::new();
    let reader = body
        .get_operators_reader()
        .map_err(|e| DecodeError::Malformed(e.to_string()))?;
    for op in reader {
        let op = op.map_err(|e| DecodeError::Malformed(e.to_string()))?;
        ops.push(translate(types, &op)?);
    }
    resolve_continuations(&mut ops)?;
    Ok(Func {
        ty: ty_idx,
        locals,
        ops,
    })
}

/// Fills in `Block`/`If` continuation indices by matching structured ops.
fn resolve_continuations(ops: &mut [Op]) -> Result<(), DecodeError> {
    let mut stack: Vec<usize> = Vec::new();
    for i in 0..ops.len() {
        match ops[i] {
            Op::Block { .. } | Op::Loop { .. } | Op::If { .. } => stack.push(i),
            Op::Else => {
                let opener = *stack
                    .last()
                    .ok_or_else(|| DecodeError::Malformed("stray else".to_string()))?;
                if let Op::If { false_target, .. } = &mut ops[opener] {
                    *false_target =
                        u32::try_from(i + 1).map_err(|_| DecodeError::UnsupportedType)?;
                } else {
                    return Err(DecodeError::Malformed("else outside if".to_string()));
                }
            }
            Op::End => {
                let Some(opener) = stack.pop() else {
                    continue; // the function's own final end
                };
                let cont_idx = u32::try_from(i + 1).map_err(|_| DecodeError::UnsupportedType)?;
                match &mut ops[opener] {
                    Op::Block { cont, .. } => *cont = cont_idx,
                    Op::If {
                        cont, false_target, ..
                    } => {
                        *cont = cont_idx;
                        if *false_target == 0 {
                            *false_target = cont_idx;
                        }
                    }
                    Op::Loop { .. } => {}
                    _ => unreachable!("only structured ops are pushed"),
                }
            }
            _ => {}
        }
    }
    Ok(())
}

const fn mem_offset(memarg: &MemArg) -> u64 {
    memarg.offset
}

#[allow(clippy::too_many_lines)] // single dispatch over the operator set
fn translate(types: &[FuncType], op: &Operator<'_>) -> Result<Op, DecodeError> {
    use NumOp as N;
    let out = match op {
        Operator::Unreachable => Op::Unreachable,
        Operator::Nop => Op::Nop,
        Operator::Block { blockty } => {
            let (params, results) = block_arity(types, *blockty)?;
            Op::Block {
                cont: 0,
                params,
                results,
            }
        }
        Operator::Loop { blockty } => {
            let (params, _) = block_arity(types, *blockty)?;
            Op::Loop { params }
        }
        Operator::If { blockty } => {
            let (params, results) = block_arity(types, *blockty)?;
            Op::If {
                false_target: 0,
                cont: 0,
                params,
                results,
            }
        }
        Operator::Else => Op::Else,
        Operator::End => Op::End,
        Operator::Br { relative_depth } => Op::Br(*relative_depth),
        Operator::BrIf { relative_depth } => Op::BrIf(*relative_depth),
        Operator::BrTable { targets } => {
            let list = targets
                .targets()
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| DecodeError::Malformed(e.to_string()))?;
            Op::BrTable(Box::new(BrTargets {
                targets: list,
                default: targets.default(),
            }))
        }
        Operator::Return => Op::Return,
        Operator::Call { function_index } => Op::Call(*function_index),
        Operator::CallIndirect { type_index, .. } => Op::CallIndirect { ty: *type_index },
        Operator::Drop => Op::Drop,
        Operator::Select | Operator::TypedSelect { .. } => Op::Select,
        Operator::LocalGet { local_index } => Op::LocalGet(*local_index),
        Operator::LocalSet { local_index } => Op::LocalSet(*local_index),
        Operator::LocalTee { local_index } => Op::LocalTee(*local_index),
        Operator::GlobalGet { global_index } => Op::GlobalGet(*global_index),
        Operator::GlobalSet { global_index } => Op::GlobalSet(*global_index),
        Operator::I32Const { value } => Op::I32Const(*value),
        Operator::I64Const { value } => Op::I64Const(*value),
        Operator::I32Load { memarg } => Op::Load(LoadKind::I32, mem_offset(memarg)),
        Operator::I64Load { memarg } => Op::Load(LoadKind::I64, mem_offset(memarg)),
        Operator::I32Load8S { memarg } => Op::Load(LoadKind::I32S8, mem_offset(memarg)),
        Operator::I32Load8U { memarg } => Op::Load(LoadKind::I32U8, mem_offset(memarg)),
        Operator::I32Load16S { memarg } => Op::Load(LoadKind::I32S16, mem_offset(memarg)),
        Operator::I32Load16U { memarg } => Op::Load(LoadKind::I32U16, mem_offset(memarg)),
        Operator::I64Load8S { memarg } => Op::Load(LoadKind::I64S8, mem_offset(memarg)),
        Operator::I64Load8U { memarg } => Op::Load(LoadKind::I64U8, mem_offset(memarg)),
        Operator::I64Load16S { memarg } => Op::Load(LoadKind::I64S16, mem_offset(memarg)),
        Operator::I64Load16U { memarg } => Op::Load(LoadKind::I64U16, mem_offset(memarg)),
        Operator::I64Load32S { memarg } => Op::Load(LoadKind::I64S32, mem_offset(memarg)),
        Operator::I64Load32U { memarg } => Op::Load(LoadKind::I64U32, mem_offset(memarg)),
        Operator::I32Store { memarg } => Op::Store(StoreKind::I32, mem_offset(memarg)),
        Operator::I64Store { memarg } => Op::Store(StoreKind::I64, mem_offset(memarg)),
        Operator::I32Store8 { memarg } => Op::Store(StoreKind::I32W8, mem_offset(memarg)),
        Operator::I32Store16 { memarg } => Op::Store(StoreKind::I32W16, mem_offset(memarg)),
        Operator::I64Store8 { memarg } => Op::Store(StoreKind::I64W8, mem_offset(memarg)),
        Operator::I64Store16 { memarg } => Op::Store(StoreKind::I64W16, mem_offset(memarg)),
        Operator::I64Store32 { memarg } => Op::Store(StoreKind::I64W32, mem_offset(memarg)),
        Operator::MemorySize { .. } => Op::MemorySize,
        Operator::MemoryGrow { .. } => Op::MemoryGrow,
        Operator::MemoryFill { .. } => Op::MemoryFill,
        Operator::MemoryCopy { .. } => Op::MemoryCopy,
        Operator::I32Eqz => Op::Unary(N::I32Eqz),
        Operator::I64Eqz => Op::Unary(N::I64Eqz),
        Operator::I32Clz => Op::Unary(N::I32Clz),
        Operator::I32Ctz => Op::Unary(N::I32Ctz),
        Operator::I32Popcnt => Op::Unary(N::I32Popcnt),
        Operator::I64Clz => Op::Unary(N::I64Clz),
        Operator::I64Ctz => Op::Unary(N::I64Ctz),
        Operator::I64Popcnt => Op::Unary(N::I64Popcnt),
        Operator::I32Extend8S => Op::Unary(N::I32Extend8S),
        Operator::I32Extend16S => Op::Unary(N::I32Extend16S),
        Operator::I64Extend8S => Op::Unary(N::I64Extend8S),
        Operator::I64Extend16S => Op::Unary(N::I64Extend16S),
        Operator::I64Extend32S => Op::Unary(N::I64Extend32S),
        Operator::I32WrapI64 => Op::Unary(N::I32WrapI64),
        Operator::I64ExtendI32S => Op::Unary(N::I64ExtendI32S),
        Operator::I64ExtendI32U => Op::Unary(N::I64ExtendI32U),
        Operator::I32Add => Op::Binary(N::I32Add),
        Operator::I32Sub => Op::Binary(N::I32Sub),
        Operator::I32Mul => Op::Binary(N::I32Mul),
        Operator::I32DivS => Op::Binary(N::I32DivS),
        Operator::I32DivU => Op::Binary(N::I32DivU),
        Operator::I32RemS => Op::Binary(N::I32RemS),
        Operator::I32RemU => Op::Binary(N::I32RemU),
        Operator::I32And => Op::Binary(N::I32And),
        Operator::I32Or => Op::Binary(N::I32Or),
        Operator::I32Xor => Op::Binary(N::I32Xor),
        Operator::I32Shl => Op::Binary(N::I32Shl),
        Operator::I32ShrS => Op::Binary(N::I32ShrS),
        Operator::I32ShrU => Op::Binary(N::I32ShrU),
        Operator::I32Rotl => Op::Binary(N::I32Rotl),
        Operator::I32Rotr => Op::Binary(N::I32Rotr),
        Operator::I32Eq => Op::Binary(N::I32Eq),
        Operator::I32Ne => Op::Binary(N::I32Ne),
        Operator::I32LtS => Op::Binary(N::I32LtS),
        Operator::I32LtU => Op::Binary(N::I32LtU),
        Operator::I32GtS => Op::Binary(N::I32GtS),
        Operator::I32GtU => Op::Binary(N::I32GtU),
        Operator::I32LeS => Op::Binary(N::I32LeS),
        Operator::I32LeU => Op::Binary(N::I32LeU),
        Operator::I32GeS => Op::Binary(N::I32GeS),
        Operator::I32GeU => Op::Binary(N::I32GeU),
        Operator::I64Add => Op::Binary(N::I64Add),
        Operator::I64Sub => Op::Binary(N::I64Sub),
        Operator::I64Mul => Op::Binary(N::I64Mul),
        Operator::I64DivS => Op::Binary(N::I64DivS),
        Operator::I64DivU => Op::Binary(N::I64DivU),
        Operator::I64RemS => Op::Binary(N::I64RemS),
        Operator::I64RemU => Op::Binary(N::I64RemU),
        Operator::I64And => Op::Binary(N::I64And),
        Operator::I64Or => Op::Binary(N::I64Or),
        Operator::I64Xor => Op::Binary(N::I64Xor),
        Operator::I64Shl => Op::Binary(N::I64Shl),
        Operator::I64ShrS => Op::Binary(N::I64ShrS),
        Operator::I64ShrU => Op::Binary(N::I64ShrU),
        Operator::I64Rotl => Op::Binary(N::I64Rotl),
        Operator::I64Rotr => Op::Binary(N::I64Rotr),
        Operator::I64Eq => Op::Binary(N::I64Eq),
        Operator::I64Ne => Op::Binary(N::I64Ne),
        Operator::I64LtS => Op::Binary(N::I64LtS),
        Operator::I64LtU => Op::Binary(N::I64LtU),
        Operator::I64GtS => Op::Binary(N::I64GtS),
        Operator::I64GtU => Op::Binary(N::I64GtU),
        Operator::I64LeS => Op::Binary(N::I64LeS),
        Operator::I64LeU => Op::Binary(N::I64LeU),
        Operator::I64GeS => Op::Binary(N::I64GeS),
        Operator::I64GeU => Op::Binary(N::I64GeU),
        other => return Err(DecodeError::UnsupportedOp(format!("{other:?}"))),
    };
    Ok(out)
}

//! The execution engine: a plain stack interpreter over decoded modules.
//!
//! Execution operates on a [`Store`] holding the mutable state of one or more
//! core instances — the component layer instantiates several modules sharing
//! memories and canon-defined functions; the bare-module path wraps a single
//! module. Calls to canon-defined functions leave the interpreter through the
//! [`CanonDispatch`] trait, whose implementor may recursively call back in
//! (guest realloc during lowering).

use crate::error::{DecodeError, Trap};
use crate::module::{RefModule, Ty};
use crate::ops::{LoadKind, Op, StoreKind, Value, eval_binary, eval_unary, fuel_cost};

pub(crate) const PAGE: usize = 64 * 1024;
const MAX_CALL_DEPTH: usize = 512;

/// An execution failure: a wasm trap, or a canonical-ABI violation at the
/// component boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// A wasm trap.
    Trap(Trap),
    /// A canonical-ABI violation (unknown handle, undropped borrows).
    Canon(CanonError),
}

/// Canonical-ABI violations, mirroring the blessed engine's error classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonError {
    /// A handle index with no live table entry.
    UnknownHandle,
    /// A live handle of the wrong resource type — the mode-escape trap.
    WrongHandleType,
    /// Borrow handles still live when the export returned.
    BorrowsRemain,
    /// A deterministic kernel refusal, carrying the host's message.
    Host(String),
    /// An unresolved canon definition — a decoder or instantiation defect,
    /// never guest-reachable.
    Internal(&'static str),
}

impl From<Trap> for ExecError {
    fn from(t: Trap) -> Self {
        Self::Trap(t)
    }
}

/// The address of a callable function.
#[derive(Debug, Clone, Copy)]
pub(crate) enum FuncAddr {
    /// A wasm function: instance index and global function index within it.
    Wasm {
        /// Store instance index.
        instance: u32,
        /// Function index in that instance's index space.
        func: u32,
    },
    /// A canon-defined function, dispatched through [`CanonDispatch`].
    Canon(u32),
}

/// One linear memory.
pub(crate) struct Memory {
    pub data: Vec<u8>,
    pub max_pages: u64,
}

/// One table entry: the callee plus its declared type for signature checks.
#[derive(Clone, Copy)]
pub(crate) struct TableEntry {
    pub addr: FuncAddr,
    /// Owning module index and type index, for structural comparison.
    pub module: u32,
    pub ty: u32,
}

/// Per-instance state.
pub(crate) struct InstanceData {
    /// Index into the module list.
    pub module: u32,
    /// The full function index space: imports resolved, then local functions.
    pub funcs: Vec<FuncAddr>,
    /// Store memory index, if the module declares or imports one.
    pub memory: Option<u32>,
    /// Store table index, if any.
    pub table: Option<u32>,
    /// Global values.
    pub globals: Vec<Value>,
}

/// Mutable execution state shared by all instances of one instantiation.
#[derive(Default)]
pub(crate) struct Store {
    pub memories: Vec<Memory>,
    pub tables: Vec<Vec<Option<TableEntry>>>,
    pub instances: Vec<InstanceData>,
    pub depth: usize,
    /// Optional instruction budget; `None` is unbounded.
    pub steps_remaining: Option<u64>,
    /// Fuel consumed under the spec schedule ([`fuel_cost`] plus one per
    /// function entry, plus one per byte moved by `memory.fill`/`memory.copy`).
    pub fuel_consumed: u64,
}

/// Dispatch for canon-defined functions.
pub(crate) trait CanonDispatch {
    /// Core-level parameter count of the canon function.
    fn param_count(&self, id: u32) -> usize;

    /// Executes the canon function; may recursively call [`call`].
    fn dispatch(
        &mut self,
        modules: &[&RefModule],
        store: &mut Store,
        id: u32,
        args: Vec<Value>,
    ) -> Result<Vec<Value>, ExecError>;
}

/// A dispatcher for stores with no canon functions.
pub(crate) struct NoCanon;

impl CanonDispatch for NoCanon {
    fn param_count(&self, _id: u32) -> usize {
        unreachable!("bare modules define no canon functions")
    }

    fn dispatch(
        &mut self,
        _modules: &[&RefModule],
        _store: &mut Store,
        _id: u32,
        _args: Vec<Value>,
    ) -> Result<Vec<Value>, ExecError> {
        unreachable!("bare modules define no canon functions")
    }
}

/// Calls a function by address.
pub(crate) fn call(
    modules: &[&RefModule],
    canon: &mut dyn CanonDispatch,
    store: &mut Store,
    addr: FuncAddr,
    args: Vec<Value>,
) -> Result<Vec<Value>, ExecError> {
    match addr {
        FuncAddr::Canon(id) => canon.dispatch(modules, store, id, args),
        FuncAddr::Wasm { instance, func } => {
            if store.depth >= MAX_CALL_DEPTH {
                return Err(Trap::CallDepthExhausted.into());
            }
            store.depth += 1;
            let result = run(modules, canon, store, instance, func, args);
            store.depth -= 1;
            result
        }
    }
}

struct Label {
    height: usize,
    arity: usize,
    cont: u32,
    is_loop: bool,
}

#[allow(clippy::too_many_lines)] // the interpreter loop is one dispatch over Op
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // wasm narrowing semantics
fn run(
    modules: &[&RefModule],
    canon: &mut dyn CanonDispatch,
    store: &mut Store,
    instance: u32,
    func_idx: u32,
    args: Vec<Value>,
) -> Result<Vec<Value>, ExecError> {
    let module_idx = store.instances[instance as usize].module;
    let module = modules[module_idx as usize];
    let local_idx = func_idx as usize - module.imports.func_count();
    let func = &module.funcs[local_idx];
    let func_ty = &module.types[func.ty as usize];
    let result_arity = func_ty.results.len();

    let mut locals = args;
    locals.extend(func.locals.iter().map(|t| t.zero()));

    let mut stack: Vec<Value> = Vec::new();
    let mut control: Vec<Label> = vec![Label {
        height: 0,
        arity: result_arity,
        cont: u32::try_from(func.ops.len()).unwrap_or(u32::MAX),
        is_loop: false,
    }];
    let mut pc = 0usize;
    store.fuel_consumed += 1; // function entry

    while pc < func.ops.len() {
        store.fuel_consumed += fuel_cost(&func.ops[pc]);
        if let Some(remaining) = store.steps_remaining.as_mut() {
            if *remaining == 0 {
                return Err(Trap::StepBudgetExhausted.into());
            }
            *remaining -= 1;
        }
        match &func.ops[pc] {
            Op::Unreachable => return Err(Trap::Unreachable.into()),
            Op::Nop => {}
            Op::Block {
                cont,
                params,
                results,
            } => control.push(Label {
                height: stack.len() - usize::from(*params),
                arity: usize::from(*results),
                cont: *cont,
                is_loop: false,
            }),
            Op::Loop { params } => control.push(Label {
                height: stack.len() - usize::from(*params),
                arity: usize::from(*params),
                cont: u32::try_from(pc + 1).unwrap_or(u32::MAX),
                is_loop: true,
            }),
            Op::If {
                false_target,
                cont,
                params,
                results,
            } => {
                let cond = stack.pop().expect("validated").as_i32();
                if cond == 0 && false_target == cont {
                    // No else arm: skip the whole construct without a label —
                    // the end it jumps past will never pop one.
                    pc = *cont as usize;
                    continue;
                }
                control.push(Label {
                    height: stack.len() - usize::from(*params),
                    arity: usize::from(*results),
                    cont: *cont,
                    is_loop: false,
                });
                if cond == 0 {
                    pc = *false_target as usize;
                    continue;
                }
            }
            Op::Else => {
                // Reached from the true arm: branch to the enclosing end.
                branch(&mut stack, &mut control, 0, &mut pc);
                continue;
            }
            Op::End => {
                let label = control.pop().expect("validated");
                if control.is_empty() {
                    return Ok(split_top(&mut stack, label.arity));
                }
            }
            Op::Br(depth) => {
                branch(&mut stack, &mut control, *depth as usize, &mut pc);
                continue;
            }
            Op::BrIf(depth) => {
                if stack.pop().expect("validated").as_i32() != 0 {
                    branch(&mut stack, &mut control, *depth as usize, &mut pc);
                    continue;
                }
            }
            Op::BrTable(targets) => {
                let idx = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                let depth = targets.targets.get(idx).copied().unwrap_or(targets.default);
                branch(&mut stack, &mut control, depth as usize, &mut pc);
                continue;
            }
            Op::Return => return Ok(split_top(&mut stack, result_arity)),
            Op::Call(idx) => {
                let addr = store.instances[instance as usize].funcs[*idx as usize];
                dispatch_call(modules, canon, store, addr, &mut stack)?;
            }
            Op::CallIndirect { ty } => {
                let slot = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                let table_idx = store.instances[instance as usize]
                    .table
                    .expect("validated: call_indirect requires a table");
                let entry = *store.tables[table_idx as usize]
                    .get(slot)
                    .ok_or(Trap::TableOutOfBounds)?;
                let entry = entry.ok_or(Trap::IndirectCallToNull)?;
                let expected = &module.types[*ty as usize];
                let actual = &modules[entry.module as usize].types[entry.ty as usize];
                if expected != actual {
                    return Err(Trap::BadSignature.into());
                }
                dispatch_call(modules, canon, store, entry.addr, &mut stack)?;
            }
            Op::Drop => {
                stack.pop();
            }
            Op::Select => {
                let cond = stack.pop().expect("validated").as_i32();
                let b = stack.pop().expect("validated");
                let a = stack.pop().expect("validated");
                stack.push(if cond == 0 { b } else { a });
            }
            Op::LocalGet(i) => stack.push(locals[*i as usize]),
            Op::LocalSet(i) => locals[*i as usize] = stack.pop().expect("validated"),
            Op::LocalTee(i) => locals[*i as usize] = *stack.last().expect("validated"),
            Op::GlobalGet(i) => {
                stack.push(store.instances[instance as usize].globals[*i as usize]);
            }
            Op::GlobalSet(i) => {
                store.instances[instance as usize].globals[*i as usize] =
                    stack.pop().expect("validated");
            }
            Op::I32Const(v) => stack.push(Value::I32(*v)),
            Op::I64Const(v) => stack.push(Value::I64(*v)),
            Op::Load(kind, offset) => {
                let addr = stack.pop().expect("validated");
                let mem = memory(store, instance);
                stack.push(load(mem, *kind, addr, *offset)?);
            }
            Op::Store(kind, offset) => {
                let value = stack.pop().expect("validated");
                let addr = stack.pop().expect("validated");
                let mem = memory_mut(store, instance);
                store_value(mem, *kind, addr, value, *offset)?;
            }
            Op::MemorySize => {
                let mem = memory(store, instance);
                stack.push(Value::I32(
                    i32::try_from(mem.data.len() / PAGE).unwrap_or(i32::MAX),
                ));
            }
            Op::MemoryGrow => {
                let delta = u64::from(stack.pop().expect("validated").as_i32().cast_unsigned());
                let mem = memory_mut(store, instance);
                let current = (mem.data.len() / PAGE) as u64;
                if current + delta > mem.max_pages {
                    stack.push(Value::I32(-1));
                } else {
                    let new_len = usize::try_from(current + delta)
                        .expect("bounded by the declared maximum")
                        .saturating_mul(PAGE);
                    mem.data.resize(new_len, 0);
                    stack.push(Value::I32(i32::try_from(current).unwrap_or(i32::MAX)));
                }
            }
            Op::MemoryFill => {
                let n = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                let val = stack.pop().expect("validated").as_i32() as u8;
                let dest = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                // The engine charges the byte count before the bounds check.
                store.fuel_consumed += n as u64;
                let mem = memory_mut(store, instance);
                let end = dest.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                if end > mem.data.len() {
                    return Err(Trap::MemoryOutOfBounds.into());
                }
                mem.data[dest..end].fill(val);
            }
            Op::MemoryCopy => {
                let n = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                let src = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                let dest = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                // The engine charges the byte count before the bounds check.
                store.fuel_consumed += n as u64;
                let mem = memory_mut(store, instance);
                let src_end = src.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                let dest_end = dest.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                if src_end > mem.data.len() || dest_end > mem.data.len() {
                    return Err(Trap::MemoryOutOfBounds.into());
                }
                mem.data.copy_within(src..src_end, dest);
            }
            Op::Unary(op) => {
                let v = stack.pop().expect("validated");
                stack.push(eval_unary(*op, v));
            }
            Op::Binary(op) => {
                let b = stack.pop().expect("validated");
                let a = stack.pop().expect("validated");
                stack.push(eval_binary(*op, a, b)?);
            }
        }
        pc += 1;
    }
    // Reached only by a branch to the function-level label: the branch
    // truncated to the label's height and left exactly the results.
    Ok(split_top(&mut stack, result_arity))
}

fn dispatch_call(
    modules: &[&RefModule],
    canon: &mut dyn CanonDispatch,
    store: &mut Store,
    addr: FuncAddr,
    stack: &mut Vec<Value>,
) -> Result<(), ExecError> {
    let param_count = match addr {
        FuncAddr::Canon(id) => canon.param_count(id),
        FuncAddr::Wasm { instance, func } => {
            let module = modules[store.instances[instance as usize].module as usize];
            module.func_type(func).params.len()
        }
    };
    let args = split_top(stack, param_count);
    let results = call(modules, canon, store, addr, args)?;
    stack.extend(results);
    Ok(())
}

fn memory(store: &Store, instance: u32) -> &Memory {
    let idx = store.instances[instance as usize]
        .memory
        .expect("validated: memory op requires a memory");
    &store.memories[idx as usize]
}

fn memory_mut(store: &mut Store, instance: u32) -> &mut Memory {
    let idx = store.instances[instance as usize]
        .memory
        .expect("validated: memory op requires a memory");
    &mut store.memories[idx as usize]
}

fn addr_range(mem: &Memory, base: Value, offset: u64, size: usize) -> Result<usize, Trap> {
    let effective = u64::from(base.as_i32().cast_unsigned()) + offset;
    let start = usize::try_from(effective).map_err(|_| Trap::MemoryOutOfBounds)?;
    let end = start.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
    if end > mem.data.len() {
        return Err(Trap::MemoryOutOfBounds);
    }
    Ok(start)
}

fn load(mem: &Memory, kind: LoadKind, base: Value, offset: u64) -> Result<Value, Trap> {
    let bytes = |n: usize| -> Result<&[u8], Trap> {
        let start = addr_range(mem, base, offset, n)?;
        Ok(&mem.data[start..start + n])
    };
    let v = match kind {
        LoadKind::I32 => Value::I32(i32::from_le_bytes(bytes(4)?.try_into().unwrap())),
        LoadKind::I64 => Value::I64(i64::from_le_bytes(bytes(8)?.try_into().unwrap())),
        LoadKind::I32U8 => Value::I32(i32::from(bytes(1)?[0])),
        LoadKind::I32S8 => Value::I32(i32::from(bytes(1)?[0].cast_signed())),
        LoadKind::I32U16 => {
            Value::I32(i32::from(u16::from_le_bytes(bytes(2)?.try_into().unwrap())))
        }
        LoadKind::I32S16 => {
            Value::I32(i32::from(i16::from_le_bytes(bytes(2)?.try_into().unwrap())))
        }
        LoadKind::I64U8 => Value::I64(i64::from(bytes(1)?[0])),
        LoadKind::I64S8 => Value::I64(i64::from(bytes(1)?[0].cast_signed())),
        LoadKind::I64U16 => {
            Value::I64(i64::from(u16::from_le_bytes(bytes(2)?.try_into().unwrap())))
        }
        LoadKind::I64S16 => {
            Value::I64(i64::from(i16::from_le_bytes(bytes(2)?.try_into().unwrap())))
        }
        LoadKind::I64U32 => {
            Value::I64(i64::from(u32::from_le_bytes(bytes(4)?.try_into().unwrap())))
        }
        LoadKind::I64S32 => {
            Value::I64(i64::from(i32::from_le_bytes(bytes(4)?.try_into().unwrap())))
        }
    };
    Ok(v)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // wasm narrowing stores
fn store_value(
    mem: &mut Memory,
    kind: StoreKind,
    base: Value,
    value: Value,
    offset: u64,
) -> Result<(), Trap> {
    let (data, n): ([u8; 8], usize) = match kind {
        StoreKind::I32 => (extend(&value.as_i32().to_le_bytes()), 4),
        StoreKind::I64 => (value.as_i64().to_le_bytes(), 8),
        StoreKind::I32W8 => (extend(&[value.as_i32() as u8]), 1),
        StoreKind::I32W16 => (extend(&(value.as_i32() as u16).to_le_bytes()), 2),
        StoreKind::I64W8 => (extend(&[value.as_i64() as u8]), 1),
        StoreKind::I64W16 => (extend(&(value.as_i64() as u16).to_le_bytes()), 2),
        StoreKind::I64W32 => (extend(&(value.as_i64() as u32).to_le_bytes()), 4),
    };
    let start = addr_range(mem, base, offset, n)?;
    mem.data[start..start + n].copy_from_slice(&data[..n]);
    Ok(())
}

/// Pops `arity` values, truncates to the label's height, pushes them back,
/// and sets the program counter to the label's continuation.
fn branch(stack: &mut Vec<Value>, control: &mut Vec<Label>, depth: usize, pc: &mut usize) {
    let idx = control.len() - 1 - depth;
    let (height, arity, cont, is_loop) = {
        let label = &control[idx];
        (label.height, label.arity, label.cont, label.is_loop)
    };
    let kept = split_top(stack, arity);
    stack.truncate(height);
    stack.extend(kept);
    if is_loop {
        control.truncate(idx + 1);
    } else {
        control.truncate(idx);
    }
    *pc = cont as usize;
}

fn split_top(stack: &mut Vec<Value>, n: usize) -> Vec<Value> {
    stack.split_off(stack.len() - n)
}

const fn extend(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < bytes.len() {
        out[i] = bytes[i];
        i += 1;
    }
    out
}

/// Builds a store instance from a module, creating its declared memory and
/// table and applying active segments. Imported items must already be in
/// `imports` resolution order matching the module's import section.
pub(crate) fn instantiate_module(
    modules: &[&RefModule],
    store: &mut Store,
    module_idx: u32,
    imported_funcs: Vec<FuncAddr>,
    imported_memory: Option<u32>,
    imported_table: Option<u32>,
) -> Result<u32, Trap> {
    let module = modules[module_idx as usize];

    let memory = if let Some((initial, max)) = module.memory {
        let data = vec![0u8; usize::try_from(initial).unwrap_or(0) * PAGE];
        store.memories.push(Memory {
            data,
            max_pages: max,
        });
        Some(u32::try_from(store.memories.len() - 1).expect("bounded"))
    } else {
        imported_memory
    };

    // The engine compiles one init function per module that needs one: any
    // active data segment forces it, as do element segments applying to an
    // imported table (a local table's elements are precomputed host-side).
    // Its entry costs one fuel; each data segment adds one plus one per
    // byte; element writes are free.
    let inits_imported_table = module.table.is_none() && !module.elements.is_empty();
    if !module.datas.is_empty() || inits_imported_table {
        store.fuel_consumed += 1;
    }
    if let Some(mem_idx) = memory {
        for seg in &module.datas {
            store.fuel_consumed += 1 + seg.items.len() as u64;
            let mem = &mut store.memories[mem_idx as usize];
            let start = seg.offset as usize;
            let end = start + seg.items.len();
            if end > mem.data.len() {
                return Err(Trap::MemoryOutOfBounds);
            }
            mem.data[start..end].copy_from_slice(&seg.items);
        }
    }

    let instance_idx = u32::try_from(store.instances.len()).expect("bounded");
    let mut funcs = imported_funcs;
    let base = funcs.len();
    for i in 0..module.funcs.len() {
        funcs.push(FuncAddr::Wasm {
            instance: instance_idx,
            func: u32::try_from(base + i).expect("bounded"),
        });
    }

    let table = if let Some((initial, _max)) = module.table {
        store
            .tables
            .push(vec![None; usize::try_from(initial).unwrap_or(0)]);
        Some(u32::try_from(store.tables.len() - 1).expect("bounded"))
    } else {
        imported_table
    };

    if let Some(table_idx) = table {
        for seg in &module.elements {
            let start = seg.offset as usize;
            let end = start + seg.items.len();
            if end > store.tables[table_idx as usize].len() {
                return Err(Trap::TableOutOfBounds);
            }
            for (slot, func) in (start..end).zip(&seg.items) {
                let addr = funcs[*func as usize];
                let ty = module.func_type_index(*func);
                store.tables[table_idx as usize][slot] = Some(TableEntry {
                    addr,
                    module: module_idx,
                    ty,
                });
            }
        }
    }

    store.instances.push(InstanceData {
        module: module_idx,
        funcs,
        memory,
        table,
        globals: module.globals.iter().map(|g| g.init).collect(),
    });
    Ok(instance_idx)
}

/// A bare-module instance: no imports, no canon functions.
pub struct RefInstance<'m> {
    module: &'m RefModule,
    store: Store,
}

impl<'m> RefInstance<'m> {
    /// Instantiates a module with no imports.
    ///
    /// # Errors
    ///
    /// Traps if an active segment falls out of bounds.
    ///
    /// # Panics
    ///
    /// If the module declares imports; bare instantiation is import-free by
    /// contract.
    pub fn instantiate(module: &'m RefModule) -> Result<Self, Trap> {
        assert!(
            module.imports.entries.is_empty(),
            "bare instantiation requires an import-free module"
        );
        let mut store = Store::default();
        instantiate_module(&[module], &mut store, 0, Vec::new(), None, None)?;
        Ok(Self { module, store })
    }

    /// Bounds each subsequent invocation to `limit` interpreted instructions
    /// — a harness safety valve for generated corpora.
    pub const fn set_step_limit(&mut self, limit: u64) {
        self.store.steps_remaining = Some(limit);
    }

    /// Total fuel consumed under the spec schedule.
    #[must_use]
    pub const fn fuel_consumed(&self) -> u64 {
        self.store.fuel_consumed
    }

    /// Invokes an exported function.
    ///
    /// # Errors
    ///
    /// [`DecodeError::NoSuchExport`] / [`DecodeError::ArgumentMismatch`] for
    /// bad invocations; otherwise the trap the execution produced.
    pub fn invoke(
        &mut self,
        export: &str,
        args: &[Value],
    ) -> Result<Result<Vec<Value>, Trap>, DecodeError> {
        let idx = *self
            .module
            .exports
            .get(export)
            .ok_or_else(|| DecodeError::NoSuchExport(export.to_string()))?;
        let ty = self.module.func_type(idx);
        if ty.params.len() != args.len() {
            return Err(DecodeError::ArgumentMismatch);
        }
        for (arg, want) in args.iter().zip(&ty.params) {
            let ok = matches!(
                (arg, want),
                (Value::I32(_), Ty::I32) | (Value::I64(_), Ty::I64)
            );
            if !ok {
                return Err(DecodeError::ArgumentMismatch);
            }
        }
        self.store.depth = 0;
        let addr = FuncAddr::Wasm {
            instance: 0,
            func: idx,
        };
        match call(
            &[self.module],
            &mut NoCanon,
            &mut self.store,
            addr,
            args.to_vec(),
        ) {
            Ok(values) => Ok(Ok(values)),
            Err(ExecError::Trap(t)) => Ok(Err(t)),
            Err(ExecError::Canon(_)) => unreachable!("bare modules have no canon boundary"),
        }
    }
}

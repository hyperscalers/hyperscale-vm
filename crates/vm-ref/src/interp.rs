//! The execution engine: a plain stack interpreter over the decoded module.

use crate::error::{DecodeError, Trap};
use crate::module::{RefModule, Ty};
use crate::ops::{LoadKind, Op, StoreKind, Value, eval_binary, eval_unary};

const PAGE: usize = 64 * 1024;
const MAX_CALL_DEPTH: usize = 512;

/// An instantiated module.
pub struct RefInstance<'m> {
    module: &'m RefModule,
    memory: Vec<u8>,
    memory_max_pages: u64,
    globals: Vec<Value>,
    table: Vec<Option<u32>>,
    depth: usize,
}

impl<'m> RefInstance<'m> {
    /// Instantiates: builds memory and table, applies active segments.
    ///
    /// # Errors
    ///
    /// Traps if an active segment falls out of bounds, matching wasm
    /// instantiation semantics.
    pub fn instantiate(module: &'m RefModule) -> Result<Self, Trap> {
        let (initial, max) = module.memory.unwrap_or((0, 0));
        let mut memory = vec![0u8; usize::try_from(initial).unwrap_or(0) * PAGE];
        for seg in &module.datas {
            let start = seg.offset as usize;
            let end = start + seg.items.len();
            if end > memory.len() {
                return Err(Trap::MemoryOutOfBounds);
            }
            memory[start..end].copy_from_slice(&seg.items);
        }

        let table_len = module.table.map_or(0, |(initial, _)| initial);
        let mut table: Vec<Option<u32>> = vec![None; usize::try_from(table_len).unwrap_or(0)];
        for seg in &module.elements {
            let start = seg.offset as usize;
            let end = start + seg.items.len();
            if end > table.len() {
                return Err(Trap::TableOutOfBounds);
            }
            for (slot, func) in table[start..end].iter_mut().zip(&seg.items) {
                *slot = Some(*func);
            }
        }

        Ok(Self {
            module,
            memory,
            memory_max_pages: max,
            globals: module.globals.iter().map(|g| g.init).collect(),
            table,
            depth: 0,
        })
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
        let func = &self.module.funcs[idx as usize];
        let ty = &self.module.types[func.ty as usize];
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
        self.depth = 0;
        Ok(self.call(idx, args.to_vec()))
    }

    fn call(&mut self, func_idx: u32, args: Vec<Value>) -> Result<Vec<Value>, Trap> {
        if self.depth >= MAX_CALL_DEPTH {
            return Err(Trap::CallDepthExhausted);
        }
        self.depth += 1;
        let result = self.run(func_idx, args);
        self.depth -= 1;
        result
    }

    #[allow(clippy::too_many_lines)] // the interpreter loop is one dispatch over Op
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // wasm narrowing semantics
    fn run(&mut self, func_idx: u32, args: Vec<Value>) -> Result<Vec<Value>, Trap> {
        let func = &self.module.funcs[func_idx as usize];
        let func_ty = &self.module.types[func.ty as usize];
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

        while pc < func.ops.len() {
            match &func.ops[pc] {
                Op::Unreachable => return Err(Trap::Unreachable),
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
                        // No else arm: skip the whole construct without a
                        // label — the end it jumps past will never pop one.
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
                        let results = split_top(&mut stack, label.arity);
                        return Ok(results);
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
                Op::Return => {
                    let results = split_top(&mut stack, result_arity);
                    return Ok(results);
                }
                Op::Call(idx) => {
                    self.dispatch(*idx, &mut stack)?;
                }
                Op::CallIndirect { ty } => {
                    let slot = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let entry = *self.table.get(slot).ok_or(Trap::TableOutOfBounds)?;
                    let target = entry.ok_or(Trap::IndirectCallToNull)?;
                    let target_ty = self.module.funcs[target as usize].ty;
                    if self.module.types[target_ty as usize] != self.module.types[*ty as usize] {
                        return Err(Trap::BadSignature);
                    }
                    self.dispatch(target, &mut stack)?;
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
                Op::GlobalGet(i) => stack.push(self.globals[*i as usize]),
                Op::GlobalSet(i) => self.globals[*i as usize] = stack.pop().expect("validated"),
                Op::I32Const(v) => stack.push(Value::I32(*v)),
                Op::I64Const(v) => stack.push(Value::I64(*v)),
                Op::Load(kind, offset) => {
                    let addr = stack.pop().expect("validated");
                    stack.push(self.load(*kind, addr, *offset)?);
                }
                Op::Store(kind, offset) => {
                    let value = stack.pop().expect("validated");
                    let addr = stack.pop().expect("validated");
                    self.store(*kind, addr, value, *offset)?;
                }
                Op::MemorySize => {
                    stack.push(Value::I32(
                        i32::try_from(self.memory.len() / PAGE).unwrap_or(i32::MAX),
                    ));
                }
                Op::MemoryGrow => {
                    let delta = u64::from(stack.pop().expect("validated").as_i32().cast_unsigned());
                    let current = (self.memory.len() / PAGE) as u64;
                    if current + delta > self.memory_max_pages {
                        stack.push(Value::I32(-1));
                    } else {
                        let new_len = usize::try_from(current + delta)
                            .expect("bounded by the declared maximum")
                            .saturating_mul(PAGE);
                        self.memory.resize(new_len, 0);
                        stack.push(Value::I32(i32::try_from(current).unwrap_or(i32::MAX)));
                    }
                }
                Op::MemoryFill => {
                    let n = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let val = stack.pop().expect("validated").as_i32() as u8;
                    let dest = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let end = dest.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                    if end > self.memory.len() {
                        return Err(Trap::MemoryOutOfBounds);
                    }
                    self.memory[dest..end].fill(val);
                }
                Op::MemoryCopy => {
                    let n = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let src = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let dest = stack.pop().expect("validated").as_i32().cast_unsigned() as usize;
                    let src_end = src.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                    let dest_end = dest.checked_add(n).ok_or(Trap::MemoryOutOfBounds)?;
                    if src_end > self.memory.len() || dest_end > self.memory.len() {
                        return Err(Trap::MemoryOutOfBounds);
                    }
                    self.memory.copy_within(src..src_end, dest);
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
        // Fell off the end (final End consumed the function label already or
        // the loop exited): unreachable for validated code.
        unreachable!("validated function bodies end with End");
    }

    fn dispatch(&mut self, func_idx: u32, stack: &mut Vec<Value>) -> Result<(), Trap> {
        let param_count = {
            let f = &self.module.funcs[func_idx as usize];
            self.module.types[f.ty as usize].params.len()
        };
        let args = split_top(stack, param_count);
        let results = self.call(func_idx, args)?;
        stack.extend(results);
        Ok(())
    }

    fn addr(&self, base: Value, offset: u64, size: usize) -> Result<usize, Trap> {
        let effective = u64::from(base.as_i32().cast_unsigned()) + offset;
        let start = usize::try_from(effective).map_err(|_| Trap::MemoryOutOfBounds)?;
        let end = start.checked_add(size).ok_or(Trap::MemoryOutOfBounds)?;
        if end > self.memory.len() {
            return Err(Trap::MemoryOutOfBounds);
        }
        Ok(start)
    }

    fn load(&self, kind: LoadKind, base: Value, offset: u64) -> Result<Value, Trap> {
        let bytes = |s: usize, n: usize| -> Result<&[u8], Trap> {
            let start = self.addr(base, offset, n)?;
            let _ = s;
            Ok(&self.memory[start..start + n])
        };
        let v = match kind {
            LoadKind::I32 => Value::I32(i32::from_le_bytes(bytes(0, 4)?.try_into().unwrap())),
            LoadKind::I64 => Value::I64(i64::from_le_bytes(bytes(0, 8)?.try_into().unwrap())),
            LoadKind::I32U8 => Value::I32(i32::from(bytes(0, 1)?[0])),
            LoadKind::I32S8 => Value::I32(i32::from(bytes(0, 1)?[0].cast_signed())),
            LoadKind::I32U16 => Value::I32(i32::from(u16::from_le_bytes(
                bytes(0, 2)?.try_into().unwrap(),
            ))),
            LoadKind::I32S16 => Value::I32(i32::from(i16::from_le_bytes(
                bytes(0, 2)?.try_into().unwrap(),
            ))),
            LoadKind::I64U8 => Value::I64(i64::from(bytes(0, 1)?[0])),
            LoadKind::I64S8 => Value::I64(i64::from(bytes(0, 1)?[0].cast_signed())),
            LoadKind::I64U16 => Value::I64(i64::from(u16::from_le_bytes(
                bytes(0, 2)?.try_into().unwrap(),
            ))),
            LoadKind::I64S16 => Value::I64(i64::from(i16::from_le_bytes(
                bytes(0, 2)?.try_into().unwrap(),
            ))),
            LoadKind::I64U32 => Value::I64(i64::from(u32::from_le_bytes(
                bytes(0, 4)?.try_into().unwrap(),
            ))),
            LoadKind::I64S32 => Value::I64(i64::from(i32::from_le_bytes(
                bytes(0, 4)?.try_into().unwrap(),
            ))),
        };
        Ok(v)
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // wasm narrowing stores
    fn store(
        &mut self,
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
        let start = self.addr(base, offset, n)?;
        self.memory[start..start + n].copy_from_slice(&data[..n]);
        Ok(())
    }
}

struct Label {
    height: usize,
    arity: usize,
    cont: u32,
    is_loop: bool,
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

fn extend(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[..bytes.len()].copy_from_slice(bytes);
    out
}

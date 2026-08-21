//! The owned instruction set and numeric semantics.
//!
//! Operators are translated out of wasmparser's borrowed form at decode time;
//! execution semantics here are written against the wasm specification,
//! independently of any engine.

use crate::error::Trap;

/// A runtime value. The profile is integer-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value {
    /// A 32-bit integer.
    I32(i32),
    /// A 64-bit integer.
    I64(i64),
}

impl Value {
    pub(crate) fn as_i32(self) -> i32 {
        match self {
            Self::I32(v) => v,
            Self::I64(_) => unreachable!("validated code never mistypes"),
        }
    }

    pub(crate) fn as_i64(self) -> i64 {
        match self {
            Self::I64(v) => v,
            Self::I32(_) => unreachable!("validated code never mistypes"),
        }
    }
}

/// A numeric operator, unary or binary per the translation.
#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)] // operator names are the wasm mnemonics; restating them is noise
pub enum NumOp {
    I32Eqz,
    I64Eqz,
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I64Clz,
    I64Ctz,
    I64Popcnt,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Add,
    I32Sub,
    I32Mul,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrS,
    I32ShrU,
    I32Rotl,
    I32Rotr,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrS,
    I64ShrU,
    I64Rotl,
    I64Rotr,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
}

/// A load shape: destination width and in-memory width/signedness.
#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)] // names are the wasm mnemonics
pub enum LoadKind {
    I32,
    I64,
    I32U8,
    I32S8,
    I32U16,
    I32S16,
    I64U8,
    I64S8,
    I64U16,
    I64S16,
    I64U32,
    I64S32,
}

/// A store shape: source width and in-memory width.
#[derive(Debug, Clone, Copy)]
#[allow(missing_docs)] // names are the wasm mnemonics
pub enum StoreKind {
    I32,
    I64,
    I32W8,
    I32W16,
    I64W8,
    I64W16,
    I64W32,
}

/// One decoded instruction.
#[derive(Debug, Clone)]
pub enum Op {
    /// `unreachable`.
    Unreachable,
    /// `nop`.
    Nop,
    /// `block`, with the index one past its `end` and its label arities.
    Block {
        /// Program counter one past the matching `end`.
        cont: u32,
        /// Parameter count of the block type.
        params: u8,
        /// Result count of the block type.
        results: u8,
    },
    /// `loop`; branching to it re-enters at the following instruction.
    Loop {
        /// Parameter count of the block type.
        params: u8,
    },
    /// `if`, with the else/end continuation indices.
    If {
        /// Program counter one past the matching `else` (or `end` if none).
        false_target: u32,
        /// Program counter one past the matching `end`.
        cont: u32,
        /// Parameter count of the block type.
        params: u8,
        /// Result count of the block type.
        results: u8,
    },
    /// `else`: behaves as a branch to the enclosing label.
    Else,
    /// `end`: closes the innermost label.
    End,
    /// `br depth`.
    Br(u32),
    /// `br_if depth`.
    BrIf(u32),
    /// `br_table`, boxed to keep `Op` small.
    BrTable(Box<BrTargets>),
    /// `return`.
    Return,
    /// `call func`.
    Call(u32),
    /// `call_indirect` through table 0.
    CallIndirect {
        /// Expected type index.
        ty: u32,
    },
    /// `drop`.
    Drop,
    /// `select` (typed or untyped — identical semantics for integers).
    Select,
    /// `local.get`.
    LocalGet(u32),
    /// `local.set`.
    LocalSet(u32),
    /// `local.tee`.
    LocalTee(u32),
    /// `global.get`.
    GlobalGet(u32),
    /// `global.set`.
    GlobalSet(u32),
    /// `i32.const`.
    I32Const(i32),
    /// `i64.const`.
    I64Const(i64),
    /// A load with its static offset.
    Load(LoadKind, u64),
    /// A store with its static offset.
    Store(StoreKind, u64),
    /// `memory.size`.
    MemorySize,
    /// `memory.grow`.
    MemoryGrow,
    /// `memory.fill`.
    MemoryFill,
    /// `memory.copy`.
    MemoryCopy,
    /// A unary numeric operator.
    Unary(NumOp),
    /// A binary numeric operator.
    Binary(NumOp),
}

/// `br_table` targets plus the default.
#[derive(Debug, Clone)]
pub struct BrTargets {
    /// Indexed targets.
    pub targets: Vec<u32>,
    /// Default target.
    pub default: u32,
}

/// The fuel schedule, stated in the spec's own operator vocabulary.
///
/// `nop`, `drop`, and pure control structure (`block`, `loop`, `unreachable`,
/// `return`, `else`, `end`) are free; every other operator costs one; each
/// function entry costs one. `memory.fill`/`memory.copy` additionally cost
/// one per byte moved, charged at the execution site in the interpreter.
///
/// This is an independent statement of the schedule the blessed engine is
/// configured with, sharing no constant with it. The harness holds the two
/// to each other operator by operator, and the differential fuel lane holds
/// the whole accounting to the engine's.
#[must_use]
pub const fn fuel_cost(op: &Op) -> u64 {
    match op {
        Op::Nop
        | Op::Drop
        | Op::Block { .. }
        | Op::Loop { .. }
        | Op::Unreachable
        | Op::Return
        | Op::Else
        | Op::End => 0,
        _ => 1,
    }
}

fn bool32(b: bool) -> Value {
    Value::I32(i32::from(b))
}

/// Evaluates a unary operator.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] // wasm wrap/extend semantics
pub(crate) fn eval_unary(op: NumOp, v: Value) -> Value {
    match op {
        NumOp::I32Eqz => bool32(v.as_i32() == 0),
        NumOp::I64Eqz => bool32(v.as_i64() == 0),
        NumOp::I32Clz => Value::I32(v.as_i32().leading_zeros().cast_signed()),
        NumOp::I32Ctz => Value::I32(v.as_i32().trailing_zeros().cast_signed()),
        NumOp::I32Popcnt => Value::I32(v.as_i32().count_ones().cast_signed()),
        NumOp::I64Clz => Value::I64(i64::from(v.as_i64().leading_zeros())),
        NumOp::I64Ctz => Value::I64(i64::from(v.as_i64().trailing_zeros())),
        NumOp::I64Popcnt => Value::I64(i64::from(v.as_i64().count_ones())),
        NumOp::I32Extend8S => Value::I32(i32::from(v.as_i32() as i8)),
        NumOp::I32Extend16S => Value::I32(i32::from(v.as_i32() as i16)),
        NumOp::I64Extend8S => Value::I64(i64::from(v.as_i64() as i8)),
        NumOp::I64Extend16S => Value::I64(i64::from(v.as_i64() as i16)),
        NumOp::I64Extend32S => Value::I64(i64::from(v.as_i64() as i32)),
        NumOp::I32WrapI64 => Value::I32(v.as_i64() as i32),
        NumOp::I64ExtendI32S => Value::I64(i64::from(v.as_i32())),
        NumOp::I64ExtendI32U => Value::I64(i64::from(v.as_i32().cast_unsigned())),
        _ => unreachable!("translated as binary"),
    }
}

/// Evaluates a binary operator; division and remainder can trap.
#[allow(clippy::too_many_lines)] // single dispatch over the operator set
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // wasm shift-count semantics
pub(crate) fn eval_binary(op: NumOp, a: Value, b: Value) -> Result<Value, Trap> {
    let v = match op {
        NumOp::I32Add => Value::I32(a.as_i32().wrapping_add(b.as_i32())),
        NumOp::I32Sub => Value::I32(a.as_i32().wrapping_sub(b.as_i32())),
        NumOp::I32Mul => Value::I32(a.as_i32().wrapping_mul(b.as_i32())),
        NumOp::I32DivS => {
            let (a, b) = (a.as_i32(), b.as_i32());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            if a == i32::MIN && b == -1 {
                return Err(Trap::IntegerOverflow);
            }
            Value::I32(a.wrapping_div(b))
        }
        NumOp::I32DivU => {
            let (a, b) = (a.as_i32().cast_unsigned(), b.as_i32().cast_unsigned());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I32((a / b).cast_signed())
        }
        NumOp::I32RemS => {
            let (a, b) = (a.as_i32(), b.as_i32());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I32(a.wrapping_rem(b))
        }
        NumOp::I32RemU => {
            let (a, b) = (a.as_i32().cast_unsigned(), b.as_i32().cast_unsigned());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I32((a % b).cast_signed())
        }
        NumOp::I32And => Value::I32(a.as_i32() & b.as_i32()),
        NumOp::I32Or => Value::I32(a.as_i32() | b.as_i32()),
        NumOp::I32Xor => Value::I32(a.as_i32() ^ b.as_i32()),
        NumOp::I32Shl => Value::I32(a.as_i32().wrapping_shl(b.as_i32().cast_unsigned())),
        NumOp::I32ShrS => Value::I32(a.as_i32().wrapping_shr(b.as_i32().cast_unsigned())),
        NumOp::I32ShrU => Value::I32(
            a.as_i32()
                .cast_unsigned()
                .wrapping_shr(b.as_i32().cast_unsigned())
                .cast_signed(),
        ),
        NumOp::I32Rotl => Value::I32(a.as_i32().rotate_left(b.as_i32().cast_unsigned() & 31)),
        NumOp::I32Rotr => Value::I32(a.as_i32().rotate_right(b.as_i32().cast_unsigned() & 31)),
        NumOp::I32Eq => bool32(a.as_i32() == b.as_i32()),
        NumOp::I32Ne => bool32(a.as_i32() != b.as_i32()),
        NumOp::I32LtS => bool32(a.as_i32() < b.as_i32()),
        NumOp::I32LtU => bool32(a.as_i32().cast_unsigned() < b.as_i32().cast_unsigned()),
        NumOp::I32GtS => bool32(a.as_i32() > b.as_i32()),
        NumOp::I32GtU => bool32(a.as_i32().cast_unsigned() > b.as_i32().cast_unsigned()),
        NumOp::I32LeS => bool32(a.as_i32() <= b.as_i32()),
        NumOp::I32LeU => bool32(a.as_i32().cast_unsigned() <= b.as_i32().cast_unsigned()),
        NumOp::I32GeS => bool32(a.as_i32() >= b.as_i32()),
        NumOp::I32GeU => bool32(a.as_i32().cast_unsigned() >= b.as_i32().cast_unsigned()),
        NumOp::I64Add => Value::I64(a.as_i64().wrapping_add(b.as_i64())),
        NumOp::I64Sub => Value::I64(a.as_i64().wrapping_sub(b.as_i64())),
        NumOp::I64Mul => Value::I64(a.as_i64().wrapping_mul(b.as_i64())),
        NumOp::I64DivS => {
            let (a, b) = (a.as_i64(), b.as_i64());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            if a == i64::MIN && b == -1 {
                return Err(Trap::IntegerOverflow);
            }
            Value::I64(a.wrapping_div(b))
        }
        NumOp::I64DivU => {
            let (a, b) = (a.as_i64().cast_unsigned(), b.as_i64().cast_unsigned());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I64((a / b).cast_signed())
        }
        NumOp::I64RemS => {
            let (a, b) = (a.as_i64(), b.as_i64());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I64(a.wrapping_rem(b))
        }
        NumOp::I64RemU => {
            let (a, b) = (a.as_i64().cast_unsigned(), b.as_i64().cast_unsigned());
            if b == 0 {
                return Err(Trap::IntegerDivisionByZero);
            }
            Value::I64((a % b).cast_signed())
        }
        NumOp::I64And => Value::I64(a.as_i64() & b.as_i64()),
        NumOp::I64Or => Value::I64(a.as_i64() | b.as_i64()),
        NumOp::I64Xor => Value::I64(a.as_i64() ^ b.as_i64()),
        NumOp::I64Shl => Value::I64(a.as_i64().wrapping_shl(b.as_i64() as u32)),
        NumOp::I64ShrS => Value::I64(a.as_i64().wrapping_shr(b.as_i64() as u32)),
        NumOp::I64ShrU => Value::I64(
            a.as_i64()
                .cast_unsigned()
                .wrapping_shr(b.as_i64() as u32)
                .cast_signed(),
        ),
        NumOp::I64Rotl => Value::I64(a.as_i64().rotate_left(b.as_i64() as u32 & 63)),
        NumOp::I64Rotr => Value::I64(a.as_i64().rotate_right(b.as_i64() as u32 & 63)),
        NumOp::I64Eq => bool32(a.as_i64() == b.as_i64()),
        NumOp::I64Ne => bool32(a.as_i64() != b.as_i64()),
        NumOp::I64LtS => bool32(a.as_i64() < b.as_i64()),
        NumOp::I64LtU => bool32(a.as_i64().cast_unsigned() < b.as_i64().cast_unsigned()),
        NumOp::I64GtS => bool32(a.as_i64() > b.as_i64()),
        NumOp::I64GtU => bool32(a.as_i64().cast_unsigned() > b.as_i64().cast_unsigned()),
        NumOp::I64LeS => bool32(a.as_i64() <= b.as_i64()),
        NumOp::I64LeU => bool32(a.as_i64().cast_unsigned() <= b.as_i64().cast_unsigned()),
        NumOp::I64GeS => bool32(a.as_i64() >= b.as_i64()),
        NumOp::I64GeU => bool32(a.as_i64().cast_unsigned() >= b.as_i64().cast_unsigned()),
        _ => unreachable!("translated as unary"),
    };
    Ok(v)
}

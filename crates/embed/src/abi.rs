//! The core ABI: how a guest module and the kernel exchange bytes.
//!
//! One rule decides where bytes travel. The guest owns its memory, so
//! whatever the kernel has bytes for that the guest has not made room
//! for waits in a *register* until the guest allocates and collects it;
//! everything else crosses at a pointer the guest chose, through a
//! bounds-checked slice of the one memory it exports. The host never
//! re-enters the guest — no allocator callback, no destructor — which is
//! what lets a stack bound count one chain and a totality walk read one
//! module.
//!
//! Stated once, here, and executed by both engines: the blessed engine
//! wraps each dispatch below as a host function and the reference
//! interpreter resolves the same functions from its import table. What
//! stays independent between them is execution. A slice check is not a
//! second opinion, so a second copy of it would witness nothing.
//!
//! # Registers
//!
//! Three kinds. An *input register* holds one non-scalar export argument
//! — bytes, an address, an id list — at the parameter's own position,
//! and the guest sees an `i32` byte length in the argument's place; it
//! collects the bytes with [`arg`]. The *answer register* holds the
//! bytes of the last variable-length host result; the call returned
//! their length and the guest collects them with [`take`]. The guest's
//! own results go the other way through [`reply`] and [`answer`].
//!
//! A register is *filled* by the operation that produces it, at any
//! length, zero included, and *cleared* by the one collect. Collecting a
//! register that is not filled — never filled, already collected, or an
//! index that is no parameter — is an ABI violation. A register left
//! uncollected was paid for and is dropped with the call: bytes are
//! priced when the kernel produces or consumes them, never when the
//! guest collects them, so `arg` and `take` cost their instructions and
//! nothing per byte.
//!
//! # Values
//!
//! Handles, counts, lengths, flags and enums are `i32`; a `u64` is
//! `i64`. An `amount` is sixteen bytes, low half then high, little
//! endian; a `wide`, a `word` and an `address` are thirty-two, four
//! little-endian limbs. Fixed-width arguments arrive by pointer and
//! fixed-width results leave through an out-pointer the guest passes.
//! A `drawn` is a tag — [`DRAWN_PENDING`], [`DRAWN_READY`],
//! [`DRAWN_EXPIRED`] — with the word at the out-pointer only when ready.

use core::cmp::Ordering;

use hyperscale_vm_types::math::{Rounding, U256};
use hyperscale_vm_types::{AbortReason, Drawn, SEED_BYTES};

use crate::meter::{
    self, AMOUNT_BOUNDARY_BYTES, FuelSink, HostAccess, MeterError, WIDE_BOUNDARY_BYTES,
};
use crate::{GuestArg, KernelHost};

/// The byte width of an `amount` at the boundary: the width it has.
pub const AMOUNT_BYTES: usize = AMOUNT_BOUNDARY_BYTES;

/// The byte width of a `wide`, a `word` and an `address` at the boundary:
/// four limbs.
pub const LIMBS_BYTES: usize = WIDE_BOUNDARY_BYTES;

/// `drawn`: the seal's epoch is not folded yet.
pub const DRAWN_PENDING: u32 = 0;
/// `drawn`: the word is at the out-pointer.
pub const DRAWN_READY: u32 = 1;
/// `drawn`: the seal will never open.
pub const DRAWN_EXPIRED: u32 = 2;

/// `rounding`: toward zero.
pub const ROUNDING_DOWN: u32 = 0;
/// `rounding`: away from zero.
pub const ROUNDING_UP: u32 = 1;

/// `ordering`: the first is smaller.
pub const ORDERING_LESS: u32 = 0;
/// `ordering`: the two are equal.
pub const ORDERING_EQUAL: u32 = 1;
/// `ordering`: the first is larger.
pub const ORDERING_GREATER: u32 = 2;

/// The import namespaces, as core `(module, name)` module halves.
pub const STATE: &str = "hyperscale:kernel/state";
/// The wide arithmetic namespace.
pub const MATH: &str = "hyperscale:kernel/math";
/// The environment namespace.
pub const ENV: &str = "hyperscale:kernel/env";
/// The cryptography namespace.
pub const CRYPTO: &str = "hyperscale:kernel/crypto";
/// The events namespace.
pub const EVENTS: &str = "hyperscale:kernel/events";
/// The register namespace: [`arg`], [`take`], [`reply`] and [`answer`].
pub const ABI: &str = "hyperscale:kernel/abi";

/// The one memory a guest exports, by name.
pub const MEMORY: &str = "memory";

/// The guest's linear memory, as the ABI reads and writes it.
///
/// One rule: a bounds-checked slice. A pointer and length that do not
/// fit are an ABI violation, which is the guest's fault rather than a
/// trap the engine wording would vary on.
pub trait GuestMemory {
    /// The bytes at `ptr`, `len` of them.
    ///
    /// # Errors
    ///
    /// An ABI violation where the range leaves the memory.
    fn read(&self, ptr: u32, len: u32) -> Result<&[u8], MeterError>;

    /// Writes `bytes` at `ptr`.
    ///
    /// # Errors
    ///
    /// An ABI violation where the range leaves the memory.
    fn write(&mut self, ptr: u32, bytes: &[u8]) -> Result<(), MeterError>;
}

impl GuestMemory for [u8] {
    fn read(&self, ptr: u32, len: u32) -> Result<&[u8], MeterError> {
        let start = ptr as usize;
        let end = start.checked_add(len as usize).ok_or_else(violation)?;
        self.get(start..end).ok_or_else(violation)
    }

    fn write(&mut self, ptr: u32, bytes: &[u8]) -> Result<(), MeterError> {
        let start = ptr as usize;
        let end = start.checked_add(bytes.len()).ok_or_else(violation)?;
        self.get_mut(start..end)
            .ok_or_else(violation)?
            .copy_from_slice(bytes);
        Ok(())
    }
}

const fn violation() -> MeterError {
    MeterError::Refused(AbortReason::AbiViolation)
}

/// What the guest handed back through [`reply`] and [`answer`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Reply {
    /// The buckets, in declared output order.
    pub edges: Vec<u32>,
    /// The answer bytes, where the guest gave any.
    pub answer: Option<Vec<u8>>,
}

/// The register file of one invocation.
///
/// Built by [`lower`] with the input registers filled, threaded through
/// the call beside the host, and read back for what the guest replied.
#[derive(Debug, Default)]
pub struct Registers {
    /// One slot per export parameter; filled for the non-scalar ones.
    inputs: Vec<Option<Vec<u8>>>,
    /// The last variable-length host result, until taken.
    answer: Option<Vec<u8>>,
    /// The edges the guest replied, once it has.
    edges: Option<Vec<u32>>,
    /// The answer the guest gave, once it has.
    answered: Option<Vec<u8>>,
}

impl Registers {
    /// What the guest replied, or `None` where it never called
    /// [`reply`] — a return outside the convention.
    pub fn reply(&mut self) -> Option<Reply> {
        let edges = self.edges.take()?;
        Some(Reply {
            edges,
            answer: self.answered.take(),
        })
    }

    fn fill_answer(&mut self, bytes: Vec<u8>) -> Result<u32, MeterError> {
        let len = width(&bytes)?;
        self.answer = Some(bytes);
        Ok(len)
    }
}

/// What a dispatch reads the boundary through.
///
/// The guest's memory, the host, the budget, and the registers, as one
/// object rather than four: an engine lends them as one — a host
/// function holds its store, and the memory is an export of the
/// instance in it.
pub trait Boundary: HostAccess + FuelSink + GuestMemory {
    /// The invocation's register file.
    fn registers(&mut self) -> &mut Registers;
}

/// What an export parameter is, as the binding declares it.
///
/// The table from here to [`CoreType`] is what the gate holds a core
/// signature to, because a core signature alone cannot say it: a site
/// and a bucket both flatten to `i32`, and so does the length of a
/// register argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamKind {
    /// A borrowed site, as its table index.
    Site,
    /// A guard verdict.
    Flag,
    /// A 64-bit scalar.
    U64,
    /// An address, through an input register.
    Address,
    /// Bytes, through an input register.
    Bytes,
    /// Instance ids, through an input register, eight bytes each.
    Ids,
    /// An owned bucket, as its table index.
    Bucket,
}

/// A core value type at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreType {
    /// `i32`.
    I32,
    /// `i64`.
    I64,
}

/// A core value at the boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreValue {
    /// An `i32`, as its bits.
    I32(u32),
    /// An `i64`, as its bits.
    I64(u64),
}

impl ParamKind {
    /// The core type a parameter of this kind is declared as.
    #[must_use]
    pub const fn core_type(self) -> CoreType {
        match self {
            Self::Site | Self::Flag | Self::Address | Self::Bytes | Self::Ids | Self::Bucket => {
                CoreType::I32
            }
            Self::U64 => CoreType::I64,
        }
    }
}

impl GuestArg<'_> {
    /// The kind of parameter this argument fills.
    #[must_use]
    pub const fn kind(&self) -> ParamKind {
        match self {
            Self::Site { .. } => ParamKind::Site,
            Self::Bool(_) => ParamKind::Flag,
            Self::U64(_) => ParamKind::U64,
            Self::Address(_) => ParamKind::Address,
            Self::Bytes(_) => ParamKind::Bytes,
            Self::Ids(_) => ParamKind::Ids,
            Self::Bucket(_) => ParamKind::Bucket,
        }
    }
}

/// The core result types an export declares: nothing where it cannot
/// decline, one `i32` where it can — zero for completed, `index + 1`
/// for a decline on the package's error table.
#[must_use]
pub const fn returns(declines: bool) -> &'static [CoreType] {
    if declines { &[CoreType::I32] } else { &[] }
}

/// The export's core parameters, and the registers filled for it.
///
/// # Errors
///
/// An ABI violation where an argument is too wide for a register: the
/// kernel bounds every value it assembles, so this is a defect.
pub fn lower(args: &[GuestArg<'_>]) -> Result<(Vec<CoreValue>, Registers), MeterError> {
    let mut values = Vec::with_capacity(args.len());
    let mut inputs = Vec::with_capacity(args.len());
    for arg in args {
        let register = match arg {
            GuestArg::Site { site } => {
                values.push(CoreValue::I32(*site));
                None
            }
            GuestArg::Bool(flag) => {
                values.push(CoreValue::I32(u32::from(*flag)));
                None
            }
            GuestArg::U64(scalar) => {
                values.push(CoreValue::I64(*scalar));
                None
            }
            GuestArg::Address(address) => Some(address.to_bytes().to_vec()),
            GuestArg::Bytes(bytes) => Some(bytes.to_vec()),
            GuestArg::Ids(ids) => Some(ids.iter().flat_map(|id| id.to_le_bytes()).collect()),
            GuestArg::Bucket(rep) => {
                values.push(CoreValue::I32(*rep));
                None
            }
        };
        if let Some(bytes) = register {
            values.push(CoreValue::I32(width(&bytes)?));
            inputs.push(Some(bytes));
        } else {
            inputs.push(None);
        }
    }
    Ok((
        values,
        Registers {
            inputs,
            ..Registers::default()
        },
    ))
}

fn width(bytes: &[u8]) -> Result<u32, MeterError> {
    u32::try_from(bytes.len()).map_err(|_| violation())
}

// ---- encodings -----------------------------------------------------------

fn read_fixed<const N: usize, M: GuestMemory + ?Sized>(
    port: &M,
    ptr: u32,
) -> Result<[u8; N], MeterError> {
    let len = u32::try_from(N).map_err(|_| violation())?;
    port.read(ptr, len)?.try_into().map_err(|_| violation())
}

fn read_amount<M: GuestMemory + ?Sized>(port: &M, ptr: u32) -> Result<u128, MeterError> {
    read_fixed::<AMOUNT_BYTES, M>(port, ptr).map(u128::from_le_bytes)
}

fn write_amount<M: GuestMemory + ?Sized>(
    port: &mut M,
    ptr: u32,
    amount: u128,
) -> Result<(), MeterError> {
    port.write(ptr, &amount.to_le_bytes())
}

fn read_wide<M: GuestMemory + ?Sized>(port: &M, ptr: u32) -> Result<U256, MeterError> {
    let bytes = read_fixed::<LIMBS_BYTES, M>(port, ptr)?;
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    Ok(U256::from_limbs(limbs))
}

fn write_wide<M: GuestMemory + ?Sized>(
    port: &mut M,
    ptr: u32,
    wide: U256,
) -> Result<(), MeterError> {
    let mut bytes = [0u8; LIMBS_BYTES];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(wide.limbs()) {
        *chunk = limb.to_le_bytes();
    }
    port.write(ptr, &bytes)
}

fn read_ids<M: GuestMemory + ?Sized>(
    port: &M,
    ptr: u32,
    count: u32,
) -> Result<Vec<u64>, MeterError> {
    let len = count.checked_mul(8).ok_or_else(violation)?;
    Ok(port
        .read(ptr, len)?
        .as_chunks::<8>()
        .0
        .iter()
        .map(|chunk| u64::from_le_bytes(*chunk))
        .collect())
}

const fn rounding(value: u32) -> Result<Rounding, MeterError> {
    match value {
        ROUNDING_DOWN => Ok(Rounding::Down),
        ROUNDING_UP => Ok(Rounding::Up),
        _ => Err(violation()),
    }
}

const fn ordering(value: Ordering) -> u32 {
    match value {
        Ordering::Less => ORDERING_LESS,
        Ordering::Equal => ORDERING_EQUAL,
        Ordering::Greater => ORDERING_GREATER,
    }
}

// ---- hyperscale:kernel/abi -------------------------------------------------

/// `abi.arg`: collect input register `index` at `ptr`.
///
/// # Errors
///
/// An ABI violation where the register is not filled or the range
/// leaves the memory.
pub fn arg<P: Boundary>(port: &mut P, index: u32, ptr: u32) -> Result<(), MeterError> {
    let bytes = port
        .registers()
        .inputs
        .get_mut(index as usize)
        .and_then(Option::take)
        .ok_or_else(violation)?;
    port.write(ptr, &bytes)
}

/// `abi.take`: collect the answer register at `ptr`.
///
/// # Errors
///
/// An ABI violation where the register is not filled or the range
/// leaves the memory.
pub fn take<P: Boundary>(port: &mut P, ptr: u32) -> Result<(), MeterError> {
    let bytes = port.registers().answer.take().ok_or_else(violation)?;
    port.write(ptr, &bytes)
}

/// `abi.reply`: the buckets the export hands back, in declared output
/// order, `count` of them at `ptr` as little-endian `u32`s. Exactly once
/// per completed call.
///
/// # Errors
///
/// [`AbortReason::BadReturnShape`] on a second reply; an ABI violation
/// where the range leaves the memory.
pub fn reply<P: Boundary>(port: &mut P, ptr: u32, count: u32) -> Result<(), MeterError> {
    if port.registers().edges.is_some() {
        return Err(MeterError::Refused(AbortReason::BadReturnShape));
    }
    let len = count.checked_mul(4).ok_or_else(violation)?;
    let edges = port
        .read(ptr, len)?
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .collect();
    port.registers().edges = Some(edges);
    Ok(())
}

/// `abi.answer`: the bytes the export answers with. At most once per
/// call, and only an export whose binding answers calls it.
///
/// # Errors
///
/// [`AbortReason::BadReturnShape`] on a second answer; an ABI violation
/// where the range leaves the memory.
pub fn answer<P: Boundary>(port: &mut P, ptr: u32, len: u32) -> Result<(), MeterError> {
    if port.registers().answered.is_some() {
        return Err(MeterError::Refused(AbortReason::BadReturnShape));
    }
    let bytes = port.read(ptr, len)?.to_vec();
    port.registers().answered = Some(bytes);
    Ok(())
}

// ---- hyperscale:kernel/state ---------------------------------------------

/// `state.site-len`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_len<P: Boundary>(port: &mut P, site: u32) -> Result<u32, MeterError> {
    meter::site_len(port, site)
}

/// `state.site-declared`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_declared<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<u32, MeterError> {
    meter::site_declared(port, site, element).map(u32::from)
}

/// `state.site-get`: fills the answer register and returns its length.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_get<P: Boundary>(port: &mut P, site: u32, element: u32) -> Result<u32, MeterError> {
    let value = meter::site_get(port, site, element)?;
    port.registers().fill_answer(value)
}

/// `state.site-set`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_set<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    ptr: u32,
    len: u32,
) -> Result<(), MeterError> {
    let value = port.read(ptr, len)?.to_vec();
    meter::site_set(port, site, element, value)
}

/// `state.site-seal`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_seal<P: Boundary>(port: &mut P, site: u32, element: u32) -> Result<(), MeterError> {
    meter::site_seal(port, site, element)
}

/// `state.site-open-seal`: the tag, with the word at `out` when ready.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_open_seal<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    out: u32,
) -> Result<u32, MeterError> {
    match meter::site_open_seal(port, site, element)? {
        Drawn::Pending => Ok(DRAWN_PENDING),
        Drawn::Expired => Ok(DRAWN_EXPIRED),
        Drawn::Ready(word) => {
            const _: () = assert!(SEED_BYTES == LIMBS_BYTES, "a word is four limbs");
            port.write(out, &word)?;
            Ok(DRAWN_READY)
        }
    }
}

/// `state.site-clear`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_clear<P: Boundary>(port: &mut P, site: u32, element: u32) -> Result<(), MeterError> {
    meter::site_clear(port, site, element)
}

/// `state.site-balance`: the amount at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_balance<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    out: u32,
) -> Result<(), MeterError> {
    let held = meter::site_balance(port, site, element)?;
    write_amount(port, out, held)
}

/// `state.site-take`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_take<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    amount: u32,
) -> Result<u32, MeterError> {
    let amount = read_amount(port, amount)?;
    meter::site_take(port, site, element, amount)
}

/// `state.site-put`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_put<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    funds: u32,
) -> Result<(), MeterError> {
    meter::site_put(port, site, element, funds)
}

/// `state.site-reserve-take`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_reserve_take<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
) -> Result<u32, MeterError> {
    meter::site_reserve_take(port, site, element)
}

/// `state.site-count`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_count<P: Boundary>(port: &mut P, site: u32, element: u32) -> Result<u32, MeterError> {
    meter::site_count(port, site, element)
}

/// `state.site-covered`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_covered<P: Boundary>(port: &mut P, site: u32, element: u32) -> Result<u32, MeterError> {
    meter::site_covered(port, site, element).map(u32::from)
}

/// `state.site-order`: the order key at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_order<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
    out: u32,
) -> Result<(), MeterError> {
    let order = meter::site_order(port, site, element, index)?;
    write_amount(port, out, order)
}

/// `state.site-entry`: fills the answer register and returns its length.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_entry<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
) -> Result<u32, MeterError> {
    let value = meter::site_entry(port, site, element, index)?;
    port.registers().fill_answer(value)
}

/// `state.site-entry-set`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_entry_set<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
    ptr: u32,
    len: u32,
) -> Result<(), MeterError> {
    let value = port.read(ptr, len)?.to_vec();
    meter::site_entry_set(port, site, element, index, value)
}

/// `state.site-insert`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_insert<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    order: u32,
    ptr: u32,
    len: u32,
) -> Result<(), MeterError> {
    let order = read_amount(port, order)?;
    let value = port.read(ptr, len)?.to_vec();
    meter::site_insert(port, site, element, order, value)
}

/// `state.site-remove`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_remove<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    index: u32,
) -> Result<(), MeterError> {
    meter::site_remove(port, site, element, index)
}

/// `state.site-instance-take`: `count` ids at `ids`, eight bytes each.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_instance_take<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    ids: u32,
    count: u32,
) -> Result<u32, MeterError> {
    let ids = read_ids(port, ids, count)?;
    meter::site_instance_take(port, site, element, &ids)
}

/// `state.site-instance-put`.
///
/// # Errors
///
/// [`MeterError`].
pub fn site_instance_put<P: Boundary>(
    port: &mut P,
    site: u32,
    element: u32,
    funds: u32,
    ptr: u32,
    len: u32,
) -> Result<(), MeterError> {
    let value = port.read(ptr, len)?.to_vec();
    meter::site_instance_put(port, site, element, funds, value)
}

/// `state.bucket-take`.
///
/// # Errors
///
/// [`MeterError`].
pub fn bucket_take<P: Boundary>(port: &mut P, bucket: u32, amount: u32) -> Result<u32, MeterError> {
    let amount = read_amount(port, amount)?;
    meter::bucket_take(port, bucket, amount)
}

/// `state.bucket-split`.
///
/// # Errors
///
/// [`MeterError`].
pub fn bucket_split<P: Boundary>(
    port: &mut P,
    bucket: u32,
    num: u32,
    den: u32,
) -> Result<u32, MeterError> {
    let num = read_wide(port, num)?;
    let den = read_wide(port, den)?;
    meter::bucket_split(port, bucket, num, den)
}

/// `state.bucket-put`.
///
/// # Errors
///
/// [`MeterError`].
pub fn bucket_put<P: Boundary>(port: &mut P, bucket: u32, other: u32) -> Result<(), MeterError> {
    meter::bucket_put(port, bucket, other)
}

/// `state.bucket-amount`: the amount at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn bucket_amount<P: Boundary>(port: &mut P, bucket: u32, out: u32) -> Result<(), MeterError> {
    let amount = meter::bucket_amount(port, bucket)?;
    write_amount(port, out, amount)
}

/// `state.bucket-drop`.
///
/// # Errors
///
/// [`MeterError`].
pub fn bucket_drop<P: Boundary>(port: &mut P, bucket: u32) -> Result<(), MeterError> {
    meter::bucket_drop(port, bucket)
}

/// `state.mint`.
///
/// # Errors
///
/// [`MeterError`].
pub fn mint<P: Boundary>(port: &mut P, grant: u32, amount: u32) -> Result<u32, MeterError> {
    let amount = read_amount(port, amount)?;
    meter::mint(port, grant, amount)
}

/// `state.mint-instances`: `count` ids at `ids`, eight bytes each.
///
/// # Errors
///
/// [`MeterError`].
pub fn mint_instances<P: Boundary>(
    port: &mut P,
    grant: u32,
    ids: u32,
    count: u32,
) -> Result<u32, MeterError> {
    let ids = read_ids(port, ids, count)?;
    meter::mint_instances(port, grant, &ids)
}

/// `state.burn`.
///
/// # Errors
///
/// [`MeterError`].
pub fn burn<P: Boundary>(port: &mut P, funds: u32) -> Result<(), MeterError> {
    meter::burn(port, funds)
}

// ---- hyperscale:kernel/math ----------------------------------------------

/// `math.mul-div`: the result at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn mul_div<P: Boundary>(
    port: &mut P,
    a: u32,
    b: u32,
    c: u32,
    r: u32,
    out: u32,
) -> Result<(), MeterError> {
    let (a, b, c) = (
        read_wide(port, a)?,
        read_wide(port, b)?,
        read_wide(port, c)?,
    );
    let result = meter::mul_div(port, a, b, c, rounding(r)?)?;
    write_wide(port, out, result)
}

/// `math.geometric-mean`: the result at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn geometric_mean<P: Boundary>(
    port: &mut P,
    a: u32,
    b: u32,
    out: u32,
) -> Result<(), MeterError> {
    let (a, b) = (read_wide(port, a)?, read_wide(port, b)?);
    let result = meter::geometric_mean(port, a, b)?;
    write_wide(port, out, result)
}

/// `math.fraction-compose`: the numerator at `out_num`, the denominator
/// at `out_den`.
///
/// # Errors
///
/// [`MeterError`].
#[allow(clippy::too_many_arguments)] // four operands, two results, the memory and the port
pub fn fraction_compose<P: Boundary>(
    port: &mut P,
    an: u32,
    ad: u32,
    bn: u32,
    bd: u32,
    out_num: u32,
    out_den: u32,
) -> Result<(), MeterError> {
    let (an, ad) = (read_wide(port, an)?, read_wide(port, ad)?);
    let (bn, bd) = (read_wide(port, bn)?, read_wide(port, bd)?);
    let (num, den) = meter::fraction_compose(port, an, ad, bn, bd)?;
    write_wide(port, out_num, num)?;
    write_wide(port, out_den, den)
}

/// `math.fraction-cmp`.
///
/// # Errors
///
/// [`MeterError`].
pub fn fraction_cmp<P: Boundary>(
    port: &mut P,
    an: u32,
    ad: u32,
    bn: u32,
    bd: u32,
) -> Result<u32, MeterError> {
    let (an, ad) = (read_wide(port, an)?, read_wide(port, ad)?);
    let (bn, bd) = (read_wide(port, bn)?, read_wide(port, bd)?);
    meter::fraction_cmp(port, an, ad, bn, bd).map(ordering)
}

/// `math.fixed-pow`: the result at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn fixed_pow<P: Boundary>(
    port: &mut P,
    base: u32,
    exp: u32,
    r: u32,
    out: u32,
) -> Result<(), MeterError> {
    let base = read_wide(port, base)?;
    let result = meter::fixed_pow(port, base, exp, rounding(r)?)?;
    write_wide(port, out, result)
}

// ---- hyperscale:kernel/env, crypto, events --------------------------------

/// `env.clock`.
pub fn clock<P: Boundary>(port: &mut P) -> u64 {
    port.host().clock_ms()
}

/// `crypto.hash`: the digest at `out`.
///
/// # Errors
///
/// [`MeterError`].
pub fn hash<P: Boundary>(port: &mut P, ptr: u32, len: u32, out: u32) -> Result<(), MeterError> {
    let data = port.read(ptr, len)?.to_vec();
    let digest = meter::hash(port, &data)?;
    port.write(out, &digest)
}

/// `events.emit`.
///
/// # Errors
///
/// [`MeterError`].
pub fn emit<P: Boundary>(
    port: &mut P,
    event_type: u32,
    ptr: u32,
    len: u32,
) -> Result<(), MeterError> {
    let payload = port.read(ptr, len)?.to_vec();
    meter::emit(port, event_type, payload)
}

/// Every import the ABI defines, as `(module, name)` and the core
/// signature the guest declares it with.
///
/// One table so the two engines' import resolution and the validator's
/// import gate read one list rather than three.
pub const IMPORTS: &[(&str, &str, &[CoreType], &[CoreType])] = {
    use CoreType::{I32, I64};
    &[
        (ABI, "arg", &[I32, I32], &[]),
        (ABI, "take", &[I32], &[]),
        (ABI, "reply", &[I32, I32], &[]),
        (ABI, "answer", &[I32, I32], &[]),
        (STATE, "site-len", &[I32], &[I32]),
        (STATE, "site-declared", &[I32, I32], &[I32]),
        (STATE, "site-get", &[I32, I32], &[I32]),
        (STATE, "site-set", &[I32, I32, I32, I32], &[]),
        (STATE, "site-seal", &[I32, I32], &[]),
        (STATE, "site-open-seal", &[I32, I32, I32], &[I32]),
        (STATE, "site-clear", &[I32, I32], &[]),
        (STATE, "site-balance", &[I32, I32, I32], &[]),
        (STATE, "site-take", &[I32, I32, I32], &[I32]),
        (STATE, "site-put", &[I32, I32, I32], &[]),
        (STATE, "site-reserve-take", &[I32, I32], &[I32]),
        (STATE, "site-count", &[I32, I32], &[I32]),
        (STATE, "site-covered", &[I32, I32], &[I32]),
        (STATE, "site-order", &[I32, I32, I32, I32], &[]),
        (STATE, "site-entry", &[I32, I32, I32], &[I32]),
        (STATE, "site-entry-set", &[I32, I32, I32, I32, I32], &[]),
        (STATE, "site-insert", &[I32, I32, I32, I32, I32], &[]),
        (STATE, "site-remove", &[I32, I32, I32], &[]),
        (STATE, "site-instance-take", &[I32, I32, I32, I32], &[I32]),
        (STATE, "site-instance-put", &[I32, I32, I32, I32, I32], &[]),
        (STATE, "bucket-take", &[I32, I32], &[I32]),
        (STATE, "bucket-split", &[I32, I32, I32], &[I32]),
        (STATE, "bucket-put", &[I32, I32], &[]),
        (STATE, "bucket-amount", &[I32, I32], &[]),
        (STATE, "bucket-drop", &[I32], &[]),
        (STATE, "mint", &[I32, I32], &[I32]),
        (STATE, "mint-instances", &[I32, I32, I32], &[I32]),
        (STATE, "burn", &[I32], &[]),
        (MATH, "mul-div", &[I32, I32, I32, I32, I32], &[]),
        (MATH, "geometric-mean", &[I32, I32, I32], &[]),
        (
            MATH,
            "fraction-compose",
            &[I32, I32, I32, I32, I32, I32],
            &[],
        ),
        (MATH, "fraction-cmp", &[I32, I32, I32, I32], &[I32]),
        (MATH, "fixed-pow", &[I32, I32, I32, I32], &[]),
        (ENV, "clock", &[], &[I64]),
        (CRYPTO, "hash", &[I32, I32, I32], &[]),
        (EVENTS, "emit", &[I32, I32, I32], &[]),
    ]
};

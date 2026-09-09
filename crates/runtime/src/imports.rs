//! The kernel imports, wired into a core linker.
//!
//! One `func_wrap` per dispatch in [`hyperscale_vm_embed::abi`], and
//! nothing decided here: the engine contributes the store — its data
//! the host and the registers, its fuel the budget, the instance's one
//! memory the bytes — and the dispatch reads all four through one
//! [`Boundary`]. What this file knows is how a wasmtime `Caller` is
//! those four things.

use hyperscale_vm_embed::abi::{self, Boundary, GuestMemory, IMPORTS, MEMORY, Registers};
use hyperscale_vm_embed::meter::{Exhausted, FuelSink, HostAccess, MeterError};
use hyperscale_vm_embed::{GuestArg, KernelHost};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Caller, Extern, Linker, Memory, Result, Val};

use crate::abort::{fault, host_trap};

/// The store's data while a guest runs: the host, and the registers of
/// the call in flight.
///
/// The memory is remembered from the first host call of an invocation,
/// so the export lookup happens once per call rather than once per
/// import.
pub struct Invoking<H> {
    host: H,
    registers: Registers,
    memory: Option<Memory>,
}

impl<H> Invoking<H> {
    /// A store's data before any call: the host, and empty registers.
    pub fn new(host: H) -> Self {
        Self {
            host,
            registers: Registers::default(),
            memory: None,
        }
    }

    /// The host.
    pub const fn host(&self) -> &H {
        &self.host
    }

    /// The host, to operate on.
    pub const fn host_mut(&mut self) -> &mut H {
        &mut self.host
    }

    /// The host, once the store is done with.
    pub fn into_host(self) -> H {
        self.host
    }

    /// Begins one call: its registers, as [`abi::lower`] built them,
    /// and the instance's memory.
    pub(crate) fn begin(&mut self, registers: Registers, memory: Memory) {
        self.registers = registers;
        self.memory = Some(memory);
    }

    /// The registers of the call in flight.
    pub(crate) const fn registers(&mut self) -> &mut Registers {
        &mut self.registers
    }
}

/// The caller of one host function, seen as the boundary.
struct Port<'c, 'a, H: 'static> {
    caller: &'c mut Caller<'a, Invoking<H>>,
    memory: Memory,
}

impl<'c, 'a, H: KernelHost + 'static> Port<'c, 'a, H> {
    fn new(caller: &'c mut Caller<'a, Invoking<H>>) -> Result<Self> {
        let memory = if let Some(memory) = caller.data().memory {
            memory
        } else {
            let memory = caller
                .get_export(MEMORY)
                .and_then(Extern::into_memory)
                .ok_or_else(|| host_trap(AbortReason::AbiViolation))?;
            caller.data_mut().memory = Some(memory);
            memory
        };
        Ok(Self { caller, memory })
    }
}

impl<H: KernelHost + 'static> GuestMemory for Port<'_, '_, H> {
    fn read(&self, ptr: u32, len: u32) -> std::result::Result<&[u8], MeterError> {
        self.memory.data(&*self.caller).read(ptr, len)
    }

    fn write(&mut self, ptr: u32, bytes: &[u8]) -> std::result::Result<(), MeterError> {
        self.memory.data_mut(&mut *self.caller).write(ptr, bytes)
    }
}

impl<H: KernelHost + 'static> HostAccess for Port<'_, '_, H> {
    type Host = H;

    fn host(&mut self) -> &mut H {
        &mut self.caller.data_mut().host
    }
}

impl<H: KernelHost + 'static> FuelSink for Port<'_, '_, H> {
    fn consume(&mut self, fuel: u64) -> std::result::Result<(), Exhausted> {
        let current = self.caller.get_fuel().expect("fuel metering is enabled");
        if let Some(remaining) = current.checked_sub(fuel) {
            self.caller
                .set_fuel(remaining)
                .expect("fuel metering is enabled");
            Ok(())
        } else {
            // Zeroed first, matching the engine's own exhaustion behavior.
            self.caller.set_fuel(0).expect("fuel metering is enabled");
            Err(Exhausted)
        }
    }
}

impl<H: KernelHost + 'static> Boundary for Port<'_, '_, H> {
    fn registers(&mut self) -> &mut Registers {
        &mut self.caller.data_mut().registers
    }
}

/// One import: the caller becomes the boundary, the dispatch runs, and
/// a failure becomes the engine's error with its class recoverable.
macro_rules! import {
    ($linker:ident, $module:expr, $name:literal,
     $dispatch:ident($($arg:ident: $ty:ty),*) -> $ret:ty) => {
        $linker.func_wrap(
            $module,
            $name,
            |mut caller: Caller<'_, Invoking<H>>, $($arg: $ty),*| -> Result<$ret> {
                abi::$dispatch(&mut Port::new(&mut caller)?, $($arg),*).map_err(fault)
            },
        )?;
    };
    ($linker:ident, $module:expr, $name:literal,
     $dispatch:ident($($arg:ident: $ty:ty),*)) => {
        import!($linker, $module, $name, $dispatch($($arg: $ty),*) -> ());
    };
}

/// Adds every kernel import to a core linker.
///
/// The set is [`IMPORTS`], and the validator admits exactly that set, so
/// a module the gate passed is one the linker resolves.
///
/// # Errors
///
/// Fails only on duplicate definitions in the linker — a wiring defect,
/// never an input-dependent condition.
#[allow(clippy::too_many_lines)] // one registration per import
pub fn add_kernel_imports<H: KernelHost + 'static>(linker: &mut Linker<Invoking<H>>) -> Result<()> {
    use abi::{ABI, CRYPTO, ENV, EVENTS, MATH, STATE};

    import!(linker, ABI, "arg", arg(index: u32, ptr: u32));
    import!(linker, ABI, "take", take(ptr: u32));
    import!(linker, ABI, "reply", reply(ptr: u32, count: u32));
    import!(linker, ABI, "answer", answer(ptr: u32, len: u32));

    import!(linker, STATE, "site-len", site_len(site: u32) -> u32);
    import!(
        linker,
        STATE,
        "site-declared",
        site_declared(site: u32, element: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-get",
        site_get(site: u32, element: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-set",
        site_set(site: u32, element: u32, ptr: u32, len: u32)
    );
    import!(
        linker,
        STATE,
        "site-seal",
        site_seal(site: u32, element: u32)
    );
    import!(
        linker,
        STATE,
        "site-open-seal",
        site_open_seal(site: u32, element: u32, out: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-clear",
        site_clear(site: u32, element: u32)
    );
    import!(
        linker,
        STATE,
        "site-balance",
        site_balance(site: u32, element: u32, out: u32)
    );
    import!(
        linker,
        STATE,
        "site-take",
        site_take(site: u32, element: u32, amount: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-put",
        site_put(site: u32, element: u32, funds: u32)
    );
    import!(
        linker,
        STATE,
        "site-reserve-take",
        site_reserve_take(site: u32, element: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-count",
        site_count(site: u32, element: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-covered",
        site_covered(site: u32, element: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-order",
        site_order(site: u32, element: u32, index: u32, out: u32)
    );
    import!(
        linker,
        STATE,
        "site-entry",
        site_entry(site: u32, element: u32, index: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-entry-set",
        site_entry_set(site: u32, element: u32, index: u32, ptr: u32, len: u32)
    );
    import!(
        linker,
        STATE,
        "site-insert",
        site_insert(site: u32, element: u32, order: u32, ptr: u32, len: u32)
    );
    import!(
        linker,
        STATE,
        "site-remove",
        site_remove(site: u32, element: u32, index: u32)
    );
    import!(
        linker,
        STATE,
        "site-instance-take",
        site_instance_take(site: u32, element: u32, ids: u32, count: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "site-instance-put",
        site_instance_put(site: u32, element: u32, funds: u32, ptr: u32, len: u32)
    );
    import!(
        linker,
        STATE,
        "bucket-take",
        bucket_take(bucket: u32, amount: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "bucket-split",
        bucket_split(bucket: u32, num: u32, den: u32) -> u32
    );
    import!(
        linker,
        STATE,
        "bucket-put",
        bucket_put(bucket: u32, other: u32)
    );
    import!(
        linker,
        STATE,
        "bucket-amount",
        bucket_amount(bucket: u32, out: u32)
    );
    import!(linker, STATE, "bucket-drop", bucket_drop(bucket: u32));
    import!(linker, STATE, "mint", mint(grant: u32, amount: u32) -> u32);
    import!(
        linker,
        STATE,
        "mint-instances",
        mint_instances(grant: u32, ids: u32, count: u32) -> u32
    );
    import!(linker, STATE, "burn", burn(funds: u32));

    import!(
        linker,
        MATH,
        "mul-div",
        mul_div(a: u32, b: u32, c: u32, r: u32, out: u32)
    );
    import!(
        linker,
        MATH,
        "geometric-mean",
        geometric_mean(a: u32, b: u32, out: u32)
    );
    import!(
        linker,
        MATH,
        "fraction-compose",
        fraction_compose(an: u32, ad: u32, bn: u32, bd: u32, out_num: u32, out_den: u32)
    );
    import!(
        linker,
        MATH,
        "fraction-cmp",
        fraction_cmp(an: u32, ad: u32, bn: u32, bd: u32) -> u32
    );
    import!(
        linker,
        MATH,
        "fixed-pow",
        fixed_pow(base: u32, exp: u32, r: u32, out: u32)
    );

    linker.func_wrap(
        ENV,
        "clock",
        |mut caller: Caller<'_, Invoking<H>>| -> Result<u64> {
            Ok(abi::clock(&mut Port::new(&mut caller)?))
        },
    )?;

    import!(linker, CRYPTO, "hash", hash(ptr: u32, len: u32, out: u32));
    import!(
        linker,
        EVENTS,
        "emit",
        emit(event_type: u32, ptr: u32, len: u32)
    );

    debug_assert_eq!(
        IMPORTS.len(),
        40,
        "every entry of the import table is registered above"
    );
    Ok(())
}

/// The core values an invocation's arguments lower to, as the engine's.
pub(crate) fn lowered(args: &[GuestArg<'_>]) -> Result<(Vec<Val>, Registers)> {
    let (values, registers) = abi::lower(args).map_err(fault)?;
    let values = values
        .into_iter()
        .map(|value| match value {
            abi::CoreValue::I32(bits) => Val::I32(bits.cast_signed()),
            abi::CoreValue::I64(bits) => Val::I64(bits.cast_signed()),
        })
        .collect();
    Ok((values, registers))
}

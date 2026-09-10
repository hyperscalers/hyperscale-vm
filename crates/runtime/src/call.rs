//! Invocation of a module export by the binding's own values.
//!
//! The embedder that drives a package's ABI binding has the assembled
//! arguments and the export's name, and nothing else: the arguments
//! lower to core values and the input registers, the call runs, and what
//! the export replied comes back through the registers it filled.

use hyperscale_vm_embed::abi::MEMORY;
use hyperscale_vm_embed::{GuestArg, Invocation, Invoked, KernelHost};
use hyperscale_vm_types::AbortReason;
use wasmtime::{Error, Instance, Result, Store, Val};

use crate::abort::{CallError, classify, host_trap};
use crate::budget::{counter, remaining};
use crate::imports::{Invoking, lowered};

/// How an invocation ended, as the artifact's own result type says it can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Returned {
    /// The export returned: the value edges it produced, as the buckets
    /// the kernel now holds again, in the order the signature declares
    /// its outputs, and the value it answered with beside them.
    Produced {
        /// The buckets, in output order.
        edges: Vec<u32>,
        /// What the method handed back that is not an edge. `None`
        /// where the method answers nothing.
        answer: Option<Vec<u8>>,
    },

    /// The export declined, with an index into its package's error table.
    ///
    /// Not a failure of the call — the guest ran to completion and said
    /// no on its own terms, which is what makes its fuel an ordinary
    /// completed figure rather than an abort's.
    Declined(u32),
}

fn shape(export: &str, found: &str) -> Error {
    CallError::BadReturnShape {
        export: export.to_owned(),
        found: found.to_owned(),
    }
    .into()
}

/// Invoke `export` on `instance` with `args`.
///
/// The arguments lower to core values and the input registers; the
/// export's own result type says whether it can decline — one `i32` —
/// and what it produced comes back through the registers it replied
/// into. A decline discards whatever was replied before it.
///
/// # Errors
///
/// A missing export, an argument outside the convention, a guest trap,
/// a host refusal, or a return outside the convention.
pub fn call_export<H: KernelHost + 'static>(
    store: &mut Store<Invoking<H>>,
    instance: &Instance,
    export: &str,
    args: &[GuestArg<'_>],
) -> Result<Returned> {
    let Some(func) = instance.get_func(&mut *store, export) else {
        return Err(CallError::ExportMissing(export.to_owned()).into());
    };
    let memory = instance
        .get_memory(&mut *store, MEMORY)
        .ok_or_else(|| host_trap(AbortReason::AbiViolation))?;
    let (params, registers) = lowered(args)?;
    let counter = counter(&mut *store, instance);
    store.data_mut().begin(registers, memory, counter);
    let arity = func.ty(&*store).results().len();
    let mut results = vec![Val::I32(0); arity];
    func.call(&mut *store, &params, &mut results)?;
    match results.first() {
        None | Some(Val::I32(0)) => {}
        Some(Val::I32(code)) => {
            return Ok(Returned::Declined(code.cast_unsigned() - 1));
        }
        Some(other) => return Err(shape(export, &format!("{other:?}"))),
    }
    let reply = store
        .data_mut()
        .registers()
        .reply()
        .ok_or_else(|| shape(export, "no reply"))?;
    Ok(Returned::Produced {
        edges: reply.edges,
        answer: reply.answer,
    })
}

/// Invoke `export` and fold how it ended into the protocol's vocabulary.
///
/// The verdict, and the fuel spent of `budget`: what the counter has
/// given up since the instance was set to it, so a second call on one
/// instance reads cumulatively.
///
/// Infallible where [`call_export`] is not, because every way a call can
/// end is a deterministic verdict — a trap is a class, an off-convention
/// result is a class — so an embedder holds no error channel whose
/// handling could drift from another embedder's.
///
/// # Panics
///
/// Panics if the instance exports no counter: the module was not
/// admitted through the meter.
pub fn invoke_export<H: KernelHost + 'static>(
    store: &mut Store<Invoking<H>>,
    instance: &Instance,
    export: &str,
    args: &[GuestArg<'_>],
    budget: u64,
) -> Invocation {
    let result = match call_export(store, instance, export, args) {
        Ok(Returned::Produced { edges, answer }) => Invoked::Produced { edges, answer },
        Ok(Returned::Declined(code)) => Invoked::Declined(code),
        Err(error) => Invoked::Aborted(classify(&error)),
    };
    let counter = counter(&mut *store, instance);
    let fuel = budget.saturating_sub(remaining(&mut *store, &counter));
    Invocation { result, fuel }
}

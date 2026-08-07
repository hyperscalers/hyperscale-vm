//! Dynamic invocation of a component export.
//!
//! The typed-function path needs the export's Rust signature at the call
//! site, which is exactly what an embedder that dispatches by name has
//! and an embedder driven by a package's own ABI binding does not. This
//! is the same call built from values: handles as resources of the
//! mode's own type, amounts and addresses as `list<u8>`, order keys and
//! prices as `u64`.
//!
//! It belongs beside [`crate::world`] because the resource types it
//! constructs are that world's, and because the mapping from a mode to
//! its handle type is the same one the linker registers.

use wasmtime::component::{Instance, Resource, ResourceAny, Val};
use wasmtime::{AsContextMut, Result, bail};

use crate::world::{
    DeltaCell, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
};

/// Which of the state interface's resources a handle is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CellKind {
    /// `read-cell`.
    Read,
    /// `locked-cell`.
    Locked,
    /// `write-cell`.
    Write,
    /// `delta-cell`.
    Delta,
    /// `reserve-cell`.
    Reserve,
    /// `range-read`.
    RangeRead,
    /// `range-write`.
    RangeWrite,
}

/// One argument of a dynamic invocation.
#[derive(Clone, Copy, Debug)]
pub enum HostArg<'a> {
    /// A capability handle at `rep`, of the mode's own resource type.
    Handle {
        /// The host-assigned rep the kernel materialized.
        rep: u32,
        /// Which resource type to construct it as.
        kind: CellKind,
    },
    /// A `u64` scalar.
    U64(u64),
    /// A `list<u8>`.
    Bytes(&'a [u8]),
}

/// The handle for one rep, as the resource type its mode names.
///
/// Registered as an owned host handle rather than a borrowed one, which
/// is a property of the value path and not of what the guest receives:
/// a borrow is only representable inside an active call scope, and there
/// is none while a call's arguments are still being assembled. The guest
/// parameter is `borrow<cell>` either way — the canonical ABI lends this
/// handle for the duration of the call and takes it back at scope exit —
/// and a `Resource` carries no destructor, so ownership here names a
/// table slot and nothing that could be destroyed.
fn handle(kind: CellKind, rep: u32, store: impl AsContextMut) -> Result<ResourceAny> {
    match kind {
        CellKind::Read => ResourceAny::try_from_resource(Resource::<ReadCell>::new_own(rep), store),
        CellKind::Locked => {
            ResourceAny::try_from_resource(Resource::<LockedCell>::new_own(rep), store)
        }
        CellKind::Write => {
            ResourceAny::try_from_resource(Resource::<WriteCell>::new_own(rep), store)
        }
        CellKind::Delta => {
            ResourceAny::try_from_resource(Resource::<DeltaCell>::new_own(rep), store)
        }
        CellKind::Reserve => {
            ResourceAny::try_from_resource(Resource::<ReserveCell>::new_own(rep), store)
        }
        CellKind::RangeRead => {
            ResourceAny::try_from_resource(Resource::<RangeRead>::new_own(rep), store)
        }
        CellKind::RangeWrite => {
            ResourceAny::try_from_resource(Resource::<RangeWrite>::new_own(rep), store)
        }
    }
}

/// Invoke `export` on `instance` with `args`, expecting one `list<u8>`
/// result when `returns` is set and none otherwise.
///
/// # Errors
///
/// A missing export, an argument the canonical ABI refuses, a guest trap,
/// or a result that is not the single byte list the convention fixes.
pub fn call_export<T: 'static>(
    mut store: impl AsContextMut<Data = T>,
    instance: &Instance,
    export: &str,
    args: &[HostArg<'_>],
    returns: bool,
) -> Result<Option<Vec<u8>>> {
    let Some(func) = instance.get_func(store.as_context_mut(), export) else {
        bail!("component exports no function `{export}`");
    };
    let mut lowered = Vec::with_capacity(args.len());
    for arg in args {
        lowered.push(match arg {
            HostArg::Handle { rep, kind } => {
                Val::Resource(handle(*kind, *rep, store.as_context_mut())?)
            }
            HostArg::U64(scalar) => Val::U64(*scalar),
            HostArg::Bytes(bytes) => Val::List(bytes.iter().copied().map(Val::U8).collect()),
        });
    }
    let mut results = vec![Val::Bool(false); usize::from(returns)];
    func.call(store.as_context_mut(), &lowered, &mut results)?;
    match results.first() {
        None => Ok(None),
        Some(Val::List(values)) => {
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                match value {
                    Val::U8(byte) => bytes.push(*byte),
                    other => bail!("`{export}` returned a list of {other:?}, not of bytes"),
                }
            }
            Ok(Some(bytes))
        }
        Some(other) => bail!("`{export}` returned {other:?}, not a byte list"),
    }
}

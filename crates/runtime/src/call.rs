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
use wasmtime::{AsContextMut, Error, Result};

use crate::abort::CallError;
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

/// How an invocation ended, as the artifact's own result type says it can.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Returned {
    /// The export returned: its byte payload, when its signature has one.
    Values(Option<Vec<u8>>),
    /// The export declined, with an index into its package's error table.
    ///
    /// Not a failure of the call — the guest ran to completion and said
    /// no on its own terms, which is what makes its fuel an ordinary
    /// completed figure rather than an engine-defined one.
    Declined(u32),
}

/// Invoke `export` on `instance` with `args`.
///
/// The result arity comes from the export's own type rather than from
/// the manifest node driving it: how a method ends is a fact about the
/// artifact, and a caller that supplied its own count could disagree
/// with the code.
///
/// # Errors
///
/// A missing export, an argument the canonical ABI refuses, a guest trap,
/// or a result outside the shapes the convention fixes.
pub fn call_export<T: 'static>(
    mut store: impl AsContextMut<Data = T>,
    instance: &Instance,
    export: &str,
    args: &[HostArg<'_>],
) -> Result<Returned> {
    let Some(func) = instance.get_func(store.as_context_mut(), export) else {
        return Err(CallError::ExportMissing(export.to_owned()).into());
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
    let arity = func.ty(store.as_context()).results().len();
    let mut results = vec![Val::Bool(false); arity];
    func.call(store.as_context_mut(), &lowered, &mut results)?;
    match results.first() {
        // No result at all, or an ok arm with no payload: a method that
        // produces nothing, whether or not it can decline.
        None | Some(Val::Result(Ok(None))) => Ok(Returned::Values(None)),
        Some(Val::Result(Ok(Some(value)))) => {
            byte_list(export, value).map(|bytes| Returned::Values(Some(bytes)))
        }
        Some(Val::Result(Err(Some(code)))) => match **code {
            Val::U32(code) => Ok(Returned::Declined(code)),
            ref other => Err(shape(export, &format!("declined with {other:?}"))),
        },
        Some(value) => byte_list(export, value).map(|bytes| Returned::Values(Some(bytes))),
    }
}

/// The bytes of a `list<u8>` value, or a shape refusal naming what came
/// back instead.
fn byte_list(export: &str, value: &Val) -> Result<Vec<u8>> {
    let Val::List(values) = value else {
        return Err(shape(export, &format!("{value:?}")));
    };
    let mut bytes = Vec::with_capacity(values.len());
    for value in values {
        match value {
            Val::U8(byte) => bytes.push(*byte),
            other => return Err(shape(export, &format!("a list of {other:?}"))),
        }
    }
    Ok(bytes)
}

fn shape(export: &str, found: &str) -> Error {
    CallError::BadReturnShape {
        export: export.to_owned(),
        found: found.to_owned(),
    }
    .into()
}

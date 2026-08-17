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

use hyperscale_vm_embed::{CellKind, GuestArg};
use hyperscale_vm_types::{Address, ISSUER_REP};
use wasmtime::component::{Instance, Resource, ResourceAny, Val};
use wasmtime::{AsContextMut, Error, Result};

use crate::abort::CallError;
use crate::world::{
    Bucket, DeltaCell, Issuer, LockedCell, RangeRead, RangeWrite, ReadCell, ReserveCell, WriteCell,
};

/// An address as the world's `record address`: four little-endian words.
///
/// The halving is the representation, not a narrowing — the component
/// model has no 256-bit scalar, and four `u64`s flatten where a byte list
/// would travel through memory.
fn address_val(address: Address) -> Val {
    let bytes = address.to_bytes();
    let word = |at: usize| {
        Val::U64(u64::from_le_bytes(
            bytes[at..at + 8].try_into().expect("eight bytes"),
        ))
    };
    Val::Record(vec![
        ("a".to_owned(), word(0)),
        ("b".to_owned(), word(8)),
        ("c".to_owned(), word(16)),
        ("d".to_owned(), word(24)),
    ])
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
    /// The export returned the value edges it produced, as the buckets
    /// the kernel now holds again, in the order the signature declares
    /// its outputs.
    Edges(Vec<u32>),

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
    args: &[GuestArg<'_>],
) -> Result<Returned> {
    let Some(func) = instance.get_func(store.as_context_mut(), export) else {
        return Err(CallError::ExportMissing(export.to_owned()).into());
    };
    let mut lowered = Vec::with_capacity(args.len());
    for arg in args {
        lowered.push(match arg {
            GuestArg::Handle { rep, kind } => {
                Val::Resource(handle(*kind, *rep, store.as_context_mut())?)
            }
            GuestArg::U64(scalar) => Val::U64(*scalar),
            GuestArg::Address(address) => address_val(*address),
            GuestArg::Bytes(bytes) => Val::List(bytes.iter().copied().map(Val::U8).collect()),
            GuestArg::Bucket(rep) => Val::Resource(ResourceAny::try_from_resource(
                Resource::<Bucket>::new_own(*rep),
                store.as_context_mut(),
            )?),
            GuestArg::Issuer => Val::Resource(ResourceAny::try_from_resource(
                Resource::<Issuer>::new_own(ISSUER_REP),
                store.as_context_mut(),
            )?),
        });
    }
    let arity = func.ty(store.as_context()).results().len();
    let mut results = vec![Val::Bool(false); arity];
    func.call(store.as_context_mut(), &lowered, &mut results)?;
    // The shape decides, not the caller: how a method ends is a fact
    // about the artifact, and an edge is told from a payload by what came
    // back rather than by what a manifest expected.
    let returned = match results.first() {
        None | Some(Val::Result(Ok(None))) => return Ok(Returned::Edges(Vec::new())),
        Some(Val::Result(Err(Some(code)))) => {
            return match **code {
                Val::U32(code) => Ok(Returned::Declined(code)),
                ref other => Err(shape(export, &format!("declined with {other:?}"))),
            };
        }
        Some(Val::Result(Ok(Some(value)))) => value.as_ref(),
        Some(value) => value,
    };
    match returned {
        Val::Resource(handle) => Ok(Returned::Edges(vec![
            handle
                .try_into_resource::<Bucket>(store.as_context_mut())?
                .rep(),
        ])),
        Val::Tuple(edges) => {
            let mut reps = Vec::with_capacity(edges.len());
            for edge in edges {
                let Val::Resource(handle) = edge else {
                    return Err(shape(export, &format!("an edge tuple of {edge:?}")));
                };
                reps.push(
                    handle
                        .try_into_resource::<Bucket>(store.as_context_mut())?
                        .rep(),
                );
            }
            Ok(Returned::Edges(reps))
        }
        value => Err(shape(export, &format!("{value:?}"))),
    }
}

fn shape(export: &str, found: &str) -> Error {
    CallError::BadReturnShape {
        export: export.to_owned(),
        found: found.to_owned(),
    }
    .into()
}

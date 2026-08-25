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

use hyperscale_vm_embed::{GuestArg, Invocation, Invoked};
use hyperscale_vm_types::{ADDRESS_WORDS, Address, ISSUER_REP};
use wasmtime::component::{Instance, Resource, ResourceAny, Val};
use wasmtime::{AsContextMut, Error, Result, Store};

use crate::abort::{CallError, classify, exhausted};
use crate::world::{Bucket, Capability, Issuer, Run};

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
    Val::Record(
        ADDRESS_WORDS
            .iter()
            .enumerate()
            .map(|(index, name)| ((*name).to_owned(), word(index * 8)))
            .collect(),
    )
}

/// The handle for one rep.
///
/// Registered as an owned host handle rather than a borrowed one, which
/// is a property of the value path and not of what the guest receives:
/// a borrow is only representable inside an active call scope, and there
/// is none while a call's arguments are still being assembled. The guest
/// parameter is `borrow<capability>` either way — the canonical ABI lends this
/// handle for the duration of the call and takes it back at scope exit —
/// and a `Resource` carries no destructor, so ownership here names a
/// table slot and nothing that could be destroyed.
fn handle(rep: u32, store: impl AsContextMut) -> Result<ResourceAny> {
    ResourceAny::try_from_resource(Resource::<Capability>::new_own(rep), store)
}

/// The run resource one `for-each` site's expansion is lent as.
///
/// Its own type beside [`handle`] because the rep is a position in the
/// session's run table rather than in its capability table, and which
/// capability an index reaches is the run's answer — so a rep here and a
/// rep there mean different things, and the type is what says so.
fn run(rep: u32, store: impl AsContextMut) -> Result<ResourceAny> {
    ResourceAny::try_from_resource(Resource::<Run>::new_own(rep), store)
}

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
            GuestArg::Handle { rep } => Val::Resource(handle(*rep, store.as_context_mut())?),
            GuestArg::Run { rep } => Val::Resource(run(*rep, store.as_context_mut())?),
            GuestArg::Bool(taken) => Val::Bool(*taken),
            GuestArg::U64(scalar) => Val::U64(*scalar),
            GuestArg::Address(address) => address_val(*address),
            GuestArg::Bytes(bytes) => Val::List(bytes.iter().copied().map(Val::U8).collect()),
            GuestArg::Ids(ids) => Val::List(ids.iter().copied().map(Val::U64).collect()),
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
    let nothing = Returned::Produced {
        edges: Vec::new(),
        answer: None,
    };
    let returned = match results.first() {
        None | Some(Val::Result(Ok(None))) => return Ok(nothing),
        Some(Val::Result(Err(Some(code)))) => {
            return match **code {
                Val::U32(code) => Ok(Returned::Declined(code)),
                ref other => Err(shape(export, &format!("declined with {other:?}"))),
            };
        }
        Some(Val::Result(Ok(Some(value)))) => value.as_ref(),
        Some(value) => value,
    };
    // An answer leads where a method has one, so a lone byte list is an
    // answer and a tuple's first element may be. Everything after it is
    // an edge either way.
    let (answer, edges) = match returned {
        Val::List(bytes) => {
            return answered(export, bytes).map(|answer| Returned::Produced {
                edges: Vec::new(),
                answer: Some(answer),
            });
        }
        Val::Tuple(values) => match values.split_first() {
            Some((Val::List(bytes), rest)) => (Some(answered(export, bytes)?), rest),
            _ => (None, values.as_slice()),
        },
        edge => (None, std::slice::from_ref(edge)),
    };
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
    Ok(Returned::Produced {
        edges: reps,
        answer,
    })
}

/// A byte-list result as the bytes it is.
fn answered(export: &str, bytes: &[Val]) -> Result<Vec<u8>> {
    bytes
        .iter()
        .map(|byte| match byte {
            Val::U8(byte) => Ok(*byte),
            other => Err(shape(export, &format!("an answer of {other:?}"))),
        })
        .collect()
}

fn shape(export: &str, found: &str) -> Error {
    CallError::BadReturnShape {
        export: export.to_owned(),
        found: found.to_owned(),
    }
    .into()
}

/// Invoke `export` and fold how it ended into the protocol's vocabulary:
/// the verdict, the fuel spent of `budget`, and whether the budget
/// exhausted.
///
/// Infallible where [`call_export`] is not, because every way a call can
/// end is a deterministic verdict — a trap is a class, an off-convention
/// result is a class — so an embedder holds no error channel whose
/// handling could drift from another embedder's.
///
/// # Panics
///
/// Panics if the store does not meter fuel, which the blessed config
/// always enables.
pub fn invoke_export<T: 'static>(
    store: &mut Store<T>,
    instance: &Instance,
    export: &str,
    args: &[GuestArg<'_>],
    budget: u64,
) -> Invocation {
    let outcome = call_export(&mut *store, instance, export, args);
    let exhausted = outcome.as_ref().err().is_some_and(exhausted);
    let result = match outcome {
        Ok(Returned::Produced { edges, answer }) => Invoked::Produced { edges, answer },
        Ok(Returned::Declined(code)) => Invoked::Declined(code),
        Err(error) => Invoked::Aborted(classify(&error)),
    };
    let fuel = budget - store.get_fuel().expect("fuel metering is enabled");
    Invocation {
        result,
        fuel,
        exhausted,
    }
}

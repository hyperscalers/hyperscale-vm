//! The seam between the kernel and whatever executes a package.
//!
//! Two halves of one boundary. [`KernelHost`] is what an engine calls: the
//! kernel's operations as reps and bytes, each answering with a
//! deterministic refusal class rather than a message. [`GuestArg`] and
//! [`Invoked`] are what crosses it: an invocation's arguments as the
//! kernel assembled them, and how the invocation ended.
//!
//! Here rather than beside either party, because both are written to by
//! more than one of them. Three callers reach the host surface — the
//! blessed engine through its linker, the reference interpreter through
//! its canon dispatch, and the SDK's native accessors — and a surface
//! stated once per caller is a surface that drifts. What an engine may
//! not do is word a refusal of its own or infer a handle's mode from the
//! export it happens to be calling; both are decided here, upstream of
//! every embedding.
//!
//! Deliberately thin: no store, no session, no engine. The kernel's own
//! call — `GuestCall`, `InvokeResult`, `GuestBackend` — names a session
//! and so stays in the kernel, which is what keeps this crate reachable
//! from a package's host build.

mod call;
mod host;
pub mod meter;

pub use call::{GuestArg, Invocation, Invoked};
pub use host::KernelHost;

//! One assembled invocation: what goes in, and how it ended.

use hyperscale_vm_types::{AbortReason, Address, CellKind};

/// One assembled argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestArg<'a> {
    /// A borrowed capability handle: its rep in the session's table and
    /// the resource type to construct it as.
    Handle {
        /// The table position the session assigned.
        rep: u32,
        /// The handle type.
        kind: CellKind,
    },
    /// A clause's own guard verdict.
    Bool(bool),
    /// A 64-bit scalar.
    U64(u64),
    /// An address, as the world's own record.
    Address(Address),
    /// A `list<u8>` argument.
    Bytes(&'a [u8]),
    /// A value edge, transferred to the guest as the bucket the kernel
    /// holds for it.
    ///
    /// Ownership, not a loan: the canonical ABI seats it in the guest's
    /// table, and the kernel's rep is not reachable from the caller again
    /// unless the guest hands it back.
    Bucket(u32),
    /// This invocation's authority to issue, granted from the method's
    /// own declared outputs.
    Issuer,
}

/// How one invocation ended.
///
/// Three ways rather than two, because returning on an error arm is
/// neither of the other two: the guest ran to completion and said no.
/// That distinction is what separates a declared refusal from a defect
/// everywhere downstream — the outcome it records, and the fee it pays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invoked {
    /// The export returned the value edges it produced, as the buckets
    /// the kernel holds again — none, where its signature declares none.
    Produced(Vec<u32>),
    /// The export declined, with an index into its package's error table.
    Declined(u32),
    /// The invocation failed, in the class the engine classified it as.
    ///
    /// A class rather than a message, so an engine has no formatting
    /// decision to make and two engines cannot word one failure two ways.
    Aborted(AbortReason),
}

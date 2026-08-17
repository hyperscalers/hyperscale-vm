//! What one transaction did, as a test asks about it.

use hyperscale_vm_effects::AbortReason;
use hyperscale_vm_kernel::{Outcome as KernelOutcome, Receipt};

/// The receipt one [`transact`](crate::Chain::transact) produced.
///
/// A receipt is the whole record and a test usually wants one question
/// answered, so the questions are here and the record is underneath for
/// the ones that are not.
pub struct Outcome {
    receipt: Receipt,
    /// The declining node's package error table, where one declined.
    errors: Vec<String>,
}

impl Outcome {
    pub(crate) const fn new(receipt: Receipt, errors: Vec<String>) -> Self {
        Self { receipt, errors }
    }

    /// The receipt itself: the delta, the events, the fuel.
    #[must_use]
    pub const fn receipt(&self) -> &Receipt {
        &self.receipt
    }

    /// Whether the transaction ran to completion.
    #[must_use]
    pub const fn completed(&self) -> bool {
        matches!(self.receipt.outcome, KernelOutcome::Completed { .. })
    }

    /// The error code the method declined with, if it declined.
    ///
    /// An index into the package's own error table — a race the sender
    /// lost, not a defect it committed, which is why it reads as a value
    /// rather than as a failure.
    #[must_use]
    pub const fn declined(&self) -> Option<u32> {
        match self.receipt.outcome {
            KernelOutcome::Declined { code, .. } => Some(code),
            _ => None,
        }
    }

    /// The name the declining package gave the code it returned.
    ///
    /// The package's own error table, read at the index the code names —
    /// so a test asserts on what an author wrote rather than on the
    /// position the table happens to hold it at.
    #[must_use]
    pub fn declined_as(&self) -> Option<&str> {
        let code = self.declined()?;
        self.errors.get(code as usize).map(String::as_str)
    }

    /// The class the invocation trapped with, if it trapped.
    #[must_use]
    pub const fn aborted(&self) -> Option<AbortReason> {
        match self.receipt.outcome {
            KernelOutcome::UserError { reason } => Some(reason),
            _ => None,
        }
    }

    /// The payloads emitted under one of the package's event types, in
    /// emission order.
    ///
    /// The type is the index the package's own event table fixes, which
    /// is what a generated event constant carries.
    #[must_use]
    pub fn events(&self, event_type: u32) -> Vec<&[u8]> {
        self.receipt
            .events
            .iter()
            .filter(|event| event.event_type == event_type)
            .map(|event| event.payload.as_slice())
            .collect()
    }

    /// Panics with the outcome unless the transaction completed.
    ///
    /// What a test says when the point of the transaction is its effect
    /// rather than its verdict: a decline three lines up would otherwise
    /// surface as a balance that did not move.
    ///
    /// # Panics
    ///
    /// If the transaction did anything but complete.
    pub fn expect_completed(&self) {
        assert!(
            self.completed(),
            "the transaction did not complete: {:?}",
            self.receipt.outcome
        );
    }
}

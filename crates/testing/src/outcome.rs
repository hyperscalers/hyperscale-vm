//! What one transaction did, as a test asks about it.

use hyperscale_vm_effects::address_text;
use hyperscale_vm_kernel::Receipt;
use hyperscale_vm_sdk::client::Answered;
use hyperscale_vm_sdk::hbor::{HborDecode, from_slice};
use hyperscale_vm_types::{AbortReason, Address, Answer, Outcome as KernelOutcome};

/// The receipt one [`transact`](crate::Chain::transact) produced.
///
/// A receipt is the whole record and a test usually wants one question
/// answered, so the questions are here and the record is underneath for
/// the ones that are not.
///
/// `Debug` because an assertion that fails wants to say what it got, and
/// what a transaction did is the first thing a reader asks.
#[derive(Debug)]
pub struct Outcome<T = ()> {
    receipt: Receipt,
    /// The declining node's package error table, where one declined.
    errors: Vec<String>,
    /// The outcome read back into legible terms, where the receipt's own
    /// `Debug` is not: an unmet condition as the requirement that put it
    /// there, a decline as the method and the name its package gave the
    /// code.
    explained: Option<String>,
    /// Whatever writing the manifest handed back — nothing, usually, and
    /// the handle on an answer where a call produced one.
    ///
    /// A type parameter with a default, so the surface is unchanged for
    /// the transactions that hand back nothing and there is somewhere for
    /// an answer's node to live for the ones that do.
    written: T,
}

impl<T> Outcome<T> {
    pub(crate) const fn new(
        receipt: Receipt,
        errors: Vec<String>,
        explained: Option<String>,
        written: T,
    ) -> Self {
        Self {
            receipt,
            errors,
            explained,
            written,
        }
    }

    /// What writing the manifest handed back.
    ///
    /// Where a transaction wrote several answering calls, this is the
    /// tuple of their handles, and [`Outcome::answer_at`] reads each.
    pub const fn written(&self) -> &T {
        &self.written
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

    /// The kernel's refusal, where the transaction was refused around
    /// the call rather than run: everything that is not a completion, a
    /// decline, or the sender's own trap.
    ///
    /// Its own question because the other three all answer no to a
    /// refusal, and a test asserting `!completed()` would pass on a
    /// refusal it never meant to accept.
    #[must_use]
    pub const fn refused(&self) -> Option<&KernelOutcome> {
        match &self.receipt.outcome {
            KernelOutcome::Completed { .. }
            | KernelOutcome::Declined { .. }
            | KernelOutcome::UserError { .. } => None,
            refusal => Some(refusal),
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

    /// What the calls that answered handed back, in node order.
    ///
    /// A method's answer rides the receipt rather than the graph, because
    /// a value is not an edge and a manifest has nowhere else to put one.
    /// Empty where nothing the transaction called returns a value.
    #[must_use]
    pub fn answers(&self) -> &[Answer] {
        match &self.receipt.outcome {
            KernelOutcome::Completed { answers } => answers,
            _ => &[],
        }
    }

    /// The value one call answered with.
    ///
    /// `handle` is what that call handed back when it was written, so
    /// neither which node answered nor what its bytes decode as is a
    /// thing the reader restates — both are the method's own, carried
    /// here by the wrapper.
    ///
    /// # Panics
    ///
    /// If no node at that position answered, or its bytes are not a `T`.
    #[must_use]
    pub fn answer_at<A: HborDecode>(&self, handle: Answered<A>) -> A {
        let answer = self
            .answers()
            .iter()
            .find(|answer| answer.node == handle.node())
            .unwrap_or_else(|| panic!("node {} answered nothing", handle.node()));
        from_slice(&answer.value).expect("an answer decodes as what the method returned")
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
            "the transaction did not complete: {}",
            self.refused_as()
        );
    }

    /// Why the transaction did not complete, in the most legible terms
    /// available.
    ///
    /// An unmet condition reads back as the requirement that put it
    /// there — the resource, the behaviour, and the question — because
    /// what the receipt carries is a leaf key, and a leaf key is a hash
    /// of the party and the badge that inverts to neither. A decline
    /// reads back as the method and the name its package gave the code,
    /// because the receipt carries a node index and a table index. Every
    /// other verdict is already self-describing and reads as itself.
    #[must_use]
    pub fn refused_as(&self) -> String {
        self.explained
            .clone()
            .unwrap_or_else(|| format!("{:?}", self.receipt.outcome))
    }
}

/// The sentence a decline reads back as: the method, its target, and the
/// name the package gave the code.
///
/// Rendered while the routed calls are in hand, because the receipt
/// alone carries a node index and a table index — two coordinates
/// nobody can act on.
pub fn explain_decline(
    node: u32,
    code: u32,
    call: Option<(&str, Address)>,
    errors: &[String],
) -> String {
    let Some((method, target)) = call else {
        return format!("node {node} declined with code {code}");
    };
    let target = address_text(target);
    errors.get(code as usize).map_or_else(
        || {
            format!(
                "node {node}: `{method}` on {target} declined with code {code}, past its \
                 {}-entry error table",
                errors.len()
            )
        },
        |name| format!("node {node}: `{method}` on {target} declined: {name}"),
    )
}

/// A transaction whose manifest ended in one answering call.
///
/// The common shape, and the one where nothing has to be named: the
/// wrapper knew which node and knew the type, so a reader asks for the
/// answer and gets it.
impl<A: HborDecode> Outcome<Answered<A>> {
    /// What the call answered with.
    ///
    /// # Panics
    ///
    /// If the node answered nothing, or its bytes are not an `A`.
    #[must_use]
    pub fn answer(&self) -> A {
        self.answer_at(*self.written())
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{Address, AddressClass};

    use super::explain_decline;

    fn target() -> Address {
        Address::new([0xAB; 31], AddressClass::Component)
    }

    /// The common arm: the table names the code, and the sentence is the
    /// method plus that name.
    #[test]
    fn a_decline_reads_as_the_method_and_the_named_error() {
        let errors = vec!["slippage-exceeded".to_owned(), "empty-pool".to_owned()];
        let sentence = explain_decline(2, 0, Some(("swap", target())), &errors);
        assert!(sentence.contains("`swap`"), "{sentence}");
        assert!(sentence.contains("slippage-exceeded"), "{sentence}");
        assert!(sentence.contains("node 2"), "{sentence}");
    }

    /// A code past the table still prints, marked as such rather than
    /// dressed up as a name.
    #[test]
    fn a_code_past_the_table_is_marked_as_such() {
        let errors = vec!["short".to_owned()];
        let sentence = explain_decline(1, 7, Some(("repay", target())), &errors);
        assert!(sentence.contains("code 7"), "{sentence}");
        assert!(
            sentence.contains("past its 1-entry error table"),
            "{sentence}"
        );
    }

    /// No routed call at the node — the bare coordinates, honestly.
    #[test]
    fn a_decline_with_no_call_prints_its_coordinates() {
        assert_eq!(
            explain_decline(3, 1, None, &[]),
            "node 3 declined with code 1"
        );
    }
}

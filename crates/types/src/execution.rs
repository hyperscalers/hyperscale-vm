//! The record execution leaves behind: events and the outcome taxonomy.
//!
//! Both are receipt content — what a transaction *said* happened and how
//! it ended — carried on every participant of a cross-shard transaction
//! and checked byte for byte between committees. The caps here bound the
//! kernel's emission and the wire's decode with the same constants, so the
//! two cannot drift.

use hyperscale_hbor::Hbor;

use crate::address::{Address, SubstateKey};

/// The events one transaction may emit.
pub const MAX_EVENTS_PER_TX: usize = 256;

/// The bytes one event payload may carry.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 4096;

/// The event types one package may declare — the bound on an emitted
/// index, checked without resolving it.
pub const MAX_EVENT_TYPES: u32 = 1024;

/// One event a transaction emitted.
///
/// The kernel stamps the emitter from the invocation rather than taking it
/// from the guest — attribution is what decides which shard stores the
/// event, so it cannot be a claim. The type is an index into the emitting
/// package's event table; packages are content-addressed and immutable, so
/// an index can never come to mean something else, and resolving it is the
/// consumer's business.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub struct Event {
    /// The instance that emitted it.
    pub emitter: Address,
    /// The index into the emitting package's event table.
    pub event_type: u32,
    /// The event's opaque payload.
    #[hbor(max = MAX_EVENT_PAYLOAD_BYTES)]
    pub payload: Vec<u8>,
}

/// How execution ended: the abort taxonomy as the receipt records it.
#[derive(Clone, Debug, PartialEq, Eq, Hbor)]
pub enum Outcome {
    /// The export returned; its scalar result if it had one.
    Completed {
        /// The export's return value, when the signature has one.
        value: Option<u64>,
    },
    /// A guest defect: a trap, a panic, a kernel refusal of bad guest
    /// arguments, a declaration defect. The sender's fault; priced at the
    /// sender.
    UserError {
        /// The deterministic reason class.
        reason: String,
    },
    /// A lost deterministic race: a declared reservation the committed
    /// balance could not cover — aborted before any execution — or an
    /// unconditional debit past the floor of committed minus outstanding
    /// reservations, aborted at commit with its fuel charged.
    Infeasible {
        /// The cell that could not cover it.
        key: SubstateKey,
        /// The uncovered amount.
        amount: u128,
    },
    /// A signed edge bound the produced amount did not meet.
    ///
    /// The manifest's own guarantee, asserted independently of the callee:
    /// a producer returning less than the consumer declared fails the
    /// transaction whatever the producer's own code checked. Priced with
    /// [`Outcome::Infeasible`] rather than as a defect — the sender
    /// declared a bound and the world moved between signing and
    /// execution, which is a lost race.
    ConstraintUnmet {
        /// The consuming node.
        node: u32,
        /// The consumed parameter's position on that node.
        param: u32,
        /// What the edge actually carried.
        amount: u128,
    },
    /// A guarded call whose presented evidence is not the identity its
    /// target requires.
    ///
    /// The signer's own fault and priced as such: what a node presents
    /// and what its target requires are both signed content, so a
    /// composer could have known — while whether the target still admits
    /// that identity is the target's state, which is why the verdict is
    /// reached here rather than at admission.
    Unauthorized {
        /// The calling node.
        node: u32,
    },
    /// A subintent this transaction commits was already spent.
    ///
    /// The composer lost a race it could not have won: canonical order
    /// picks between two compositions carrying one subintent, an earlier
    /// block may have committed it, or its signer may have cancelled it
    /// by spending the nullifier directly. None of those is visible to a
    /// composer at signing time, so this is priced with
    /// [`Outcome::Infeasible`] — a conflict tiebreak and a stale
    /// declaration are the two cases the taxonomy names.
    NullifierSpent {
        /// The nullifier cell an earlier committer wrote.
        key: SubstateKey,
    },
    /// A kernel or store invariant failure — never the sender's fault, and
    /// never expected to occur.
    ProtocolError {
        /// The deterministic reason class.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{DecodeError, assert_canonical, from_slice, to_vec};

    use super::{Address, Event, MAX_EVENT_PAYLOAD_BYTES, Outcome, SubstateKey};
    use crate::address::{AddressClass, LocalKey};

    #[test]
    fn the_execution_record_is_canonical() {
        assert_canonical(&Event {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 3,
            payload: vec![9, 9],
        });
        assert_canonical(&Outcome::Completed { value: Some(7) });
        assert_canonical(&Outcome::Infeasible {
            key: SubstateKey {
                owner: Address::new([2; 31], AddressClass::Component),
                local: LocalKey([3; 16]),
            },
            amount: 100,
        });
        assert_canonical(&Outcome::UserError {
            reason: "trap".to_owned(),
        });
    }

    /// A peer's claim, built without the cap the emitter enforces.
    #[derive(Debug, Clone, PartialEq, Eq, hyperscale_hbor::Hbor)]
    struct Uncapped {
        emitter: Address,
        event_type: u32,
        payload: Vec<u8>,
    }

    /// The wire refuses what the kernel would never emit, on the same
    /// constant the kernel enforces.
    #[test]
    fn an_oversized_payload_rejects_at_decode() {
        let mut over = Event {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 0,
            payload: vec![0; MAX_EVENT_PAYLOAD_BYTES + 1],
        };
        assert!(to_vec(&over).is_err());
        over.payload.truncate(MAX_EVENT_PAYLOAD_BYTES);
        let bytes = to_vec(&over).unwrap();
        assert!(from_slice::<Event>(&bytes).is_ok());

        let smuggled = to_vec(&Uncapped {
            emitter: Address::new([1; 31], AddressClass::Component),
            event_type: 0,
            payload: vec![0; MAX_EVENT_PAYLOAD_BYTES + 1],
        })
        .unwrap();
        assert!(matches!(
            from_slice::<Event>(&smuggled),
            Err(DecodeError::BoundExceeded { .. })
        ));
    }
}

//! The wire vocabulary both workspaces speak.
//!
//! A type lives here when the VM defines its meaning and the consensus
//! workspace must carry it: the address space state lives in, the envelope
//! a composer signs, and the record execution leaves behind. Everything
//! here is HBOR-native — this workspace has no other encoding to offer —
//! and everything is content, not disposition: what a transaction *is* and
//! what execution *said*, never what the network does about them.
//!
//! The crate is a leaf on purpose: `hbor` and an error derive, no wasm
//! machinery, no crypto, no clock. Signing *content* is defined here — the
//! preimage a signature covers — while producing and verifying signatures
//! binds a hash and a curve, which belongs to the workspace that owns the
//! protocol's cryptography. The same line keeps validity windows here as
//! plain milliseconds: judging them against a clock is consensus's side.

pub mod address;
pub mod amount;
pub mod envelope;
pub mod execution;
pub mod mode;
pub mod work;
pub mod writes;

pub use address::{
    Address, AddressClass, CallTarget, ComponentAddr, InvalidAddress, LEAF_KEY_BYTES, LocalKey,
    NativeAddr, NotAResource, NotCallable, PackageAddr, PrincipalAddr, ResourceAddr, ResourceRef,
    SchemeId, SubstateKey, WrongClass,
};
pub use amount::{AMOUNT_CELL_BYTES, amount_cell, encode_amount, read_amount};
pub use envelope::{
    MAX_MESSAGE_LEN, MAX_SUBINTENTS, MAX_TX_BYTES_LEN, NetworkId, SubintentSig, TransactionBody,
    TransactionEnvelope, TxHash,
};
pub use execution::{Event, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Outcome};
pub use mode::{Mode, ModeKind, compatible};
pub use work::{FOOTPRINT_WEIGHT, FUEL_WEIGHT, TX_UNITS, declared_work, work_units};
pub use writes::{MAX_CELL_VALUE_LEN, Movement, SettledWrites, StateWrites};

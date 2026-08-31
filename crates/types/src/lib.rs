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
//! preimage a signature covers, and the scheme vocabulary its key and
//! signature are read under — while producing and verifying them binds a
//! hash and a curve, which belongs to the workspace that owns the
//! protocol's cryptography and reaches back through [`SchemeVerifier`].
//! The same line keeps validity windows here as plain milliseconds:
//! judging them against a clock is consensus's side.

pub mod address;
pub mod amount;
pub mod effect;
pub mod envelope;
pub mod execution;
pub mod hashing;
pub mod math;
pub mod mode;
pub mod scheme;
pub mod seeds;
pub mod work;
pub mod writes;

pub use address::text::{NetworkWord, TextError};
pub use address::{
    ADDRESS_WORDS, Address, AddressClass, CallTarget, CollectionId, ComponentAddr, EffectTarget,
    InvalidAddress, LEAF_KEY_BYTES, LocalKey, NativeAddr, NotCallable, PackageAddr, PrincipalAddr,
    ResourceAddr, SubstateKey, WrongClass,
};
pub use amount::{AMOUNT_CELL_BYTES, amount_cell, encode_amount, read_amount};
pub use effect::{Effect, EffectConflict, EffectSet};
pub use envelope::{
    MAX_MESSAGE_LEN, MAX_SUBINTENTS, MAX_TX_BYTES_LEN, NULLIFIER_GRACE_MS, NetworkId, SubintentSig,
    TransactionBody, TransactionEnvelope, TxHash,
};
pub use execution::{
    ABSENT_REP, AbortReason, Answer, Event, MAX_ANSWER_BYTES, MAX_ERROR_CODES,
    MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, MAX_MANIFEST_NODES, Outcome,
    UnmetCondition,
};
pub use hashing::ProtocolHasher;
pub use mode::{ConflictClass, Mode, ModeKind, Moves, Presence, compatible};
pub use scheme::{
    AccountSigner, MAX_KEY_BYTES, MAX_SIG_BYTES, SchemeId, SchemeSpec, SchemeVerifier,
};
pub use seeds::{Drawn, SEAL_MATURITY_EPOCHS, SEED_BYTES, SeedWindow, Seeded};
pub use work::{
    AUTH_BYTE_WEIGHT, FOOTPRINT_WEIGHT, FUEL_WEIGHT, TX_UNITS, VERIFY_WEIGHT, declared_work,
    signature_work, work_units,
};
pub use writes::{
    EntryKey, EntryLeaf, MAX_CELL_VALUE_LEN, Movement, SettledCells, SettledEntries, SettledWrites,
    StateWrites, entry_leaf_key,
};

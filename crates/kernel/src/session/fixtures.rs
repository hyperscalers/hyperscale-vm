//! Shared fixtures for the session module's tests.

use std::collections::BTreeSet;
use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, DeclaredAccess, Hash32, SlotId, TestHasher, child_key};
use hyperscale_vm_types::{
    Address, AddressClass, Effect, EffectSet, Mode, ResourceAddr, SubstateKey, TxHash,
};

use super::materialize::{Contents, contents_of};
use super::{EnvInputs, KernelSession};
use crate::overlay::OverlayStore;
use crate::store::MemoryStore;

pub(super) fn key(byte: u8) -> SubstateKey {
    child_key(
        &TestHasher,
        Address::new([byte; 31], AddressClass::Component),
        SlotId(1),
        &[],
    )
}

pub(super) const fn tx(byte: u8) -> TxHash {
    TxHash(Hash32([byte; 32]))
}

/// A stand-in protocol hash: the length in the first byte shows the
/// seam carries the guest's bytes through, and a rolling mix over the
/// rest shows *which* bytes — enough to tell two preimages of one
/// length apart, which is what a derivation mixing a key needs.
pub(super) fn hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0] = u8::try_from(data.len()).unwrap_or(u8::MAX);
    let mut mix: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        mix = (mix ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    out[1..9].copy_from_slice(&mix.to_le_bytes());
    out
}

pub(super) const fn env() -> EnvInputs {
    EnvInputs::unsealed(5)
}

pub(super) fn declared(effects: &[Effect]) -> EffectSet {
    let mut set = EffectSet::new();
    for effect in effects {
        set.insert(*effect).unwrap();
    }
    set
}

/// Canonical order as the clause order — right for tests that build a
/// set directly and have no signature to evaluate.
pub(super) fn ord(set: &EffectSet) -> Vec<Effect> {
    set.iter().collect()
}

/// What every cell these fixtures move value through holds.
pub(super) const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);

/// What each entry of an ordered declaration holds.
///
/// A movement names a cell that holds value, and a hand-built set has
/// no clause left to say what — so a fixture standing in for a
/// signature says it here, or the movement is refused before any body
/// runs.
///
/// Answered per cell rather than per clause, because that is the
/// shape of the fact: every clause reaching a cell some movement
/// reaches says the same thing about it, which is what
/// [`MaterializeError::MixedContents`](super::MaterializeError::MixedContents)
/// holds a signature to.
pub(super) fn holding(ordered: &[Effect]) -> Vec<DeclaredAccess> {
    let value: BTreeSet<Contents> = ordered
        .iter()
        .filter(|effect| matches!(effect.mode, Mode::Delta | Mode::Reserve { .. }))
        .map(|effect| contents_of(effect.target))
        .collect();
    ordered
        .iter()
        .map(|effect| DeclaredAccess {
            reach: None,
            effect: *effect,
            holds: value
                .contains(&contents_of(effect.target))
                .then_some(RESOURCE),
        })
        .collect()
}

/// A session over cells that all hold value — what a fixture wants
/// when the write it declares is a debit rather than a byte write.
pub(super) fn session_holding(store: MemoryStore, set: &EffectSet) -> KernelSession {
    let declaration = Declaration::from_set(set.clone()).denominated(|_| Some(RESOURCE));
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declaration,
        tx(1),
        env(),
        hash,
    )
    .expect("materializes")
}

pub(super) fn session_over(store: MemoryStore, set: &EffectSet) -> KernelSession {
    session_under(store, set, env())
}

/// The same, under an environment the caller states — how a case puts a
/// seed window behind a session.
pub(super) fn session_under(store: MemoryStore, set: &EffectSet, env: EnvInputs) -> KernelSession {
    session_for(store, set, env, tx(1))
}

/// The same, under a transaction the caller names — how a case asks
/// whether an answer depends on which attempt asked for it.
pub(super) fn session_for(
    store: MemoryStore,
    set: &EffectSet,
    env: EnvInputs,
    tx: TxHash,
) -> KernelSession {
    let declaration = Declaration {
        ordered: holding(&ord(set)),
        ..Declaration::from_set(set.clone())
    };
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declaration,
        tx,
        env,
        hash,
    )
    .expect("materializes")
}

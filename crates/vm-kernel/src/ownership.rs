//! Structural ownership: creation under the owning context and explicit
//! move.
//!
//! An object's owner is part of its key, assigned at creation from the
//! creating context and never recovered from stored references. No
//! operation mutates the owner half of an existing key: re-parenting
//! exists only as [`move_object`], which removes under the source owner
//! and re-creates under the destination — both sides recorded as writes,
//! so both owners must be in the effect set once capabilities gate the
//! store.

use hyperscale_vm_effects::{Address, Hasher, ManifestHash, SubstateKey, fresh_local};

use crate::store::{StoreError, SubstateStore};

/// The creating context: who owns what this call creates, and the
/// derivation root that makes every created key deterministic.
///
/// Fresh keys are `owner | fresh_local(manifest hash, node index, slot)` —
/// the identical derivation the effect DSL's fresh-key expression
/// evaluates, so a declared creation and the kernel's execution of it name
/// the same key by construction.
#[derive(Clone, Copy, Debug)]
pub struct CreationContext {
    owner: Address,
    manifest_hash: ManifestHash,
    node_index: u32,
    next_slot: u32,
}

impl CreationContext {
    /// A context owning its creations under `owner`, deriving from the
    /// invoking manifest node.
    #[must_use]
    pub const fn new(owner: Address, manifest_hash: ManifestHash, node_index: u32) -> Self {
        Self {
            owner,
            manifest_hash,
            node_index,
            next_slot: 0,
        }
    }

    /// The context's owner.
    #[must_use]
    pub const fn owner(&self) -> Address {
        self.owner
    }

    /// The next fresh key under this context's owner. Slots advance per
    /// creation; the counter wraps only past 2^32 creations, unreachable
    /// under any fuel bound.
    pub fn fresh_key(&mut self, hasher: &dyn Hasher) -> SubstateKey {
        let local = fresh_local(hasher, self.manifest_hash, self.node_index, self.next_slot);
        self.next_slot = self.next_slot.wrapping_add(1);
        SubstateKey {
            owner: self.owner,
            local,
        }
    }

    /// Create a substate at the next fresh key.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`] from the write.
    pub fn create<S: SubstateStore>(
        &mut self,
        store: &mut S,
        hasher: &dyn Hasher,
        value: Vec<u8>,
    ) -> Result<SubstateKey, StoreError> {
        let key = self.fresh_key(hasher);
        store.write(key, value)?;
        Ok(key)
    }

    /// Create a substate at the next fresh key and permanently lock it —
    /// the creation-fixed configuration path.
    ///
    /// # Errors
    ///
    /// Any [`StoreError`] from the write or the lock.
    pub fn create_locked<S: SubstateStore>(
        &mut self,
        store: &mut S,
        hasher: &dyn Hasher,
        value: Vec<u8>,
    ) -> Result<SubstateKey, StoreError> {
        let key = self.create(store, hasher, value)?;
        store.lock(key)?;
        Ok(key)
    }
}

/// Why a move rejected.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MoveError {
    /// The source substate does not exist.
    #[error("nothing to move at {0:?}")]
    Missing(SubstateKey),
    /// The destination key is already occupied.
    #[error("move destination {0:?} is occupied")]
    Occupied(SubstateKey),
    /// A store failure — a locked source, above all.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Explicitly re-parent a substate: remove it under its source owner and
/// re-create it, same local half, under the destination. Returns the new
/// key.
///
/// # Errors
///
/// [`MoveError::Missing`] if the source is absent, [`MoveError::Occupied`]
/// if the destination key holds a value, or any store failure.
pub fn move_object<S: SubstateStore>(
    store: &mut S,
    source: SubstateKey,
    to: Address,
) -> Result<SubstateKey, MoveError> {
    let destination = SubstateKey {
        owner: to,
        local: source.local,
    };
    if store.read(destination)?.is_some() {
        return Err(MoveError::Occupied(destination));
    }
    let value = store.remove(source)?.ok_or(MoveError::Missing(source))?;
    store.write(destination, value)?;
    Ok(destination)
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_effects::{Address, Hash32, ManifestHash, TestHasher};

    use super::{CreationContext, MoveError, move_object};
    use crate::store::{MemoryStore, StoreError, SubstateStore};

    fn context(owner_byte: u8) -> CreationContext {
        CreationContext::new(Address([owner_byte; 16]), ManifestHash(Hash32([7; 32])), 2)
    }

    #[test]
    fn creations_land_under_the_context_owner_at_distinct_slots() {
        let mut store = MemoryStore::new();
        let mut ctx = context(1);
        let first = ctx.create(&mut store, &TestHasher, vec![1]).unwrap();
        let second = ctx.create(&mut store, &TestHasher, vec![2]).unwrap();
        assert_eq!(first.owner, ctx.owner());
        assert_eq!(second.owner, ctx.owner());
        assert_ne!(first.local, second.local);
        assert_eq!(store.read(first).unwrap(), Some(vec![1]));

        let locked = ctx.create_locked(&mut store, &TestHasher, vec![3]).unwrap();
        assert!(store.is_locked(locked));
    }

    #[test]
    fn moves_relocate_and_never_overwrite() {
        let mut store = MemoryStore::new();
        let mut ctx = context(1);
        let source = ctx.create(&mut store, &TestHasher, vec![9]).unwrap();

        let destination = move_object(&mut store, source, Address([2; 16])).unwrap();
        assert_eq!(destination.owner, Address([2; 16]));
        assert_eq!(destination.local, source.local);
        assert_eq!(store.read(source).unwrap(), None);
        assert_eq!(store.read(destination).unwrap(), Some(vec![9]));

        // Nothing left at the source to move.
        assert_eq!(
            move_object(&mut store, source, Address([3; 16])),
            Err(MoveError::Missing(source))
        );
        // A move can never destroy destination state: slot zero under owner
        // three already exists, and the relocated object shares that local.
        let mut other = context(3);
        let clashing = other.create(&mut store, &TestHasher, vec![1]).unwrap();
        assert_eq!(clashing.local, destination.local);
        assert_eq!(
            move_object(&mut store, destination, clashing.owner),
            Err(MoveError::Occupied(clashing))
        );

        // A locked substate cannot move.
        let locked = ctx.create_locked(&mut store, &TestHasher, vec![4]).unwrap();
        assert_eq!(
            move_object(&mut store, locked, Address([5; 16])),
            Err(MoveError::Store(StoreError::Locked(locked)))
        );
    }
}

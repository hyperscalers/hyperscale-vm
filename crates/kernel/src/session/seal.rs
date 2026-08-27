//! The sealed draw: a commitment written now, opened on a seed that did
//! not exist when it was written.
//!
//! A self-contained sub-machine with its own domain tag, its own
//! maturity rule and its own three refusals. What a seal commits to is
//! fixed by the epoch the kernel records and the key of the cell holding
//! it — nothing about the attempt that opens it enters, so two attempts
//! at one seal answer alike and abandoning one buys nothing.

use hyperscale_vm_types::{Drawn, LEAF_KEY_BYTES, SEAL_MATURITY_EPOCHS, SEED_BYTES, Seeded};

use super::{KernelSession, Op, SessionTrap};
use crate::store::WorkingStore as _;

/// Domain tag for a sealed draw.
///
/// Its own tag because the digest it produces is not the protocol hash
/// of anything a package could also ask for: a body that could compute
/// its own draw from parts it holds would not need the seal.
pub const DOMAIN_SEALED_DRAW: &[u8] = b"hyperscale/vm/sealed-draw";

/// The byte a seal cell's bytes open with: what marks them as the
/// kernel's own writing rather than a record sharing the width.
///
/// A bare eight-byte epoch would read any guest-written `u64` — a
/// counter, a timestamp — as a seal, and one whose figure decodes to a
/// lapsed epoch would then be silently overwritten by `seal`. The tag
/// is what lets those refuse as `NotASeal` instead; a body that spells
/// the seal's own shape by hand has said what it means the cell for.
const SEAL_TAG: u8 = 0x5E;

/// The epoch a seal cell's bytes record.
///
/// The tag and eight little-endian bytes, and nothing else: anything of
/// another shape is a package that wrote over its own seal through the
/// same handle it opens with.
fn sealed_epoch(site: u32, held: &[u8]) -> Result<u64, SessionTrap> {
    match held {
        [SEAL_TAG, epoch @ ..] => epoch
            .try_into()
            .map(u64::from_le_bytes)
            .map_err(|_| SessionTrap::NotASeal(site)),
        _ => Err(SessionTrap::NotASeal(site)),
    }
}

/// The bytes `seal` writes: the running epoch behind the kernel's tag.
fn seal_bytes(epoch: u64) -> Vec<u8> {
    let mut sealed = Vec::with_capacity(1 + size_of::<u64>());
    sealed.push(SEAL_TAG);
    sealed.extend_from_slice(&epoch.to_le_bytes());
    sealed
}

impl KernelSession {
    /// Seal this cell on the epoch now running.
    ///
    /// The kernel writes the epoch rather than taking one, and that is
    /// the whole of the commitment. A body that named its own would name
    /// an epoch already rolled, and open onto a word it could have
    /// computed before deciding to seal — so what a seal commits to
    /// would be whatever its writer already knew.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`].
    pub fn seal(&mut self, site: u32, element: u32) -> Result<(), SessionTrap> {
        let key = self.acting_key(site, element, Op::Seal)?;
        // A leaf already under a seal takes another only where the
        // standing one will never open. A matured seed is public, and so
        // is the word it produces, so replacing a seal that can still
        // open is a re-roll of a draw somebody has already read — and a
        // package left to enforce that itself would be a package one
        // careless method away from offering the re-roll.
        //
        // A cell holding anything that is not a seal takes none either:
        // a seal cell is dedicated. Writing the epoch over a guest's own
        // bytes would destroy them through the very handle that wrote
        // them, so the repurposed cell is refused as `NotASeal` rather
        // than silently emptied — a fresh cell is where a first seal
        // goes.
        if let Some(held) = self.store.read(key)?
            && !matches!(
                self.matured_seed(sealed_epoch(site, &held)?),
                Seeded::Expired
            )
        {
            return Err(SessionTrap::SealStanding(site));
        }
        Ok(self.store.write(key, seal_bytes(self.env.epoch))?)
    }

    /// The draw the seal in this cell matures into.
    ///
    /// Everything the word is made of was fixed before the transaction
    /// that reads it: the seed of the epoch the cell's own seal records
    /// with the protocol's maturity put past it, and the key of the cell
    /// the handle names. Nothing about the attempt enters — not its
    /// hash, not its sender, not the block that carries it — so two
    /// attempts at one seal answer alike and abandoning one buys
    /// nothing.
    ///
    /// The cell's key is what separates two seals of one package. A
    /// nonce would put that choice in a body, where a package could mint
    /// itself as many candidate draws as it liked.
    ///
    /// # Errors
    ///
    /// Any [`SessionTrap`], including [`SessionTrap::NotASeal`] for a
    /// leaf a guest wrote its own bytes over.
    pub fn open_seal(&mut self, site: u32, element: u32) -> Result<Drawn, SessionTrap> {
        let key = self.acting_key(site, element, Op::OpenSeal)?;
        let held = self.store.read(key)?.unwrap_or_default();
        let epoch = sealed_epoch(site, &held)?;
        Ok(match self.matured_seed(epoch) {
            Seeded::Pending => Drawn::Pending,
            Seeded::Expired => Drawn::Expired,
            Seeded::Ready(seed) => {
                let mut preimage =
                    Vec::with_capacity(DOMAIN_SEALED_DRAW.len() + SEED_BYTES + LEAF_KEY_BYTES);
                preimage.extend_from_slice(DOMAIN_SEALED_DRAW);
                preimage.extend_from_slice(&seed);
                preimage.extend_from_slice(&key.to_bytes());
                Drawn::Ready((self.hash_fn)(&preimage))
            }
        })
    }

    /// The seed a seal written in `epoch` matures into.
    ///
    /// The offset is the whole of the maturity rule: what a seal
    /// commits to is a value that did not exist when it was written, and
    /// [`SEAL_MATURITY_EPOCHS`] is how far past the writing that
    /// becomes true.
    #[must_use]
    pub fn matured_seed(&self, epoch: u64) -> Seeded {
        self.env
            .seeds
            .at(epoch.saturating_add(SEAL_MATURITY_EPOCHS))
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_vm_types::{
        Drawn, Effect, EffectSet, EffectTarget, Mode, Moves, SEAL_MATURITY_EPOCHS, SEED_BYTES,
        SeedWindow, Seeded, SubstateKey,
    };

    use super::super::fixtures::{declared, env, key, session_for, session_under, tx};
    use super::super::{EnvInputs, KernelSession, Op, SessionTrap, TxHash};
    use crate::store::MemoryStore;

    /// A seal resolves against the epoch two past the one it was
    /// written in, and the offset is the commitment: a seal cannot open
    /// onto a value that existed when it was written.
    #[test]
    fn a_seal_matures_two_epochs_past_its_own() {
        let seeds = SeedWindow::new(
            std::collections::BTreeMap::from([(6, [0x11; 32]), (8, [0x22; 32])]),
            Some(8),
        );
        let session = session_under(
            MemoryStore::new(),
            &declared(&[]),
            EnvInputs { seeds, ..env() },
        );

        assert_eq!(session.matured_seed(6), Seeded::Ready([0x22; 32]));
        assert_eq!(
            session.matured_seed(4),
            Seeded::Ready([0x11; 32]),
            "a seal reads the epoch it named, not the newest one folded"
        );
        assert_eq!(
            session.matured_seed(5),
            Seeded::Expired,
            "an epoch the host folded and will not stand behind is gone"
        );
        assert_eq!(
            session.matured_seed(7),
            Seeded::Pending,
            "a seal whose epoch has not been folded is a wait"
        );
    }

    /// A window with one usable seed, so a seal written in `epoch`
    /// opens and nothing else does.
    fn sealed_env(epoch: u64) -> EnvInputs {
        EnvInputs {
            epoch,
            seeds: SeedWindow::new(
                std::collections::BTreeMap::from([(
                    epoch + SEAL_MATURITY_EPOCHS,
                    [0x5E; SEED_BYTES],
                )]),
                Some(epoch + SEAL_MATURITY_EPOCHS),
            ),
            ..env()
        }
    }

    fn writing(at: SubstateKey) -> EffectSet {
        declared(&[Effect {
            target: EffectTarget::Point(at),
            mode: Mode::Write { moves: Moves::Both },
        }])
    }

    /// A session over one written cell, sealed in the epoch its own
    /// environment is running.
    fn sealed_session(set: &EffectSet, env: EnvInputs, tx: TxHash) -> KernelSession {
        let mut session = session_for(MemoryStore::new(), set, env, tx);
        session.seal(0, 0).expect("a write handle takes a seal");
        session
    }

    /// The property the whole seal exists for: what a seal opens onto is
    /// a function of committed state and of a seed rolled after it was
    /// written, and of nothing about the attempt that reads it.
    ///
    /// Two transactions, two hashes, one seal — one word. A derivation
    /// that reached for the transaction would answer twice here, and
    /// answering twice is what lets a loser abandon an attempt and try
    /// again for a different outcome.
    #[test]
    fn one_seal_answers_one_word_however_many_attempts_ask() {
        let set = writing(key(1));
        let words: Vec<_> = [tx(0xA1), tx(0xB2)]
            .into_iter()
            .map(|tx| {
                sealed_session(&set, sealed_env(9), tx)
                    .open_seal(0, 0)
                    .expect("a write handle holds a seal")
            })
            .collect();

        assert!(matches!(words[0], Drawn::Ready(_)));
        assert_eq!(words[0], words[1], "the attempt is not an input");
    }

    /// A seal cell is dedicated: a cell that has held anything but a
    /// seal takes none, however stale what it holds. The refusal is the
    /// guest's own bytes' protection — writing the epoch over them would
    /// destroy them through the very handle that wrote them — and it is
    /// the same `NotASeal` an opened-over cell answers, because both are
    /// one fact: this cell does not hold a seal.
    ///
    /// The eight-byte case is the tag's whole reason: an untagged `u64`
    /// counter whose figure decodes to a long-lapsed epoch is exactly
    /// what a width-only reading would have read as a replaceable seal
    /// and silently emptied.
    #[test]
    fn a_cell_holding_guest_bytes_takes_no_seal() {
        for guest_bytes in [vec![0xAB; 3], 2u64.to_le_bytes().to_vec()] {
            let set = writing(key(1));
            let mut session = session_for(MemoryStore::new(), &set, sealed_env(9), tx(1));
            session
                .write_cell_set(0, 0, guest_bytes.clone())
                .expect("a write handle sets");
            assert_eq!(session.seal(0, 0), Err(SessionTrap::NotASeal(0)));
            assert_eq!(
                session.cell_get(0, 0),
                Ok(guest_bytes),
                "the refusal leaves the guest's bytes standing"
            );
        }
    }

    /// Two cells, one epoch, two words. The cell's key is what separates
    /// a package's draws, so a package that wants a second one holds a
    /// second cell — and cannot mint itself candidates to choose among
    /// by naming a nonce.
    #[test]
    fn two_sealed_cells_of_one_epoch_draw_apart() {
        let first = sealed_session(&writing(key(1)), sealed_env(9), tx(1))
            .open_seal(0, 0)
            .expect("a write handle holds a seal");
        let second = sealed_session(&writing(key(2)), sealed_env(9), tx(1))
            .open_seal(0, 0)
            .expect("a write handle holds a seal");

        assert!(matches!(first, Drawn::Ready(_)));
        assert_ne!(first, second);
    }

    /// The epoch a seal records is the kernel's, not a body's.
    ///
    /// A body that chose it could name an epoch already rolled — whose
    /// seed is public, and whose word it could therefore compute before
    /// deciding to seal at all. What the cell holds is the running
    /// epoch and nothing a guest handed over.
    #[test]
    fn a_seal_records_the_epoch_the_kernel_is_running() {
        let mut session = sealed_session(&writing(key(1)), sealed_env(9), tx(1));
        let mut sealed = vec![0x5E];
        sealed.extend_from_slice(&9u64.to_le_bytes());
        assert_eq!(
            session.cell_get(0, 0),
            Ok(sealed),
            "the leaf holds the tag and the running epoch"
        );

        // The same cell written over by hand, naming an epoch whose seed
        // is already rolled: the derivation reads the leaf, so this is
        // the only way to reach one — and it is a package's declaration
        // and body disagreeing about what the leaf is for.
        session
            .write_cell_set(0, 0, vec![0xFF; 3])
            .expect("a write handle sets");
        assert_eq!(session.open_seal(0, 0), Err(SessionTrap::NotASeal(0)));
    }

    /// A lapsed seal is the one a package may replace, and the only
    /// one.
    ///
    /// The word a matured seal opens onto is public the moment its seed
    /// rolls, so a package that could take a second seal over one that
    /// still answers would be offering a re-roll of a draw somebody has
    /// already read. A seal that will never open is the case where
    /// there is nothing to re-roll.
    #[test]
    fn only_a_lapsed_seal_gives_way_to_another() {
        let set = writing(key(1));

        // Standing, and matured: the word is there to be read, so the
        // cell keeps the seal that answers it.
        let mut ready = sealed_session(&set, sealed_env(9), tx(1));
        assert_eq!(ready.seal(0, 0), Err(SessionTrap::SealStanding(0)));
        assert!(matches!(ready.open_seal(0, 0), Ok(Drawn::Ready(_))));

        // Standing, and early: nothing to read yet, and nothing to gain
        // by waiting for a different one.
        let mut early = sealed_session(
            &set,
            EnvInputs {
                epoch: 10,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(early.seal(0, 0), Err(SessionTrap::SealStanding(0)));

        // Lapsed: the seal will never open, so the round takes another
        // and the cell records the epoch running now.
        let mut lapsed = sealed_session(
            &set,
            EnvInputs {
                epoch: 8,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(lapsed.open_seal(0, 0), Ok(Drawn::Expired));
        assert_eq!(lapsed.seal(0, 0), Ok(()));
        let mut resealed = vec![0x5E];
        resealed.extend_from_slice(&8u64.to_le_bytes());
        assert_eq!(lapsed.cell_get(0, 0), Ok(resealed));
    }

    /// A seal is opened through the handle that holds it, so a
    /// capability that is not an exclusive write has no draw to give.
    #[test]
    fn a_seal_opens_only_through_the_cell_that_holds_it() {
        let set = declared(&[Effect {
            target: EffectTarget::Point(key(1)),
            mode: Mode::Read,
        }]);
        let mut session = session_under(MemoryStore::new(), &set, sealed_env(9));
        assert!(matches!(
            session.seal(0, 0),
            Err(SessionTrap::Ungranted {
                attempted: Op::Seal,
                ..
            })
        ));
        assert!(matches!(
            session.open_seal(0, 0),
            Err(SessionTrap::Ungranted {
                attempted: Op::OpenSeal,
                ..
            })
        ));
    }

    /// The two ways a seal fails to open are two answers, because a
    /// package does different things with them: wait, or close again.
    ///
    /// Both are reached by moving the window rather than the seal: what
    /// the cell records is fixed when it is written, so a seal is early
    /// or lapsed according to what the beacon has rolled since.
    #[test]
    fn an_early_seal_waits_where_a_lapsed_one_is_over() {
        let set = writing(key(1));
        let mut early = sealed_session(
            &set,
            EnvInputs {
                epoch: 10,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(early.open_seal(0, 0), Ok(Drawn::Pending));

        let mut lapsed = sealed_session(
            &set,
            EnvInputs {
                epoch: 8,
                ..sealed_env(9)
            },
            tx(1),
        );
        assert_eq!(lapsed.open_seal(0, 0), Ok(Drawn::Expired));
    }
}

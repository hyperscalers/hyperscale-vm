//! The epoch seeds an execution can resolve a sealed draw against.

use std::collections::BTreeMap;
use std::sync::Arc;

/// The width every seed and every word the protocol carries.
pub const SEED_BYTES: usize = 32;

/// How many epochs after a seal is written its draw becomes readable.
///
/// Two, not one. The reveals folded into the seed of the first epoch
/// after a seal are already partly determined while the seal is being
/// written — a seal placed late in an epoch would be a commitment
/// against a value most of which exists. Nothing folded into the second
/// epoch's seed exists yet.
pub const SEAL_MATURITY_EPOCHS: u64 = 2;

/// What the environment answers about one epoch's seed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seeded {
    /// The seed, from a roll a draw may settle on.
    Ready([u8; SEED_BYTES]),
    /// The epoch is ahead of what the host has folded. Ask again later.
    Pending,
    /// Behind the window the host keeps, or rolled by a fallback nobody
    /// should settle value on. Both mean the same thing to a caller:
    /// this seal will never open, so seal again.
    Expired,
}

/// What a sealed cell answers when asked for its draw.
///
/// Three answers rather than an option, because a caller does three
/// different things with them: wait, seal again, or draw. Collapsing the
/// first two would leave a package spinning on a seal that will never
/// open, or abandoning one that is merely early.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drawn {
    /// The epoch the seal matures into is not folded yet.
    Pending,
    /// The word the seal committed to.
    Ready([u8; SEED_BYTES]),
    /// The seal will never open.
    Expired,
}

/// The seeds an execution can reach, as the host supplies them.
///
/// Holds only what a draw may settle on. Which epochs those are is the
/// host's judgment — how far back it keeps them, and which rolls it will
/// stand behind — so the vocabulary here is three answers and no policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SeedWindow {
    /// Shared rather than owned: one window governs a whole batch and
    /// every transaction in it carries the environment by value.
    /// `None` is the empty window, which is what lets an unfolded one be
    /// a constant.
    usable: Option<Arc<BTreeMap<u64, [u8; SEED_BYTES]>>>,
    newest: Option<u64>,
}

impl SeedWindow {
    /// A window over `usable`, where `newest` is the latest epoch the
    /// host has folded at all — including the ones it will not stand
    /// behind, which is what separates an epoch that has not happened
    /// from one that happened unusably.
    #[must_use]
    pub fn new(usable: BTreeMap<u64, [u8; SEED_BYTES]>, newest: Option<u64>) -> Self {
        Self {
            usable: Some(Arc::new(usable)),
            newest,
        }
    }

    /// A window nothing can be resolved against — every epoch is ahead
    /// of a host that has folded nothing.
    #[must_use]
    pub const fn unfolded() -> Self {
        Self {
            usable: None,
            newest: None,
        }
    }

    /// The seed at `epoch`, or which way it falls outside.
    #[must_use]
    pub fn at(&self, epoch: u64) -> Seeded {
        if let Some(seed) = self.usable.as_ref().and_then(|held| held.get(&epoch)) {
            return Seeded::Ready(*seed);
        }
        match self.newest {
            Some(newest) if epoch <= newest => Seeded::Expired,
            _ => Seeded::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> SeedWindow {
        SeedWindow::new(BTreeMap::from([(4, [0x11; 32]), (6, [0x22; 32])]), Some(7))
    }

    #[test]
    fn a_usable_epoch_answers_its_seed() {
        assert_eq!(window().at(4), Seeded::Ready([0x11; 32]));
    }

    /// The three answers are three because a caller does three different
    /// things with them: wait, give up, or draw. An epoch the host
    /// folded but will not stand behind is a give-up, and an epoch it
    /// has not reached is a wait, and neither can be read off the
    /// absence of a seed alone.
    #[test]
    fn a_gap_below_the_frontier_is_not_a_gap_above_it() {
        assert_eq!(window().at(5), Seeded::Expired);
        assert_eq!(window().at(8), Seeded::Pending);
        assert_eq!(window().at(7), Seeded::Expired);
    }

    #[test]
    fn an_unfolded_window_is_ahead_of_everything() {
        assert_eq!(SeedWindow::unfolded().at(0), Seeded::Pending);
    }
}

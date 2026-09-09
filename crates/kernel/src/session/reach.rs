//! What a frame may name in one table.
//!
//! A handle is a number the guest writes, and the table it indexes is
//! the whole transaction's. What keeps one node's body from naming
//! another node's site, or the bucket an earlier node left in flight, is
//! not the table but the frame: a frame resolves exactly the handles it
//! was lent, plus the ones it made while it ran. The same rule governs
//! sites and buckets, so it is one type held once beside each table.
//!
//! A frame's reach is a set rather than a mark on the table, because a
//! mark would be wrong for buckets: an edge routed into a frame is older
//! than the frame consuming it, so nothing about a bucket's position says
//! whose it is.

use std::collections::BTreeSet;

/// The reps one frame may resolve in a table.
///
/// Bounded only while a frame is entered. A session nobody entered
/// resolves every rep its table holds, which is what lets a session be
/// acted through the moment it exists; production always enters a
/// frame, and a frame starts from nothing.
#[derive(Debug, Default)]
pub(super) struct Reach {
    lent: Option<BTreeSet<u32>>,
}

impl Reach {
    /// Enter a frame: nothing is reachable until it is lent or made.
    pub(super) fn enter(&mut self) {
        self.lent = Some(BTreeSet::new());
    }

    /// Leave the frame: the table is reachable whole again, for the
    /// kernel's own work between frames.
    pub(super) fn leave(&mut self) {
        self.lent = None;
    }

    /// Lend `rep` to the frame, or make it the frame's. Nothing to do
    /// outside a frame, where every rep is already in reach.
    pub(super) fn lend(&mut self, rep: u32) {
        if let Some(lent) = &mut self.lent {
            lent.insert(rep);
        }
    }

    /// Whether the frame may resolve `rep`.
    pub(super) fn holds(&self, rep: u32) -> bool {
        self.lent.as_ref().is_none_or(|lent| lent.contains(&rep))
    }
}

#[cfg(test)]
mod tests {
    use super::Reach;

    #[test]
    fn a_session_nobody_entered_reaches_everything() {
        let reach = Reach::default();
        assert!(reach.holds(0));
        assert!(reach.holds(u32::MAX));
    }

    #[test]
    fn a_frame_reaches_what_it_was_lent_and_nothing_else() {
        let mut reach = Reach::default();
        reach.enter();
        assert!(!reach.holds(0));
        reach.lend(3);
        assert!(reach.holds(3));
        assert!(!reach.holds(0));
        reach.leave();
        assert!(reach.holds(0));
    }

    #[test]
    fn entering_again_starts_from_nothing() {
        let mut reach = Reach::default();
        reach.enter();
        reach.lend(7);
        reach.enter();
        assert!(!reach.holds(7));
    }
}

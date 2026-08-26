//! The lottery: a pot anyone may enter, and a winner nobody chooses.
//!
//! The declaration is the package's own: `metadata()` traces the module
//! the component is built from, so the signatures a caller routes on and
//! the code that executes them, and the handle a client calls it
//! through, are all read off one text.
//!
//! `enter(who, funds)`: one ticket at the entrant's hashed order and the
//! stake into the pot, both commutative with every other entry — two
//! people entering at once write two entries and one delta, and neither
//! waits on the other. It is public, and the authority behind an entry is
//! the funds it carries, gated upstream at the withdrawal that produced
//! them. Whoever pays may name whoever they like as the entrant, which is
//! buying somebody a ticket.
//!
//! `close()`: an exclusive write onto an empty leaf, where the kernel
//! stamps the epoch. Public for a reason that is not laziness — a seal
//! takes no argument, so whoever closes the round chooses when it
//! closes and nothing about what it draws.
//!
//! `settle(cap)`: the seal opened, a fresh read of the entrants interval
//! at the caller's cap, and an exclusive write of the result. Public on
//! the same terms. The cap is the caller's because the page is the
//! caller's bill — but which tickets count is nobody's: the kernel
//! answers whether the page covered the round, a short round declines,
//! and every settled winner was drawn over every ticket at a cost that
//! rose with the round.

guest!(lottery, "../../../guests/lottery/src/lib.rs");

pub use package::lottery::Outcome;

/// The entrant cap the corpus settles at: the round a single page covers.
pub const ROUND_CAP: u32 = 64;

/// The code `settle` declines with when its page did not cover the
/// round — tickets past the cap exist, unwalked and unconsidered.
pub const ROUND_TRUNCATED: u32 = 0;

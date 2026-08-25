//! Every path a guest can take that changes who controls value, and the
//! verdict each carries.
//!
//! Covering the movement primitives is not the same as covering the
//! movements: every leak this kind of seam has ever sprung was a second
//! writer somebody forgot about. So the enumeration is a test rather
//! than a list in prose — the world file is the guest's whole reach, and
//! a call that moves a bucket and is not answered here fails the build.
//!
//! What it does not cover, deliberately: paths the kernel takes on its
//! own behalf, outside the session and any declaration. Those are the
//! host's, and they carry their own exemptions where they are written.

/// The world every guest is linked against. Read as source rather than
/// as a parsed model: what is under test is that a name appearing here
/// was considered, and a substring is enough to establish that.
const WORLD: &str = include_str!("../wit/kernel.wit");

/// Why a value-carrying call needs no movement requirement of its own,
/// or which one it gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verdict {
    /// The declared mode carries the direction, so the requirement the
    /// access earns is the one its polarity names.
    ByMode,
    /// One declared access reaches both directions, so both
    /// requirements are injected. A negative capability may over-bind
    /// and must never under-bind.
    BothDirections,
    /// Value in flight: no cell, no owner, and nothing yet to judge.
    /// Safe to exempt only because a transaction holding value at the
    /// close does not commit — `KernelSession::finish` refuses while any
    /// live bucket carries anything.
    InFlight,
    /// Supply, which is its own behaviour rather than a movement of an
    /// existing holding — judged against the resource's own authority
    /// entry, injected onto the issuing frame and answered where every
    /// actor question is.
    OwnBehaviour,
}

use Verdict::{BothDirections, ByMode, InFlight, OwnBehaviour};

/// The verdict every bucket-carrying call in the world carries.
///
/// A run is the same operation over a `for-each` expansion, so it takes
/// the verdict of the call it repeats — and it is listed rather than
/// derived, because "it looked like the one above it" is exactly how a
/// second writer gets forgotten.
const VERDICTS: &[(&str, Verdict)] = &[
    // One call for every value mode and every width, so one verdict
    // covers what the exclusive hold and the commutative movement both
    // do: each reaches both directions through one declared access, and
    // which of them the capability carries changes when the debit is
    // judged rather than what it moves.
    ("site-take", BothDirections),
    ("site-put", BothDirections),
    // A reservation is a conditional decrement, and the only mode whose
    // direction the declaration carries.
    ("site-reserve-take", ByMode),
    // Instances move both ways through an interval, whose slot admits
    // read and write and says nothing about which.
    ("site-instance-take", BothDirections),
    ("site-instance-put", BothDirections),
    // In flight between a producer and a consumer.
    ("bucket-take", InFlight),
    ("bucket-split", InFlight),
    ("bucket-put", InFlight),
    // Supply, under the resource's own entries — and the entry each
    // reaches is the direction it takes, so a burn-only declaration is
    // never asked who may mint.
    ("mint", OwnBehaviour),
    ("mint-instances", OwnBehaviour),
    ("burn", OwnBehaviour),
];

/// Every function the world declares, as its name and its signature.
fn world_functions() -> Vec<(String, String)> {
    WORLD
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (name, rest) = line.split_once(": func")?;
            (!name.is_empty() && name.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
                .then(|| (name.to_owned(), rest.to_owned()))
        })
        .collect()
}

/// A call moves value when ownership of a bucket crosses it.
///
/// Ownership rather than any mention: a borrowed bucket is read, and
/// reading what a bucket holds moves nothing.
fn moves_value(signature: &str) -> bool {
    signature.contains("own<bucket>")
}

/// The enumeration itself: every call that moves a bucket has a verdict,
/// and every verdict answers a call that exists.
#[test]
fn every_value_carrying_call_has_a_verdict() {
    let mut unanswered: Vec<String> = Vec::new();
    let mut carrying: Vec<String> = Vec::new();
    for (name, signature) in world_functions() {
        if !moves_value(&signature) {
            continue;
        }
        if !VERDICTS.iter().any(|(answered, _)| *answered == name) {
            unanswered.push(name.clone());
        }
        carrying.push(name);
    }
    assert!(
        unanswered.is_empty(),
        "these calls move value and carry no verdict: {unanswered:?}\n\
         a path that changes who controls value is covered or exempt, and \
         landing one without saying which is what every seam in the survey \
         got wrong"
    );

    let stale: Vec<&str> = VERDICTS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !carrying.iter().any(|found| found == name))
        .collect();
    assert!(
        stale.is_empty(),
        "these verdicts answer calls the world no longer declares: {stale:?}"
    );
}

/// The two directional facts the injection rests on, stated where a
/// change to either would be caught.
#[test]
fn only_a_reservation_carries_its_direction() {
    let directional: Vec<&str> = VERDICTS
        .iter()
        .filter(|(_, verdict)| *verdict == ByMode)
        .map(|(name, _)| *name)
        .collect();
    assert_eq!(directional, vec!["site-reserve-take"]);

    // And every other cell-bearing call is bidirectional through one
    // access, which is why both requirements are injected there.
    let both = VERDICTS
        .iter()
        .filter(|(_, verdict)| *verdict == BothDirections)
        .count();
    assert_eq!(both, 4);
}

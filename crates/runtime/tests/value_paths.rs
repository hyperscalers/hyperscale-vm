//! Every path a guest can take that changes who controls value, and the
//! verdict each carries.
//!
//! Covering the movement primitives is not the same as covering the
//! movements: every leak this kind of seam has ever sprung was a second
//! writer somebody forgot about. So the enumeration is a test rather
//! than a list in prose — the import table is the guest's whole reach,
//! and a call that moves a bucket and is not answered here fails the
//! build.
//!
//! What it does not cover, deliberately: paths the kernel takes on its
//! own behalf, outside the session and any declaration. Those are the
//! host's, and they carry their own exemptions where they are written.

use hyperscale_vm_embed::abi::IMPORTS;

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
    /// entry, injected onto the frame and answered where every actor
    /// question is. Which entry, and against whose record, is the
    /// declaration's: an issuance derives the resource and reads the
    /// entry off itself, a destruction takes the edge's and reads it off
    /// the record the caller presented.
    OwnBehaviour,
}

use Verdict::{BothDirections, ByMode, InFlight, OwnBehaviour};

/// The verdict every bucket-carrying call in the import table carries.
///
/// Listed rather than derived, because "it looked like the one above
/// it" is exactly how a second writer gets forgotten.
const VERDICTS: &[(&str, Verdict)] = &[
    // One call for every value mode and every width, so one verdict
    // covers what the exclusive hold and the commutative movement both
    // do: each reaches both directions through one declared access, and
    // which of them the capability carries changes when the debit is
    // judged rather than what it moves.
    ("site_take", BothDirections),
    ("site_put", BothDirections),
    // A reservation is a conditional decrement, and the only mode whose
    // direction the declaration carries.
    ("site_reserve_take", ByMode),
    // Instances move both ways through an interval, whose slot admits
    // read and write and says nothing about which.
    ("site_instance_take", BothDirections),
    ("site_instance_put", BothDirections),
    // In flight between a producer and a consumer.
    ("bucket_take", InFlight),
    ("bucket_split", InFlight),
    ("bucket_put", InFlight),
    // Supply, under the resource's own entries — and the entry each
    // reaches is the direction it takes, so a burn-only declaration is
    // never asked who may mint. `burn` names no grant because a bucket
    // carries the resource it holds, which is what lets one call serve
    // the issuer retiring its own and a holder retiring somebody else's.
    ("mint", OwnBehaviour),
    ("mint_instances", OwnBehaviour),
    ("burn", OwnBehaviour),
];

/// The imports through which no bucket's ownership crosses: reads,
/// writes of bytes, the register collects, arithmetic, and the
/// environment. A bucket's amount is read through `bucket_amount` and
/// its slot released through `bucket_drop`, and neither changes who
/// controls what it carries.
///
/// Enumerated so that a new import has to be filed under one list or
/// the other before the build passes.
const NOT_CARRYING: &[&str] = &[
    "arg",
    "take",
    "reply",
    "answer",
    "site_len",
    "site_declared",
    "site_get",
    "site_set",
    "site_seal",
    "site_open_seal",
    "site_clear",
    "site_balance",
    "site_count",
    "site_covered",
    "site_order",
    "site_entry",
    "site_entry_set",
    "site_insert",
    "site_remove",
    "bucket_amount",
    "bucket_drop",
    "mul_div",
    "geometric_mean",
    "fraction_compose",
    "fraction_cmp",
    "fixed_pow",
    "clock",
    "hash",
    "emit",
];

/// The enumeration itself: every import is filed as carrying value or
/// not, every carrying call has a verdict, and every verdict answers a
/// call that exists.
#[test]
fn every_value_carrying_call_has_a_verdict() {
    let mut unfiled: Vec<&str> = Vec::new();
    for (_, name, _, _) in IMPORTS {
        let carrying = VERDICTS.iter().any(|(answered, _)| answered == name);
        let not_carrying = NOT_CARRYING.contains(name);
        if carrying == not_carrying {
            unfiled.push(name);
        }
    }
    assert!(
        unfiled.is_empty(),
        "these imports are filed under both lists or neither: {unfiled:?}\n\
         a path that changes who controls value is covered or exempt, and \
         landing one without saying which is what every seam in the survey \
         got wrong"
    );

    let stale: Vec<&str> = VERDICTS
        .iter()
        .map(|(name, _)| *name)
        .chain(NOT_CARRYING.iter().copied())
        .filter(|name| !IMPORTS.iter().any(|(_, found, _, _)| found == name))
        .collect();
    assert!(
        stale.is_empty(),
        "these entries answer calls the kernel no longer defines: {stale:?}"
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
    assert_eq!(directional, vec!["site_reserve_take"]);

    // And every other cell-bearing call is bidirectional through one
    // access, which is why both requirements are injected there.
    let both = VERDICTS
        .iter()
        .filter(|(_, verdict)| *verdict == BothDirections)
        .count();
    assert_eq!(both, 4);
}

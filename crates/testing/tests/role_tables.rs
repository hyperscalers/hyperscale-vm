//! A package's own stored rule: one cell behind its own one-way door,
//! and a gate that reads it where it lives.
//!
//! The admin's authority is a badge the registry itself issues, so
//! handing the admin seat over is an ordinary holdings transfer that
//! touches no cell of the governed component — and the stored form is
//! there for the rule that has to change. Nothing about it is the
//! protocol's: a rule in a cell is a rule in a cell, and what it takes to
//! replace one is this package's own answer.

use hyperscale_vm_effects::{Presented, RuleBytes, StoredRule, TestHasher};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{Chain, PrincipalAddr, account, package, principal};
use hyperscale_vm_types::{Outcome, Presence, ResourceAddr, UnmetCondition};

const FOUNDER: PrincipalAddr = principal(0x51);
const SUCCESSOR: PrincipalAddr = principal(0x52);

#[blueprint]
mod registry {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity, RuleBytes, clock_ms};

    /// The badge the table's rules name: the registry's own issue, so
    /// holding it is holding the seat and selling the seat is a
    /// transfer. The registry comes up holding its one instance, which
    /// leaves as the edge the bring-up yields.
    #[resource(non_fungible, initial(0))]
    struct AdminBadge;

    /// Only the founder may bring the registry up or seed its table.
    #[config]
    #[requires(founder)]
    struct Settings {
        founder: Address,
    }

    /// A replacement waiting on the delay that governed when it was made.
    #[record]
    struct Pending {
        effective_at_ms: u64,
        rule: RuleBytes,
    }

    #[state]
    struct Registry {
        admin: Cell<Option<RuleBytes>>,
        pending: Cell<Option<Pending>>,
        delay_ms: Cell<u64>,
        flag: Cell<Quantity>,
    }

    impl Registry {
        /// Seed the roles, under the one-way door the table's own
        /// absence is.
        ///
        /// A call of its own rather than part of the bring-up: what the
        /// cell holds is what a caller hands over, and an attribute has
        /// no way to say it. The cell's `Absent` door is what makes it
        /// once-only, so it needs no help from the seal.
        #[requires(founder)]
        pub fn seed_admin(&mut self, rule: RuleBytes, delay_ms: u64) {
            self.admin.create(rule);
            self.delay_ms.set(delay_ms);
        }

        /// The admin surface.
        #[requires(governs(admin))]
        pub fn set_flag(&mut self, value: Quantity) {
            self.flag.set(value);
        }

        /// Rotate the rule: a replacement waiting out the stored delay.
        #[requires(governs(admin))]
        pub fn propose_admin(&mut self, rule: RuleBytes) {
            let effective_at_ms = clock_ms().saturating_add(self.delay_ms.get());
            self.pending.set(Some(Pending {
                effective_at_ms,
                rule,
            }));
        }

        /// Enact a replacement whose delay has run out.
        ///
        /// Open to anyone, because it does only what the clock already
        /// licensed. Nothing happens before the instant the replacement
        /// named.
        pub fn promote(&mut self) {
            if let Some(pending) = self.pending.get()
                && pending.effective_at_ms <= clock_ms()
            {
                self.admin.set(Some(pending.rule));
                self.pending.set(None);
            }
        }
    }
}

const DELAY_MS: u64 = 100_000;

fn setup() -> (Chain, registry::client::Registry) {
    let mut chain = Chain::native();
    chain.publish(package!(registry));
    let instance = chain.instantiate::<registry::client::Registry>(
        FOUNDER,
        registry::client::Settings {
            founder: FOUNDER.address(),
        },
    );
    (chain, instance)
}

/// The registry's own admin badge.
fn badge(instance: registry::client::Registry) -> ResourceAddr {
    instance.issued_admin_badge(&TestHasher)
}

/// A rule as a cell stores it.
fn stored(rule: &StoredRule) -> RuleBytes {
    RuleBytes::try_from(rule).expect("a rule within the caps encodes")
}

/// Seed the registry's admin rule with instance 0 of the badge its
/// bring-up already filed in the founder's account.
fn seeded() -> (Chain, registry::client::Registry) {
    let (mut chain, instance) = setup();
    let rule = stored(&StoredRule::claim(Presented::of_instance(
        badge(instance),
        0,
    )));
    chain
        .transact(FOUNDER, |b| {
            let founder = account::authorize(b, FOUNDER)?;
            instance.seed_admin(b, founder, rule.clone(), DELAY_MS)
        })
        .expect_completed();
    (chain, instance)
}

/// A component whose rule nobody seeded refuses its gated call as the
/// unmet rule — a routed verdict a caller can read, never a trap.
///
/// What an unwritten cell admits is the identity the address itself
/// derives, and a component derives from no key: there is nothing to
/// present for it, so the branch that would open the surface has no
/// satisfier and the surface stays closed until somebody seeds a rule.
#[test]
fn an_unseeded_registry_refuses_its_surface_as_the_routed_absence() {
    let (mut chain, instance) = setup();
    let outcome = chain
        .transact(FOUNDER, |b| instance.set_flag(b, 7))
        .refused()
        .cloned()
        .expect("an unseeded rule refuses");
    assert!(
        matches!(
            outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { .. },
            }
        ),
        "refused as the unmet rule: {outcome:?}",
    );
}

/// Seeding the table opens the surface to whoever holds the badge its
/// rules name — the badge the bring-up already minted.
#[test]
fn a_seeded_table_opens_the_surface_to_the_badge_holder() {
    let (mut chain, instance) = seeded();
    chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_as(held, instance, "set-flag", (7u128,))?.none()
        })
        .expect_completed();
}

/// The one-way door: a second seeding is refused where the table
/// lives, before any body runs.
#[test]
fn a_second_seeding_is_refused_where_the_table_lives() {
    let (mut chain, instance) = seeded();
    let rule = stored(&StoredRule::claim(Presented::of_instance(
        badge(instance),
        0,
    )));
    let outcome = chain
        .transact(FOUNDER, |b| {
            let founder = account::authorize(b, FOUNDER)?;
            instance.seed_admin(b, founder, rule.clone(), DELAY_MS)
        })
        .refused()
        .cloned()
        .expect("the second seeding is refused");
    assert!(
        matches!(
            outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Absent,
                    ..
                },
            }
        ),
        "refused as the unmet absence: {outcome:?}",
    );
}

/// Handing the seat over is a holdings transfer: the old holder's
/// presentation refuses, the new holder's admits, and no cell of the
/// governed component moved.
#[test]
fn a_transferred_badge_rotates_the_admin_without_touching_the_registry() {
    let (mut chain, instance) = seeded();
    chain
        .transact(FOUNDER, |b| {
            let owner = account::authorize(b, FOUNDER)?;
            let seat = account::withdraw_nf(b, owner, badge(instance), &[0])?;
            account::deposit_nf(b, SUCCESSOR, seat)
        })
        .expect_completed();

    // The old holder's presentation refuses as the possession it no
    // longer has.
    let outcome = chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_as(held, instance, "set-flag", (9u128,))?.none()
        })
        .refused()
        .cloned()
        .expect("a badge no longer held does not present");
    assert!(matches!(
        outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                required: Presence::Present,
                ..
            },
        }
    ));

    // And the new holder operates.
    chain
        .transact(SUCCESSOR, |b| {
            let held = account::present_instance(b, SUCCESSOR, badge(instance), 0)?;
            b.call_as(held, instance, "set-flag", (9u128,))?.none()
        })
        .expect_completed();
}

/// A rewritten role governs only after the stored delay: before
/// maturity the badge still rules and the successor is refused; after
/// it, the roles have traded places.
#[test]
fn a_rotation_governs_only_after_the_stored_delay() {
    let (chain, instance) = seeded();
    let mut chain = chain.at(1_000_000);
    chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            let rule = stored(&StoredRule::claim(Presented::of_subject(SUCCESSOR)));
            b.call_as(held, instance, "propose-admin", (rule,))?.none()
        })
        .expect_completed();

    // Before maturity the proposal governs nothing.
    assert!(
        chain
            .transact(SUCCESSOR, |b| instance.set_flag(b, 3))
            .refused()
            .is_some(),
        "an unmatured proposal admits nobody new",
    );
    chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_as(held, instance, "set-flag", (3u128,))?.none()
        })
        .expect_completed();

    // After it, anybody may enact what the clock has licensed — and
    // until somebody does, the rule that governs is still the old one.
    let mut chain = chain.at(1_000_000 + DELAY_MS);
    assert!(
        chain
            .transact(SUCCESSOR, |b| instance.set_flag(b, 4))
            .refused()
            .is_some(),
        "a replacement past its instant still has to be enacted",
    );
    chain
        .transact(SUCCESSOR, |b| instance.promote(b))
        .expect_completed();
    chain
        .transact(SUCCESSOR, |b| instance.set_flag(b, 4))
        .expect_completed();
    assert!(
        chain
            .transact(FOUNDER, |b| {
                let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
                b.call_as(held, instance, "set-flag", (4u128,))?.none()
            })
            .refused()
            .is_some(),
        "and the badge's rule is the one it replaced",
    );
}

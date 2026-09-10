//! A package's own stored rule: one cell behind its own one-way door,
//! and a gate that reads it where it lives.
//!
//! The admin's authority is a badge the registry itself issues, so
//! handing the admin seat over is an ordinary holdings transfer that
//! touches no cell of the governed component — and the stored form is
//! there for the rule that has to change. Nothing about it is the
//! protocol's: a rule in a cell is a rule in a cell, and what it takes to
//! replace one is this package's own answer.

use hyperscale_vm_effects::{Claim, RuleBytes, StoredRule, TestHasher};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_stdlib::instantiate;
use hyperscale_vm_testing::{Chain, Component, PrincipalAddr, account, package, principal};
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

    /// Only the founder may bring the registry up.
    #[config]
    #[requires(config.founder)]
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
        /// Bring the registry up with its admin rule seeded, so there is
        /// no instant at which the component is actual and its surface
        /// has no rule to open it.
        ///
        /// The body of the seal rather than a call after it: what the
        /// cell holds is what the founder hands over, and the rule names
        /// the badge this same bring-up mints. The founder's gate is the
        /// configuration's, inherited here.
        pub fn instantiate(&mut self, rule: RuleBytes, delay_ms: u64) {
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

/// The registry's own admin badge.
fn badge(instance: registry::client::Registry) -> ResourceAddr {
    instance.issued_admin_badge(&TestHasher)
}

/// A rule as a cell stores it.
fn stored(rule: &StoredRule) -> RuleBytes {
    RuleBytes::try_from(rule).expect("a rule within the caps encodes")
}

/// A rule naming instance `id` of the badge the registry's own bring-up
/// mints.
fn admin_rule(instance: registry::client::Registry, id: u64) -> RuleBytes {
    stored(&StoredRule::claim(Claim::of_instance(badge(instance), id)))
}

/// The registry, derived and then brought up in one transaction that
/// seeds its admin rule — a rule over instance `id` of the badge the
/// same transaction mints and files in the founder's account.
///
/// Two steps rather than one because the rule names the instance: its
/// badge's address exists once the record is derived, and the bring-up
/// is what makes the record actual.
fn seeded_naming(id: u64) -> (Chain, registry::client::Registry) {
    let mut chain = Chain::native();
    chain.publish(package!(registry));
    let instance = chain.derive::<registry::client::Registry>(registry::client::Settings {
        founder: FOUNDER.address(),
    });
    chain
        .bring_up(FOUNDER, instance, (admin_rule(instance, id), DELAY_MS))
        .expect_completed();
    (chain, instance)
}

/// The registry seeded with the one badge instance its bring-up minted.
fn seeded() -> (Chain, registry::client::Registry) {
    seeded_naming(0)
}

/// A registry someone other than its founder tries to bring up is
/// refused before any body runs: the gate is the configuration's, and
/// the body it now wraps changes nothing about who may reach it.
#[test]
fn only_the_founder_brings_the_registry_up() {
    let mut chain = Chain::native();
    chain.publish(package!(registry));
    let instance = chain.derive::<registry::client::Registry>(registry::client::Settings {
        founder: FOUNDER.address(),
    });
    let refused = chain
        .try_transact(SUCCESSOR, |b| {
            instantiate(
                b,
                SUCCESSOR,
                instance.address(),
                (admin_rule(instance, 0), DELAY_MS),
            )
        })
        .err();
    assert!(
        refused.is_some(),
        "a stranger's bring-up is refused before any body runs"
    );
}

/// A refusal names which instance was presented, not just which badge.
///
/// An approval on instance 3 and one on instance 7 are two different
/// claims about one resource. A rendering that drops the instance says
/// the right badge was presented and mysteriously refused, which sends
/// the reader looking for the wrong fault. The rule here names an
/// instance nobody was minted, so what the founder presents is the
/// wrong seat rather than no seat.
#[test]
fn a_refusal_names_the_instance_that_was_presented() {
    let (mut chain, instance) = seeded_naming(1);
    let refused = chain.transact(FOUNDER, |b| {
        let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
        b.call_presenting(held, instance, "set-flag", (7u128,))?
            .none()
    });
    let told = refused.refused_as();
    assert!(told.contains("instance 0"), "{told}");
}

/// The bring-up opens the surface to whoever holds the badge its rule
/// names — the badge the same bring-up minted — in the very next
/// transaction, with no window in which the table is empty.
#[test]
fn a_seeded_table_opens_the_surface_to_the_badge_holder() {
    let (mut chain, instance) = seeded();
    chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_presenting(held, instance, "set-flag", (7u128,))?
                .none()
        })
        .expect_completed();
}

/// The one-way door: a second bring-up of an actual component is
/// refused where its leaves live, before any body runs — the
/// configuration leaf's absence is the fence, and the table's is the
/// cell's own.
#[test]
fn a_second_bring_up_is_refused_where_the_component_lives() {
    let (mut chain, instance) = seeded();
    let outcome = chain
        .bring_up(FOUNDER, instance, (admin_rule(instance, 0), DELAY_MS))
        .refused()
        .cloned()
        .expect("the second bring-up is refused");
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
            let seat = account::withdraw_nf(b, FOUNDER, badge(instance), &[0])?;
            account::deposit_nf(b, SUCCESSOR, seat)
        })
        .expect_completed();

    // The old holder's presentation refuses as the possession it no
    // longer has.
    let outcome = chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_presenting(held, instance, "set-flag", (9u128,))?
                .none()
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
            b.call_presenting(held, instance, "set-flag", (9u128,))?
                .none()
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
            let rule = stored(&StoredRule::claim(Claim::of_subject(SUCCESSOR)));
            b.call_presenting(held, instance, "propose-admin", (rule,))?
                .none()
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
            b.call_presenting(held, instance, "set-flag", (3u128,))?
                .none()
        })
        .expect_completed();

    // After it, anybody may enact what the clock has licensed — and
    // until somebody does, the rule that governs is still the old one.
    let mut chain = chain.at(1_000_000 + DELAY_MS);
    let outcome = chain
        .transact(SUCCESSOR, |b| instance.set_flag(b, 4))
        .refused()
        .cloned()
        .expect("a replacement past its instant still has to be enacted");
    assert!(
        matches!(
            outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { .. },
            }
        ),
        "refused as the standing rule, unsatisfied: {outcome:?}",
    );
    chain
        .transact(SUCCESSOR, |b| instance.promote(b))
        .expect_completed();
    chain
        .transact(SUCCESSOR, |b| instance.set_flag(b, 4))
        .expect_completed();
    let outcome = chain
        .transact(FOUNDER, |b| {
            let held = account::present_instance(b, FOUNDER, badge(instance), 0)?;
            b.call_presenting(held, instance, "set-flag", (4u128,))?
                .none()
        })
        .refused()
        .cloned()
        .expect("the badge's rule is the one it replaced");
    assert!(
        matches!(
            outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Satisfies { .. },
            }
        ),
        "refused as the replaced rule, unsatisfied by the old badge: {outcome:?}",
    );
}

//! What a body derives, pinned where a snapshot cannot reach.
//!
//! The declaration a `#[blueprint]` module produces is committed per
//! package in `crates/effects/snapshots`, which is the whole-corpus
//! answer: a diff there is the derivation moving, and it is a thing to
//! read. What that cannot say is *why* a shape lowers the way it does, so
//! the contracts below are written to make one question each — a
//! conditional's arms, an unordered collection's hashed order, the
//! deterministic environment, an instance's own resources — and the
//! assertions name the property rather than the value.

// The contracts below are read by `#[blueprint]`, never called: what these
// tests exercise is the metadata derived from the bodies, and the derivation
// runs at expansion time. In a real contract crate the module is public and
// its methods are the package's exported surface, so nothing is dead there —
// the appearance is an artifact of a contract living inside a test binary.
#![allow(dead_code)]

use hyperscale_vm_effects::{Clause, ModeExpr};
use hyperscale_vm_sdk::blueprint;

/// Control-flow spellings of one access set, each beside its straight-line
/// equivalent. A conditional access is declared on every arm, so whichever
/// spelling the author reaches for, the declaration is the same superset.
#[blueprint]
mod shapes {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Keyed, Quantity, Vault};

    #[state]
    struct Shapes {
        #[role(1)]
        vaults: Keyed<Vault>,
    }

    impl Shapes {
        /// A loop over a *computed* list declares what one pass declares:
        /// the entries it walks were covered before it started. Ranging
        /// over the argument itself would be a `for-each` — one access
        /// set per element — which is a different declaration and the
        /// point of reading the loop off what it ranges over.
        #[allow(clippy::needless_pass_by_value)] // a contract consumes its arguments
        pub fn looped(&mut self, a: Address, ids: Vec<u8>) {
            let mut vault = self.vaults.at(a);
            // `ids` itself is a term, and ranging over it would be a
            // `for-each`; the length is not, so this is a plain loop.
            for _id in ids.len()..1 {
                vault.declared();
            }
        }

        #[allow(clippy::needless_pass_by_value)] // a contract consumes its arguments
        pub fn once(&mut self, a: Address, _ids: Vec<u8>) {
            let mut vault = self.vaults.at(a);
            vault.declared();
        }

        pub fn branched(&mut self, flag: u64, a: Address, b: Address) {
            match flag {
                0 => self.vaults.at(a).declared(),
                _ => self.vaults.at(b).declared(),
            }
        }

        pub fn straight(&mut self, _flag: u64, a: Address, b: Address) {
            self.vaults.at(a).declared();
            self.vaults.at(b).declared();
        }

        pub fn asserted(&mut self, a: Address) {
            assert_eq!(self.vaults.at(a).balance(), Quantity::ZERO);
        }

        #[allow(clippy::equatable_if_let)] // the spelling under test is the if-let itself
        pub fn scrutinised(&mut self, a: Address) {
            if let Quantity::ZERO = self.vaults.at(a).balance() {}
        }

        pub fn read(&mut self, a: Address) {
            let _ = self.vaults.at(a).balance();
        }

        pub fn guarded(&mut self, flag: u64, a: Address) {
            let 0 = flag else {
                self.vaults.at(a).declared();
                return;
            };
        }

        pub fn plain(&mut self, _flag: u64, a: Address) {
            self.vaults.at(a).declared();
        }
    }
}

#[test]
fn every_spelling_of_a_conditional_declares_the_same_accesses() {
    let metadata = shapes::blueprint().metadata();
    let effects = |name: &str| &metadata.methods[name].effects;
    assert_eq!(effects("branched"), effects("straight"), "match arms");
    assert_eq!(effects("asserted"), effects("read"), "assert argument");
    assert_eq!(effects("scrutinised"), effects("read"), "if-let scrutinee");
    assert_eq!(effects("guarded"), effects("plain"), "let-else diverge");
    assert_eq!(
        effects("looped"),
        effects("once"),
        "loop over a runtime list"
    );
}

/// The unordered surface: point access by hashed key, capped sweeps from a
/// cursor. What the test pins is the lowered shape — the entry's order is
/// an `OrderKey` over the argument, salted by the collection's owner and
/// role, and a sweep is a range to the top of the order space.
#[blueprint]
mod registry {
    use hyperscale_vm_sdk::state::Unordered;

    #[state]
    struct Registry {
        #[role(2)]
        names: Unordered<u128>,
    }

    impl Registry {
        /// Bind `name` to `value`.
        pub fn bind(&mut self, name: u64, value: u128) {
            let _ = value;
            self.names.at(name).set(0);
        }

        /// Read the binding for `name`.
        pub fn resolve(&mut self, name: u64) -> u128 {
            self.names.at(name).get()
        }

        /// One crank of a paginated walk over everything held.
        pub fn sweep(&mut self, cursor: u128) {
            let entries = self.names.sweep(cursor, 8);
            let _ = entries.count();
        }
    }
}

#[test]
fn an_unordered_collection_declares_hashed_entries_and_capped_sweeps() {
    use hyperscale_vm_effects::{Clause, Expr, ModeExpr, RoleId, TargetExpr, Value};

    let metadata = registry::blueprint().metadata();
    let hashed_entry = || TargetExpr::Entry {
        owner: Expr::SelfAddr,
        collection: RoleId(2),
        material: vec![],
        order: Expr::OrderKey {
            owner: Box::new(Expr::SelfAddr),
            role: RoleId(2),
            material: vec![Expr::Arg(0)],
        },
    };
    assert_eq!(
        metadata.methods["bind"].effects,
        vec![Clause::Effect {
            target: hashed_entry(),
            mode: ModeExpr::Write,
        }],
    );
    assert_eq!(
        metadata.methods["resolve"].effects,
        vec![Clause::Effect {
            target: hashed_entry(),
            mode: ModeExpr::Read,
        }],
    );
    assert_eq!(
        metadata.methods["sweep"].effects,
        vec![Clause::Effect {
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: RoleId(2),
                material: vec![],
                lo: Expr::Arg(0),
                hi: Expr::Literal(Value::U128(u128::MAX)),
                cap: 8,
            },
            mode: ModeExpr::Read,
        }],
    );
}

/// The deterministic environment, which a body may read and a declaration
/// says nothing about.
///
/// Identical on every replica by construction rather than by exclusion:
/// the clock is the committing block's own weighted-time anchor, the
/// draw is domain-separated per transaction, and the hash is the
/// protocol's. So a method reading all three declares exactly what a
/// method reading none of them does.
#[blueprint]
mod environment {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Keyed, Vault, clock_ms, hash, randomness};

    #[state]
    struct Environment {
        #[role(1)]
        vaults: Keyed<Vault>,
        #[role(2)]
        seen: Cell<u64>,
    }

    impl Environment {
        pub fn stamp(&mut self, holder: Address) {
            let digest = hash(&randomness());
            let drawn = u128::from(digest[0]);
            let _ = drawn;
            self.vaults.at(holder).declared();
            self.seen.set(clock_ms());
        }

        pub fn plain(&mut self, holder: Address) {
            self.vaults.at(holder).declared();
            self.seen.set(0);
        }
    }
}

#[test]
fn reading_the_environment_declares_nothing() {
    let metadata = environment::blueprint().metadata();
    let effects = |name: &str| &metadata.methods[name].effects;
    assert_eq!(effects("stamp"), effects("plain"), "environment reads");
    // And nothing of it reaches the guest through the ABI: the kernel
    // answers each call where it is made, so none is a bound value.
    assert_eq!(
        metadata.methods["stamp"].abi, metadata.methods["plain"].abi,
        "environment bindings"
    );
}

/// A resource an instance issues: the stake unit a pool hands back, and
/// the badge that operates it.
///
/// Both derive from the instance's own address rather than from its
/// configuration, and they have to — an address commits the
/// configuration, so a configured field naming a value derived from that
/// address would not be expressible. The mark is what separates one from
/// the other.
#[blueprint]
mod issuer {
    use hyperscale_vm_sdk::state::{Bucket, Cell, Fixed, Keyed, Quantity, Rounding, Vault, issue};

    #[state]
    struct Issuer {
        #[role(1)]
        staked: Cell<Quantity>,
        /// A stored rate, to pin the mode a value-shaped cell that is not
        /// value folds to.
        #[role(3)]
        index: Cell<Fixed<(), ()>>,
        #[role(2)]
        vaults: Keyed<Vault>,
    }

    impl Issuer {
        /// Accrue the stored index, which is a read-modify-write and
        /// never a movement.
        pub fn accrue(&mut self) {
            let index = self.index.get();
            self.index.set(index + Fixed::ONE);
            let _ = Rounding::Down;
        }

        /// Take a delegation and hand back units at par.
        pub fn stake(&mut self, funds: Bucket) -> Bucket {
            let staked = funds.quantity();
            self.staked.set(staked);
            self.vaults.at(funds.resource()).put(funds);
            issue(b"", staked)
        }

        /// The operator surface, gated on the badge the pool issues.
        #[guarded(issued(b"owner-badge"))]
        pub fn retire(&mut self) {
            self.staked.set(Quantity::ZERO);
        }
    }
}

#[test]
fn a_stored_rate_folds_to_an_exclusive_write_never_a_movement() {
    let blueprint = issuer::blueprint();
    let metadata = blueprint.metadata();
    let modes: Vec<ModeExpr> = metadata.methods["accrue"]
        .effects
        .iter()
        .map(|clause| match clause {
            Clause::Effect { mode, .. } => mode.clone(),
            Clause::ForEach { .. } => panic!("the accrual maps over nothing"),
        })
        .collect();
    // A rate is not value: nothing moves into or out of the cell, so the
    // site folds to the exclusive read-modify-write and the commutative
    // movement semantics that read an amount cell are unreachable for it.
    assert_eq!(modes, vec![ModeExpr::Write]);
}

#[test]
fn an_instance_issues_resources_its_own_address_derives() {
    use hyperscale_vm_effects::{Accessibility, Expr, Value};

    let metadata = issuer::blueprint().metadata();
    // The unit is the instance's primary issue: no material at all,
    // which is a different resource from any marked one.
    assert_eq!(
        metadata.methods["stake"].outputs,
        vec![Expr::SelfResource { material: vec![] }],
    );
    // The badge is the same derivation over the mark that separates it.
    assert_eq!(
        metadata.methods["retire"].accessibility,
        Accessibility::Guarded(Expr::SelfResource {
            material: vec![Expr::Literal(Value::Bytes(b"owner-badge".to_vec()))],
        }),
    );
}

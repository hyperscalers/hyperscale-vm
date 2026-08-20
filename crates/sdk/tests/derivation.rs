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

use hyperscale_vm_effects::{Clause, ModeExpr, ResourceKind, RuleExpr};
use hyperscale_vm_sdk::blueprint;

/// Control-flow spellings of one access set, each beside its straight-line
/// equivalent. A conditional access is declared on every arm, so whichever
/// spelling the author reaches for, the declaration is the same superset.
#[blueprint]
mod shapes {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Quantity;

    #[state]
    struct Shapes {}

    impl Shapes {
        /// A loop over a *computed* list declares what one pass declares:
        /// the entries it walks were covered before it started. Ranging
        /// over the argument itself would be a `for-each` — one access
        /// set per element — which is a different declaration and the
        /// point of reading the loop off what it ranges over.
        #[allow(clippy::needless_pass_by_value)] // a contract consumes its arguments
        pub fn looped(&mut self, a: Address, ids: Vec<u8>) {
            let mut vault = self.vault(a);
            // `ids` itself is a term, and ranging over it would be a
            // `for-each`; the length is not, so this is a plain loop.
            for _id in ids.len()..1 {
                vault.declared();
            }
        }

        #[allow(clippy::needless_pass_by_value)] // a contract consumes its arguments
        pub fn once(&mut self, a: Address, _ids: Vec<u8>) {
            let mut vault = self.vault(a);
            vault.declared();
        }

        pub fn branched(&mut self, flag: u64, a: Address, other: Address) {
            match flag {
                0 => self.vault(a).declared(),
                _ => self.vault(other).declared(),
            }
        }

        pub fn straight(&mut self, _flag: u64, a: Address, other: Address) {
            self.vault(a).declared();
            self.vault(other).declared();
        }

        pub fn asserted(&mut self, a: Address) {
            assert_eq!(self.vault(a).balance(), Quantity::ZERO);
        }

        #[allow(clippy::equatable_if_let)] // the spelling under test is the if-let itself
        pub fn scrutinised(&mut self, a: Address) {
            if let Quantity::ZERO = self.vault(a).balance() {}
        }

        pub fn read(&mut self, a: Address) {
            let _ = self.vault(a).balance();
        }

        pub fn guarded(&mut self, flag: u64, a: Address) {
            let 0 = flag else {
                self.vault(a).declared();
                return;
            };
        }

        pub fn plain(&mut self, _flag: u64, a: Address) {
            self.vault(a).declared();
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
    use hyperscale_vm_effects::{Clause, Expr, ModeExpr, SlotId, TargetExpr, Value};

    let metadata = registry::blueprint().metadata();
    let hashed_entry = || TargetExpr::Entry {
        owner: Expr::SelfAddr,
        collection: SlotId(16),
        material: vec![],
        order: Expr::OrderKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotId(16),
            material: vec![Expr::Arg(0)],
        },
    };
    assert_eq!(
        metadata.methods["bind"].effects,
        vec![Clause::Effect {
            guard: None,
            target: hashed_entry(),
            mode: ModeExpr::Write,
            denomination: None,
        }],
    );
    assert_eq!(
        metadata.methods["resolve"].effects,
        vec![Clause::Effect {
            guard: None,
            target: hashed_entry(),
            mode: ModeExpr::Read,
            denomination: None,
        }],
    );
    assert_eq!(
        metadata.methods["sweep"].effects,
        vec![Clause::Effect {
            guard: None,
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: SlotId(16),
                material: vec![],
                lo: Expr::Arg(0),
                hi: Expr::Literal(Value::U128(u128::MAX)),
                cap: Expr::Literal(Value::U64(8)),
            },
            mode: ModeExpr::Read,
            denomination: None,
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
    use hyperscale_vm_sdk::state::{Cell, clock_ms, hash, randomness};

    #[state]
    struct Environment {
        seen: Cell<u64>,
    }

    impl Environment {
        pub fn stamp(&mut self, holder: Address) {
            let digest = hash(&randomness());
            let drawn = u128::from(digest[0]);
            let _ = drawn;
            self.vault(holder).declared();
            self.seen.set(clock_ms());
        }

        pub fn plain(&mut self, holder: Address) {
            self.vault(holder).declared();
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
    use hyperscale_vm_sdk::state::{Bucket, Cell, Fixed, Quantity, Rounding, mint};

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[state]
    struct Issuer {
        staked: Cell<Quantity>,
        /// A stored rate, to pin the mode a value-shaped cell that is not
        /// value folds to.
        index: Cell<Fixed<(), ()>>,
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
            self.vault(funds.resource()).put(funds);
            mint(b"", staked)
        }

        /// The operator surface, gated on the badge the pool issues.
        #[requires(issued(OwnerBadge))]
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
            Clause::ForEach { .. } | Clause::Requires { .. } | Clause::Mints { .. } => {
                panic!("the accrual maps over nothing and requires nothing")
            }
        })
        .collect();
    // A rate is not value: nothing moves into or out of the cell, so the
    // site folds to the exclusive read-modify-write and the commutative
    // movement semantics that read an amount cell are unreachable for it.
    assert_eq!(modes, vec![ModeExpr::Write]);
}

#[test]
fn an_instance_issues_resources_its_own_address_derives() {
    use hyperscale_vm_effects::{Clause, ConditionExpr, Expr, Value};

    let metadata = issuer::blueprint().metadata();
    // The unit is the instance's primary issue: no material at all,
    // which is a different resource from any marked one.
    assert_eq!(
        metadata.methods["stake"].outputs,
        vec![Expr::SelfResource {
            kind: ResourceKind::Fungible,
            material: vec![],
        }],
    );
    // The badge is the same derivation over the mark that separates it.
    assert!(
        metadata.methods["retire"]
            .effects
            .contains(&Clause::Requires {
                guard: None,
                condition: ConditionExpr::Satisfies {
                    rule: RuleExpr::claim(Expr::SelfResource {
                        kind: ResourceKind::NonFungible,
                        material: vec![Expr::Literal(Value::Bytes(b"owner-badge".to_vec()))],
                    }),
                },
            })
    );
}

/// A body that branches on its own argument, three ways: a branch the
/// declaration can read, one it cannot, and the same readable branch
/// under a mark that trades precision for trap freedom.
#[blueprint]
mod switch {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Cell, Quantity};

    #[config]
    struct Settings {
        left: Address,
        right: Address,
    }

    #[state]
    struct Switch {
        left: Cell<Quantity>,
        right: Cell<Quantity>,
    }

    impl Switch {
        /// One of two vaults, and the declaration says which.
        pub fn credit(&mut self, funds: Bucket, to_left: u64) {
            let settings = self.config().locked();
            if to_left == 1 {
                self.vault(settings.left).put(funds);
            } else {
                self.vault(settings.right).put(funds);
            }
        }

        /// One arm keys the vault by configuration and the other by the
        /// edge's own resource, so only one arm says anything about what
        /// the edge carries.
        pub fn credit_one_way(&mut self, funds: Bucket, to_left: u64) {
            let settings = self.config().locked();
            if to_left == 1 {
                self.vault(settings.left).put(funds);
            } else {
                self.vault(funds.resource()).put(funds);
            }
        }

        /// The same shape over a condition the DSL cannot read, which
        /// declares the union and still runs.
        ///
        /// Two cells rather than two vaults: an edge credited to both
        /// arms of an unreadable branch would have to carry both
        /// resources, which is the contradiction the denomination check
        /// exists for and not what this is about.
        pub fn bump_opaque(&mut self, tag: u64) {
            if tag.count_ones() > 1 {
                self.left.set(self.left.get());
            } else {
                self.right.set(self.right.get());
            }
        }
    }
}

/// The precision half: a method that writes one of two cells declares
/// exactly the one it will write, and hands the guest the verdict rather
/// than a second copy of the condition.
#[test]
fn a_branch_the_declaration_can_read_guards_its_own_clauses() {
    use hyperscale_vm_effects::{AbiParam, Clause, Expr, ModeExpr, Value};

    let metadata = switch::blueprint().metadata();
    let credit = &metadata.methods["credit"];

    // Two clauses, each under its arm's condition, and the second the
    // syntactic negation of the first — which is what lets the presence
    // pass tell an `if`/`else` from a contradiction.
    let cond = Expr::Eq(
        Box::new(Expr::Arg(1)),
        Box::new(Expr::Literal(Value::U64(1))),
    );
    let guards: Vec<Option<Expr>> = credit
        .effects
        .iter()
        .map(|clause| clause.guard().cloned())
        .collect();
    // The configuration read the body opens is nobody's branch, so it
    // carries no guard; the two vault movements carry their arm's.
    assert_eq!(
        guards,
        vec![
            None,
            Some(cond.clone()),
            Some(Expr::Not(Box::new(cond.clone()))),
        ],
    );

    // Both arms move value, so both clauses are commutative.
    assert!(credit.effects[1..].iter().all(|clause| matches!(
        clause,
        Clause::Effect {
            mode: ModeExpr::Delta,
            ..
        }
    )));

    // One verdict crosses, naming the arm that declared first.
    assert_eq!(
        credit
            .abi
            .iter()
            .filter(|binding| matches!(binding, AbiParam::Guard(_)))
            .collect::<Vec<_>>(),
        vec![&AbiParam::Guard(1)],
    );

    // The edge is credited to one of two vaults, so its denomination is
    // the selection rather than either side — one expression, exact, and
    // admission holds a caller to both resources and nothing else.
    assert_eq!(
        credit.denominations,
        vec![
            Some(Expr::If {
                cond: Box::new(Expr::Not(Box::new(cond))),
                then: Box::new(Expr::Config(1)),
                otherwise: Box::new(Expr::Config(0)),
            }),
            None,
        ],
    );
}

/// A parameter denominated on one arm and nowhere else records its
/// guarded expression as though it were unconditional. The promise is
/// what a caller's edge must satisfy, so stating it unconditionally
/// over-constrains admission rather than under-constraining it — which
/// is the direction a promise is allowed to be wrong in.
#[test]
fn a_denomination_from_one_arm_is_recorded_unconditionally() {
    use hyperscale_vm_effects::Expr;

    let metadata = switch::blueprint().metadata();
    assert_eq!(
        metadata.methods["credit-one-way"].denominations,
        vec![Some(Expr::Config(0)), None],
    );
}

/// Precision is what a total method trades for the mark. A total leg
/// runs with every declared handle materialized, and a guarded-out
/// clause materializes none — so the branch declares the union it used
/// to, binds no verdict, and both handles arrive.
#[blueprint]
mod always {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Always {
        left: Cell<Quantity>,
        right: Cell<Quantity>,
    }

    impl Always {
        #[total]
        pub fn bump(&mut self, to_left: u64) {
            if to_left == 1 {
                self.left.set(self.left.get());
            } else {
                self.right.set(self.right.get());
            }
        }
    }
}

#[test]
fn a_total_method_declares_the_union_and_binds_no_verdict() {
    use hyperscale_vm_effects::{AbiParam, Totality};

    let metadata = always::blueprint().metadata();
    let bump = &metadata.methods["bump"];
    assert_eq!(bump.totality, Totality::Total);
    assert_eq!(bump.effects.len(), 2, "both arms are declared");
    assert!(
        bump.effects.iter().all(|clause| clause.guard().is_none()),
        "and neither under a condition, because a total leg materialises every handle"
    );
    assert!(
        !bump
            .abi
            .iter()
            .any(|binding| matches!(binding, AbiParam::Guard(_))),
    );
    assert_eq!(
        bump.abi
            .iter()
            .filter(|binding| matches!(binding, AbiParam::Handle(_)))
            .count(),
        2,
        "both handles arrive"
    );
}

/// The superset stays the fallback: a condition the DSL cannot express
/// declares both arms, which is what keeps a body free to branch on
/// things a declaration has no business seeing.
#[test]
fn a_branch_the_declaration_cannot_read_declares_the_union() {
    use hyperscale_vm_effects::AbiParam;

    let metadata = switch::blueprint().metadata();
    let opaque = &metadata.methods["bump-opaque"];
    assert_eq!(opaque.effects.len(), 2);
    assert!(
        opaque.effects.iter().all(|clause| clause.guard().is_none()),
        "an unreadable condition guards nothing"
    );
    assert!(
        !opaque
            .abi
            .iter()
            .any(|binding| matches!(binding, AbiParam::Guard(_))),
        "and binds no verdict, because there is none to bind"
    );
}

/// A body that reaches one cell from more than one place, three ways.
///
/// A guard is a fact about the cell rather than about where the access
/// was written, so the condition a clause carries is the one holding at
/// every place the cell is reached. Where those disagree the only such
/// condition is the trivial one, and the clause is declared always.
#[blueprint]
mod shared {
    use hyperscale_vm_sdk::state::Cell;

    #[state]
    struct Shared {
        counter: Cell<u64>,
        other: Cell<u64>,
    }

    impl Shared {
        /// Written inside a branch and again after it — so it is written
        /// whatever the branch decides.
        pub fn after(&mut self, which: u64) {
            if which == 1 {
                self.counter.set(1);
            }
            self.counter.set(2);
        }

        /// Written by both arms, which between them cover every call.
        pub fn both(&mut self, which: u64) {
            if which == 1 {
                self.counter.set(1);
            } else {
                self.counter.set(2);
            }
        }

        /// One arm shares its cell with the code around the branch and
        /// the other does not, so precision survives where it is
        /// available.
        pub fn mixed(&mut self, which: u64) {
            if which == 1 {
                self.counter.set(1);
            } else {
                self.other.set(2);
            }
            self.counter.set(3);
        }
    }
}

/// A cell reached from more than one place is declared always, and the
/// branch hands over no verdict about it.
///
/// The guest half is what this protects. A body that writes a cell
/// unconditionally would reach its handle on every call, so a clause
/// declared only on one arm would leave the other arm holding a handle
/// nothing materialized — and the shard the cell lives on would not even
/// be a participant.
#[test]
fn a_cell_reached_from_more_than_one_place_is_declared_always() {
    use hyperscale_vm_effects::{AbiParam, Expr, Value};

    let metadata = shared::blueprint().metadata();
    let verdicts = |method: &str| {
        metadata.methods[method]
            .abi
            .iter()
            .filter(|binding| matches!(binding, AbiParam::Guard(_)))
            .collect::<Vec<_>>()
    };
    let guards = |method: &str| {
        metadata.methods[method]
            .effects
            .iter()
            .map(|clause| clause.guard().cloned())
            .collect::<Vec<_>>()
    };

    // Written inside the branch and after it: one clause, no condition,
    // and nothing for the guest to branch its declaration on.
    assert_eq!(guards("after"), vec![None]);
    assert!(verdicts("after").is_empty());

    // Written by both arms: the same statement, because between them the
    // arms cover every call.
    assert_eq!(guards("both"), vec![None]);
    assert!(verdicts("both").is_empty());

    // And the precision is per cell rather than per branch: the shared
    // one is declared always, the arm's own keeps its condition, and the
    // verdict that crosses is that arm's.
    let cond = Expr::Eq(
        Box::new(Expr::Arg(0)),
        Box::new(Expr::Literal(Value::U64(1))),
    );
    assert_eq!(guards("mixed"), vec![None, Some(Expr::Not(Box::new(cond)))]);
    assert_eq!(verdicts("mixed"), vec![&AbiParam::Guard(1)]);
}

/// A component whose admin set is configuration rather than storage:
/// the free gate, whose reads take no admission key and make its owner
/// no participant. Both shapes an admin set takes are here — either of
/// two, and two of three.
#[blueprint]
mod board {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[config]
    struct Settings {
        chair: Address,
        deputy: Address,
        third: Address,
    }

    #[state]
    struct Board {
        fee: Cell<Quantity>,
    }

    impl Board {
        /// Either officer alone.
        #[requires(chair || deputy)]
        pub fn set_fee(&mut self, fee: Quantity) {
            self.fee.set(fee);
        }

        /// Two of the three, whichever two.
        ///
        /// Published under a name its Rust identifier does not derive:
        /// what a package publishes outlives the identifier that
        /// happened to name it, so the rename is stated once.
        #[name("reset")]
        #[requires(n_of(2, chair, deputy, third))]
        pub fn clear_fee(&mut self) {
            self.fee.set(Quantity::ZERO);
        }

        /// Both officers, and the chain flattens rather than nesting.
        #[requires(chair && deputy && third)]
        pub fn dissolve(&mut self) {
            self.fee.set(Quantity::ZERO);
        }
    }
}

/// The algebra a stored rule has, on the side that declares rather than
/// stores: a threshold over configuration slots, written with Rust's own
/// operators and its own precedence.
#[test]
fn a_declared_gate_carries_the_whole_threshold_algebra() {
    use hyperscale_vm_effects::{Clause, ConditionExpr, Expr};

    let metadata = board::blueprint().metadata();
    let slot = |index| RuleExpr::claim(Expr::Config(index));

    // `||` is a count of one.
    let requires = |method: &str| {
        metadata.methods[method]
            .effects
            .iter()
            .find_map(|clause| match clause {
                Clause::Requires {
                    condition: ConditionExpr::Satisfies { rule },
                    ..
                } => Some(rule.clone()),
                _ => None,
            })
            .expect("a gated method requires its rule")
    };
    assert_eq!(
        requires("set-fee"),
        RuleExpr::CountOf {
            count: 1,
            rules: vec![slot(0), slot(1)],
        },
    );
    // `n_of` is the threshold no operator expresses, and this one is
    // published under a name its identifier does not derive.
    assert_eq!(
        requires("reset"),
        RuleExpr::CountOf {
            count: 2,
            rules: vec![slot(0), slot(1), slot(2)],
        },
    );
    // `&&` is a count of every branch, and a chain of one operator is
    // one threshold rather than two — depth is the cap that binds first.
    assert_eq!(
        requires("dissolve"),
        RuleExpr::CountOf {
            count: 3,
            rules: vec![slot(0), slot(1), slot(2)],
        },
    );
}

/// A method taking two edges and banking them as one. Whatever the merge
/// produces is credited to a configured vault, so both halves are fixed —
/// the one the body names at the cell, and the one it names at the merge.
#[blueprint]
mod counter {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Bucket;

    #[config]
    struct Settings {
        asset: Address,
    }

    #[state]
    struct Counter {}

    impl Counter {
        /// Bank both edges, merged.
        pub fn bank(&mut self, mut first: Bucket, second: Bucket) {
            first.put(second);
            self.vault(self.config().asset).put(first);
        }
    }
}

/// A merge fixes both halves, and the second is stated against the first
/// rather than against the cell.
///
/// Both spellings mean the same resource at execution — the router
/// evaluates `ResourceOf(Arg(0))` to whatever argument zero carries, and
/// argument zero is itself held to the configured asset — but stating it
/// this way is what keeps the constraint true of the merge rather than of
/// the cell that happened to consume it.
#[test]
fn a_merge_denominates_both_of_the_edges_it_joins() {
    use hyperscale_vm_effects::Expr;

    let metadata = counter::blueprint().metadata();
    assert_eq!(
        metadata.methods["bank"].denominations,
        vec![
            Some(Expr::Config(0)),
            Some(Expr::ResourceOf(Box::new(Expr::Arg(0)))),
        ],
    );
}

/// Selection: a key chosen between two configured sides, a table lookup a
/// miss does not refuse, and a compound key spelled as a product.
#[blueprint]
mod selection {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Table, Unordered};

    #[config]
    struct Pair {
        left: Address,
        right: Address,
        routes: Table<Address, Address>,
        fallback: Address,
    }

    #[state]
    struct Selection {
        seen: Unordered<u128>,
    }

    impl Selection {
        /// One of two configured sides, and only one.
        pub fn either(&mut self, pick: Address) {
            let settings = self.config().locked();
            let side = if pick == settings.left {
                settings.left
            } else {
                settings.right
            };
            self.vault(side).declared();
        }

        /// The superset the same choice declares when the arms are
        /// bodies rather than values.
        pub fn both(&mut self, pick: Address) {
            let settings = self.config().locked();
            if pick == settings.left {
                self.vault(settings.left).declared();
            } else {
                self.vault(settings.right).declared();
            }
        }

        /// A lookup a miss answers rather than refuses: the table is read
        /// only where it holds the key, because the untaken arm of a
        /// selection never runs.
        pub fn routed(&mut self, who: Address) {
            let settings = self.config().locked();
            let target = if settings.routes.contains(who) {
                settings.routes.get(who)
            } else {
                settings.fallback
            };
            self.vault(target).declared();
        }

        /// A collection entry at a key that takes two values to name.
        pub fn paired(&mut self, a: u64, b: u64) {
            self.seen.at((a, b)).set(0);
        }

        /// The whole comparison surface, which is two DSL variants
        /// rearranged: what an author writes is what the declaration
        /// reads, so no spelling falls back to the superset silently.
        #[allow(clippy::nonminimal_bool)] // the redundancy is the spelling under test
        pub fn compared(&mut self, a: u64, b: u64) {
            let settings = self.config().locked();
            let side = if a != b && !(a >= b) || a <= b {
                settings.left
            } else {
                settings.right
            };
            self.vault(side).declared();
        }
    }
}

#[test]
fn a_conditional_key_declares_one_cell_where_a_conditional_body_declares_both() {
    use hyperscale_vm_effects::{
        EvalInputs, Expr, Hash32, ManifestHash, SlotId, TargetExpr, TestHasher, Value, child_key,
        evaluate_effects,
    };
    use hyperscale_vm_sdk::VAULT;
    use hyperscale_vm_types::{Address, AddressClass, EffectTarget};

    let metadata = selection::blueprint().metadata();
    let effects = |name: &str| metadata.methods[name].effects.clone();
    let address = |byte: u8| Address::new([byte; 31], AddressClass::Resource);
    let (left, right) = (address(0x11), address(0x22));

    // One vault clause against two, off the same choice: the arms of a
    // selection are values the declaration reads, and the arms of an `if`
    // statement are bodies it can only take the union of. Both also pin
    // the configuration they read the sides from.
    assert_eq!(effects("either").len(), 2);
    assert_eq!(effects("both").len(), 3);

    // And the one clause resolves to whichever side the call picks —
    // never to both, and never to a third thing.
    let self_addr = Address::new([7; 31], AddressClass::Component);
    let config = [
        Value::Address(left),
        Value::Address(right),
        Value::List(Vec::new()),
        Value::Address(left),
    ];
    for (paid, expected) in [(left, left), (right, right), (address(0x33), right)] {
        let args = [Value::Address(paid)];
        let inputs = EvalInputs {
            self_addr,
            args: &args,
            config: &config,
            node_index: 0,
            identity: ManifestHash(Hash32([9; 32])),
        };
        let set = evaluate_effects(&effects("either"), &inputs, &TestHasher).unwrap();
        let vaults: Vec<_> = [left, right, address(0x33)]
            .into_iter()
            .filter(|side| {
                let key = EffectTarget::Point(child_key(
                    &TestHasher,
                    self_addr,
                    VAULT,
                    &[Value::Address(*side).canonical_bytes()],
                ));
                set.iter().any(|effect| effect.target == key)
            })
            .collect();
        assert_eq!(vaults, vec![expected], "the side the call selects, alone");
    }

    // A miss is the package's own answer rather than a routing refusal,
    // which is what the short-circuit buys: an empty table routes every
    // caller to the fallback instead of failing to route at all.
    let args = [Value::Address(right)];
    let inputs = EvalInputs {
        self_addr,
        args: &args,
        config: &config,
        node_index: 0,
        identity: ManifestHash(Hash32([9; 32])),
    };
    let set = evaluate_effects(&effects("routed"), &inputs, &TestHasher).unwrap();
    let fallback = EffectTarget::Point(child_key(
        &TestHasher,
        self_addr,
        VAULT,
        &[Value::Address(left).canonical_bytes()],
    ));
    assert!(
        set.iter().any(|effect| effect.target == fallback),
        "the fallback, because the table holds nothing"
    );

    // A compound key is a product, and it is the material rather than a
    // second collection.
    let paired = effects("paired");
    let [Clause::Effect { target, .. }] = paired.as_slice() else {
        panic!("one entry");
    };
    let TargetExpr::Entry { order, .. } = target else {
        panic!("an unordered entry");
    };
    assert_eq!(
        order,
        &Expr::OrderKey {
            owner: Box::new(Expr::SelfAddr),
            slot: SlotId(16),
            material: vec![Expr::Tuple(vec![Expr::Arg(0), Expr::Arg(1)])],
        }
    );
}

#[test]
fn every_comparison_reaches_the_two_the_vocabulary_has() {
    use hyperscale_vm_effects::{Expr, TargetExpr};

    let metadata = selection::blueprint().metadata();
    let cond = metadata.methods["compared"]
        .effects
        .iter()
        .find_map(|clause| match clause {
            Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey { material, .. }),
                ..
            } => match material.as_slice() {
                [Expr::If { cond, .. }] => Some(cond),
                _ => None,
            },
            _ => None,
        })
        .expect("a vault keyed on a selection");
    let (a, b) = (Box::new(Expr::Arg(0)), Box::new(Expr::Arg(1)));
    // `a != b && !(a >= b) || a <= b`, with `!=` a negated equality and
    // the three orderings one `Lt` apiece, swapped or negated.
    assert_eq!(
        **cond,
        Expr::Or(
            Box::new(Expr::And(
                Box::new(Expr::Not(Box::new(Expr::Eq(a.clone(), b.clone())))),
                Box::new(Expr::Not(Box::new(Expr::Not(Box::new(Expr::Lt(
                    a.clone(),
                    b.clone()
                )))))),
            )),
            Box::new(Expr::Not(Box::new(Expr::Lt(b, a)))),
        )
    );
}

/// A collection that holds no value, narrowed the way holdings are: the
/// sub-collection key is whatever its author found useful — a validator,
/// a name — which is a key and not a resource. The derivation leaves the
/// clause undenominated, or the first narrowing by a non-resource meets
/// a resource check at routing that has no business reading its key.
#[blueprint]
mod roster {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::Ordered;

    #[state]
    struct Roster {
        /// One weight per seat, filed per validator.
        seats: Ordered<u128>,
    }

    impl Roster {
        /// File a seat for `validator` at `index`.
        pub fn seat(&mut self, validator: Address, index: u128) {
            self.seats.of(validator).at(index).set(0);
        }

        /// Every seat filed for `validator`, up to the cap.
        pub fn page(&mut self, validator: Address) {
            let entries = self.seats.of(validator).range(0, u128::MAX, 8);
            let _ = entries.count();
        }
    }
}

#[test]
fn a_valueless_narrowing_is_a_key_not_a_denomination() {
    let metadata = roster::blueprint().metadata();
    for method in ["seat", "page"] {
        let effects = &metadata.methods[method].effects;
        assert_eq!(effects.len(), 1, "{method} declares one clause");
        let Clause::Effect { denomination, .. } = &effects[0] else {
            panic!("{method} declares an access");
        };
        assert!(denomination.is_none(), "{method} denominates nothing");
    }
}

/// A parameter the body reads as a value at its declared narrow type —
/// carried into an event rather than spent as a key. Both generated
/// prologues narrow the rebuilt address, so this binary compiling is the
/// native half of the pin and the derived kind below is the declared
/// half.
#[blueprint]
mod noted {
    use hyperscale_vm_sdk::ResourceAddr;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// Funds moved, and what they were.
    #[event]
    struct Moved {
        resource: ResourceAddr,
        amount: Quantity,
    }

    #[state]
    struct Noted {}

    impl Noted {
        /// Bank the edge and say what it carried.
        pub fn note(&mut self, funds: Bucket, resource: ResourceAddr) {
            let amount = funds.quantity();
            self.vault(resource).put(funds);
            Moved { resource, amount }.emit();
        }
    }
}

#[test]
fn a_narrow_parameter_declares_its_classes_in_its_kind() {
    use hyperscale_vm_effects::ParamType;

    let metadata = noted::blueprint().metadata();
    assert_eq!(
        metadata.methods["note"].params,
        vec![ParamType::Bucket, ParamType::Resource],
    );
}

/// The whole address family, each type at its own kind. The derivation
/// maps a declared type to the classes it admits, and the generated
/// client widens every narrow one — so this module compiling is the
/// wrapper half of the pin.
#[blueprint]
mod family {
    use hyperscale_vm_sdk::{
        Address, CallTarget, ComponentAddr, PackageAddr, PrincipalAddr, ResourceAddr,
    };

    #[state]
    struct Family {}

    impl Family {
        /// The wide type and the position kind.
        pub fn positions(&mut self, _any: Address, _target: CallTarget) {}

        /// The four single-class kinds.
        pub fn classes(
            &mut self,
            _component: ComponentAddr,
            _package: PackageAddr,
            _principal: PrincipalAddr,
            _resource: ResourceAddr,
        ) {
        }
    }
}

#[test]
fn every_address_type_declares_its_own_kind() {
    use hyperscale_vm_effects::ParamType;

    let metadata = family::blueprint().metadata();
    assert_eq!(
        metadata.methods["positions"].params,
        vec![ParamType::Address, ParamType::CallTarget],
    );
    assert_eq!(
        metadata.methods["classes"].params,
        vec![
            ParamType::Component,
            ParamType::Package,
            ParamType::Principal,
            ParamType::Resource,
        ],
    );
}

/// The holdings interval is the value-bearing collection, and its
/// narrowing is its denomination: one expression names the sub-collection
/// and the resource its entries are instances of.
#[blueprint]
mod shelf {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Ids, NfBucket, Ordered};

    #[state]
    struct Shelf {
        ledger: Ordered<u64>,
    }

    impl Shelf {
        /// Take the named instances out of the caller's holdings.
        pub fn pull(&mut self, resource: Address, ids: Ids) -> NfBucket {
            self.holdings(resource).all().take(ids)
        }

        /// A page whose size is spelled rather than derived: the count
        /// of the ids, as an explicit cap on a chosen interval.
        pub fn window(&mut self, ids: Ids) {
            let entries = self.ledger.range(0, u128::MAX, ids.count());
            let _ = entries.count();
        }

        /// A page sized by two counts at once: `+` over derivable
        /// values is itself derivable.
        pub fn window_both(&mut self, some: Ids, more: Ids) {
            let entries = self.ledger.range(0, u128::MAX, some.count() + more.count());
            let _ = entries.count();
        }

        /// Two moves through one capless interval: the derived cap is
        /// the sum of what each walks.
        pub fn restock(&mut self, out: Ids, back: NfBucket) -> NfBucket {
            let mut holdings = self.holdings(back.resource()).all();
            holdings.file(back);
            holdings.take(out)
        }
    }
}

#[test]
fn a_holdings_interval_is_denominated_by_its_narrowing() {
    use hyperscale_vm_effects::{Expr, TargetExpr};

    let metadata = shelf::blueprint().metadata();
    let effects = &metadata.methods["pull"].effects;
    assert_eq!(effects.len(), 1, "pull declares one clause");
    let Clause::Effect {
        target,
        denomination,
        ..
    } = &effects[0]
    else {
        panic!("pull declares an access");
    };
    // The cap is the count of the ids the take names — derived from the
    // move itself, so the declaration cannot under-state the walk.
    assert!(matches!(
        target,
        TargetExpr::Range { cap, .. } if *cap == Expr::Len(Box::new(Expr::Arg(1)))
    ));
    assert_eq!(denomination.as_deref(), Some(&Expr::Arg(0)));
}

/// `.count()` is the explicit spelling of the same projection the
/// capless interval derives: the length of what an argument names,
/// usable wherever a cap is.
#[test]
fn a_spelled_count_lowers_to_the_length_projection() {
    use hyperscale_vm_effects::{Expr, TargetExpr};

    let metadata = shelf::blueprint().metadata();
    let effects = &metadata.methods["window"].effects;
    let Clause::Effect { target, .. } = &effects[0] else {
        panic!("window declares an access");
    };
    assert!(matches!(
        target,
        TargetExpr::Range { cap, .. } if *cap == Expr::Len(Box::new(Expr::Arg(0)))
    ));
}

/// `+` between two derivable counts lowers to the DSL's own sum, so a
/// cap covering more than one move is spelled with the operator the
/// body would have reached for anyway.
#[test]
fn a_spelled_sum_lowers_to_the_addition() {
    use hyperscale_vm_effects::{Expr, TargetExpr};

    let metadata = shelf::blueprint().metadata();
    let effects = &metadata.methods["window-both"].effects;
    let Clause::Effect { target, .. } = &effects[0] else {
        panic!("window-both declares an access");
    };
    let count = |arg| Box::new(Expr::Len(Box::new(Expr::Arg(arg))));
    assert!(matches!(
        target,
        TargetExpr::Range { cap, .. } if *cap == Expr::Add(count(0), count(1))
    ));
}

/// A body that moves twice through one capless interval declares the
/// sum: each move's count is derived where it lands, and the cap is
/// what the two together walk.
#[test]
fn two_moves_through_one_interval_derive_the_summed_cap() {
    use hyperscale_vm_effects::{Expr, TargetExpr};

    let metadata = shelf::blueprint().metadata();
    let effects = &metadata.methods["restock"].effects;
    let Clause::Effect { target, .. } = &effects[0] else {
        panic!("restock declares an access");
    };
    let filed = Box::new(Expr::Len(Box::new(Expr::IdsOf(Box::new(Expr::Arg(1))))));
    let taken = Box::new(Expr::Len(Box::new(Expr::Arg(0))));
    assert!(matches!(
        target,
        TargetExpr::Range { cap, .. } if *cap == Expr::Add(filed, taken)
    ));
}

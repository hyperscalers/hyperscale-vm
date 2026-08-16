//! The question this spike was opened to answer: can a body written as
//! ordinary Rust yield the declaration, with no separate declaration
//! written by hand?
//!
//! Same bar as `stdlib_parity`, one level higher up. There the declarations
//! were written against the builder API and compared to the authored
//! fixtures. Here nobody writes a declaration at all — the contract below
//! is a contract, and `#[blueprint]` derives the metadata from its body.
//! The comparison is still whole-structure equality against the authored
//! form.
//!
//! Only the account is left to compare. amm and book are traced by their
//! own fixtures now, so a comparison against them would be a thing
//! compared to itself; what guards those is a committed snapshot of what
//! the derivation produces, in `crates/fixtures`.

// The contracts below are read by `#[blueprint]`, never called: what these
// tests exercise is the metadata derived from the bodies, and the derivation
// runs at expansion time. In a real contract crate the module is public and
// its methods are the package's exported surface, so nothing is dead there —
// the appearance is an artifact of a contract living inside a test binary.
#![allow(dead_code)]

use hyperscale_vm_effects::{PackageMetadata, Totality};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_stdlib::account as account_package;

// The account is the one package still authored twice: its own guest is
// hand-written, so a derived module beside it is what says the two agree.
// Read rather than copied, so what this compares is the artifact's own
// module and not a second one that resembles it.
#[path = "../../../guests/derived-account/src/lib.rs"]
mod derived_account;

use derived_account::account;

/// Compare everything a body determines — the ABI binding included.
///
/// The binding used to be excluded, on the ground that a macro never sees
/// the component's exported parameter list. It sees it now: the list *is*
/// the binding, decided by which values the emitted body could not
/// compute, so comparing it is the strongest statement this test can make
/// about the derivation.
///
/// `skip` names the methods whose authored artifact is a hand-written
/// guest making a choice a body-derived one does not. There is exactly
/// one: the account's `deposit` declares a claims-cell movement its own
/// guest never performs, so its binding carries no handle for a clause a
/// derived guest opens. The two converge where the account's artifact
/// itself becomes derived.
fn assert_derived(
    traced: &PackageMetadata,
    authored: &PackageMetadata,
    package: &str,
    skip: &[&str],
) {
    assert_eq!(
        traced.methods.keys().collect::<Vec<_>>(),
        authored.methods.keys().collect::<Vec<_>>(),
        "{package}: the method sets differ"
    );
    for (name, signature) in &authored.methods {
        let got = &traced.methods[name];
        assert_eq!(got.params, signature.params, "{package}::{name} params");
        assert_eq!(got.outputs, signature.outputs, "{package}::{name} outputs");
        assert_eq!(got.effects, signature.effects, "{package}::{name} effects");
        assert_eq!(got.calls, signature.calls, "{package}::{name} calls");
        assert_eq!(
            got.accessibility, signature.accessibility,
            "{package}::{name} accessibility"
        );
        assert_eq!(got.mints, signature.mints, "{package}::{name} mints");
        assert_eq!(
            got.totality, signature.totality,
            "{package}::{name} totality"
        );
        if !skip.contains(&name.as_str()) {
            assert_eq!(got.abi, signature.abi, "{package}::{name} abi");
        }
    }
    assert_eq!(traced.errors, authored.errors, "{package}: error table");
}

#[test]
fn the_account_body_derives_its_authored_signature() {
    // The account's traceable surface: the holdings pair and the custody
    // gate stay authored-only, because the blueprint vocabulary has no
    // material-keyed range, no id-set output, and no gate-owned read —
    // the inference backend is a later phase, and these are its first
    // customers.
    let mut authored = account_package::metadata();
    for gap in ["deposit-nf", "withdraw-nf", "present-badge"] {
        authored.methods.remove(gap);
    }
    // The account's totality marks are the artifact's, and `deposit`'s
    // `Total` is one the publish-time checker grants rather than a body
    // yields; the derivation claims the weakest mark the export type
    // supports and leaves the grant where it is made.
    authored
        .methods
        .get_mut("deposit")
        .expect("declared")
        .totality = Totality::Infallible;
    assert_derived(
        &account::blueprint().metadata(),
        &authored,
        "account",
        &["deposit"],
    );
}

/// Control-flow spellings of one access set, each beside its straight-line
/// equivalent. A conditional access is declared on every arm, so whichever
/// spelling the author reaches for, the declaration is the same superset.
#[blueprint]
mod shapes {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Keyed};

    #[state]
    struct Shapes {
        #[role(1)]
        vaults: Keyed<Amount>,
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
            for id in ids.len()..1 {
                vault.add(u128::from(id as u64));
            }
        }

        #[allow(clippy::needless_pass_by_value)] // a contract consumes its arguments
        pub fn once(&mut self, a: Address, _ids: Vec<u8>) {
            let mut vault = self.vaults.at(a);
            vault.add(0);
        }

        pub fn branched(&mut self, flag: u64, a: Address, b: Address) {
            match flag {
                0 => self.vaults.at(a).add(0),
                _ => self.vaults.at(b).add(0),
            }
        }

        pub fn straight(&mut self, _flag: u64, a: Address, b: Address) {
            self.vaults.at(a).add(0);
            self.vaults.at(b).add(0);
        }

        pub fn asserted(&mut self, a: Address) {
            assert_eq!(self.vaults.at(a).get(), 0);
        }

        #[allow(clippy::equatable_if_let)] // the spelling under test is the if-let itself
        pub fn scrutinised(&mut self, a: Address) {
            if let 0 = self.vaults.at(a).get() {}
        }

        pub fn read(&mut self, a: Address) {
            let _ = self.vaults.at(a).get();
        }

        pub fn guarded(&mut self, flag: u64, a: Address) {
            let 0 = flag else {
                self.vaults.at(a).add(0);
                return;
            };
        }

        pub fn plain(&mut self, _flag: u64, a: Address) {
            self.vaults.at(a).add(0);
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
    use hyperscale_vm_sdk::state::{Amount, Cell, Keyed, clock_ms, hash, randomness};

    #[state]
    struct Environment {
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(2)]
        seen: Cell<u64>,
    }

    impl Environment {
        pub fn stamp(&mut self, holder: Address) {
            let digest = hash(&randomness());
            let drawn = u128::from(digest[0]);
            self.vaults.at(holder).add(drawn);
            self.seen.set(clock_ms());
        }

        pub fn plain(&mut self, holder: Address) {
            self.vaults.at(holder).add(0);
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

//! The question this spike was opened to answer: can a body written as
//! ordinary Rust yield the declaration, with no separate declaration
//! written by hand?
//!
//! Same bar as `stdlib_parity`, one level higher up. There the declarations
//! were written against the builder API and compared to the authored
//! fixtures. Here nobody writes a declaration at all — the contracts below
//! are contracts, and `#[blueprint]` derives the metadata from their
//! bodies. The comparison is still whole-structure equality against
//! `vm-effects::stdlib`.
//!
//! Everything that survives is therefore true of the derived form too: the
//! fixtures are routed under test elsewhere in the workspace, and these
//! packages are byte-identical to them.

// The contracts below are read by `#[blueprint]`, never called: what these
// tests exercise is the metadata derived from the bodies, and the derivation
// runs at expansion time. In a real contract crate the module is public and
// its methods are the package's exported surface, so nothing is dead there —
// the appearance is an artifact of a contract living inside a test binary.
#![allow(dead_code)]
// `&mut self` is the contract's own statement that a method mutates
// component state. That the host-side stub handles in `sdk::state` happen to
// take `&self` is an artifact of their being unimplemented off-guest, not a
// reason to narrow a contract's signature.
#![allow(clippy::needless_pass_by_ref_mut)]

use hyperscale_vm_effects::PackageMetadata;
use hyperscale_vm_effects::stdlib::{account_metadata, amm_metadata, book_metadata};
use hyperscale_vm_sdk::blueprint;

#[blueprint]
mod account {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Cell, Keyed, RoleSet};

    #[state]
    struct Account {
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(2)]
        claims: Keyed<Amount>,
        #[role(9)]
        auth: Cell<u64>,
    }

    impl Account {
        /// Reserve `amount` on the caller's vault for `resource`.
        pub fn withdraw(&mut self, resource: Address, amount: u128) -> Bucket {
            self.vaults.at(resource).reserve(amount)
        }

        /// Credit the vault and the guaranteed-delivery cell beside it.
        pub fn deposit(&mut self, funds: Bucket) {
            self.vaults.at(funds.resource()).add(funds.amount());
            self.claims.at(funds.resource()).add(0);
        }

        /// The sign-in's whole body is its gate's read: the cell the
        /// account's stored rule lives in.
        pub fn authorize(&mut self) {
            let _ = self.auth.get();
        }

        /// Create the stored-authority cell; an existing one is the
        /// body's refusal.
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn securify(&mut self, roles: RoleSet, delay_ms: u64) {
            let _ = (roles, delay_ms);
            self.auth.set(0);
        }

        /// Append a pending replacement, maturing after the stored
        /// delay.
        #[allow(clippy::needless_pass_by_value)] // the contract consumes the roles it stores
        pub fn propose(&mut self, roles: RoleSet, delay_ms: u64) {
            let _ = (roles, delay_ms);
            self.auth.set(0);
        }

        /// Drop an unmatured proposal.
        pub fn cancel(&mut self) {
            self.auth.set(0);
        }

        /// Promote the pending proposal now.
        pub fn confirm(&mut self) {
            self.auth.set(0);
        }
    }
}

#[blueprint]
mod amm {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked};

    struct Settings {
        x: Address,
        y: Address,
        fee_bps: u64,
    }

    #[state]
    struct Amm {
        #[role(3)]
        config: Locked<Settings>,
        #[role(1)]
        vaults: Keyed<Amount>,
    }

    impl Amm {
        /// Swap `input` against the pool, returning the bought side.
        pub fn swap(&mut self, input: Bucket, min_out: u128) -> Bucket {
            // Pins the whole configuration record: the fee is read from it,
            // so the swap wants it stable, not merely consulted.
            let settings = self.config.locked();
            let mut sold = self.vaults.at(settings.x);
            let mut bought = self.vaults.at(settings.y);

            let x = sold.get();
            let y = bought.get();
            let dx = input.amount() * u128::from(10_000 - settings.fee_bps) / 10_000;
            let out = y * dx / (x + dx);
            assert!(out >= min_out, "output below the declared floor");

            sold.set(x + input.amount());
            bought.set(y - out);
            Bucket::of(settings.y, out)
        }
    }
}

#[blueprint]
mod book {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Amount, Bucket, Keyed, Locked, Ordered, fresh_id, pack};

    struct Pair {
        base: Address,
        quote: Address,
    }

    #[state]
    struct Book {
        #[role(4)]
        asks: Ordered<u128>,
        #[role(1)]
        vaults: Keyed<Amount>,
        #[role(3)]
        config: Locked<Pair>,
    }

    impl Book {
        /// Insert an ask at `price`, escrowing the maker's funds.
        #[name("place-ask")]
        pub fn place_ask(&mut self, price: u64, funds: Bucket) {
            // Price over a fresh sequence id: unique without reading the
            // book, which is what lets the entry key be declared.
            self.asks.at(pack(price, fresh_id())).set(funds.amount());
            self.vaults.at(funds.resource()).add(funds.amount());
        }

        /// Buy base within the declared price interval, best price first.
        #[name("fill-asks")]
        pub fn fill_asks(&mut self, from: u64, to: u64, payment: Bucket) -> (Bucket, Bucket) {
            // The whole tiebreaker span at each end, so the interval covers
            // every sequence at the boundary prices.
            let mut asks = self.asks.range(pack(from, 0), pack(to, u64::MAX), 64);
            let mut bought = 0;
            let mut spent = 0;

            let mut index = 0;
            while index < asks.count() {
                let size = asks.entry(index);
                bought += size;
                spent += size;
                asks.remove(index);
                index += 1;
            }

            // Note the config fields are read without pinning the leaf:
            // configuration is locked state, consultable without a claim.
            self.vaults.at(self.config.base).sub(bought);
            self.vaults.at(payment.resource()).add(spent);

            (
                Bucket::of(self.config.base, bought),
                Bucket::of(payment.resource(), payment.amount() - spent),
            )
        }
    }
}

/// Compare everything a body determines.
///
/// The ABI binding is deliberately excluded: a macro sees the author's
/// Rust method and the handles its body opens, never the component's
/// exported parameter list, which is authored beside the WIT. What
/// validates the binding is the publish check, against the export type in
/// the artifact itself.
fn assert_derived(traced: &PackageMetadata, authored: &PackageMetadata, package: &str) {
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
    }
}

#[test]
fn the_account_body_derives_its_authored_signature() {
    // The account's traceable surface: the holdings pair and the custody
    // gate stay authored-only, because the blueprint vocabulary has no
    // material-keyed range, no id-set output, and no gate-owned read —
    // the inference backend is a later phase, and these are its first
    // customers.
    let mut authored = account_metadata();
    for gap in ["deposit-nf", "withdraw-nf", "present-badge"] {
        authored.methods.remove(gap);
    }
    assert_derived(&account::blueprint().metadata(), &authored, "account");
}

#[test]
fn the_pool_body_derives_its_authored_signature() {
    assert_derived(&amm::blueprint().metadata(), &amm_metadata(), "amm");
}

#[test]
fn the_book_body_derives_its_authored_signature() {
    assert_derived(&book::blueprint().metadata(), &book_metadata(), "book");
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

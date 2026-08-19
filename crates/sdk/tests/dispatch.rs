//! The native half of what `#[blueprint]` emits.
//!
//! One package, called through the dispatch the macro generates rather
//! than through the component it also generates — so what is under test
//! is the binding walk, the body it wraps, and how each of the three ways
//! an invocation can end comes back.

use std::sync::Arc;

use hyperscale_vm_effects::{Declaration, Hash32, Hasher, SlotId, TestHasher, Value, child_key};
use hyperscale_vm_kernel::{Capability, EnvInputs, Held, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::host::{CellKind, GuestArg, Invoked};
use hyperscale_vm_types::{
    ABSENT_REP, AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode,
    Presence, SubstateKey, TxHash, encode_amount,
};

const OWNER: Address = Address::new([0x21; 31], AddressClass::Component);
const RESOURCE: Address = Address::new([0xE1; 31], AddressClass::Resource);

#[blueprint]
mod till {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Quantity};

    /// What a withdrawal declines with when the till is short.
    #[error]
    enum Error {
        Short,
    }

    #[state]
    struct Till {}

    impl Till {
        /// Credit the vault the arriving edge belongs in.
        pub fn deposit(&mut self, funds: Bucket, resource: Address) {
            self.vault(resource).put(funds);
        }

        /// Hand back `amount`, declining a till that cannot cover it.
        pub fn withdraw(&mut self, resource: Address, amount: Quantity) -> Result<Bucket, Error> {
            let mut vault = self.vault(resource);
            if vault.balance() < amount {
                return Err(Error::Short);
            }
            Ok(vault.take(amount))
        }

        /// Read the vault and do nothing with the figure but check it.
        pub fn weigh(&mut self, resource: Address) {
            assert!(self.vault(resource).balance() >= Quantity::ZERO);
        }

        /// Read the vault and insist on something it will not be.
        pub fn insist(&mut self, resource: Address) {
            assert_eq!(
                self.vault(resource).balance(),
                Quantity::from_subunits(u128::MAX),
                "the till is not full"
            );
        }
    }
}

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

fn vault() -> SubstateKey {
    child_key(
        &TestHasher,
        OWNER,
        SlotId(1),
        &[Value::Address(RESOURCE).canonical_bytes()],
    )
}

/// A session holding the till's vault at `mode`, with `funded` in it.
fn session(mode: Mode, funded: u128) -> KernelSession {
    let mut store = MemoryStore::new();
    if funded > 0 {
        store
            .write(vault(), encode_amount(funded).to_vec())
            .expect("the store takes a vault cell");
    }

    let mut declared = EffectSet::new();
    declared
        .insert(Effect {
            target: EffectTarget::Point(vault()),
            mode,
        })
        .expect("the effect set takes it");
    // The one cell these bodies move value through, so it says what it
    // holds — a cell that said nothing would grant no movement.
    let declaration = Declaration::from_set(declared).denominated(|_| Some(RESOURCE));
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declaration,
        TxHash(Hash32([4; 32])),
        EnvInputs {
            clock_ms: 1_000,
            randomness: [5; 32],
        },
        hash,
    )
    .expect("the declaration materializes")
}

/// A body whose branch the declaration can read, so each arm declares
/// what it touches and the export takes the verdict beside the handles.
#[blueprint]
mod switch {
    use hyperscale_vm_sdk::state::{Cell, Quantity};

    #[state]
    struct Switch {
        left: Cell<Quantity>,
        right: Cell<Quantity>,
    }

    impl Switch {
        pub fn bump(&mut self, to_left: u64) {
            if to_left == 1 {
                self.left.set(self.left.get());
            } else {
                self.right.set(self.right.get());
            }
        }
    }
}

/// A session over two write cells, which is what a branch over two
/// leaves declares when both arms are materialized.
fn two_cells() -> KernelSession {
    let mut declared = EffectSet::new();
    for slot in [16u16, 17] {
        declared
            .insert(Effect {
                target: EffectTarget::Point(child_key(&TestHasher, OWNER, SlotId(slot), &[])),
                mode: Mode::Write {
                    requires: Presence::Either,
                },
            })
            .expect("the effect set takes it");
    }
    // Nothing here holds value: these are the cells a body writes as
    // bytes, which is what a declaration saying nothing means — one
    // answer per clause, all of them silent.
    KernelSession::materialize(
        OverlayStore::new(Arc::new(MemoryStore::new())),
        &Declaration::from_set(declared),
        TxHash(Hash32([4; 32])),
        EnvInputs {
            clock_ms: 1_000,
            randomness: [5; 32],
        },
        hash,
    )
    .expect("the declaration materializes")
}

/// The guest branches on the declaration's own verdict, so what it
/// touches and what was declared cannot disagree — and where they would,
/// the handle it reaches for was never materialized and says so.
#[test]
fn a_body_branches_on_the_verdict_it_was_handed() {
    // The verdict says the first arm, and the second arm's handle is the
    // one no clause backed.
    let (session, invoked) = switch::invoke(
        "bump",
        two_cells(),
        &[
            GuestArg::Handle {
                rep: 0,
                kind: CellKind::Write,
            },
            GuestArg::Handle {
                rep: ABSENT_REP,
                kind: CellKind::Write,
            },
            GuestArg::Bool(true),
        ],
    );
    assert!(matches!(invoked, Invoked::Produced(ref edges) if edges.is_empty()));
    session
        .finish(None, 0)
        .expect("nothing outside the declared set was touched");

    // Handed the other verdict, it reaches the other handle — and the
    // one that is absent this time is the first.
    let (session, invoked) = switch::invoke(
        "bump",
        two_cells(),
        &[
            GuestArg::Handle {
                rep: ABSENT_REP,
                kind: CellKind::Write,
            },
            GuestArg::Handle {
                rep: 1,
                kind: CellKind::Write,
            },
            GuestArg::Bool(false),
        ],
    );
    assert!(matches!(invoked, Invoked::Produced(ref edges) if edges.is_empty()));
    session
        .finish(None, 0)
        .expect("nothing outside the declared set was touched");
}

/// A verdict that disagrees with what was materialized is a body whose
/// control flow diverged from its declaration. Nothing was put at the
/// rep on purpose, and reaching it aborts by that name rather than as a
/// handle nobody lowered.
#[test]
fn a_verdict_the_declaration_did_not_reach_aborts_by_name() {
    let (_, invoked) = switch::invoke(
        "bump",
        two_cells(),
        &[
            GuestArg::Handle {
                rep: ABSENT_REP,
                kind: CellKind::Write,
            },
            GuestArg::Handle {
                rep: 1,
                kind: CellKind::Write,
            },
            GuestArg::Bool(true),
        ],
    );
    assert_eq!(invoked, Invoked::Aborted(AbortReason::UndeclaredBranch));
}

/// The one capability the declaration materialized, as the walk passes
/// it: rep zero, at the kind the clause's mode names.
const fn cell(kind: CellKind) -> GuestArg<'static> {
    GuestArg::Handle { rep: 0, kind }
}

/// A `u128` as it crosses: the cell representation the vocabulary
/// decodes, which is what anything wider than a `u64` arrives as.
const fn wide(value: u128) -> [u8; 16] {
    value.to_le_bytes()
}

/// A credit lands where the clause named, and the body says nothing
/// about the key: the kernel evaluated it, so the export never sees it.
#[test]
fn an_edge_the_body_credits_lands_in_the_declared_cell() {
    let mut session = session(Mode::Delta, 0);
    let funds = session.open_bucket(Held::Amount(70), RESOURCE);

    let (session, invoked) = till::invoke(
        "deposit",
        session,
        &[cell(CellKind::Delta), GuestArg::Bucket(funds)],
    );

    assert!(matches!(invoked, Invoked::Produced(ref edges) if edges.is_empty()));
    let (receipt, _) = session
        .finish(None, 0)
        .expect("nothing outside the declared set was touched");
    // A commutative credit is a movement rather than an absolute: what
    // the receipt carries is what to add, not what the cell became.
    assert_eq!(
        receipt.delta.movements.get(&vault()).map(|m| m.credit),
        Some(70)
    );
}

#[test]
fn an_edge_the_body_produces_comes_back_as_the_kernels_own() {
    let session = session(
        Mode::Write {
            requires: Presence::Either,
        },
        100,
    );

    let (mut session, invoked) = till::invoke(
        "withdraw",
        session,
        &[cell(CellKind::Amount), GuestArg::Bytes(&wide(30))],
    );

    let Invoked::Produced(edges) = invoked else {
        panic!("a covered withdrawal produces its edge");
    };
    assert_eq!(edges.len(), 1, "one declared output, one edge");
    assert_eq!(
        session
            .take_bucket(edges[0])
            .expect("the edge is held")
            .quantity(),
        30
    );
}

#[test]
fn the_error_arm_declines_rather_than_trapping() {
    let session = session(
        Mode::Write {
            requires: Presence::Either,
        },
        10,
    );

    let (_, invoked) = till::invoke(
        "withdraw",
        session,
        &[cell(CellKind::Amount), GuestArg::Bytes(&wide(30))],
    );

    assert_eq!(invoked, Invoked::Declined(0), "the package's own code");
}

#[test]
fn a_body_that_panics_aborts_as_the_trap_it_would_be() {
    let session = session(Mode::Read, 10);

    // A read of a vault is a read of a balance, so the handle is the one
    // value comes through rather than the one bytes do — and what fails
    // is the body's own assertion about the figure it read.
    let (_, invoked) = till::invoke("insist", session, &[cell(CellKind::AmountRead)]);

    assert_eq!(invoked, Invoked::Aborted(AbortReason::Unreachable));
}

/// Reading a balance takes no exclusivity, and gives back no bytes.
///
/// A curve is a function of its reserves, so asking is the one thing a
/// body does with a balance that changes nothing — and a method that
/// only asks should contend with nobody. What it must not get is the
/// byte handle: a vault is sixteen bytes, and a body that could read
/// them would be reading a balance as bytes, which is what the two
/// value types exist to stop.
#[test]
fn a_read_of_a_vault_answers_a_quantity_and_not_bytes() {
    // A fresh read, which excludes no other reader.
    let held = session(Mode::Read, 10);
    assert!(matches!(
        held.capabilities().first(),
        Some(Capability::AmountRead(_))
    ));

    // The body reads the balance through it and gets the figure.
    let (_, invoked) = till::invoke("weigh", held, &[cell(CellKind::AmountRead)]);
    assert_eq!(invoked, Invoked::Produced(vec![]));

    // And the byte handle is not what a vault read materialises, so an
    // export borrowing one is handed a mode it never declared.
    let (_, invoked) = till::invoke("weigh", session(Mode::Read, 10), &[cell(CellKind::Read)]);
    assert_eq!(invoked, Invoked::Aborted(AbortReason::AbiViolation));
}

/// A handle materialized at one mode cannot be read as another: the
/// canonical ABI's mode escape, reached here by the same route.
#[test]
fn a_capability_at_the_wrong_mode_is_a_violation() {
    let session = session(
        Mode::Write {
            requires: Presence::Either,
        },
        10,
    );

    // `withdraw` reads and writes, so its clause materialized exclusive;
    // a rep arriving as a fresh read is a mode the export never declared.
    let (_, invoked) = till::invoke(
        "withdraw",
        session,
        &[cell(CellKind::Read), GuestArg::Bytes(&wide(30))],
    );

    assert_eq!(invoked, Invoked::Aborted(AbortReason::AbiViolation));
}

#[test]
fn an_export_the_package_does_not_answer_is_a_violation() {
    let session = session(Mode::Read, 0);

    let (_, invoked) = till::invoke("nonesuch", session, &[]);

    assert_eq!(invoked, Invoked::Aborted(AbortReason::AbiViolation));
}

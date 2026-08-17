//! The native half of what `#[blueprint]` emits.
//!
//! One package, called through the dispatch the macro generates rather
//! than through the component it also generates — so what is under test
//! is the binding walk, the body it wraps, and how each of the three ways
//! an invocation can end comes back.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Hash32, Hasher, Mode, RoleId,
    SubstateKey, TestHasher, Value, child_key,
};
use hyperscale_vm_kernel::{
    AbortReason, EnvInputs, Held, KernelSession, MemoryStore, Outcome, OverlayStore, TxHash,
    WorkingStore, encode_amount,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::host::{CellKind, GuestArg, Invoked};

const OWNER: Address = Address::new([0x21; 31], AddressClass::Component);
const RESOURCE: Address = Address::new([0xE1; 31], AddressClass::Resource);

#[blueprint]
mod till {
    use hyperscale_vm_sdk::Address;
    use hyperscale_vm_sdk::state::{Bucket, Keyed, Quantity};

    /// What a withdrawal declines with when the till is short.
    #[error]
    enum Error {
        Short,
    }

    #[state]
    struct Till {
        #[role(1)]
        vaults: Keyed<Quantity>,
    }

    impl Till {
        /// Credit the vault the arriving edge belongs in.
        pub fn deposit(&mut self, funds: Bucket, resource: Address) {
            self.vaults.at(resource).put(funds);
        }

        /// Hand back `amount`, declining a till that cannot cover it.
        pub fn withdraw(&mut self, resource: Address, amount: Quantity) -> Result<Bucket, Error> {
            let mut vault = self.vaults.at(resource);
            if vault.get() < amount {
                return Err(Error::Short);
            }
            Ok(vault.take(amount))
        }

        /// Read the vault and insist on something it will not be.
        pub fn insist(&mut self, resource: Address) {
            assert_eq!(
                self.vaults.at(resource).get(),
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
        RoleId(1),
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
    store.clear_log();

    let mut declared = EffectSet::new();
    declared
        .insert(Effect {
            target: EffectTarget::Point(vault()),
            mode,
        })
        .expect("the effect set takes it");
    let ordered: Vec<_> = declared.iter().collect();
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &declared,
        &ordered,
        TxHash(Hash32([4; 32])),
        EnvInputs {
            clock_ms: 1_000,
            randomness: [5; 32],
        },
        hash,
    )
    .expect("the declaration materializes")
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
    let funds = session.open_bucket(Held::Amount(70));

    let (session, invoked) = till::invoke(
        "deposit",
        session,
        &[cell(CellKind::Delta), GuestArg::Bucket(funds)],
    );

    assert!(matches!(invoked, Invoked::Produced(ref edges) if edges.is_empty()));
    let (receipt, _) = session
        .finish(Outcome::Completed { value: None }, 0)
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
    let session = session(Mode::Write, 100);

    let (mut session, invoked) = till::invoke(
        "withdraw",
        session,
        &[cell(CellKind::Write), GuestArg::Bytes(&wide(30))],
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
    let session = session(Mode::Write, 10);

    let (_, invoked) = till::invoke(
        "withdraw",
        session,
        &[cell(CellKind::Write), GuestArg::Bytes(&wide(30))],
    );

    assert_eq!(invoked, Invoked::Declined(0), "the package's own code");
}

#[test]
fn a_body_that_panics_aborts_as_the_trap_it_would_be() {
    let session = session(Mode::Read, 10);

    let (_, invoked) = till::invoke("insist", session, &[cell(CellKind::Read)]);

    assert_eq!(invoked, Invoked::Aborted(AbortReason::Unreachable));
}

/// A handle materialized at one mode cannot be read as another: the
/// canonical ABI's mode escape, reached here by the same route.
#[test]
fn a_capability_at_the_wrong_mode_is_a_violation() {
    let session = session(Mode::Write, 10);

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

//! The kernel's own arm of direction narrowing: a hold that gave up a
//! direction refuses the movement it gave up.
//!
//! Admission judges a declared direction and the composer never emits
//! the other one, so this backstop is unreachable through the ordinary
//! path — which is exactly why it is pinned: if admission ever
//! mis-narrows, the kernel is what stands between a credit-only
//! declaration and a debit.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Declaration, DeclaredAccess, Hash32, Hasher, SlotId, TestHasher, Value, child_key,
};
use hyperscale_vm_kernel::{EnvInputs, KernelSession, MemoryStore, OverlayStore};
use hyperscale_vm_types::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, ResourceAddr, SubstateKey,
    TxHash, encode_amount,
};

const OWNER: Address = Address::new([0x61; 31], AddressClass::Component);
const UNIT: ResourceAddr = ResourceAddr::new([0xC1; 31]);

fn cell() -> SubstateKey {
    child_key(
        &TestHasher,
        OWNER,
        SlotId(1),
        &[Value::Address(UNIT.address()).canonical_bytes()],
    )
}

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A session over one funded cell held under `mode`.
fn session(mode: Mode) -> KernelSession {
    let ordered = vec![DeclaredAccess {
        reach: None,
        effect: Effect {
            target: EffectTarget::Point(cell()),
            mode,
        },
        holds: Some(UNIT),
        clause: None,
    }];
    let mut set = EffectSet::new();
    for declared in &ordered {
        set.insert(declared.effect).expect("one clause folds");
    }
    let mut store = MemoryStore::new();
    store.write(cell(), encode_amount(100).to_vec());
    KernelSession::materialize(
        OverlayStore::new(Arc::new(store)),
        &Declaration {
            set,
            ordered,
            ..Declaration::default()
        },
        TxHash(Hash32([9; 32])),
        EnvInputs::unsealed(0),
        hash,
    )
    .expect("the declaration materializes")
}

/// A credit-only delta refuses the debit, and its handle says which
/// direction it kept.
#[test]
fn a_credit_only_delta_refuses_the_debit() {
    let mut session = session(Mode::Delta { moves: Moves::In });
    let refused = session
        .cell_take(0, 0, 10)
        .expect_err("the declaration kept only the credit");
    let said = refused.to_string();
    assert!(
        said.contains("credit") && said.contains("does not grant"),
        "the refusal says which direction the hold kept: {said}"
    );
}

/// A debit-only delta refuses the credit, symmetrically.
#[test]
fn a_debit_only_delta_refuses_the_credit() {
    let mut session = session(Mode::Delta { moves: Moves::Out });
    let funds = session
        .cell_take(0, 0, 10)
        .expect("the kept direction answers");
    let refused = session
        .cell_put(0, 0, funds)
        .expect_err("the declaration kept only the debit");
    let said = refused.to_string();
    assert!(
        said.contains("debit") && said.contains("does not grant"),
        "the refusal says which direction the hold kept: {said}"
    );
}

/// The exclusive hold narrows the same way, in its own words: an
/// exclusive value hold that kept one direction describes itself as a
/// cell that may only be credited, or only debited.
#[test]
fn an_exclusive_hold_refuses_the_direction_it_gave_up() {
    let mut credit_only = session(Mode::Write { moves: Moves::In });
    let refused = credit_only
        .cell_take(0, 0, 10)
        .expect_err("the exclusive hold kept only the credit");
    assert!(
        refused.to_string().contains("credited"),
        "the handle says what it holds: {refused}"
    );

    let mut debit_only = session(Mode::Write { moves: Moves::Out });
    let funds = debit_only
        .cell_take(0, 0, 10)
        .expect("the kept direction answers");
    let refused = debit_only
        .cell_put(0, 0, funds)
        .expect_err("the exclusive hold kept only the debit");
    assert!(
        refused.to_string().contains("debited"),
        "the handle says what it holds: {refused}"
    );
}

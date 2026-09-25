//! A vault deposit is the kernel's: the walk credits the bucket into the
//! site the declaration bound and never invokes the package's export, so
//! the credit is the same whatever the package's code would have done.

use std::sync::Arc;

use hyperscale_vm_effects::{
    Body, CallArg, Declaration, EdgeContent, Hash32, Hasher, NodeCall, PackageHash, SlotId,
    TestHasher, child_key,
};
use hyperscale_vm_embed::GuestArg;
use hyperscale_vm_kernel::{
    Baseline, BatchTx, EnvInputs, ExecutionMode, GuestBackend, GuestCall, InvokeResult, Invoked,
    KernelSession, ManifestWalk, MemoryStore, Receipt, execute_batch,
};
use hyperscale_vm_types::{
    AbortReason, Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, Moves, Outcome,
    ResourceAddr, SubstateKey, TxHash, encode_amount,
};

const RESOURCE: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const PAYER: u8 = 0xA1;
const PAYEE: u8 = 0xC1;

fn test_hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

const fn owner(byte: u8) -> Address {
    Address::new([byte; 31], AddressClass::Component)
}

fn cell(byte: u8) -> SubstateKey {
    child_key(&TestHasher, owner(byte), SlotId(1), &[])
}

/// A backend whose only code is the payer's `take`: every other export
/// panics, so a deposit reaching it fails the test rather than the
/// transaction.
struct TakeOnly;

impl GuestBackend for TakeOnly {
    fn invoke(&self, mut session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
        assert_eq!(call.export, "take", "the walk invoked {}", call.export);
        let Some(GuestArg::Site { site }) = call.args.first() else {
            panic!("the payer is lent its reserve");
        };
        let edge = session.reserve_take(*site, 0).unwrap();
        InvokeResult {
            session,
            fuel: 0,
            result: Invoked::Produced {
                edges: vec![edge],
                answer: None,
            },
        }
    }
}

fn node(target: u8, export: &str, args: Vec<CallArg>, outputs: usize, body: Body) -> NodeCall {
    NodeCall {
        package: PackageHash(Hash32([0xAB; 32])),
        target: owner(target),
        export: export.into(),
        args,
        edges: Vec::new(),
        outputs: vec![EdgeContent::Fungible; outputs],
        answers: false,
        issues: Vec::new(),
        evidence: Vec::new(),
        requires: Vec::new(),
        body,
    }
}

/// The payer reserves `amount` and a deposit node credits it to the
/// payee, the deposit's arguments being `deposit_args`.
fn transfer(amount: u128, deposit_args: Vec<CallArg>) -> BatchTx {
    let mut set = EffectSet::new();
    set.insert_at_cap(Effect {
        target: EffectTarget::Point(cell(PAYER)),
        mode: Mode::Reserve { amount },
    })
    .unwrap();
    set.insert_at_cap(Effect {
        target: EffectTarget::Point(cell(PAYEE)),
        mode: Mode::Delta { moves: Moves::In },
    })
    .unwrap();
    let declaration = Declaration::from_set(set).denominated(|effect| {
        matches!(effect.mode, Mode::Delta { .. } | Mode::Reserve { .. }).then_some(RESOURCE)
    });
    let rep = |wanted: fn(&Mode) -> bool| {
        let index = declaration
            .ordered
            .iter()
            .position(|access| wanted(&access.effect.mode))
            .unwrap();
        Some(u32::try_from(index).unwrap())
    };
    let reserve = rep(|mode| matches!(mode, Mode::Reserve { .. }));
    let credit = rep(|mode| matches!(mode, Mode::Delta { .. }));
    let deposit_args = deposit_args
        .into_iter()
        .map(|arg| match arg {
            CallArg::Site { .. } => CallArg::Site {
                entries: vec![credit],
            },
            other => other,
        })
        .collect();
    BatchTx::new(
        TxHash(Hash32([0x11; 32])),
        declaration,
        EnvInputs::unsealed(1_000),
    )
    .with_calls(vec![
        node(
            PAYER,
            "take",
            vec![CallArg::Site {
                entries: vec![reserve],
            }],
            1,
            Body::Guest,
        ),
        node(PAYEE, "deposit", deposit_args, 0, Body::Deposit),
    ])
}

fn run(entry: BatchTx) -> Receipt {
    let mut store = MemoryStore::new();
    store.write(cell(PAYER), encode_amount(500).to_vec());
    let tx = entry.tx;
    let outcome = execute_batch(
        Arc::new(store) as Arc<dyn Baseline>,
        &[entry],
        &ManifestWalk { backend: &TakeOnly },
        test_hash,
        ExecutionMode::Serial,
    )
    .unwrap();
    outcome.receipts[&tx].clone()
}

/// The deposit's binding: its vault site, then the payer's bucket.
fn site_then_bucket() -> Vec<CallArg> {
    vec![
        CallArg::Site {
            entries: Vec::new(),
        },
        CallArg::Bucket {
            source: 0,
            output: 0,
        },
    ]
}

/// The deposit completes and credits the payee without its export being
/// invoked.
#[test]
fn a_deposit_never_invokes_its_body() {
    let receipt = run(transfer(200, site_then_bucket()));
    assert!(
        matches!(receipt.outcome, Outcome::Completed { .. }),
        "{receipt:?}"
    );
    assert_eq!(receipt.delta.movements[&cell(PAYEE)].credit, 200);
}

/// A deposit whose arguments are not one site then one bucket is the
/// batch's defect, refused before anything is credited.
#[test]
fn a_deposit_not_bound_as_one_site_and_one_bucket_is_a_composition_defect() {
    let mut swapped = site_then_bucket();
    swapped.reverse();
    let receipt = run(transfer(200, swapped));
    assert_eq!(
        receipt.outcome,
        Outcome::ProtocolError {
            reason: AbortReason::DepositUnbound
        }
    );
}

//! What a cell holds does not change by being held.
//!
//! A vault is a hash and nothing inverts it, so what a leaf holds is
//! whatever the declaration reaching it says. Nothing relates one
//! method's answer to another's — every publish-side judgment is per
//! signature — and a package that said one resource on the way in and
//! another on the way out would be a converter between any two
//! resources, at par, with no supply moved.
//!
//! What closes it is the key: a value cell is keyed by what it holds, so
//! two names are two cells. A pot filled under one name is not the pot a
//! withdrawal under the other reaches.

use hyperscale_vm_effects::{
    AbiParam, Clause, Expr, MethodSignature, ModeExpr, PackageMetadata, ParamType, SlotId,
    TargetExpr, Totality, Value,
};
use hyperscale_vm_kernel::{GuestArg, Invoked, KernelSession};
use hyperscale_vm_testing::{Chain, Package, account, principal, resource};
use hyperscale_vm_types::{AbortReason, ComponentAddr, PrincipalAddr, ResourceAddr};

const ATTACKER: PrincipalAddr = principal(0x22);
/// What the attacker actually has.
const CHEAP: ResourceAddr = resource(0xC1);
/// What they would walk out with; nobody issues it.
const DEAR: ResourceAddr = resource(0xD1);
/// The package's own first slot — nothing protocol about it.
const POT: SlotId = SlotId(16);

/// The pot holding `held`, keyed by it as every value cell is.
fn pot(held: ResourceAddr) -> TargetExpr {
    TargetExpr::Point(Expr::ChildKey {
        owner: Box::new(Expr::SelfAddr),
        slot: POT,
        material: vec![Expr::Literal(Value::Address(held.address()))],
    })
}

fn holding(held: ResourceAddr, mode: ModeExpr) -> Clause {
    Clause::Effect {
        guard: None,
        target: pot(held),
        mode,
        denomination: Some(Box::new(Expr::Literal(Value::Address(held.address())))),
    }
}

/// `fill` takes the cheap resource in; `drain` hands the dear one out.
/// Both are well formed, and they are not the same cell.
fn mixer() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "fill".into(),
        MethodSignature {
            totality: Totality::Infallible,
            params: vec![ParamType::Bucket],
            abi: vec![AbiParam::Handle { clause: 0, site: 0 }, AbiParam::Bucket(0)],
            effects: vec![holding(CHEAP, ModeExpr::Delta)],
            ..MethodSignature::default()
        },
    );
    metadata.methods.insert(
        "drain".into(),
        MethodSignature {
            totality: Totality::Infallible,
            params: vec![ParamType::U64],
            outputs: vec![Expr::Literal(Value::Address(DEAR.address()))],
            abi: vec![
                AbiParam::Handle { clause: 0, site: 0 },
                AbiParam::Derived(Expr::Arg(0)),
            ],
            effects: vec![holding(DEAR, ModeExpr::Write)],
            ..MethodSignature::default()
        },
    );
    metadata
}

fn mixer_body(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    match export {
        "fill" => {
            let [GuestArg::Site { site }, GuestArg::Bucket(funds)] = args else {
                panic!("a handle and an edge: {args:?}");
            };
            match session.cell_put(*site, 0, *funds) {
                Ok(()) => (
                    session,
                    Invoked::Produced {
                        edges: vec![],
                        answer: None,
                    },
                ),
                Err(trap) => (session, Invoked::Aborted(trap.into())),
            }
        }
        "drain" => {
            let [GuestArg::Site { site }, GuestArg::U64(amount)] = args else {
                panic!("a handle and an amount: {args:?}");
            };
            match session.cell_take(*site, 0, u128::from(*amount)) {
                Ok(bucket) => (
                    session,
                    Invoked::Produced {
                        edges: vec![bucket],
                        answer: None,
                    },
                ),
                Err(trap) => (session, Invoked::Aborted(trap.into())),
            }
        }
        other => panic!("no such export: {other}"),
    }
}

#[test]
fn value_does_not_change_resource_by_crossing_a_cell() {
    let mut chain = Chain::native();
    let package = chain.publish(Package::new(
        mixer(),
        env!("CARGO_MANIFEST_DIR"),
        mixer_body,
    ));
    let mixer: ComponentAddr = chain.instantiate_raw(ATTACKER, package, ());
    chain.credit(ATTACKER, CHEAP, 1_000);

    chain
        .transact(ATTACKER, |b| {
            let attacker = account::authorize(b, ATTACKER)?;
            let funds = account::withdraw(b, attacker, CHEAP, 1_000)?;
            b.call(mixer, "fill", (funds,))?.none()
        })
        .expect_completed();

    // The cheap resource went in. The dear one is another cell, and it
    // is empty, so the debit has nothing to take.
    let outcome = chain.transact(ATTACKER, |b| {
        let funds = b.call(mixer, "drain", (1_000_u64,))?.one()?;
        account::deposit(b, ATTACKER, funds)
    });

    assert_eq!(outcome.aborted(), Some(AbortReason::CellUnderflow));
    assert_eq!(chain.balance(ATTACKER, DEAR), 0);
    assert_eq!(chain.balance(ATTACKER, CHEAP), 0, "the fill stands");
}

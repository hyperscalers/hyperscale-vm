//! A produced edge is the edge its declaration projected: the shape it
//! carries, and for a non-fungible one the ids it names.
//!
//! The declared content is what admission keys the instance cells by,
//! what a consumer binds its parameter against, and what a signed bound
//! is judged in the terms of. The macro couples the mint to the
//! declaration by construction; a hand-written guest is not so held, and
//! this is the walk holding it — both refusals landing where the edge
//! comes back, before anything downstream can file or consume it.

use hyperscale_vm_effects::{
    AbiParam, Expr, Issuance, MethodSignature, PackageMetadata, ResourceKind, Totality, Value,
};
use hyperscale_vm_kernel::{GuestArg, Invoked, KernelSession};
use hyperscale_vm_testing::{Chain, Package, PrincipalAddr, account, principal};
use hyperscale_vm_types::{AbortReason, ComponentAddr, ISSUER_REP};

const MINTER: PrincipalAddr = principal(0x41);

/// The id every declaration below names.
const DECLARED: u64 = 7;

/// The mark the issuer's resource is declared under.
const BADGE: &[u8] = b"badge";

/// One mint method, declaring instance [`DECLARED`] as its output.
fn issuer() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "mint".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Some(Issuance {
                mark: BADGE.to_vec(),
                kind: ResourceKind::NonFungible,
            }),
            abi: vec![AbiParam::Issuer],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(Expr::SelfResource {
                    kind: ResourceKind::NonFungible,
                    material: vec![Expr::Literal(Value::Bytes(BADGE.to_vec()))],
                }),
                ids: Box::new(Expr::List(vec![Expr::Literal(Value::U64(DECLARED))])),
            }],
            ..MethodSignature::default()
        },
    );
    metadata
}

/// One mint method declaring a *fungible* output, over a non-fungible
/// issuance grant.
///
/// A shape publish admits — an output's projection is judged at the
/// resource it names, not against the grant beside it — so the guest is
/// free to hand back a bucket of the other shape entirely.
fn miscast_issuer() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "mint".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Some(Issuance {
                mark: BADGE.to_vec(),
                kind: ResourceKind::NonFungible,
            }),
            abi: vec![AbiParam::Issuer],
            outputs: vec![Expr::SelfResource {
                kind: ResourceKind::NonFungible,
                material: vec![Expr::Literal(Value::Bytes(BADGE.to_vec()))],
            }],
            ..MethodSignature::default()
        },
    );
    metadata
}

/// A body minting exactly `MINTED`, whatever the declaration said.
fn body<const MINTED: u64>(
    export: &str,
    mut session: KernelSession,
    args: &[GuestArg<'_>],
) -> (KernelSession, Invoked) {
    assert_eq!(export, "mint");
    let [GuestArg::Issuer] = args else {
        panic!("the grant alone: {args:?}");
    };
    match session.mint_instances(ISSUER_REP, &[MINTED]) {
        Ok(rep) => (session, Invoked::Produced(vec![rep])),
        Err(trap) => (session, Invoked::Aborted(trap.into())),
    }
}

fn minting<const MINTED: u64>() -> (Chain, ComponentAddr) {
    let mut chain = Chain::native();
    let hash = chain.publish(Package::new(
        issuer(),
        env!("CARGO_MANIFEST_DIR"),
        body::<MINTED>,
    ));
    let instance = chain.instantiate_raw(hash, ());
    (chain, instance)
}

/// The honest body: the minted set is the declared set, and the edge
/// files like any other.
#[test]
fn the_declared_ids_are_the_minted_ids() {
    let (mut chain, instance) = minting::<DECLARED>();
    chain
        .transact(MINTER, |b| {
            let edge = b.call(instance, "mint", ())?.one()?;
            account::deposit_nf(b, MINTER, edge)
        })
        .expect_completed();
}

/// The counterfeit path: declare id 7, mint id 8, and the walk refuses
/// the edge before anything can file it into a holder's holdings.
#[test]
fn a_minted_set_other_than_the_declared_one_is_refused() {
    let (mut chain, instance) = minting::<{ DECLARED + 1 }>();
    let outcome = chain.transact(MINTER, |b| {
        let edge = b.call(instance, "mint", ())?.one()?;
        account::deposit_nf(b, MINTER, edge)
    });
    assert_eq!(outcome.aborted(), Some(AbortReason::WrongMintedIds));
}

/// The other half of the same rule: a declaration projecting a fungible
/// edge, and a body handing back the instances its grant let it mint.
///
/// Nothing downstream would read the bucket as the declaration did — a
/// consumer bound a quantity and would meet an id set — so the walk
/// refuses it where the edge comes back, on the terms a wrong arity has.
#[test]
fn an_edge_of_another_shape_than_the_declaration_is_refused() {
    let mut chain = Chain::native();
    let hash = chain.publish(Package::new(
        miscast_issuer(),
        env!("CARGO_MANIFEST_DIR"),
        body::<DECLARED>,
    ));
    let instance = chain.instantiate_raw(hash, ());
    let outcome = chain.transact(MINTER, |b| {
        let edge = b.call(instance, "mint", ())?.one()?;
        account::deposit(b, MINTER, edge)
    });
    assert_eq!(outcome.aborted(), Some(AbortReason::BadReturnShape));
}

//! A produced non-fungible edge carries the ids its declaration named.
//!
//! The declared ids are what admission keys the instance cells by and
//! what a consumer routes on. The macro couples the mint to the ids by
//! construction; a hand-written guest is not so held, and this is the
//! walk holding it: a body minting any other set is refused where the
//! edge comes back, before anything downstream can file it.

use hyperscale_vm_effects::{
    AbiParam, Expr, Issuance, MethodSignature, PackageMetadata, ResourceKind, Totality, Value,
};
use hyperscale_vm_kernel::{GuestArg, Invoked, KernelSession};
use hyperscale_vm_testing::{Chain, Package, PrincipalAddr, account, principal};
use hyperscale_vm_types::{AbortReason, ComponentAddr, ISSUER_REP};

const MINTER: PrincipalAddr = principal(0x41);

/// The id every declaration below names.
const DECLARED: u64 = 7;

/// One mint method, declaring instance [`DECLARED`] as its output.
fn issuer() -> PackageMetadata {
    let mut metadata = PackageMetadata::default();
    metadata.methods.insert(
        "mint".into(),
        MethodSignature {
            totality: Totality::Infallible,
            issues: Some(Issuance {
                mark: Vec::new(),
                kind: ResourceKind::NonFungible,
            }),
            abi: vec![AbiParam::Issuer],
            outputs: vec![Expr::NfBucket {
                resource: Box::new(Expr::SelfResource {
                    kind: ResourceKind::NonFungible,
                    material: vec![],
                }),
                ids: Box::new(Expr::List(vec![Expr::Literal(Value::U64(DECLARED))])),
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

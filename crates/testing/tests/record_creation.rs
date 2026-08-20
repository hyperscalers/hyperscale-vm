//! An issuer brings its own resources into existence.
//!
//! A record is the issuer's own cell, so writing one is an ordinary
//! declared access, and the `Absent` condition beside the write is the
//! one-way door: a second creation is refused by the shard holding the
//! leaf before any body runs. The cells a creating call writes are held
//! to the protocol's own encoding, byte for byte — a founded resource
//! and a genesis-seeded one have to be the same object.

use hyperscale_vm_effects::{
    Fungibility, ResourceKind, ResourceRecord, TestHasher, instance_data_key, issued_resource,
    resource_record_key,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_testing::{Chain, PrincipalAddr, account, package, principal};
use hyperscale_vm_types::{Outcome, Presence, UnmetCondition};

const FOUNDER: PrincipalAddr = principal(0x31);

#[blueprint]
mod issuer {
    use hyperscale_vm_sdk::state::{NfBucket, mint_nf};

    #[resource(non_fungible)]
    struct OwnerBadge;

    #[resource]
    struct Coupon;

    #[state]
    struct Issuer {}

    impl Issuer {
        /// Bring the badge into existence: its record, and its first
        /// instance, handed back as an edge for the founder to keep.
        pub fn found(&mut self) -> NfBucket {
            self.resource(OwnerBadge).create();
            mint_nf(OwnerBadge, &[0])
        }

        /// Bring the coupon into existence, displayed at six digits.
        pub fn open(&mut self) {
            self.resource(Coupon).create(6);
        }
    }
}

fn founded() -> (Chain, issuer::client::Issuer) {
    let mut chain = Chain::native();
    chain.publish(package!(issuer));
    let instance = chain.instantiate::<issuer::client::Issuer>(());
    (chain, instance)
}

/// Found the pool: create the badge's record, mint instance 0, and file
/// the edge in the founder's own account.
fn found(chain: &mut Chain, instance: issuer::client::Issuer) {
    chain
        .transact(FOUNDER, |b| {
            let badge = instance.found(b)?;
            account::deposit_nf(b, FOUNDER, badge)
        })
        .expect_completed();
}

/// The record a creating call writes is the record the protocol encodes:
/// the same cell, the same bytes, under the issuer at the resource the
/// mark derives.
#[test]
fn a_creating_call_writes_the_canonical_record() {
    let (mut chain, instance) = founded();
    found(&mut chain, instance);

    let badge = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        issuer::OWNER_BADGE,
    );
    assert_eq!(
        chain.cell(resource_record_key(&TestHasher, instance, badge)),
        Some(
            ResourceRecord {
                kind: Fungibility::NonFungible,
            }
            .to_cell()
            .expect("a record encodes")
        ),
    );
}

/// A fungible record carries the divisibility the call stated.
#[test]
fn a_fungible_record_states_its_divisibility() {
    let (mut chain, instance) = founded();
    chain
        .transact(FOUNDER, |b| instance.open(b))
        .expect_completed();

    let coupon = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::Fungible,
        issuer::COUPON,
    );
    assert_eq!(
        chain.cell(resource_record_key(&TestHasher, instance, coupon)),
        Some(
            ResourceRecord {
                kind: Fungibility::Fungible { divisibility: 6 },
            }
            .to_cell()
            .expect("a record encodes")
        ),
    );
}

/// The one-way door: a second creation is refused as the unmet `Absent`
/// condition, judged where the leaf lives, and never reaches a body.
#[test]
fn a_second_creation_is_refused_where_the_leaf_lives() {
    let (mut chain, instance) = founded();
    found(&mut chain, instance);

    let outcome = chain
        .transact(FOUNDER, |b| {
            let badge = instance.found(b)?;
            account::deposit_nf(b, FOUNDER, badge)
        })
        .refused()
        .cloned()
        .expect("the second creation is refused");
    assert!(
        matches!(
            outcome,
            Outcome::ConditionUnmet {
                condition: UnmetCondition::Holds {
                    required: Presence::Absent,
                    ..
                },
            }
        ),
        "refused as the unmet absence, not as a trap: {outcome:?}",
    );
}

/// The mint files the instance's data cell where the instance comes into
/// existence: the presence byte, at the id the mint named, under the
/// issuer — the cell genesis writes for a seated instance.
#[test]
fn a_mint_files_the_instance_cell_at_its_id() {
    let (mut chain, instance) = founded();
    found(&mut chain, instance);

    let badge = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        issuer::OWNER_BADGE,
    );
    assert_eq!(
        chain.cell(instance_data_key(&TestHasher, instance, badge, 0)),
        Some(vec![1]),
    );
}

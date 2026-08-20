//! An issuer brings its own resources into existence.
//!
//! A record is the issuer's own cell, so writing one is an ordinary
//! declared access, and the `Absent` condition beside the write is the
//! one-way door: a second creation is refused by the shard holding the
//! leaf before any body runs. The cells a creating call writes are held
//! to the protocol's own encoding, byte for byte — a founded resource
//! and a genesis-seeded one have to be the same object.

use hyperscale_vm_effects::{
    PACKAGE_SLOT_BASE, ResourceKind, ResourceRecord, SlotId, TestHasher, child_key,
    instance_data_key, issued_resource, resource_record_key,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::hbor::to_vec;
use hyperscale_vm_testing::{Chain, PrincipalAddr, account, package, principal};
use hyperscale_vm_types::{Outcome, Presence, UnmetCondition};

const FOUNDER: PrincipalAddr = principal(0x31);

#[blueprint]
mod issuer {
    use hyperscale_vm_sdk::state::{Cell, NfBucket};

    #[resource(non_fungible)]
    struct OwnerBadge;

    /// A fielded mark: the instance's data cell holds this record, in
    /// the encoding the mark itself declares.
    #[resource(non_fungible)]
    struct Seat {
        operator: u64,
        label: String,
    }

    #[resource]
    struct Coupon;

    #[state]
    struct Issuer {
        noted: Cell<u64>,
    }

    impl Issuer {
        /// Bring the badge into existence: its record, and its first
        /// instance, handed back as an edge for the founder to keep.
        pub fn found(&mut self) -> NfBucket {
            OwnerBadge::create();
            OwnerBadge::mint(0)
        }

        /// Bring the coupon into existence, displayed at six digits.
        pub fn open(&mut self) {
            Coupon::create(6);
        }

        /// Note who operates the seat at `id`, where such a seat was
        /// minted: the issuer reads its own instance's record and acts
        /// on what it holds.
        pub fn note_operator(&mut self, id: u64) {
            if let Some(seat) = Seat::at(id) {
                self.noted.set(seat.operator);
            }
        }

        /// Mint a seat and read its record back in the one body: the
        /// cell the mint files and the cell the read reaches are one
        /// site, whichever of the two the body names first.
        pub fn seat_and_note(&mut self, id: u64, operator: u64) -> NfBucket {
            let seated = Seat::mint(
                id,
                Seat {
                    operator,
                    label: "back-row".to_owned(),
                },
            );
            if let Some(seat) = Seat::at(id) {
                self.noted.set(seat.operator);
            }
            seated
        }

        /// Seat an operator: the seat's record, and the one instance
        /// carrying who operates it.
        pub fn seat(&mut self, operator: u64) -> NfBucket {
            Seat::create();
            Seat::mint(
                7,
                Seat {
                    operator,
                    label: "front-row".to_owned(),
                },
            )
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
            ResourceRecord::NonFungible
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
            ResourceRecord::Fungible { divisibility: 6 }
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

/// Mint the seat at id 7, held by an operator the record names.
fn seated(chain: &mut Chain, instance: issuer::client::Issuer) {
    chain
        .transact(FOUNDER, |b| {
            let seat = instance.seat(b, 42)?;
            account::deposit_nf(b, FOUNDER, seat)
        })
        .expect_completed();
}

/// A fielded mark's instance carries its record: the mint files the
/// mark's own encoding where a bare mark files the presence byte, at the
/// same cell under the same absence requirement.
#[test]
fn a_fielded_mint_files_the_record_its_mark_declares() {
    let (mut chain, instance) = founded();
    chain
        .transact(FOUNDER, |b| {
            let seat = instance.seat(b, 42)?;
            account::deposit_nf(b, FOUNDER, seat)
        })
        .expect_completed();

    let seat = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        issuer::SEAT,
    );
    let filed = chain
        .cell(instance_data_key(&TestHasher, instance, seat, 7))
        .expect("the instance's data cell");
    assert_eq!(
        filed,
        to_vec(&issuer::Seat {
            operator: 42,
            label: "front-row".to_owned(),
        })
        .expect("the record encodes"),
        "the cell holds the record's own encoding, not a presence byte",
    );
}

/// An id nothing minted has no cell, so a schema is readable exactly
/// where an instance exists.
#[test]
fn an_unminted_id_has_no_data_cell() {
    let (mut chain, instance) = founded();
    chain
        .transact(FOUNDER, |b| {
            let seat = instance.seat(b, 42)?;
            account::deposit_nf(b, FOUNDER, seat)
        })
        .expect_completed();

    let seat = issued_resource(
        &TestHasher,
        instance,
        ResourceKind::NonFungible,
        issuer::SEAT,
    );
    assert_eq!(
        chain.cell(instance_data_key(&TestHasher, instance, seat, 8)),
        None,
    );
}

/// The issuer reads its own instance's record back, typed: the id names
/// the cell the mint filed, and the fields decode as the mark declared
/// them.
#[test]
fn an_issuer_reads_its_instances_record_back() {
    let (mut chain, instance) = founded();
    seated(&mut chain, instance);

    chain
        .transact(FOUNDER, |b| instance.note_operator(b, 7))
        .expect_completed();
    assert_eq!(
        chain.cell(child_key(
            &TestHasher,
            instance,
            SlotId(PACKAGE_SLOT_BASE),
            &[]
        )),
        Some(42_u64.to_le_bytes().to_vec()),
        "the body wrote what it decoded off the instance's own cell",
    );
}

/// An id nothing minted reads as absence rather than as a zero record,
/// so a body can tell "no such instance" from one whose fields are zero.
#[test]
fn an_unminted_id_reads_as_absent() {
    let (mut chain, instance) = founded();
    seated(&mut chain, instance);

    chain
        .transact(FOUNDER, |b| instance.note_operator(b, 8))
        .expect_completed();
    assert_eq!(
        chain.cell(child_key(
            &TestHasher,
            instance,
            SlotId(PACKAGE_SLOT_BASE),
            &[]
        )),
        None,
        "nothing was noted, because there was no record to read",
    );
}

/// A mint files the cell a read of the same instance reaches, and the
/// body may name them in either order: one target is one site, so the
/// record the mint writes is the record the read decodes.
#[test]
fn a_mint_and_a_read_of_one_instance_are_one_cell() {
    let (mut chain, instance) = founded();
    seated(&mut chain, instance);

    chain
        .transact(FOUNDER, |b| {
            let seat = instance.seat_and_note(b, 9, 55)?;
            account::deposit_nf(b, FOUNDER, seat)
        })
        .expect_completed();
    assert_eq!(
        chain.cell(child_key(
            &TestHasher,
            instance,
            SlotId(PACKAGE_SLOT_BASE),
            &[]
        )),
        Some(55_u64.to_le_bytes().to_vec()),
        "the body read back the record it had just filed",
    );
}

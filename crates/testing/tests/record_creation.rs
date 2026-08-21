//! An issuer brings its own resources into existence.
//!
//! A record is the issuer's own cell, written where the component
//! becomes actual: instantiation seals the configuration leaf and files
//! one record per declared mark, each under the `Absent` condition that
//! is its one-way door. The cells it writes are held to the protocol's
//! own encoding, byte for byte — an instantiated resource and a
//! genesis-seeded one have to be the same object.

use hyperscale_vm_effects::{
    PACKAGE_SLOT_BASE, ResourceRecord, SlotId, TestHasher, child_key, instance_data_key,
    resource_record_key,
};
use hyperscale_vm_sdk::blueprint;
use hyperscale_vm_sdk::hbor::to_vec;
use hyperscale_vm_testing::{Chain, PrincipalAddr, account, package, principal};
use hyperscale_vm_types::{Outcome, Presence, UnmetCondition};

const FOUNDER: PrincipalAddr = principal(0x31);

#[blueprint]
mod issuer {
    use hyperscale_vm_sdk::state::{Cell, NfBucket};

    /// The issuer comes up holding this badge's one instance, which
    /// leaves as the edge the bring-up yields.
    #[resource(non_fungible, initial(0))]
    struct OwnerBadge;

    /// A fielded mark: the instance's data cell holds this record, in
    /// the encoding the mark itself declares.
    #[resource(non_fungible)]
    struct Seat {
        operator: u64,
        label: String,
    }

    #[resource(divisibility = 6)]
    struct Coupon;

    #[state]
    struct Issuer {
        noted: Cell<u64>,
    }

    impl Issuer {
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

        /// Seat an operator: the one instance carrying who operates it.
        pub fn seat(&mut self, operator: u64) -> NfBucket {
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
    let instance = chain.instantiate::<issuer::client::Issuer>(FOUNDER, ());
    (chain, instance)
}

/// Instantiation writes a record per declared mark, in the protocol's
/// own encoding: the same cells, the same bytes, under the issuer at the
/// resources its marks derive.
///
/// Every mark, not only the ones a body goes on to mint: what a resource
/// is denominated at is a fact about the component, so a client reading
/// one never has to know whether anything has been issued yet.
#[test]
fn instantiation_writes_the_canonical_record_of_every_mark() {
    let (chain, instance) = founded();

    for (resource, record) in [
        (
            instance.issued_owner_badge(&TestHasher),
            ResourceRecord::NonFungible,
        ),
        (
            instance.issued_seat(&TestHasher),
            ResourceRecord::NonFungible,
        ),
        (
            instance.issued_coupon(&TestHasher),
            ResourceRecord::Fungible { divisibility: 6 },
        ),
    ] {
        assert_eq!(
            chain.cell(resource_record_key(&TestHasher, instance, resource)),
            Some(record.to_cell().expect("a record encodes")),
            "{resource:?}",
        );
    }
}

/// The one-way door: a second instantiation is refused as the unmet
/// `Absent` condition, judged where the leaves live, and never reaches a
/// body.
#[test]
fn a_second_instantiation_is_refused_where_the_leaves_live() {
    let (mut chain, instance) = founded();

    let outcome = chain
        .transact(FOUNDER, |b| {
            let badge = b.call(instance, "instantiate", ())?.one()?;
            account::deposit_nf(b, FOUNDER, badge)
        })
        .refused()
        .cloned()
        .expect("the second instantiation is refused");
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
    let (chain, instance) = founded();

    let badge = instance.issued_owner_badge(&TestHasher);
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

    let seat = instance.issued_seat(&TestHasher);
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

    let seat = instance.issued_seat(&TestHasher);
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

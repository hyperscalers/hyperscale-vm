//! A loan that lasts one transaction, made safe by a value rather than
//! by a check.
//!
//! `Debt` grants `deposit = nobody`, so no vault may hold it under any
//! owner. What that buys the lender is the property every other flash
//! lender establishes by reading its own balance after a callback: the
//! borrower cannot end the transaction still holding the loan, because
//! the obligation beside it has nowhere to go but back. The pool's own
//! code says nothing about any of it.
//!
//! Three cases, and the middle one is the whole point: a graph that
//! forgets to repay never becomes a transaction, so the failure mode is
//! a refusal the composer reads rather than value the lender has to
//! chase.

use std::sync::LazyLock;

use hyperscale_vm_effects::vocabulary::CONFIG;
use hyperscale_vm_effects::{
    AdmissionError, EnvelopeTree, GraphArg, GraphNode, Hash32, Hasher, InstanceMeta, IntentDecl,
    ManifestGraph, PackageHash, PrefixShardResolver, Records, ResourceMeta, ResourceRecord,
    TestHasher, Value, admit_tree, child_key, resource_record_key, route_tree,
};
use hyperscale_vm_fixtures::{FLASHLOAN_COMPONENT, flashloan};
use hyperscale_vm_harness::driver::{Lanes, amount_of, run_lanes, seed_vault, vault};
use hyperscale_vm_kernel::{BatchOutcome, BatchTx, EnvInputs, MemoryStore};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account};
use hyperscale_vm_types::{
    AddressClass, ComponentAddr, Outcome, PrincipalAddr, ResourceAddr, TxHash,
};
use wasmtime::Result;
use wasmtime::error::{Context, ensure};

/// The borrower.
const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
/// What the pool lends.
const XRD: ResourceAddr = ResourceAddr::new([0xE1; 31]);

const fn env() -> EnvInputs {
    EnvInputs::unsealed(3_000)
}

fn account_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn flashloan_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"flashloan"]))
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(account_pkg(), account::metadata());
    chain
        .packages
        .publish_unchecked(flashloan_pkg(), flashloan::metadata());
    chain.instances.serve_principals(account_pkg());
    chain.instances.create(&TestHasher, pool_meta());
    chain
}

fn pool_meta() -> InstanceMeta {
    InstanceMeta {
        package: flashloan_pkg(),
        config: vec![Value::Address(XRD.address())],
        salt: Hash32([2; 32]),
    }
}

/// The pool's address, and the typed handle a manifest calls it
/// through — one derivation, read two ways.
fn pool_addr() -> ComponentAddr {
    pool_meta().address(&TestHasher)
}

fn pool() -> flashloan::Flashloan {
    flashloan::Flashloan::at(pool_addr())
}

/// The obligation the pool issues — derived from the pool and from the
/// rules its declaration grants, so its address is a function of
/// `deposit = nobody` rather than of anything configured.
fn debt() -> ResourceAddr {
    pool().issued_debt(&TestHasher)
}

/// The record a composer presents for the obligation: the address
/// preimage, built from the package's own declaration.
fn debt_record() -> ResourceMeta {
    let issuance = flashloan::metadata()
        .methods
        .into_values()
        .flat_map(|signature| signature.issues)
        .find(|issuance| issuance.mark == b"debt")
        .expect("the pool issues the obligation");
    ResourceMeta {
        namespace: pool_addr().into(),
        kind: issuance.kind,
        material: vec![Value::Bytes(b"debt".to_vec()).canonical_bytes()],
        rules: issuance
            .grants
            .resolve(&TestHasher, pool_addr().into(), &pool_meta().config)
            .expect("the declared grants resolve against the instance"),
    }
}

/// A store where the pool is actual and funded, and [`ALICE`] holds
/// enough to reserve against — a reservation is judged against committed
/// state, so a borrower cannot repay out of the loan they were just
/// handed and has to hold the float. Which is the honest shape anyway:
/// the obligation binds an amount, not the units it was lent in.
fn funded_store() -> MemoryStore {
    let mut store = MemoryStore::new();
    store.write(
        child_key(&TestHasher, pool_addr(), CONFIG, &[]),
        pool_meta()
            .leaf_bytes()
            .expect("an instance record encodes"),
    );
    store.write(
        resource_record_key(&TestHasher, pool_addr(), debt()),
        ResourceRecord::Fungible { display_digits: 0 }
            .to_cell()
            .expect("a record encodes"),
    );
    seed_vault(&mut store, pool_addr(), XRD, 1_000);
    seed_vault(&mut store, ALICE, XRD, 100);
    store
}

fn graph(write: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>) -> ManifestGraph {
    let chain = world();
    let mut b = TypedBuilder::new(&chain, &TestHasher, ALICE);
    write(&mut b).expect("every call types against its signature");
    b.build().expect("every output is consumed")
}

/// One intent, presenting the obligation's record — which a composer
/// must, since a `Restricted` address says its rules bind a movement.
fn intent(graph: ManifestGraph) -> EnvelopeTree {
    EnvelopeTree {
        root: IntentDecl {
            graph,
            params: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: vec![debt_record()],
    }
}

fn batch_entry(world: &Records, tree: &EnvelopeTree, composer: PrincipalAddr) -> Result<BatchTx> {
    let identity = tree.hash(&TestHasher);
    let admitted = admit_tree(tree, composer, identity, world, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    ensure!(
        routing.per_shard.len() == 1,
        "the null resolver routes to one shard"
    );
    let declaration = routing.declaration().clone();
    Ok(BatchTx::new(TxHash(identity.0), declaration, env()).with_calls(routing.calls))
}

static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let mut lanes = Lanes::new();
    lanes.seed(account_pkg(), ACCOUNT_COMPONENT);
    lanes.seed(flashloan_pkg(), FLASHLOAN_COMPONENT);
    lanes.seed_native(account_pkg(), account::invoke);
    lanes.seed_native(flashloan_pkg(), flashloan::invoke);
    lanes
});

fn run_both(store: &MemoryStore, batch: &[BatchTx]) -> (BatchOutcome, MemoryStore) {
    run_lanes(&LANES, store, batch)
}

/// The obligation's own address says its rules bind a movement.
///
/// The one fact a reader gets without resolving anything, and the reason
/// a composer knows to present the record at all: a resource whose
/// entries can stop a movement carries the tag, and the pool's lent
/// asset — which grants nothing — does not.
#[test]
fn the_obligation_carries_the_restricted_class() {
    assert_eq!(debt().address().class(), AddressClass::Restricted);
    assert_eq!(XRD.address().class(), AddressClass::Resource);
}

/// The loan goes out, travels through a holder's account, and comes
/// back, and the obligation is burned with it.
#[test]
fn a_repaid_loan_commits_on_both_runtimes() -> Result<()> {
    let world = world();
    let borrowed = graph(|b| {
        let alice = account::authorize(b, ALICE)?;
        let [loan, debt] = pool().draw(b, 100)?;
        account::deposit(b, ALICE, loan)?;
        let funds = account::withdraw(b, alice, XRD, 100)?;
        pool().repay(b, funds, debt)
    });
    let entry = batch_entry(&world, &intent(borrowed), ALICE)?;
    let (outcome, end) = run_both(&funded_store(), std::slice::from_ref(&entry));
    assert!(
        matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ),
        "the round trip commits: {:?}",
        outcome.receipts[&entry.tx].outcome,
    );

    // The pool is whole, the borrower is where they started, and no
    // vault anywhere holds an obligation — there is no cell for one.
    assert_eq!(amount_of(&end, vault(pool_addr(), XRD)), 1_000);
    assert_eq!(amount_of(&end, vault(ALICE, XRD)), 100);
    assert_eq!(amount_of(&end, vault(ALICE, debt())), 0);
    Ok(())
}

/// A graph that draws and does not repay never becomes a transaction.
///
/// Value is linear, so the obligation is an output nothing consumed, and
/// admission refuses the graph before it routes — the composer is told,
/// and no fee is assured against a transaction that was never going to
/// commit. This is the case a balance check in the lender's own body
/// would be answering, one callback too late.
#[test]
fn a_loan_nobody_repaid_is_refused_before_it_routes() {
    // Built by hand: the typed builder discharges every output, so the
    // graph a forgetful composer would sign is one it declines to
    // produce. What is under test is the verdict beneath that.
    let unrepaid = ManifestGraph {
        nodes: vec![GraphNode {
            target: pool_addr().into(),
            method: "draw".into(),
            args: vec![GraphArg::Literal(Value::U128(100))],
            evidence: std::collections::BTreeSet::default(),
        }],
    };
    let tree = intent(unrepaid);
    let refusal = admit_tree(&tree, ALICE, tree.hash(&TestHasher), &world(), &TestHasher)
        .expect_err("a loan nobody repaid is an output nobody consumed");
    assert!(
        matches!(refusal, AdmissionError::UnconsumedOutput { .. }),
        "the refusal is the linearity one: {refusal:?}",
    );
}

/// The obligation cannot come to rest, and the refusal is the entry's.
///
/// Not a condition nothing could meet — whether a resource may reach a
/// vault at all is decidable from the entry, without state and without a
/// body, so the graph is refused outright and the composer hears which
/// resource and which direction.
#[test]
fn the_obligation_cannot_be_routed_into_a_vault() {
    let parked = graph(|b| {
        let [loan, debt] = pool().draw(b, 100)?;
        account::deposit(b, ALICE, loan)?;
        account::deposit(b, ALICE, debt)
    });
    let tree = intent(parked);
    let refusal = admit_tree(&tree, ALICE, tree.hash(&TestHasher), &world(), &TestHasher)
        .expect_err("no vault may hold the obligation");
    let said = refusal.to_string();
    assert!(
        said.contains("grants Deposit to nobody"),
        "the refusal names the direction it refused, not the other one: {said}",
    );

    // And the record is what makes that verdict reachable rather than
    // assumed: withholding it is its own refusal, which is what the
    // class byte on the obligation's address exists to force.
    let mut withheld = tree;
    withheld.resources = Vec::new();
    let refusal = admit_tree(
        &withheld,
        ALICE,
        withheld.hash(&TestHasher),
        &world(),
        &TestHasher,
    )
    .expect_err("a restricted resource moved with no record is refused");
    assert!(
        matches!(refusal, AdmissionError::RecordWithheld { resource, .. } if resource == debt()),
        "a withheld record is refused for being withheld, not judged: {refusal:?}",
    );
}

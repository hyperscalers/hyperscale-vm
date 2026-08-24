//! A resource's granted rules: committed by its address, presented in
//! the envelope, verified by re-derivation — no cell read anywhere.
//!
//! Recall is the consumer: the one way it reaches a holder's vault is
//! the holder's own account method, gated on the rule the resource's
//! address grants. The record travels in the envelope's `resources`
//! section, and a record that lies derives a different address — so the
//! rule a holder checked when accepting the asset is the rule that
//! governs, forever, or the resource is a different resource.

use std::sync::LazyLock;

use hyperscale_vm_effects::{
    EnvelopeTree, Grant, GrantedBehaviour, Hasher, PackageHash, PrefixShardResolver, Presented,
    Records, ResourceGrants, ResourceKind, ResourceMeta, RoleBytes, StoredRule, TestHasher,
    admit_tree, route_tree,
};
use hyperscale_vm_harness::driver::{Lanes, amount_of, run_lanes, seed_vault, vault};
use hyperscale_vm_kernel::{BatchOutcome, BatchTx, EnvInputs, MemoryStore};
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, TypedError};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account};
use hyperscale_vm_types::{Address, AddressClass, Outcome, PrincipalAddr, ResourceAddr, TxHash};
use wasmtime::Result;
use wasmtime::error::{Context, ensure};

/// The account that holds the granting resource.
const HOLDER: PrincipalAddr = PrincipalAddr::new([0x61; 31]);
/// The identity the resource's granted recall rule admits.
const RECALLER: PrincipalAddr = PrincipalAddr::new([0x62; 31]);
/// An identity the rule does not admit.
const STRANGER: PrincipalAddr = PrincipalAddr::new([0x63; 31]);

/// The minter the granting resource's address commits — an address whose
/// code never runs here: nothing about a recall involves the minter.
const MINTER: Address = Address::new([0x6A; 31], AddressClass::Component);

const fn env() -> EnvInputs {
    EnvInputs::unsealed(5_000)
}

fn account_pkg() -> PackageHash {
    PackageHash(TestHasher.hash(b"package", &[b"account"]))
}

fn world() -> Records {
    let mut chain = Records::new();
    chain
        .packages
        .publish(account_pkg(), account::metadata())
        .expect("the account publishes");
    chain.instances.serve_principals(account_pkg());
    chain
}

/// The record the resource's address commits: recall granted to
/// [`RECALLER`]'s identity.
fn granting_meta() -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(
        GrantedBehaviour::Recall,
        Grant::Rule(
            RoleBytes::try_from(&StoredRule::Require(Presented::Identity(RECALLER.into())))
                .expect("a rule within the caps encodes"),
        ),
    );
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: Vec::new(),
        rules,
    }
}

fn resource() -> ResourceAddr {
    granting_meta().address(&TestHasher)
}

/// One envelope: `signer` authorizes, recalls `amount` of the granting
/// resource out of [`HOLDER`]'s account, and banks it — presenting the
/// record where `present` says to.
fn recall_tree(signer: PrincipalAddr, amount: u128, present: bool) -> Result<EnvelopeTree> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher);
    let build = |b: &mut _| -> std::result::Result<(), TypedError> {
        let caller = account::authorize(b, signer)?;
        let funds = account::recall(b, &[caller], HOLDER, resource(), amount)?;
        account::deposit(b, signer, funds)
    };
    build(&mut root).context("the recall types against the account")?;
    if present {
        env.resource(granting_meta());
    }
    env.seal(root).context("the root grants")?;
    env.build().context("the tree builds")
}

fn batch_entry(tree: &EnvelopeTree, composer: PrincipalAddr) -> Result<BatchTx> {
    let chain = world();
    let identity = tree.hash(&TestHasher);
    let admitted =
        admit_tree(tree, composer, identity, &chain, &TestHasher).context("admission")?;
    let routing = route_tree(&admitted, &PrefixShardResolver { bits: 0 });
    ensure!(routing.per_shard.len() == 1, "one shard");
    Ok(
        BatchTx::new(TxHash(identity.0), routing.declaration().clone(), env())
            .with_calls(routing.calls),
    )
}

static LANES: LazyLock<Lanes> = LazyLock::new(|| {
    let mut lanes = Lanes::new();
    lanes.seed(account_pkg(), ACCOUNT_COMPONENT);
    lanes.seed_native(account_pkg(), account::invoke);
    lanes
});

fn run(store: &MemoryStore, batch: &[BatchTx]) -> (BatchOutcome, MemoryStore) {
    run_lanes(&LANES, store, batch)
}

fn holder_store(amount: u128) -> MemoryStore {
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, resource(), amount);
    store
}

/// The recall reaches the holder's vault through the holder's own
/// method: the recaller presents its identity, the granted rule the
/// envelope-presented record carries admits it, and the funds move —
/// with the holder signing nothing and no cell read resolving the rule.
#[test]
fn a_sealed_recall_reaches_the_holder_through_their_own_account() -> Result<()> {
    let entry = batch_entry(&recall_tree(RECALLER, 60, true)?, RECALLER)?;
    let (outcome, end) = run(&holder_store(100), std::slice::from_ref(&entry));
    assert!(matches!(
        outcome.receipts[&entry.tx].outcome,
        Outcome::Completed { .. }
    ));
    assert_eq!(amount_of(&end, vault(HOLDER, resource())), 40);
    assert_eq!(amount_of(&end, vault(RECALLER, resource())), 60);
    Ok(())
}

/// An identity the granted rule does not admit is refused at the gate,
/// and the holder's vault never moves.
#[test]
fn a_stranger_is_refused_by_the_sealed_rule() -> Result<()> {
    let entry = batch_entry(&recall_tree(STRANGER, 60, true)?, STRANGER)?;
    let (outcome, end) = run(&holder_store(100), std::slice::from_ref(&entry));
    assert!(
        !matches!(
            outcome.receipts[&entry.tx].outcome,
            Outcome::Completed { .. }
        ),
        "the granted rule admits the recaller alone",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, resource())), 100);
    Ok(())
}

/// A recall whose envelope presents no record has nothing to verify a
/// rule against, and is refused at admission — before anything routes.
#[test]
fn an_unpresented_record_refuses_at_admission() -> Result<()> {
    let tree = recall_tree(RECALLER, 60, false)?;
    let identity = tree.hash(&TestHasher);
    let chain = world();
    assert!(
        admit_tree(&tree, RECALLER, identity, &chain, &TestHasher).is_err(),
        "an unpresented granted rule refuses",
    );
    Ok(())
}

/// A record with different rules derives a different address, so the
/// granted set can never be swapped under a holder: presenting the
/// altered record registers a different resource, and the one the
/// holder owns stays unverifiable — refused, not reinterpreted.
#[test]
fn a_changed_rule_is_a_different_resource() -> Result<()> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher);
    let build = |b: &mut _| -> std::result::Result<(), TypedError> {
        let caller = account::authorize(b, STRANGER)?;
        let funds = account::recall(b, &[caller], HOLDER, resource(), 60)?;
        account::deposit(b, STRANGER, funds)
    };
    build(&mut root).context("the recall types")?;
    // The stranger presents a record whose recall rule admits them —
    // but those rules derive a different address, so the resource the
    // manifest names stays unpresented.
    let mut forged = granting_meta();
    forged.rules = ResourceGrants::new();
    forged.rules.set(
        GrantedBehaviour::Recall,
        Grant::Rule(
            RoleBytes::try_from(&StoredRule::Require(Presented::Identity(STRANGER.into())))
                .expect("a rule encodes"),
        ),
    );
    assert_ne!(forged.address(&TestHasher), resource());
    env.resource(forged);
    env.seal(root).context("the root grants")?;
    let tree = env.build().context("the tree builds")?;
    let identity = tree.hash(&TestHasher);
    assert!(
        admit_tree(&tree, STRANGER, identity, &chain, &TestHasher).is_err(),
        "a forged record registers a different resource",
    );
    Ok(())
}

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

/// The badge a governed resource's `Withdraw` entry names.
const BADGE: ResourceAddr = ResourceAddr::new([0x77; 31]);

/// A resource whose withdrawal is governed by a standing credential.
fn governed_meta(entry: Grant) -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(GrantedBehaviour::Withdraw, entry);
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"governed".to_vec()],
        rules,
    }
}

fn governed(entry: Grant) -> ResourceAddr {
    governed_meta(entry).address(&TestHasher)
}

/// The holder moves the governed resource out of their own account and
/// banks it back — an ordinary transfer, declaring nothing about any
/// rule, which is the whole point.
fn governed_tree(entry: Grant) -> Result<EnvelopeTree> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher);
    let build = |b: &mut _| -> std::result::Result<(), TypedError> {
        let caller = account::authorize(b, HOLDER)?;
        let funds = account::withdraw(b, caller, governed(entry.clone()), 40)?;
        account::deposit(b, HOLDER, funds)
    };
    build(&mut root).context("the withdrawal types against the account")?;
    env.resource(governed_meta(entry));
    env.seal(root).context("the root grants")?;
    env.build().context("the tree builds")
}

/// A holder's store, holding the governed resource and — where `carries`
/// says so — the credential its withdraw rule names.
fn governed_store(entry: Grant, carries: bool) -> MemoryStore {
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, governed(entry), 100);
    if carries {
        seed_vault(&mut store, HOLDER, BADGE, 1);
    }
    store
}

/// A movement of a governed resource is judged against its entry, in a
/// declaration that says nothing about it.
///
/// The account declares a withdrawal and no rule; the requirement is
/// admission's, resolved against the vault's own owner. So a holder
/// carrying the credential moves value and one who does not cannot —
/// with the package unchanged either way, which is what makes omission
/// inexpressible rather than merely discouraged.
#[test]
fn a_credential_governs_a_withdrawal_no_package_declared() -> Result<()> {
    let entry = Grant::Credential(BADGE);

    let carried = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, end) = run(
        &governed_store(entry.clone(), true),
        std::slice::from_ref(&carried),
    );
    assert!(
        matches!(
            outcome.receipts[&carried.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a holder carrying the credential moves what they hold",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry.clone()))), 100);

    // The same transaction, the same package, one leaf absent.
    let bare = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, end) = run(
        &governed_store(entry.clone(), false),
        std::slice::from_ref(&bare),
    );
    assert!(
        !matches!(
            outcome.receipts[&bare.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a holder without it does not",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry))), 100);
    Ok(())
}

/// A resource no cell may hold refuses the graph that would rest it, at
/// admission, before anything routes or any fee is assured.
#[test]
fn a_forbidden_movement_refuses_at_admission() -> Result<()> {
    let tree = governed_tree(Grant::Never)?;
    let identity = tree.hash(&TestHasher);
    let chain = world();
    let refusal = admit_tree(&tree, HOLDER, identity, &chain, &TestHasher)
        .expect_err("a movement the entry forbids is refused");
    let said = refusal.to_string();
    assert!(
        said.contains("may not come to rest"),
        "the refusal names what it refused: {said}"
    );
    Ok(())
}

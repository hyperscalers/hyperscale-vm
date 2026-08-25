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
    EnvelopeTree, GrantedBehaviour, Hasher, Holding, PackageHash, PrefixShardResolver, Presented,
    Records, ResourceGrants, ResourceKind, ResourceMeta, RuleBytes, StoredRule, TestHasher,
    Totality, admit_tree, holdings_collection, never, route_tree,
};
use hyperscale_vm_harness::driver::{Lanes, amount_of, cells, run_lanes, seed_vault, vault};
use hyperscale_vm_kernel::{BatchOutcome, BatchTx, EnvInputs, MemoryStore};
use hyperscale_vm_manifest_builder::{EnvelopeBuilder, TypedError};
use hyperscale_vm_stdlib::{ACCOUNT_COMPONENT, account};
use hyperscale_vm_types::{
    Address, AddressClass, EffectTarget, Outcome, Presence, PrincipalAddr, ResourceAddr, TxHash,
    UnmetCondition,
};
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
        RuleBytes::try_from(&StoredRule::claim(Presented::of_subject(RECALLER)))
            .expect("a rule within the caps encodes"),
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
        RuleBytes::try_from(&StoredRule::claim(Presented::of_subject(STRANGER)))
            .expect("a rule encodes"),
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

/// A rule sealed into a resource's address.
fn sealed(rule: &StoredRule) -> RuleBytes {
    RuleBytes::try_from(rule).expect("a rule within the caps encodes")
}

/// The badge a governed resource's `Withdraw` entry names.
const BADGE: ResourceAddr = ResourceAddr::new([0x77; 31]);

/// A resource whose withdrawal is governed by a standing credential.
fn governed_meta(entry: RuleBytes) -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(GrantedBehaviour::Withdraw, entry);
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"governed".to_vec()],
        rules,
    }
}

fn governed(entry: RuleBytes) -> ResourceAddr {
    governed_meta(entry).address(&TestHasher)
}

/// The holder moves the governed resource out of their own account and
/// banks it back — an ordinary transfer, declaring nothing about any
/// rule, which is the whole point.
fn governed_tree(entry: RuleBytes) -> Result<EnvelopeTree> {
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
fn governed_store(entry: RuleBytes, carries: bool) -> MemoryStore {
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
    let entry = sealed(&StoredRule::held(BADGE, Holding::Balance));

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

/// A resource nobody may withdraw refuses the graph that would move it,
/// at admission, before anything routes or any fee is assured.
#[test]
fn a_forbidden_movement_refuses_at_admission() -> Result<()> {
    let tree = governed_tree(sealed(&never()))?;
    let identity = tree.hash(&TestHasher);
    let chain = world();
    let refusal = admit_tree(&tree, HOLDER, identity, &chain, &TestHasher)
        .expect_err("a movement the entry forbids is refused");
    let said = refusal.to_string();
    assert!(
        said.contains("grants Withdraw to nobody"),
        "the refusal names the direction it refused, not the other one: {said}"
    );
    Ok(())
}

/// A resource no vault may hold refuses the graph that would file it,
/// on the same terms and in the other direction.
///
/// Whether a resource may come to rest at all is decidable from the
/// entry, without state and without a body — so the refusal is the
/// graph's rather than a condition nothing could meet, and the composer
/// hears it before a fee is assured. What it leaves reachable is
/// everything a transient obligation is made of: minted, carried across
/// an edge, and consumed inside the transaction that made it.
#[test]
fn a_resource_no_vault_may_hold_refuses_at_admission() -> Result<()> {
    let tree = admitted_tree(sealed(&never()), STRANGER)?;
    let identity = tree.hash(&TestHasher);
    let chain = world();
    let refusal = admit_tree(&tree, HOLDER, identity, &chain, &TestHasher)
        .expect_err("a credit the entry forbids is refused");
    let said = refusal.to_string();
    assert!(
        said.contains("grants Deposit to nobody"),
        "the refusal names the direction it refused, not the other one: {said}"
    );
    Ok(())
}

/// A withdrawal credential governs withdrawals, and leaves receiving
/// alone.
///
/// The two behaviours are only independent if a declaration can carry
/// its direction. Where it cannot, a credit has to answer for the debit
/// it might have made — so a resource governing who may *send* ends up
/// governing who may *receive*, and the two collapse into one. A deposit
/// that says it only receives is asked what a recipient is asked, which
/// for this resource is nothing.
#[test]
fn a_withdrawal_credential_leaves_receiving_alone() -> Result<()> {
    let entry = sealed(&StoredRule::held(BADGE, Holding::Balance));
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher);
    let build = |b: &mut _| -> std::result::Result<(), TypedError> {
        let caller = account::authorize(b, HOLDER)?;
        let funds = account::withdraw(b, caller, governed(entry.clone()), 40)?;
        // To a party holding no credential of any kind.
        account::deposit(b, STRANGER, funds)
    };
    build(&mut root).context("the transfer types")?;
    env.resource(governed_meta(entry.clone()));
    env.seal(root).context("the root grants")?;
    let tree = env.build().context("the tree builds")?;

    let sent = batch_entry(&tree, HOLDER)?;
    let (outcome, end) = run(
        &governed_store(entry.clone(), true),
        std::slice::from_ref(&sent),
    );
    assert!(
        matches!(
            outcome.receipts[&sent.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a permitted sender reaches an unpermitted recipient: {:?}",
        outcome.receipts[&sent.tx].outcome,
    );
    assert_eq!(
        amount_of(&end, vault(STRANGER, governed(entry.clone()))),
        40
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry))), 60);
    Ok(())
}

/// The instance a non-fungible credential names, under its holder.
const CREDENTIAL_ID: u64 = 0x51;

/// A store holding the governed resource and, where `carries` says so,
/// one instance of the non-fungible badge its entry names.
fn instanced_store(entry: RuleBytes, carries: bool) -> MemoryStore {
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, governed(entry), 100);
    if carries {
        store.entry_write(
            HOLDER.address(),
            holdings_collection(&TestHasher, HOLDER, BADGE),
            u128::from(CREDENTIAL_ID),
            Vec::new(),
        );
    }
    store
}

/// A credential is a badge, whichever kind of badge it is.
///
/// A non-fungible holding is entries at instance ids rather than one
/// balance cell, so "holds any of it" is asked of the interval those
/// entries sit in — one seek, answered before any body runs, against a
/// read the injection declared. What the holder writes is the same
/// transfer either way, and what the issuer wrote is `issued(Badge)`
/// either way: the two kinds differ in what the question costs, never in
/// whether it can be asked.
#[test]
fn a_non_fungible_credential_governs_a_withdrawal_the_same_way() -> Result<()> {
    let entry = sealed(&StoredRule::held(BADGE, Holding::AnyInstance));

    let carried = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, end) = run(
        &instanced_store(entry.clone(), true),
        std::slice::from_ref(&carried),
    );
    assert!(
        matches!(
            outcome.receipts[&carried.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a holder of an instance moves what they hold: {:?}",
        outcome.receipts[&carried.tx].outcome,
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry.clone()))), 100);

    // The same transaction, the same package, the collection empty.
    let bare = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, end) = run(
        &instanced_store(entry.clone(), false),
        std::slice::from_ref(&bare),
    );
    assert_eq!(
        outcome.receipts[&bare.tx].outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Range {
                    owner: HOLDER.address(),
                    collection: holdings_collection(&TestHasher, HOLDER, BADGE),
                    lo: 0,
                    hi: u128::from(u64::MAX),
                    cap: 1,
                },
                required: Presence::Present,
            }
        },
        "a holder of none is refused by the interval the injection asked about",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry))), 100);
    Ok(())
}

/// A credential naming one instance admits its holder alone.
///
/// The narrower question and the cheaper one: an entry is a leaf, so a
/// rule naming the instance asks a point of the collection rather than
/// the whole id space — and a holder of a different instance of the same
/// badge is refused, which is what makes revocation by burning that one
/// instance mean anything.
#[test]
fn a_credential_naming_an_instance_admits_its_holder_alone() -> Result<()> {
    let entry = sealed(&StoredRule::held(BADGE, Holding::Instance(CREDENTIAL_ID)));

    let named = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, _) = run(
        &instanced_store(entry.clone(), true),
        std::slice::from_ref(&named),
    );
    assert!(
        matches!(
            outcome.receipts[&named.tx].outcome,
            Outcome::Completed { .. }
        ),
        "the instance the rule names is the instance held: {:?}",
        outcome.receipts[&named.tx].outcome,
    );

    // The same badge, another instance of it.
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, governed(entry.clone()), 100);
    store.entry_write(
        HOLDER.address(),
        holdings_collection(&TestHasher, HOLDER, BADGE),
        u128::from(CREDENTIAL_ID + 1),
        Vec::new(),
    );
    let other = batch_entry(&governed_tree(entry.clone())?, HOLDER)?;
    let (outcome, end) = run(&store, std::slice::from_ref(&other));
    assert!(
        !matches!(
            outcome.receipts[&other.tx].outcome,
            Outcome::Completed { .. }
        ),
        "another instance of the same badge is another credential",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, governed(entry))), 100);
    Ok(())
}

/// A resource whose entry governs who may be credited rather than who
/// may debit.
fn admitting_meta(entry: RuleBytes) -> ResourceMeta {
    let mut rules = ResourceGrants::new();
    rules.set(GrantedBehaviour::Deposit, entry);
    ResourceMeta {
        namespace: MINTER,
        kind: ResourceKind::Fungible,
        material: vec![b"admitting".to_vec()],
        rules,
    }
}

fn admitting(entry: RuleBytes) -> ResourceAddr {
    admitting_meta(entry).address(&TestHasher)
}

/// [`HOLDER`] sends the deposit-governed resource to `recipient`, in the
/// same ordinary transfer a package that declared nothing composes.
fn admitted_tree(entry: RuleBytes, recipient: PrincipalAddr) -> Result<EnvelopeTree> {
    let chain = world();
    let (mut env, mut root) = EnvelopeBuilder::new(&chain, &TestHasher);
    let build = |b: &mut _| -> std::result::Result<(), TypedError> {
        let caller = account::authorize(b, HOLDER)?;
        let funds = account::withdraw(b, caller, admitting(entry.clone()), 40)?;
        account::deposit(b, recipient, funds)
    };
    build(&mut root).context("the transfer types against the account")?;
    env.resource(admitting_meta(entry));
    env.seal(root).context("the root grants")?;
    env.build().context("the tree builds")
}

/// A deposit credential governs the crediting side, and a transfer to a
/// party who does not hold it writes nothing under them.
///
/// The half of the seam that cannot be a gate. A credit lands on
/// `deposit`, which is `#[total]` and may turn no caller away, so the
/// requirement is a fact about the recipient judged against committed
/// state before any body runs — and the transfer aborts whole rather
/// than landing somewhere for an issuer to sweep afterwards. The sender
/// is charged, which is right: they built a transfer to somebody who
/// cannot receive.
#[test]
fn a_deposit_credential_governs_who_may_be_credited() -> Result<()> {
    let entry = sealed(&StoredRule::held(BADGE, Holding::Balance));
    let asset = admitting(entry.clone());

    // The recipient is on the register.
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, asset, 100);
    seed_vault(&mut store, STRANGER, BADGE, 1);
    let sent = batch_entry(&admitted_tree(entry.clone(), STRANGER)?, HOLDER)?;
    let (outcome, end) = run(&store, std::slice::from_ref(&sent));
    assert!(
        matches!(
            outcome.receipts[&sent.tx].outcome,
            Outcome::Completed { .. }
        ),
        "a credited holder of the credential receives: {:?}",
        outcome.receipts[&sent.tx].outcome,
    );
    assert_eq!(amount_of(&end, vault(STRANGER, asset)), 40);

    // And is not.
    let mut store = MemoryStore::new();
    seed_vault(&mut store, HOLDER, asset, 100);
    let refused = batch_entry(&admitted_tree(entry, STRANGER)?, HOLDER)?;
    let (outcome, end) = run(&store, std::slice::from_ref(&refused));
    assert_eq!(
        outcome.receipts[&refused.tx].outcome,
        Outcome::ConditionUnmet {
            condition: UnmetCondition::Holds {
                target: EffectTarget::Point(vault(STRANGER, BADGE)),
                required: Presence::Present,
            }
        },
        "the recipient's own credential is what the credit is asked for",
    );
    assert!(
        !cells(&end)
            .keys()
            .any(|key| key.owner == STRANGER.address()),
        "and nothing lands under them: no leaf, no quarantine, nothing to sweep",
    );
    assert_eq!(amount_of(&end, vault(HOLDER, asset)), 100);
    Ok(())
}

/// Injection does not unmake a total method.
///
/// `deposit` carries a condition it never declared, and stays the method
/// whose mark says it turns no caller away — because a condition is
/// judged against committed state before the body runs, where a gate
/// would refuse a caller for presenting a proof the manifest never
/// showed them was wanted.
#[test]
fn a_credit_requirement_leaves_the_total_mark_standing() {
    assert_eq!(
        account::metadata().methods["deposit"].totality,
        Totality::Total,
        "the account's deposit is total, and injection is what it has to survive",
    );
}

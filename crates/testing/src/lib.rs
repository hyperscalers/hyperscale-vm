//! A chain a package runs on, for the author's own `cargo test`.
//!
//! What it takes to execute one transaction is a metadata cache, an
//! instance registry, a store, an admitted and routed manifest, a batch
//! entry and an engine behind the walk. All of it is machinery a package
//! author did not write and should not have to assemble: what an author
//! wants to say is *publish this, seed that, call this, and here is what
//! should have happened*.
//!
//! So [`Chain`] owns the assembly and a test says only the four things.
//! Every transaction goes through the real kernel — capability
//! materialization, the trace-subset oracle, conflict grouping, movement
//! folds, receipts — because a harness that shortcut any of it would
//! prove something other than what the chain does.
//!
//! # Which engine ran it
//!
//! Nothing in a test says but the constructor. [`Chain::native`] calls
//! the package's own bodies; `Chain::wasm` — behind the `wasm` feature —
//! builds the crate to its artifact and runs that under the blessed
//! engine, which is what a network would execute. Everything after that
//! line is engine-neutral on purpose: a test written once is a test more
//! than one engine can be held to, and the harness holds them to each
//! other.
//!
//! # What the fast lane does not answer
//!
//! Fuel, the canonical ABI's copy accounting, the deploy-time profile
//! and the totality scan are all the artifact's, and the native lane has
//! none of them. What it does answer is whether the bodies are right,
//! and the harness holds that answer to the artifact's.
//!
//! It runs under whichever profile the test was built in, and the two
//! read differently: a package is built in release, where an overflow
//! wraps, and `cargo test` builds in debug, where it panics. Debug is
//! the stricter of the two and worth having — a body that wraps is a
//! body whose author wanted `checked_add`, and one that means it says
//! `wrapping_add` and passes both. Release is the arithmetic the chain
//! runs. Neither is wrong to run; running only one is.

use std::sync::Arc;

use hyperscale_vm_effects::vocabulary::{CONFIG, VAULT};
use hyperscale_vm_effects::{
    AdmissionError, Hash32, Hasher, InstanceMeta, InstanceRegistry, MetadataCache, PackageHash,
    PrefixShardResolver, TestHasher, Value, admit, child_key, declaration_hash, issued_resource,
    route,
};
use hyperscale_vm_kernel::{
    BatchTx, EnvInputs, ExecutionMode, Locality, ManifestWalk, MemoryStore, Substates,
    decode_amount, execute_batch,
};
use hyperscale_vm_manifest_builder::{TypedBuilder, TypedError};
#[cfg(feature = "wasm")]
use hyperscale_vm_stdlib::ACCOUNT_COMPONENT;
pub use hyperscale_vm_types::{Address, ComponentAddr, PrincipalAddr, ResourceAddr};
use hyperscale_vm_types::{
    CallTarget, Outcome as KernelOutcome, SubstateKey, TxHash, encode_amount,
};

mod native;
mod outcome;
mod package;
#[cfg(feature = "wasm")]
mod wasm;

pub use hyperscale_vm_sdk::client::{Component, ConfigValues, IntoSlot};
pub use hyperscale_vm_stdlib::account;
pub use native::{Dispatch, Native};
pub use outcome::Outcome;
pub use package::Package;
#[cfg(feature = "wasm")]
pub use wasm::{Blessed, FUEL_CEILING};

/// An address the chain holds no instance of the wanted package at.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("no instance of {want:?} at {address:?}")]
pub struct WrongPackage {
    /// The address adoption was asked about.
    pub address: ComponentAddr,
    /// The package a handle of that type would have to name.
    pub want: PackageHash,
}

/// The transaction clock every [`Chain`] runs at unless told otherwise.
///
/// A fixed instant rather than the wall clock: a test that passed today
/// passes tomorrow, and a body reading the clock reads the same value on
/// every run.
pub const CLOCK_MS: u64 = 1_000_000;

/// The randomness draw every transaction sees.
const RANDOMNESS: [u8; 32] = [7; 32];

fn hash(data: &[u8]) -> [u8; 32] {
    TestHasher.hash(b"crypto", &[data]).0
}

/// A world with a store, the packages published in it, and the instances
/// created from them.
pub struct Chain {
    store: MemoryStore,
    cache: MetadataCache,
    instances: InstanceRegistry,
    engine: Engine,
    clock_ms: u64,
    /// Distinguishes one transaction's hash from the next, so a chain
    /// running the same call twice is running two transactions.
    sequence: u64,
    /// Distinguishes one instance of a package from the next, as the
    /// salt a creation record carries.
    created: u64,
}

/// Whatever runs a package's code, behind the walk.
enum Engine {
    /// The artifact a network would run, under the blessed engine.
    #[cfg(feature = "wasm")]
    Blessed(Blessed),
    /// The bodies themselves, called directly.
    Native(Native),
}

impl Chain {
    /// A chain that runs the packages' own bodies, with no engine under
    /// them.
    ///
    /// The fast lane, and the default: a call is a call, a failure has a
    /// backtrace, and nothing is compiled to wasm to get there.
    #[must_use]
    pub fn native() -> Self {
        let mut native = Native::default();
        native.seed(account_package(), account::invoke);
        Self::new(Engine::Native(native))
    }

    /// A chain that builds each package to its artifact and runs it
    /// under the blessed engine.
    ///
    /// The slow lane, and the faithful one: fuel, the canonical ABI and
    /// the deploy-time profile all stand here, and a test that passes on
    /// both has been held to what a network would do as well as to what
    /// its author meant.
    #[cfg(feature = "wasm")]
    #[must_use]
    pub fn wasm() -> Self {
        let mut blessed = Blessed::new();
        blessed.seed(account_package(), ACCOUNT_COMPONENT);
        Self::new(Engine::Blessed(blessed))
    }

    /// A chain with the account published, whichever engine runs it.
    ///
    /// Value has to come from somewhere, and every principal address is
    /// answered by that package.
    fn new(engine: Engine) -> Self {
        let mut chain = Self {
            store: MemoryStore::new(),
            cache: MetadataCache::new(),
            instances: InstanceRegistry::new(),
            engine,
            clock_ms: CLOCK_MS,
            sequence: 0,
            created: 0,
        };
        let account = account_package();
        chain
            .cache
            .publish(account, account::metadata())
            .expect("the account package publishes");
        chain.instances.serve_principals(account);
        chain
    }

    /// Run every transaction at `clock_ms` instead of [`CLOCK_MS`].
    #[must_use]
    pub const fn at(mut self, clock_ms: u64) -> Self {
        self.clock_ms = clock_ms;
        self
    }

    /// Publish a package, at the address its declaration derives.
    ///
    /// The declaration rather than the code, because the address has to
    /// be the same in both lanes: an instance's address folds the
    /// package's in, so a chain that keyed one lane on an artifact and
    /// the other on a module would put the same pool at two addresses
    /// and make the receipts incomparable. The native lane has no
    /// artifact to address at all, so the declaration is not the cheaper
    /// of two identities — it is the only one both lanes hold.
    ///
    /// Content-addressed either way: two packages that declare
    /// differently publish differently. What it is not is a network's
    /// address, which covers the code as well, and neither is any
    /// instance address that folds one in. A test reads balances and
    /// receipts, never an address it expects to see on a chain.
    ///
    /// # Panics
    ///
    /// If the package crate does not build, or its artifact does not
    /// clear the deploy-time profile — both of which are the author's
    /// answer rather than a test's — or if a declaration the chain would
    /// refuse to publish is handed to it.
    pub fn publish(&mut self, package: Package) -> PackageHash {
        let hash =
            declaration_hash(&TestHasher, &package.metadata).expect("a traced declaration encodes");
        match &mut self.engine {
            #[cfg(feature = "wasm")]
            Engine::Blessed(blessed) => blessed.build(hash, &package),
            Engine::Native(native) => native.seed(hash, package.dispatch),
        }
        // The cache door is the half of the publish gate that reads the
        // declaration alone. The other half needs an artifact and the
        // native lane has none, but a chain that published what a
        // network would refuse would let a test pass on a package nobody
        // can deploy — and a hand-written declaration is exactly where
        // that goes wrong.
        self.cache
            .publish(hash, package.metadata)
            .unwrap_or_else(|refusal| panic!("the package does not publish: {refusal}"));
        hash
    }

    /// Create an instance of `C`'s package under `config`, and answer a
    /// handle to it.
    ///
    /// The package is named once, as the handle's own type: an instance
    /// address folds in the declaration hash, and the handle is what
    /// carries the fact that this address runs that declaration. The
    /// configuration is written to the locked leaf and locked, which is
    /// what a real creation does and what a body reading `self.config`
    /// needs to be there.
    ///
    /// # Panics
    ///
    /// If `C`'s package was never published — an instance of code the
    /// chain does not hold answers no call — or if the configuration
    /// does not encode, which is a slot the package could not have
    /// declared.
    pub fn instantiate<C: Component>(&mut self, config: C::Config) -> C {
        let package =
            declaration_hash(&TestHasher, &C::metadata()).expect("a traced declaration encodes");
        assert!(
            self.cache.get(package).is_some(),
            "the package must be published before an instance of it is created"
        );
        C::at(self.create(package, config.values()))
    }

    /// Create an instance of a package the chain holds only as a hash.
    ///
    /// What a hand-written package uses, having no module for the macro
    /// to derive a handle from.
    ///
    /// # Panics
    ///
    /// If the configuration does not encode — a slot the package could
    /// not have declared.
    pub fn instantiate_raw(
        &mut self,
        package: PackageHash,
        config: impl ConfigValues,
    ) -> ComponentAddr {
        self.create(package, config.values())
    }

    /// Adopt `address` as an instance of `C`'s package.
    ///
    /// The checked half of the handle, and the one place the check has
    /// to happen: everything downstream of it is a call whose target is
    /// known to answer.
    ///
    /// # Errors
    ///
    /// The address the chain holds no instance for, or holds one of some
    /// other package at.
    ///
    /// # Panics
    ///
    /// If `C`'s traced declaration does not encode.
    pub fn adopt<C: Component>(&self, address: ComponentAddr) -> Result<C, WrongPackage> {
        let want =
            declaration_hash(&TestHasher, &C::metadata()).expect("a traced declaration encodes");
        let meta = self
            .instances
            .get(CallTarget::from(address))
            .ok_or(WrongPackage { address, want })?;
        if meta.package == want {
            Ok(C::at(address))
        } else {
            Err(WrongPackage { address, want })
        }
    }

    /// Write a creation record and its locked configuration leaf.
    fn create(&mut self, package: PackageHash, config: Vec<Value>) -> ComponentAddr {
        self.created += 1;
        let meta = InstanceMeta {
            package,
            config,
            salt: salt(self.created),
        };
        let address = meta.address(&TestHasher);
        let leaf = child_key(&TestHasher, address, CONFIG, &[]);
        let bytes = meta
            .config_bytes()
            .expect("an instance's configuration encodes");
        self.instances.create(&TestHasher, meta);
        self.store
            .write(leaf, bytes)
            .expect("the store takes a config leaf");
        self.store.lock(leaf);
        address
    }

    /// The resource an instance issues under `mark`.
    ///
    /// The same derivation `issued(mark)` reaches inside a body: an
    /// instance's own address over the mark that separates one of its
    /// resources from another. A test naming a contract's shares or its
    /// badge is asking for this, and spelling it out per test is how two
    /// spellings of one address get written.
    ///
    /// An empty mark is no material rather than one empty element, which
    /// is what the tracer means by it and the only spelling that reaches
    /// the address the body does.
    #[must_use]
    pub fn issued(instance: impl Into<ComponentAddr>, mark: &[u8]) -> ResourceAddr {
        issued_resource(&TestHasher, instance.into(), mark)
    }

    /// Put `amount` of `resource` in `owner`'s vault, as though it had
    /// always been there.
    ///
    /// Not a transaction: a test that had to mint its way to a starting
    /// balance would be testing the mint.
    ///
    /// # Panics
    ///
    /// If the store refuses the write.
    pub fn credit(
        &mut self,
        owner: impl Into<Address>,
        resource: impl Into<Address>,
        amount: u128,
    ) {
        let key = vault(owner, resource);
        self.store
            .write(key, encode_amount(amount).to_vec())
            .expect("the store takes a vault cell");
    }

    /// What `owner` holds of `resource`.
    ///
    /// # Panics
    ///
    /// If the cell is there and is not an amount.
    #[must_use]
    pub fn balance(&self, owner: impl Into<Address>, resource: impl Into<Address>) -> u128 {
        self.store.cell(vault(owner, resource)).map_or(0, |cell| {
            decode_amount(&cell).expect("a vault cell is an amount")
        })
    }

    /// Sign one transaction as `signer` and execute it.
    ///
    /// The closure builds the manifest against this chain's own
    /// published metadata, so every call is typed by the signature it
    /// names — a method or an argument the package does not have is a
    /// refusal here rather than a trap later.
    ///
    /// # Panics
    ///
    /// If the manifest does not build or admit — see
    /// [`Self::try_transact`] for asserting on such a refusal instead.
    pub fn transact(
        &mut self,
        signer: PrincipalAddr,
        build: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
    ) -> Outcome {
        self.try_transact(signer, build)
            .expect("the manifest builds and admits")
    }

    /// As [`Self::transact`], with a refusal before execution answered
    /// rather than panicked on — how a test asserts that a declared
    /// guard refuses a call.
    ///
    /// # Errors
    ///
    /// The builder's or admission's own refusal, where the transaction
    /// never reached execution.
    ///
    /// # Panics
    ///
    /// Panics if execution itself fails to produce a receipt — a batch
    /// defect, never a refusal.
    pub fn try_transact(
        &mut self,
        signer: PrincipalAddr,
        build: impl FnOnce(&mut TypedBuilder<'_>) -> Result<(), TypedError>,
    ) -> Result<Outcome, Refused> {
        let mut builder = TypedBuilder::new(&self.cache, &self.instances, &TestHasher);
        build(&mut builder)?;
        let graph = builder.build()?;

        let admitted = admit(&graph, signer, &self.cache, &self.instances, &TestHasher)?;
        let routing = route(&admitted, &PrefixShardResolver { bits: 0 });
        let declaration = routing.declaration().clone();

        self.sequence += 1;
        let tx = TxHash(salt(self.sequence));
        let entry = BatchTx::new(
            tx,
            declaration,
            EnvInputs {
                clock_ms: self.clock_ms,
                randomness: RANDOMNESS,
            },
        )
        .with_calls(routing.calls);

        // Execution replaces the chain's store, so it moves out rather
        // than being copied and dropped. Two owned copies are still
        // needed — the base the engine reads, and what the overlay
        // collapses back onto — but the third was the chain's own.
        let before = std::mem::take(&mut self.store);
        let batch = std::slice::from_ref(&entry);
        let base = Arc::new(before.clone());
        let outcome = match &self.engine {
            #[cfg(feature = "wasm")]
            Engine::Blessed(backend) => execute_batch(
                base,
                batch,
                &ManifestWalk { backend },
                hash,
                ExecutionMode::Serial,
                &Locality::All,
            ),
            Engine::Native(backend) => execute_batch(
                base,
                batch,
                &ManifestWalk { backend },
                hash,
                ExecutionMode::Serial,
                &Locality::All,
            ),
        }
        .expect("the batch is well formed");

        self.store = outcome.store.collapse_onto(before);
        let receipt = outcome
            .receipts
            .into_values()
            .next()
            .expect("one transaction, one receipt");
        // A decline names a node, and which package published the table
        // the code indexes is that node's own.
        let errors = match receipt.outcome {
            KernelOutcome::Declined { node, .. } => entry
                .calls
                .get(node as usize)
                .and_then(|call| self.cache.get(call.package))
                .map(|metadata| metadata.errors.clone())
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        Ok(Outcome::new(receipt, errors))
    }
}

/// Why a transaction never reached execution: the manifest did not
/// type, did not build, or was refused at admission.
#[derive(Debug, thiserror::Error)]
pub enum Refused {
    /// A call the package's own signature refuses.
    #[error(transparent)]
    Typed(#[from] TypedError),
    /// The manifest was refused at admission.
    #[error(transparent)]
    Admission(#[from] AdmissionError),
}

/// A principal, at an address a test can write down.
///
/// Addresses are 31 bytes of whatever derivation put them there. A test
/// cares only that two are different, so `tag` is the whole of it.
#[must_use]
pub const fn principal(tag: u8) -> PrincipalAddr {
    PrincipalAddr::new([tag; 31])
}

/// A resource, on the terms [`principal`] describes.
#[must_use]
pub const fn resource(tag: u8) -> ResourceAddr {
    ResourceAddr::new([tag; 31])
}

/// The account's address in a chain.
///
/// Its declaration, on the same terms every other package's address is
/// derived — not [`account_package_hash`](hyperscale_vm_stdlib::account_package_hash),
/// which is the committed blob's and so is a rule this chain would apply
/// to exactly one package.
fn account_package() -> PackageHash {
    declaration_hash(&TestHasher, &account::metadata()).expect("the account's declaration encodes")
}

/// A counter as the 32 bytes a salt is.
fn salt(count: u64) -> Hash32 {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&count.to_le_bytes());
    Hash32(bytes)
}

/// The vault cell one owner holds one resource in, as every declaration
/// keyed by resource derives it.
fn vault(owner: impl Into<Address>, resource: impl Into<Address>) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource.into()).canonical_bytes()],
    )
}

//! The contract SDK: blueprint declarations traced into package metadata.
//!
//! Two halves of one vocabulary. Read rather than run, [`state`] is what
//! `#[blueprint]` traces a body through to get back exactly the
//! [`hyperscale_vm_effects::MethodSignature`] routing needs, against the
//! real evaluator rather than a model of it. Compiled as the component a
//! package publishes, the same types are the calls — the `guest` module
//! binds `hyperscale:kernel` once, and each accessor is the import its
//! mode names. It compiles only on a component build, so it is not in
//! these docs.
//!
//! Which of the two a build gets is the compiling crate's own answer: the
//! `guest` feature says this crate publishes the package, and only then
//! does the wasm32 target mean the artifact rather than a consumer that
//! happens to run in a browser.
//!
//! One vocabulary rather than two is the whole of it: a body cannot reach
//! state except through these types, so the declaration a reader derives
//! and the calls the component makes are read off the same text.
//!
//! # The shape
//!
//! ```
//! use hyperscale_vm_effects::{ParamType, SlotId};
//! use hyperscale_vm_sdk::{Blueprint, sym::{Addr, Bucket, Seq, Sym, U128}};
//!
//! const VAULT: SlotId = SlotId(1);
//!
//! let pool = Blueprint::builder()
//!     .method("swap", &[ParamType::Bucket, ParamType::U128], |t| {
//!         let input: Sym<Bucket> = t.arg(0);
//!         let pairing: Sym<Seq> = t.config(1);
//!
//!         let sold = input.resource();
//!         let bought = pairing.lookup(&sold).cast::<Addr>();
//!         let pool = t.self_addr();
//!
//!         let config: Sym<_> = pool.child(SlotId(0), &[]);
//!         t.point(&config).read();
//!         t.point(&pool.child(VAULT, &[sold.clone().cast()])).write();
//!         t.point(&pool.child(VAULT, &[bought.clone().cast()])).write();
//!
//!         t.output(&bought);
//!     })
//!     .build();
//!
//! let metadata = pool.metadata();
//! assert_eq!(metadata.methods["swap"].effects.len(), 3);
//! assert_eq!(metadata.methods["swap"].outputs.len(), 1);
//! ```
//!
//! # Why tracing rather than reading the body
//!
//! `#[blueprint]` is a proc macro over the method body, but it does not
//! *read* the body for the field that matters. Recovering
//! [`hyperscale_vm_effects::Clause`] trees out of contract code would be
//! abstract interpretation of a Turing-complete language into a
//! deliberately weaker one: undecidable in general, and quiet when it
//! fails. So the macro lowers the body into this crate's own vocabulary
//! and then *runs* it, once, with symbolic inputs — and the declaration
//! is what that run recorded rather than what a reader inferred. See
//! [`trace`].
//!
//! What this costs the author is real and inherent, not a gap the SDK
//! could close with more cleverness: keys must be *stated*, because
//! routing runs before execution and state-free, so a key the body
//! computes is a key that arrives too late to route on. The macro makes
//! stating it look like Rust; it does not make it inferred.
//!
//! # What the derivation refuses
//!
//! The rejections matter as much as the derivations, because they are where
//! the architecture shows through. Routing evaluates a declaration before
//! execution and never reads state, so a key the body computes from a
//! substate value arrives too late to route on — and no amount of macro
//! cleverness changes that.
//!
//! A key read out of state:
//!
//! ```compile_fail
//! # use hyperscale_vm_sdk::blueprint;
//! #[blueprint]
//! mod bad {
//!     use hyperscale_vm_sdk::Address;
//!     use hyperscale_vm_sdk::state::{Bucket, Cell};
//!
//!     #[state]
//!     struct Bad {
//!         pointer: Cell<Address>,
//!     }
//!
//!     impl Bad {
//!         pub fn credit(&mut self, funds: Bucket) {
//!             // The key is a substate value, so no shard can name it
//!             // before executing — which is exactly when it is needed.
//!             let target = self.pointer.get();
//!             self.vault(target).put(funds);
//!         }
//!     }
//! }
//! ```
//!
//! A range whose entry cap is read out of state, on the same terms as
//! the key above — the cap evaluates with the declaration, so an
//! argument or a configured value serves and a substate value arrives
//! too late:
//!
//! ```compile_fail
//! # use hyperscale_vm_sdk::blueprint;
//! #[blueprint]
//! mod bad {
//!     use hyperscale_vm_sdk::state::{Cell, Ordered};
//!
//!     #[state]
//!     struct Bad {
//!         depth: Cell<u64>,
//!         asks: Ordered<u128>,
//!     }
//!
//!     impl Bad {
//!         pub fn sweep(&mut self) {
//!             let cap = self.depth.get();
//!             let mut window = self.asks.range(0, 100, cap);
//!             window.remove(0);
//!         }
//!     }
//! }
//! ```
//!
//! # Why a wrong declaration is not a safety problem
//!
//! `hyperscale:kernel/state` has no open-cell-by-key import. Every
//! accessor takes a `borrow` the kernel materialized, and what that
//! handle may do is the capability's answer, held by the kernel at every
//! operation rather than carried by the handle's type. A method that
//! under-declares does not get an unchecked access — it gets a handle
//! that does not exist, or one whose capability refuses what it asks. So
//! the tracer's correctness governs whether a contract *works*, not
//! whether the VM holds, which is what makes generated metadata
//! acceptable inside a content-addressed package at all.

/// The canonical encoding, re-exported so a contract crate reaches it
/// through the SDK alone.
///
/// A guest names one dependency, which is the whole point: an author
/// writes `#[record]` and the macro finds the codec, rather than the
/// protocol's crate graph appearing in the author's manifest.
pub use hyperscale_hbor as hbor;

pub mod blueprint;
#[cfg(not(component))]
pub mod client;
#[cfg(component)]
pub mod guest;
pub mod handle;
#[cfg(not(component))]
pub mod host;
pub mod num;
pub mod state;
pub mod sym;
pub mod trace;

pub use blueprint::{Blueprint, Builder, Method};
// Re-exported so `#[blueprint]` output names one crate, and so a contract
// never has to depend on `vm-effects` directly.
pub use hyperscale_vm_effects::vocabulary::{NF_VAULT, VAULT};
use hyperscale_vm_effects::{NOBODY_BYTES, always, never};

/// The granted entry anyone satisfies: the threshold over nothing.
///
/// Beside [`grant_nobody`] rather than an arm of its own, because the
/// algebra already carries a top and a bottom and a second spelling would
/// be a value an evaluator has to recognise as meaning something else.
#[must_use]
pub const fn grant_anyone() -> GrantRuleExpr {
    always()
}

/// The granted entry nobody satisfies: one of nothing.
#[must_use]
pub const fn grant_nobody() -> GrantRuleExpr {
    never()
}

/// The stored rule nobody satisfies, as a body writes one.
///
/// What a freeze writes, and the difference from removing the cell is
/// the whole of the freeze: an unwritten cell is what the address's own
/// key still governs, so a removal would hand the account back to the
/// key being frozen out.
///
/// # Panics
///
/// Never: the empty threshold is the smallest rule there is.
#[must_use]
pub fn nobody() -> RuleBytes {
    RuleBytes(NOBODY_BYTES.to_vec())
}

pub use hyperscale_vm_effects::{
    GrantClaim, GrantRuleExpr, GrantedBehaviour, GrantsExpr, Issued, LeafForm, ParamType,
    ResourceKind, RuleBytes, SlotId, SlotKind, encode_metadata,
};
/// The declaration binary a package crate ships: one line, and the
/// whole of it.
///
/// `cargo hyperscale build` gets a package's declaration by running this
/// binary and reading the canonical section bytes it prints. Running it
/// is what keeps the tracer the single implementation of what a
/// declaration means — the macro emits tracer calls rather than `Expr`
/// literals, so the declaration is derived by the same code a test
/// derives it with.
///
/// The path is the `#[blueprint]` module's, qualified by the crate that
/// holds it, because a binary is compiled beside its library and reaches
/// it by name:
///
/// ```ignore
/// // src/bin/lottery-metadata.rs
/// hyperscale_vm_sdk::declaration_main!(lottery_guest::lottery);
/// ```
///
/// The file is named for the package rather than for what it does,
/// because binaries share a name space with everything built beside
/// them and `metadata` is what every package would call its own.
#[macro_export]
macro_rules! declaration_main {
    ($($module:ident)::+) => {
        fn main() {
            use ::std::io::Write as _;

            let metadata = $($module)::+::blueprint().metadata();
            let bytes =
                $crate::encode_metadata(&metadata).expect("a traced declaration encodes");
            ::std::io::stdout()
                .write_all(&bytes)
                .expect("write the declaration");
        }
    };
}

/// Author a package from one module.
///
/// Which halves this yields is the compiling crate's own: a crate that
/// publishes the package says so with the `guest` feature and gets the
/// executing component beside the declaration, and every other consumer
/// gets the declaration and the call surface on whatever target it is
/// built for.
#[cfg(all(feature = "macros", not(feature = "guest")))]
pub use hyperscale_vm_sdk_macros::blueprint;
#[cfg(all(feature = "macros", feature = "guest"))]
pub use hyperscale_vm_sdk_macros::blueprint_publisher as blueprint;
pub use hyperscale_vm_types::{
    Address, CallTarget, ComponentAddr, PackageAddr, PrincipalAddr, ResourceAddr,
};
pub use sym::{Addr, Blob, Bucket, Flag, Key, Kind, Opaque, Seq, Sym, U64, U128};
pub use trace::{Access, Interval, Leaf, Requirement, Trace};

/// Narrow a rebuilt address to the class-typed form a parameter names.
///
/// Called by generated prologues on both targets. A parameter's kind
/// declares the classes it admits and admission refuses an argument
/// outside them, so for an argument the failure arm cannot arrive. A
/// configured address reaches a body on the word of the record that
/// wrote it, so a wrong class there is a defect of the instantiation and
/// the trap is the deterministic answer to it.
///
/// # Panics
///
/// Natively, on that wrong-class configured address. The wasm arm traps
/// bare instead, because a formatting path linked into every package
/// would price an impossibility.
#[inline]
#[must_use]
pub fn narrowed<T: TryFrom<Address>>(address: Address) -> T {
    T::try_from(address).unwrap_or_else(|_| {
        #[cfg(component)]
        ::core::arch::wasm32::unreachable();
        #[cfg(not(component))]
        panic!("a wrong-class address reached a narrowed binding")
    })
}

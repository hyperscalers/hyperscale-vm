//! The contract SDK: blueprint declarations traced into package metadata.
//!
//! Two halves of one vocabulary. On the host, [`state`] is read rather
//! than run: `#[blueprint]` traces a body written in it and gets back
//! exactly the [`hyperscale_vm_effects::MethodSignature`] routing needs,
//! against the real evaluator rather than a model of it. On the guest the
//! same types are the calls — [`guest`] binds `hyperscale:kernel` once,
//! and each accessor is the import its mode names.
//!
//! One vocabulary rather than two is the whole of it: a body cannot reach
//! state except through these types, so the declaration a host build
//! derives and the calls a guest build makes are read off the same text.
//!
//! # The shape
//!
//! ```
//! use hyperscale_vm_effects::{ParamType, RoleId};
//! use hyperscale_vm_sdk::{Blueprint, sym::{Addr, Amount, Bucket, Seq, Sym}};
//!
//! const VAULT: RoleId = RoleId(1);
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
//!         let config: Sym<_> = pool.child(RoleId(0), &[]);
//!         t.point(&config).locked();
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
//! # Why tracing rather than macros
//!
//! The obvious approach — a proc macro over the method body — cannot work
//! for the field that matters. Recovering [`hyperscale_vm_effects::Clause`]
//! trees from contract code is abstract interpretation of a Turing-complete
//! language into a deliberately weaker one: undecidable in general, and
//! quiet when it fails. So the author writes the declaration separately,
//! and the SDK runs it once with symbolic inputs. See [`trace`].
//!
//! What this costs the author is real and inherent, not a gap the SDK could
//! close with more cleverness: keys must be *stated*, because routing runs
//! before execution and state-free, so a key the body computes is a key
//! that arrives too late to route on. Tracing makes stating it look like
//! Rust; it does not make it inferred.
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
//!     use hyperscale_vm_sdk::state::{Amount, Cell, Keyed};
//!
//!     #[state]
//!     struct Bad {
//!         #[role(1)] vaults: Keyed<Amount>,
//!         #[role(2)] pointer: Cell<Address>,
//!     }
//!
//!     impl Bad {
//!         pub fn drain(&mut self) {
//!             // The key is a substate value, so no shard can name it
//!             // before executing — which is exactly when it is needed.
//!             let target = self.pointer.get();
//!             self.vaults.at(target).add(1);
//!         }
//!     }
//! }
//! ```
//!
//! A range whose entry cap is not a literal — the cap bounds the work
//! execution may do, so it is declaration, not data:
//!
//! ```compile_fail
//! # use hyperscale_vm_sdk::blueprint;
//! #[blueprint]
//! mod bad {
//!     use hyperscale_vm_sdk::state::Ordered;
//!
//!     #[state]
//!     struct Bad {
//!         #[role(4)] asks: Ordered<u128>,
//!     }
//!
//!     impl Bad {
//!         pub fn sweep(&mut self, cap: u64) {
//!             let mut window = self.asks.range(0, 100, cap as u32);
//!             window.remove(0);
//!         }
//!     }
//! }
//! ```
//!
//! A state field with no role, which would let a field reorder silently
//! move an instance's whole state:
//!
//! ```compile_fail
//! # use hyperscale_vm_sdk::blueprint;
//! #[blueprint]
//! mod bad {
//!     use hyperscale_vm_sdk::state::{Amount, Keyed};
//!
//!     #[state]
//!     struct Bad {
//!         vaults: Keyed<Amount>,
//!     }
//!
//!     impl Bad {}
//! }
//! ```
//!
//! # Why a wrong declaration is not a safety problem
//!
//! `hyperscale:kernel/state` has no open-cell-by-key import. Every accessor
//! takes a `borrow` the kernel materialized, and each mode is its own
//! resource type. A method that under-declares does not get an unchecked
//! access — it gets a handle that does not exist. So the tracer's
//! correctness governs whether a contract *works*, not whether the VM
//! holds, which is what makes generated metadata acceptable inside a
//! content-addressed package at all.

pub mod blueprint;
#[cfg(target_arch = "wasm32")]
pub mod guest;
pub mod state;
pub mod sym;
pub mod trace;

pub use blueprint::{Blueprint, Builder, HandlePlan, HandleShape, Method, TargetShape};
// Re-exported so `#[blueprint]` output names one crate, and so a contract
// never has to depend on `vm-effects` directly.
pub use hyperscale_vm_effects::{Address, AuthRole, ParamType, RoleId};
#[cfg(feature = "macros")]
pub use hyperscale_vm_sdk_macros::blueprint;
pub use sym::{Addr, Amount, Blob, Bucket, Key, Kind, Num, Opaque, Seq, Sym};
pub use trace::{Access, Trace};

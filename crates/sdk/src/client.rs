//! What a generated `client` wrapper is written against.
//!
//! `#[blueprint]` emits a `client` module beside the component and the
//! dispatch, and those wrappers name a builder, a proof, the argument
//! traits and — for a package whose instances are created — a handle
//! over the address one sits at. A guest crate depends on this crate and
//! on nothing else, so the names arrive through here rather than through
//! an edge every package would have to declare.
//!
//! Off the guest build alone. A wasm artifact composes no manifest, so
//! the wrappers are gated out of it, which is what makes emitting them
//! move no package hash and no blob.

pub use hyperscale_vm_effects::{
    Hasher, PackageMetadata, RoleTable, SlotId, StoredRule, Value as ManifestValue,
};
use hyperscale_vm_effects::{ResourceKind, SealedRulesExpr, Value, sealed_issued_resource};
pub use hyperscale_vm_manifest_builder::{
    AddressArg, Arg, Args, Bucket, BucketArg, Outputs, Proof, TypedBuilder, TypedError,
};
pub use hyperscale_vm_types::{
    Address, CallTarget, ComponentAddr, PackageAddr, PrincipalAddr, ResourceAddr,
};

use crate::num::{Quantity, UnitFixed};
use crate::state::Table;

/// The address a component issues a resource at, under one mark.
///
/// The derivation the routed grant lowers through, reached from a
/// handle rather than restated: the hasher is the protocol's, the
/// instance is the handle's, and the kind, the mark and the rules the
/// address folds are the declaration's. A call site that restated any
/// of them and got one wrong would name a vacant sibling address —
/// nothing is minted there, so nothing fails, and a gate reading it
/// reads an empty vault.
///
/// # Panics
///
/// If the declared rules do not resolve against `config` — which the
/// generated helper's own signature is what prevents, since it asks for
/// the configuration exactly where the rules name one.
#[must_use]
pub fn issued_at(
    hasher: &dyn Hasher,
    instance: impl Into<Address>,
    kind: ResourceKind,
    mark: &[u8],
    seals: &SealedRulesExpr,
    config: &[Value],
) -> ResourceAddr {
    let instance = instance.into();
    let rules = seals
        .resolve(hasher, instance, config)
        .expect("a declared sealed set resolves against its own configuration");
    sealed_issued_resource(hasher, instance, kind, &rules, mark)
}

/// A component known to run one package.
///
/// An instance address folds in the hash of the package that serves it,
/// so "this address runs that code" is a fact something can hold rather
/// than a hope a call site carries. The handle is that fact: reached by
/// creating the instance, or by adopting an address against a registry
/// that agrees, and never by asserting it.
///
/// Only a *component* can have one. A principal's address derives from a
/// key and folds in no package hash, so the account that answers every
/// principal is reached through [`PrincipalAddr`] itself — there is
/// nothing a newtype over one could check.
pub trait Component: Copy {
    /// What the instance was created under, named as the package spells
    /// it rather than as a tuple of slots.
    type Config: ConfigValues;

    /// The package's declaration, as its own module traces it.
    fn metadata() -> PackageMetadata;

    /// The handle at `address`, taken on trust.
    ///
    /// The unchecked half, for a holder that established the fact some
    /// other way — a chain that just created the instance. A caller
    /// starting from a bare address wants the checked adoption its host
    /// tier offers instead.
    fn at(address: ComponentAddr) -> Self;

    /// Where the instance sits.
    fn address(self) -> ComponentAddr;
}

/// An instance's creation-fixed configuration, as the thing creating it
/// writes one.
///
/// The kernel's form is a list of evaluated values in declaration order.
/// A package that declares a configuration struct has the macro answer
/// this for it, in field order; a package written the long way answers
/// it with the tuple it would have written anyway.
pub trait ConfigValues {
    /// The slots, in the order the package declares them.
    fn values(self) -> Vec<Value>;
}

/// One Rust value as the configuration slot it fills.
///
/// The slots a package declares are a fixed positional list, and what
/// fills one is an ordinary value with an ordinary type. This is the
/// conversion between the two, and it exists rather than `From<_> for
/// Value` because the value model is the manifest's and admits shapes —
/// tuples, lists, keys — that no configuration slot holds.
pub trait IntoSlot {
    /// The value this fills its slot with.
    fn into_slot(self) -> Value;
}

impl IntoSlot for Value {
    fn into_slot(self) -> Value {
        self
    }
}

/// A judgment fills a slot as itself.
///
/// The kind a configuration slot holds is gated nowhere — the values are
/// depth-bounded and otherwise the creator's — so a boolean policy fixed
/// at creation is a slot like any other, and an [`Expr::If`] over it is
/// how a package reads one. It cannot leak into a body: routing refuses a
/// derived guest argument that evaluates to a boolean whatever expression
/// produced it, a configuration slot included.
///
/// [`Expr::If`]: hyperscale_vm_effects::Expr::If
impl IntoSlot for bool {
    fn into_slot(self) -> Value {
        Value::Bool(self)
    }
}

impl IntoSlot for u64 {
    fn into_slot(self) -> Value {
        Value::U64(self)
    }
}

impl IntoSlot for u128 {
    fn into_slot(self) -> Value {
        Value::U128(self)
    }
}

macro_rules! address_slots {
    ($($ty:ty),* $(,)?) => {
        $(
            impl IntoSlot for $ty {
                fn into_slot(self) -> Value {
                    Value::Address(self.into())
                }
            }
        )*
    };
}

address_slots!(Address, ComponentAddr, PrincipalAddr, ResourceAddr);

/// A table fills its slot as the list of pairs the DSL's `Lookup` and
/// `Contains` walk — one slot, whatever the row count.
impl<K: IntoSlot, V: IntoSlot> IntoSlot for Table<K, V> {
    fn into_slot(self) -> Value {
        Value::List(
            self.into_rows()
                .into_iter()
                .map(|(key, value)| Value::Tuple(vec![key.into_slot(), value.into_slot()]))
                .collect(),
        )
    }
}

/// A bounded fraction fills a slot as the scaled integer it carries,
/// which is the form the leaf holds and a body reads back.
impl IntoSlot for UnitFixed {
    fn into_slot(self) -> Value {
        Value::U128(self.scaled())
    }
}

impl IntoSlot for Quantity {
    fn into_slot(self) -> Value {
        Value::U128(self.subunits())
    }
}

impl ConfigValues for Vec<Value> {
    fn values(self) -> Vec<Value> {
        self
    }
}

impl ConfigValues for () {
    fn values(self) -> Vec<Value> {
        Vec::new()
    }
}

macro_rules! config_tuples {
    ($(($($name:ident),+),)*) => {
        $(
            #[allow(non_snake_case)] // one binding per tuple position
            impl<$($name: IntoSlot),+> ConfigValues for ($($name,)+) {
                fn values(self) -> Vec<Value> {
                    let ($($name,)+) = self;
                    vec![$($name.into_slot()),+]
                }
            }
        )*
    };
}

config_tuples! {
    (A),
    (A, B),
    (A, B, C),
    (A, B, C, D),
    (A, B, C, D, E),
    (A, B, C, D, E, F),
}

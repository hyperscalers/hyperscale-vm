//! Effect signatures, the access DSL, and the routing fold.
//!
//! Access is a pure function of the signed transaction plus immutable
//! package metadata. Every callable method carries an effect signature — a
//! total function from its typed inputs to a declared `(key, mode)` set,
//! written in a restricted DSL: field projections, keyed lookups over input
//! values, canonical-address computation, bounded collection mapping, point
//! and range targets. Evaluation never reads state; the evaluator takes
//! arguments, creation-fixed instance configuration, and a hasher, and
//! nothing else.
//!
//! [`route`] folds signature evaluation over a manifest's nodes and returns
//! the transaction's routing: per-shard effect sets, snapshot proof
//! obligations, and the static call graph, whose acyclicity makes the
//! transitive effect fold a DAG fold.
//!
//! The crate is isolated: protocol hashing binds through the [`Hasher`]
//! seam, shard topology through [`ShardResolver`], and nothing here touches
//! the runtime or the protocol workspace.

pub mod dsl;
pub mod hash;
pub mod manifest;
pub mod metadata;
pub mod route;
pub mod types;

pub use dsl::{
    Clause, EvalError, EvalInputs, Expr, MAX_FOREACH_ELEMENTS, ModeExpr, TargetExpr, WindowExpr,
    evaluate_effects, evaluate_expr, fresh_id, fresh_local,
};
pub use hash::{Hash32, Hasher, TestHasher};
pub use manifest::{Manifest, ManifestHash, Node, NodeInput};
pub use metadata::{
    CallSite, InstanceMeta, InstanceRegistry, MetadataCache, MethodSignature, PackageHash,
    PackageMetadata,
};
pub use route::{
    CallEdge, CallGraph, MAX_CALL_EVALUATIONS, MethodRef, PrefixShardResolver, RouteError, Routing,
    ShardResolver, SnapshotObligation, route,
};
pub use types::{
    Address, Effect, EffectSet, EffectTarget, LocalKey, Mode, ModeKind, ReserveOverflow, RoleId,
    ShardId, SubstateKey, Value, Window, child_key, compatible,
};

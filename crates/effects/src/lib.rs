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
//! the transaction's routing: per-shard effect sets, the
//! obligations, and the static call graph, whose acyclicity makes the
//! transitive effect fold a DAG fold.
//!
//! The crate is isolated: protocol hashing binds through the [`Hasher`]
//! seam, shard topology through [`ShardResolver`], and nothing here touches
//! the runtime or the protocol workspace.

pub mod admission;
pub mod artifact;
pub mod dsl;
pub mod envelope;
pub mod footprint;
pub mod graph;
pub mod hash;
pub mod invoke;
pub mod manifest;
pub mod metadata;
pub mod route;
pub mod rule;
pub mod stdlib;
pub mod types;
pub mod vectors;

pub use admission::{AdmissionError, Admitted, MAX_YIELD_PARAMS, admit};
pub use artifact::{ArtifactError, METADATA_SECTION, attach_metadata, extract_metadata};
pub use dsl::{
    Clause, Declaration, EvalError, EvalInputs, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE,
    MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, ModeExpr, TargetExpr, evaluate_declaration,
    evaluate_effects, evaluate_expr, fresh_id, fresh_local,
};
pub use envelope::{
    AdmittedTree, EnvelopeTree, IntentDecl, MAX_SUBINTENTS, NULLIFIER_ROLE, Subintent,
    SubintentHash, SubintentRecord, YieldBinding, YieldParam, admit_tree, encode_tree,
    nullifier_key, route_tree,
};
pub use footprint::{
    EXCLUSIVITY_FLOOR, TARGET_UNITS, WIDTH_UNITS, effect_units, footprint, mode_weight, order_bits,
    span_units,
};
pub use graph::{
    Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, MAX_EVIDENCE_PER_NODE, ManifestGraph,
};
pub use hash::{Hash32, Hasher, TestHasher};
pub use hyperscale_vm_types::{
    AUTH_BYTE_WEIGHT, Event, FOOTPRINT_WEIGHT, FUEL_WEIGHT, MAX_CELL_VALUE_LEN,
    MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Outcome, SettledWrites,
    StateWrites, TX_UNITS, TxHash, VERIFY_WEIGHT, declared_work, signature_work, work_units,
};
pub use invoke::{CallArg, EDGE_CELL_BYTES, EdgeBound, NodeCall};
pub use manifest::{AuthorityGate, Bounds, Manifest, ManifestHash, Node, NodeInput};
pub use metadata::{
    AbiError, AbiParam, Accessibility, CallSite, DeclarationError, InstanceMeta, InstanceRegistry,
    MetadataCache, MethodSignature, PACKAGE_ROLE, PackageHash, PackageMetadata, ParamType,
    check_abi, check_declarations, package_hash, package_key,
};
pub use route::{
    CallEdge, CallGraph, FrameDeclaration, MAX_CALL_EVALUATIONS, MAX_MANIFEST_NODES, MethodRef,
    PrefixShardResolver, RouteError, Routing, ShardResolver, route,
};
pub use rule::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_WIRE_DEPTH, Rule};
pub use types::{
    Address, AddressClass, CallTarget, ComponentAddr, Effect, EffectSet, EffectTarget,
    InvalidAddress, LocalKey, MAX_VALUE_DEPTH, Mode, ModeKind, NativeAddr, NativeRole, NetworkWord,
    NotAResource, NotCallable, PackageAddr, PrincipalAddr, ReserveOverflow, ResourceAddr,
    ResourceRef, RoleId, SchemeId, ShardId, SubstateKey, TextError, Value, WrongClass, child_key,
    compatible, component_address, config_hash, native_address, package_address, principal_address,
    resource_address,
};

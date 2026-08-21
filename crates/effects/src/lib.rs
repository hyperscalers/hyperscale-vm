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
//! the transaction's routing: per-shard effect sets and the obligations.
//!
//! The crate is isolated: protocol hashing binds through the [`Hasher`]
//! seam, shard topology through [`ShardResolver`], and nothing here touches
//! the runtime or the protocol workspace.

pub mod admission;
pub mod artifact;
pub mod auth;
pub mod dsl;
pub mod envelope;
pub mod footprint;
pub mod graph;
pub mod hash;
pub mod instance;
pub mod invoke;
pub mod manifest;
pub mod metadata;
pub mod presented;
pub mod publish;
pub mod resource;
pub mod route;
pub mod rule;
pub mod signature;
pub mod star;
#[cfg(test)]
mod test_worlds;
pub mod types;
pub mod vectors;
pub mod vocabulary;

pub use admission::{AdmissionError, Admitted, MAX_YIELD_PARAMS, admit};
pub use artifact::{
    ArtifactError, METADATA_SECTION, METADATA_WIRE_DEPTH, attach_metadata, declaration_hash,
    decode_metadata, encode_metadata, extract_metadata, metadata_section,
};
pub use auth::{
    AuthBase, AuthCell, CONFIRMATION, MAX_AUTH_CELL_WIRE_DEPTH, MAX_PACKAGE_ROLES,
    MAX_ROLE_TABLE_WIRE_DEPTH, PACKAGE_ROLE_BASE, PRIMARY, Proposal, RECOVERY, RoleBytes, RoleId,
    RoleTable, package_role,
};
pub use dsl::{
    Clause, ConditionExpr, Declaration, DeclaredAccess, EvalError, EvalInputs, Expr,
    MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, ModeExpr,
    SealedResources, TargetExpr, evaluate_declaration, evaluate_effects, evaluate_expr, fresh_id,
    fresh_local, materialized_kind, self_child,
};
pub use envelope::{
    AdmittedTree, EnvelopeTree, IntentDecl, MAX_SUBINTENTS, NULLIFIER_SLOT, Subintent,
    SubintentHash, SubintentRecord, YieldBinding, YieldParam, admit_tree, encode_tree,
    nullifier_key, route_tree,
};
pub use footprint::{
    DEPTH_UNITS, EXCLUSIVITY_FLOOR, SCAN_SEEK_ENTRIES, TARGET_UNITS, WIDTH_UNITS, effect_units,
    footprint,
};
pub use graph::{
    Constraint, EdgeRef, EvidenceRef, GraphArg, GraphNode, MAX_EVIDENCE_PER_NODE, ManifestGraph,
};
pub use hash::{Hash32, Hasher, TestHasher};
pub use hyperscale_vm_types::{
    ABSENT_REP, ADDRESS_WORDS, AUTH_BYTE_WEIGHT, AbortReason, EntryKey, EntryLeaf, Event,
    FOOTPRINT_WEIGHT, FUEL_WEIGHT, ISSUER_REP, MAX_CELL_VALUE_LEN, MAX_ERROR_CODES,
    MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENTS_PER_TX, Outcome, SettledWrites,
    StateWrites, TX_UNITS, TxHash, VERIFY_WEIGHT, declared_work, entry_leaf_key, signature_work,
    work_units,
};
pub use instance::{InstanceMeta, InstanceRegistry, ResolveError};
pub use invoke::{CallArg, EdgeBound, NodeCall, distinct_ids};
pub use manifest::{Bounds, Condition, JudgedLeaf, Manifest, ManifestHash, Node, NodeInput};
pub use metadata::{
    MetadataCache, PACKAGE_SLOT, PackageHash, PackageMetadata, PublishRefusal, package_hash,
    package_key,
};
pub use presented::Presented;
pub use publish::{
    AbiError, CheckedSignature, DeclarationError, MetadataBoundsError, SignatureBoundsError,
    SignatureError, check_abi, check_declarations, check_metadata, check_signature, seal_clauses,
    seals,
};
pub use resource::{
    MAX_RESOURCE_MATERIAL_PARTS, RECORD_WIRE_DEPTH, ResourceKind, ResourceMeta, ResourceRecord,
    ResourceRules, SealedBehaviour, holdings_collection, holdings_entry, holdings_range,
    instance_data_key, issued_resource, resource_record_key, xrd,
};
pub use route::{
    FrameDeclaration, MAX_MANIFEST_NODES, PrefixShardResolver, Routing, ShardResolver, route,
};
pub use rule::{
    MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_WIRE_DEPTH, Rule, RuleExpr, RuleLeaf, StoredRule,
    well_formed,
};
pub use signature::{AbiParam, Issuance, MethodSignature, ParamType, Totality};
pub use star::{MAX_STAGED_DEPTH, Role, StarShape, Strategy, classify};
pub use types::{
    EdgeContent, KERNEL_SLOT_BASE, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, NativeRole,
    PACKAGE_SLOT_BASE, ShardId, SlotId, Value, child_key, collection_id, component_address,
    config_hash, native_address, order_key, package_address, package_slot, principal_address,
    resource_address, sealed_resource_address,
};

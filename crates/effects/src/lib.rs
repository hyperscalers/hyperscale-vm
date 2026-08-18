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
pub mod invoke;
pub mod manifest;
pub mod metadata;
pub mod presented;
pub mod resource;
pub mod route;
pub mod rule;
pub mod types;
pub mod vectors;
pub mod vocabulary;

pub use admission::{AdmissionError, Admitted, MAX_YIELD_PARAMS, admit};
pub use artifact::{
    ArtifactError, METADATA_SECTION, METADATA_WIRE_DEPTH, attach_metadata, declaration_hash,
    decode_metadata, encode_metadata, extract_metadata, metadata_section,
};
pub use auth::{
    AuthBase, AuthCell, AuthRole, MAX_AUTH_CELL_WIRE_DEPTH, MAX_ROLESET_WIRE_DEPTH, Proposal,
    RoleSet, StoredRoles,
};
pub use dsl::{
    Clause, Declaration, EvalError, EvalInputs, Expr, MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE,
    MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, MAX_RANGE_CAP, ModeExpr, TargetExpr,
    evaluate_declaration, evaluate_effects, evaluate_expr, fresh_id, fresh_local, self_child,
};
pub use envelope::{
    AdmittedTree, EnvelopeTree, IntentDecl, MAX_SUBINTENTS, NULLIFIER_SLOT, Subintent,
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
    AUTH_BYTE_WEIGHT, AbortReason, EntryKey, EntryLeaf, Event, FOOTPRINT_WEIGHT, FUEL_WEIGHT,
    ISSUER_REP, MAX_CELL_VALUE_LEN, MAX_ERROR_CODES, MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES,
    MAX_EVENTS_PER_TX, Outcome, SettledWrites, StateWrites, TX_UNITS, TxHash, VERIFY_WEIGHT,
    declared_work, entry_leaf_key, signature_work, work_units,
};
pub use invoke::{CallArg, EdgeBound, EdgeKind, NodeCall, cell_ids, ids_cell};
pub use manifest::{AuthorityGate, Bounds, Manifest, ManifestHash, Node, NodeInput, Possession};
pub use metadata::{
    AbiError, AbiParam, Accessibility, CustodyClaim, DeclarationError, GateShape, InstanceMeta,
    InstanceRegistry, MetadataBoundsError, MetadataCache, MethodSignature, PACKAGE_SLOT,
    PackageHash, PackageMetadata, ParamType, Totality, check_abi, check_declarations,
    check_metadata, package_hash, package_key,
};
pub use presented::Presented;
pub use resource::{
    Fungibility, ResourceRecord, holdings_collection, holdings_entry, holdings_range,
    instance_data_key, resource_record_key,
};
pub use route::{
    FrameDeclaration, MAX_MANIFEST_NODES, MAX_STAGED_DEPTH, MethodRef, PrefixShardResolver, Role,
    RouteError, Routing, ShardResolver, Strategy, route,
};
pub use rule::{MAX_RULE_BRANCHES, MAX_RULE_DEPTH, MAX_RULE_WIRE_DEPTH, Rule, RuleExpr};
pub use types::{
    Address, AddressClass, CallTarget, CollectionId, ComponentAddr, EdgeContent, Effect,
    EffectConflict, EffectSet, EffectTarget, InvalidAddress, LocalKey, MAX_IDS_PER_EDGE,
    MAX_VALUE_DEPTH, Mode, ModeKind, NativeAddr, NativeRole, NetworkWord, NotAResource,
    NotCallable, PACKAGE_SLOT_BASE, PackageAddr, Presence, PrincipalAddr, ResourceAddr,
    ResourceRef, SchemeId, ShardId, SlotId, SubstateKey, TextError, Value, WrongClass, child_key,
    collection_id, compatible, component_address, config_hash, native_address, order_key,
    package_address, package_slot, principal_address, resource_address,
};

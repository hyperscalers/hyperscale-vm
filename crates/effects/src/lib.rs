//! Effect signatures, the access DSL, and the routing fold.
//!
//! Capability is a pure function of the signed transaction plus immutable
//! package metadata. Every callable method carries an effect signature — a
//! total function from its typed inputs to a declared `(key, mode)` set,
//! written in a restricted DSL: field projections, keyed lookups over input
//! values, canonical-address computation, bounded collection mapping, point
//! and range targets. Evaluation never reads state; the evaluator takes
//! arguments, creation-fixed instance configuration, and a hasher, and
//! nothing else.
//!
//! Admission folds signature evaluation over a manifest's nodes, so an
//! [`Admitted`] carries the transaction's whole declaration — the folded
//! effect set and the clause order — beside its lowered calls.
//!
//! The crate is isolated: protocol hashing binds through the [`Hasher`]
//! seam, shard topology through [`ShardResolver`], and nothing here touches
//! the runtime or the protocol workspace.

pub mod admission;
pub mod artifact;
pub mod auth;
pub mod cells;
pub mod claim;
pub mod dsl;
pub mod explain;
pub mod footprint;
pub mod graph;
pub mod hash;
pub mod instance;
pub mod intent;
pub mod invoke;
pub mod manifest;
pub mod metadata;
pub mod publish;
pub mod records;
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

pub use admission::{
    AdmissionError, Admitted, Asks, Injected, MAX_SOCKETS, NodeOrigin, Placed, check_structure,
};
pub use artifact::{
    ArtifactError, METADATA_SECTION, METADATA_WIRE_DEPTH, attach_metadata, declaration_hash,
    decode_metadata, encode_metadata, extract_metadata, metadata_section,
};
pub use auth::{Authority, PrincipalRule, RuleBytes, auth_cell_admits};
pub use cells::{
    COMMITTED_TX_SLOT, CROSSING_CELL_BYTES, CROSSING_CLAIM_CELL_BYTES, CROSSING_CLAIM_SLOT,
    CrossingCell, CrossingClaim, CrossingSite, ESCROW_RECORD_SLOT, Kind, MARKER_CELL_BYTES, Marked,
    Marker, NULLIFIER_SLOT, Terms, committed_tx_key, crossing_claim_key, crossing_expiry_ms,
    escrow_record_key, nullifier_expiry_ms, nullifier_key,
};
pub use claim::Claim;
pub use dsl::{
    Clause, Condition, Declaration, DeclaredAccess, EvalBudget, EvalError, EvalInputs, Expr,
    MAX_CLAUSE_DEPTH, MAX_EFFECTS_PER_SIGNATURE, MAX_ENVELOPE_EVALUATION_WORK, MAX_EVALUATION_WORK,
    MAX_EXPR_DEPTH, MAX_FOREACH_ELEMENTS, ModeExpr, PresentedGrants, Reach, SlotRef, TargetExpr,
    evaluate_declaration, evaluate_effects, evaluate_expr, fresh_id, fresh_local, keying_resource,
    self_child, supports,
};
pub use explain::{
    address_text, claim_text, explain, explain_admission, explain_admission_tree, explain_method,
    explain_refusal, explain_requirements, explain_resource, grants_read_config,
};
pub use footprint::{
    DEPTH_UNITS, EXCLUSIVITY_FLOOR, SCAN_SEEK_ENTRIES, SPAN_UNITS, TARGET_UNITS, effect_units,
    footprint,
};
pub use graph::{
    ClaimRef, Constraint, EdgeRef, GiveRef, GraphArg, GraphNode, MAX_EVIDENCE_PER_NODE,
    ManifestGraph, ValueRef,
};
pub use hash::{Hash32, Hasher, TestHasher};
pub use hyperscale_vm_types::{
    ABSENT_REP, AbortReason, Address, AddressClass, Answer, BASIS_POINTS, DeclaredWork, EntryKey,
    EntryLeaf, Event, IntentHash, LegRole, LegShape, MAX_ANSWER_BYTES, MAX_ARTIFACT_BYTES,
    MAX_CALL_BYTES, MAX_CELL_VALUE_LEN, MAX_ERROR_CODES, MAX_EVENT_BYTES_PER_TX,
    MAX_EVENT_PAYLOAD_BYTES, MAX_EVENT_TYPES, MAX_EVENT_TYPES_PER_METHOD, MAX_EVENTS_PER_TX,
    MAX_MANIFEST_NODES, Outcome, PriceTable, ProtocolHasher, SettledWrites, StateWrites, TxHash,
    VERIFY_WEIGHT, ValueEdge, entry_leaf_key, signature_bytes, signature_compute,
};
pub use instance::{InstanceMeta, InstanceRegistry, ResolveError};
pub use intent::{
    Binding, Intent, IntentHeader, IntentRecord, IntentTree, MAX_ACCOUNTS, MAX_INTENTS,
    MAX_TREE_DEPTH, Member, Nullifier, SignedIntent, Socket, TREE_WIRE_DEPTH, TreeDecodeError,
    admit_tree, attest, decode_tree, encode_tree,
};
pub use invoke::{CallArg, EdgeBound, IssuanceGrant, NodeCall, distinct_ids};
pub use manifest::{Bounds, JudgedLeaf, Manifest, ManifestHash, Node, NodeInput};
pub use metadata::{
    DeclaredPackages, MetadataCache, PACKAGE_SLOT, PackageHash, PackageMetadata, PublishRefusal,
    SlotKind, SlotShape, SlotWidths, package_hash, package_key, reserved_shape,
};
pub use publish::{
    AbiError, CheckedMetadata, CheckedSignature, DeclarationError, MetadataError, PlacedBounds,
    ResourceSite, SignatureBoundsError, SignatureError, SignatureSite, check_abi,
    check_declarations, check_metadata, check_signature, founds_its_resource,
    presents_a_held_badge, seal_clauses, seals,
};
pub use records::{ChainRecords, Composed, Records, issued_record};
pub use resource::{
    GrantedBehaviour, GrantsExpr, GrantsResolveError, MAX_RESOURCE_MATERIAL_PARTS, ReachedCell,
    ResourceGrants, ResourceKind, ResourceMeta, ResourceRecord, granting_issued_resource,
    holdings_collection, holdings_entry, holdings_range, instance_data_key, issued_resource,
    protocol_resource, resource_record_key,
};
pub use route::{FrameDeclaration, PrefixShardResolver, ShardResolver, per_shard};
pub use rule::{
    ANYBODY_BYTES, GrantRuleExpr, GrantSubject, Holding, Judged, Leaf, MAX_RULE_BRANCHES,
    MAX_RULE_DEPTH, MAX_RULE_LEAVES, MAX_RULE_WIRE_DEPTH, NOBODY_BYTES, Rule, RuleExpr, RuleLeaf,
    SealedLeaf, StoredRule, always, never, well_formed,
};
pub use signature::{
    AbiParam, Issuance, Issued, MAX_ISSUANCES_PER_SIGNATURE, MAX_PROVEN_PER_SIGNATURE,
    MethodSignature, ParamType, Totality,
};
pub use star::{CrossingEdge, Star, legs_of, running_at, star_at};
pub use types::{
    EdgeContent, KERNEL_SLOT_BASE, MAX_IDS_PER_EDGE, MAX_VALUE_DEPTH, PACKAGE_SLOT_BASE, ShardId,
    SlotId, Value, bucketed_child_key, child_key, collection_id, component_address, config_hash,
    genesis_publisher, granting_resource_address, order_key, package_address, package_slot,
    principal_address, resource_address, u256_decimal,
};

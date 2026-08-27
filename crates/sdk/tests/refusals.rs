//! What the authoring vocabulary refuses, and where the message lands.
//!
//! Most cases are the macro's: a body whose declaration would come out
//! *smaller* than what the body does if the lowering guessed — a dropped
//! effect, a stale key, an output the tail never declared. The macro's
//! contract is that its only failure mode is a hard error on the
//! offending line, so these pin the line as much as the refusal.
//!
//! The rest are the declaring types' own, where nothing is guessing at
//! anything: a target that does not offer what is being reached for, so
//! the compiler answers before the macro has an opinion. Same
//! instrument, same pinned line.

use trybuild::TestCases;

#[test]
fn the_lowering_refuses_what_it_cannot_see_into() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/self_call.rs");
    refuse.compile_fail("tests/refusals/unmodelled_handle_op.rs");
    refuse.compile_fail("tests/refusals/self_escape.rs");
    refuse.compile_fail("tests/refusals/closure.rs");
    refuse.compile_fail("tests/refusals/unwalkable_macro.rs");
    refuse.compile_fail("tests/refusals/nested_loop.rs");
    refuse.compile_fail("tests/refusals/looped_instance_walk.rs");
    refuse.compile_fail("tests/refusals/element_in_derived_value.rs");
    refuse.compile_fail("tests/refusals/loopless_loop.rs");
    refuse.compile_fail("tests/refusals/uncrossable_sequence.rs");
    refuse.compile_fail("tests/refusals/untyped_credit.rs");
}

/// Not a lowering refusal but a type: an interval names no leaf a write
/// lands on, so it offers no requirement about one, and the hand-written
/// declaration path meets the same rule the macro path meets by
/// construction.
#[test]
fn the_tracer_offers_a_presence_only_where_a_leaf_is_named() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/interval_presence.rs");
}

/// Nothing but the kernel writes a seal cell.
///
/// The epoch a seal records is the whole of its commitment — a body that
/// named one could name an epoch already rolled, whose seed is public,
/// and open onto a word it had computed before deciding to seal. Two
/// things stand in front of that and the compiler answers with the
/// first: `Seal` is not a `Record`, so every generic write a cell
/// offers — `create`, `set` — wants a bound it does not satisfy (said
/// once per accessor tier, cell and slot); and it carries nothing an
/// author can reach, so there is no seal a body can make. `seal` is
/// what is left, and it takes no epoch.
#[test]
fn the_vocabulary_refuses_a_seal_a_body_wrote_itself() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/written_seal.rs");
}

/// A leaf a body reads as absent is not a leaf that body writes, in
/// either order.
///
/// The pair is unordered because the mode a site resolves to is: a
/// declaration emitted from one of the two would be a declaration the
/// body's other half contradicts, and which half a hand happened to type
/// first decides nothing.
#[test]
fn the_lowering_refuses_a_fresh_read_beside_a_write_of_one_leaf() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/write_after_vacant.rs");
    refuse.compile_fail("tests/refusals/vacant_after_write.rs");
}

/// One draw, one selection. Two picks off a single draw are perfectly
/// correlated — a winner and a prize tier reduced from the same word
/// land together — and the draw is consumed so the second one has
/// nothing to reach for. A body meaning two independent selections says
/// so with two draws.
#[test]
fn a_draw_selects_once() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/reused_draw.rs");
}

#[test]
fn the_lowering_refuses_what_it_would_declare_wrongly() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/aliased_slot.rs");
    refuse.compile_fail("tests/refusals/denominated_slot.rs");
    refuse.compile_fail("tests/refusals/mixed_pinning.rs");
    refuse.compile_fail("tests/refusals/protocol_slot.rs");
    refuse.compile_fail("tests/refusals/mode_mix.rs");
    refuse.compile_fail("tests/refusals/presence_mix.rs");
    refuse.compile_fail("tests/refusals/reassigned_key.rs");
    refuse.compile_fail("tests/refusals/branched_key.rs");
    refuse.compile_fail("tests/refusals/mixed_selection.rs");
    refuse.compile_fail("tests/refusals/branched_arm.rs");
    refuse.compile_fail("tests/refusals/early_return_output.rs");
    refuse.compile_fail("tests/refusals/two_denominations.rs");
    refuse.compile_fail("tests/refusals/assigned_balance.rs");
    refuse.compile_fail("tests/refusals/undenominated_vault.rs");
    refuse.compile_fail("tests/refusals/keyed_denomination.rs");
    refuse.compile_fail("tests/refusals/nf_vault_field.rs");
    refuse.compile_fail("tests/refusals/nf_ops_on_unit.rs");
    refuse.compile_fail("tests/refusals/capless_interval.rs");
    refuse.compile_fail("tests/refusals/underivable_all_cap.rs");
    refuse.compile_fail("tests/refusals/minted_into_foreign.rs");
    refuse.compile_fail("tests/refusals/minted_wrong_kind.rs");
    refuse.compile_fail("tests/refusals/unmarked_mint.rs");
    refuse.compile_fail("tests/refusals/instance_of_undeclared.rs");
    refuse.compile_fail("tests/refusals/overstated_record.rs");
    refuse.compile_fail("tests/refusals/emitted_record_carries_a_length.rs");
    refuse.compile_fail("tests/refusals/colliding_marks.rs");
    refuse.compile_fail("tests/refusals/rebalanced_across.rs");
    refuse.compile_fail("tests/refusals/merged_across.rs");
    refuse.compile_fail("tests/refusals/burned_foreign.rs");
    refuse.compile_fail("tests/refusals/burned_wrong_kind.rs");
    refuse.compile_fail("tests/refusals/recalled_wrong_kind.rs");
    refuse.compile_fail("tests/refusals/bare_mint_with_record.rs");
    refuse.compile_fail("tests/refusals/fielded_mint_without_record.rs");
    refuse.compile_fail("tests/refusals/fielded_fungible.rs");
    refuse.compile_fail("tests/refusals/renamed_onto_the_seal.rs");
    refuse.compile_fail("tests/refusals/grant_chains_two_badges.rs");
    refuse.compile_fail("tests/refusals/instance_of_a_balance.rs");
    refuse.compile_fail("tests/refusals/supply_of_a_schema.rs");
    refuse.compile_fail("tests/refusals/bare_instance_read.rs");
    refuse.compile_fail("tests/refusals/fungible_instance_read.rs");
    refuse.compile_fail("tests/refusals/held_foreign_edge.rs");
    refuse.compile_fail("tests/refusals/burned_what_it_minted.rs");
    refuse.compile_fail("tests/refusals/ungranted_mint.rs");
    refuse.compile_fail("tests/refusals/ungranted_burn.rs");
    refuse.compile_fail("tests/refusals/ungranted_halt.rs");
    refuse.compile_fail("tests/refusals/ungranted_recall.rs");
    refuse.compile_fail("tests/refusals/renamed_state.rs");
}

/// A mark the macro can already tell is unsupportable, refused where the
/// author wrote it rather than at the publish gate.
///
/// The artifact scan belongs to the gate, because it reads compiled code
/// the macro has not produced yet. What a gate does is not: the attribute
/// sits right beside the claim, and a refusal that waits for a publish is
/// one the author meets as a metadata error about a package rather than
/// as a mistake on a line.
#[test]
fn the_lowering_refuses_a_mark_it_can_see_is_wrong() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/total_gated.rs");
    refuse.compile_fail("tests/refusals/name_restates_the_derivation.rs");
}

/// A gate names an identity its target names, at every leaf.
///
/// A caller who names the claim they must present can always present
/// it, so one caller-named branch of a threshold is one branch the
/// caller satisfies for free — which is why every leaf answers rather
/// than the root alone.
#[test]
fn the_lowering_refuses_authority_a_caller_names() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/caller_named_branch.rs");
    refuse.compile_fail("tests/refusals/caller_named_threshold.rs");
}

/// A `#[proves]` parameter is held to the type the emitted read gives
/// it: an address for the badge, a `u64` for the instance id. The
/// alternative is a package that compiles and traps at its first call,
/// with no method name and no line.
#[test]
fn the_lowering_refuses_a_mistyped_proof_parameter() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/mistyped_badge.rs");
    refuse.compile_fail("tests/refusals/mistyped_badge_id.rs");
}

/// A refusal crosses the boundary as a bare code, so a fielded
/// `#[error]` variant is refused on the variant's own line — not left
/// to a cast error spanned at `#[blueprint]`.
#[test]
fn the_lowering_refuses_a_fielded_error_variant() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/fielded_error.rs");
}

/// A variant's code is its place in the error table, which spans the
/// module's `#[error]` enums in declaration order. A discriminant names
/// a different figure than the one the decline crosses as, so it is
/// refused where it was written.
#[test]
fn the_lowering_refuses_a_discriminated_error_variant() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/discriminated_error.rs");
}

/// A decline arm names one of the package's `#[error]` enums — any
/// other type holds no place in the error table, and the cast would
/// otherwise surface as an opaque trait error inside generated code.
#[test]
fn the_lowering_refuses_a_decline_arm_outside_the_error_table() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/undeclared_decline.rs");
}

/// Each item marker lands on one item kind, and the scans read exactly
/// that kind — a marker on the wrong one would be silently stripped
/// with nothing declared.
#[test]
fn the_lowering_refuses_a_marker_on_the_wrong_item_kind() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/config_enum.rs");
    refuse.compile_fail("tests/refusals/error_struct.rs");
}

/// A gate on a private method guards nothing: only `pub` methods lower,
/// and the attribute would be silently stripped with the export the
/// author thought they were guarding.
#[test]
fn the_lowering_refuses_a_gate_on_a_private_method() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/private_gated.rs");
}

/// A gate in another type's impl block guards nothing either: only the
/// state struct's own methods lower, and the attribute would be
/// silently stripped with the export the author thought they wrote.
#[test]
fn the_lowering_refuses_a_gate_outside_the_state_impl() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/foreign_gated.rs");
}

/// A published name names one export. The collision the `instantiate`
/// check already caught for the seal is every name's hazard, and it
/// refuses at the line that wrote it rather than panicking inside the
/// generated `blueprint()`.
#[test]
fn the_lowering_refuses_a_published_name_collision() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/colliding_name.rs");
}

/// A method carries one gate.
///
/// The gate attributes are collected before any is read, so a second one
/// — a `#[proves]` beside a `#[requires]`, or the same attribute twice —
/// is refused with both spans on the line. Reading the first and
/// stripping the rest would enforce less than the author wrote, without
/// a word.
#[test]
fn the_lowering_refuses_a_second_gate() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/two_gates.rs");
    refuse.compile_fail("tests/refusals/duplicate_requires.rs");
}

/// One `#[state]` struct, one `#[config]` struct.
///
/// Each names a namespace that is one namespace — the slot table, the
/// configuration fields — so a second struct is refused with both spans
/// rather than merged under the shared slot counter or silently
/// shadowing the first. The split-pinning case pins that the refusal
/// also closes the way around the pin-all-or-none discipline, which is
/// judged per struct.
#[test]
fn the_lowering_refuses_a_second_marker_struct() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/duplicate_state.rs");
    refuse.compile_fail("tests/refusals/duplicate_config.rs");
    refuse.compile_fail("tests/refusals/split_pinning.rs");
}

/// Possession is not a rule leaf, at any depth.
///
/// `#[requires]` is a match over presented claims and `#[proves]` is
/// where possession is spelled, so a `holds` conjoined beside a rule is
/// refused on the same terms as one nested inside a threshold or a
/// disjunction: admitting any of them makes authority a predicate
/// engine.
#[test]
fn the_lowering_refuses_possession_inside_a_rule() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/holds_in_a_rule.rs");
    refuse.compile_fail("tests/refusals/holds_beside_a_rule.rs");
    refuse.compile_fail("tests/refusals/nested_holds.rs");
    refuse.compile_fail("tests/refusals/holds_under_a_branch.rs");
}

/// A gate leaf names one authority.
///
/// A badge the package issues and an address fixed at creation are
/// different claims, and they have different spellings — so a bare name
/// is refused wherever a leaf is read, in the gate and in a grant alike,
/// and the refusal names the spelling that would have worked.
///
/// One name for both used to be the ambiguity worth its own refusal.
/// Two spellings make it unrepresentable.
#[test]
fn the_lowering_refuses_a_leaf_spelled_as_a_bare_name() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/bare_config_name.rs");
    refuse.compile_fail("tests/refusals/bare_badge_name.rs");
    refuse.compile_fail("tests/refusals/bare_grant_name.rs");
}

/// One rule grammar, and the position it was written in is the only
/// difference a refusal shows.
///
/// A gate and a granted entry take the same operators over the same
/// leaves, and used to take them through two parsers that had already
/// drifted — two spellings of the depth cap, two count parsers, one
/// `n_of` predicate applied from two places. These two cases sit either
/// side of the seam: a count that is not a literal, and a nesting past
/// the cap in the position that is not the gate.
#[test]
fn one_rule_grammar_serves_the_gate_and_the_grant() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/countless_threshold.rs");
    refuse.compile_fail("tests/refusals/granted_nests_too_deep.rs");
}

/// A threshold the vocabulary holds no rule for, refused where it was
/// written.
///
/// A count of nothing admits everyone and a count past the claims it
/// counts admits no one, and neither is a gate an author meant. The
/// tracer refuses both as well — it has to, because a declaration can be
/// hand-written — but only the macro can point at the line.
#[test]
fn the_lowering_refuses_a_threshold_nobody_could_have_meant() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/degenerate_threshold.rs");
    refuse.compile_fail("tests/refusals/vacuous_threshold.rs");
    refuse.compile_fail("tests/refusals/nested_threshold.rs");
    refuse.compile_fail("tests/refusals/wide_threshold.rs");
}

/// What the generated calling surface refuses.
///
/// Each of these is a fact the wrapper's own signature carries — the
/// arity, the parameter kinds, that no wrapper presents anything, and
/// which package the target runs — so getting one wrong is a type error
/// rather than a graph the chain declines to admit.
#[test]
fn the_generated_client_refuses_a_call_it_cannot_shape() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/client_wrong_arity.rs");
    refuse.compile_fail("tests/refusals/client_wrong_param_type.rs");
    refuse.compile_fail("tests/refusals/client_proof_to_public.rs");
    refuse.compile_fail("tests/refusals/client_foreign_handle.rs");
}

/// A marker nothing reads is refused where it sits.
///
/// The readers are kind- and place-filtered and the strip is not, so a
/// misplaced attribute — a slot pin on a config field, a gate on the
/// state struct, a mark on a private method or a helper's — would
/// otherwise vanish without declaring anything. Each refusal names the
/// placement that is read.
#[test]
fn the_macro_refuses_a_marker_nothing_reads() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/slot_on_config_field.rs");
    refuse.compile_fail("tests/refusals/requires_on_state_struct.rs");
    refuse.compile_fail("tests/refusals/total_on_private_method.rs");
    refuse.compile_fail("tests/refusals/name_in_foreign_impl.rs");
    refuse.compile_fail("tests/refusals/proves_on_struct.rs");
    refuse.compile_fail("tests/refusals/requires_on_enum.rs");
    refuse.compile_fail("tests/refusals/marker_on_free_fn.rs");
}

/// A private method is an inlining site: its body substitutes where it
/// is called, under the caller's own declaration walk. The bounds are
/// what substitution needs — no cycle, no early `return`, plain-name
/// parameters, and a name no accessor owns.
#[test]
fn the_macro_bounds_what_a_helper_may_be() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/helper_recursion.rs");
    refuse.compile_fail("tests/refusals/helper_return.rs");
    refuse.compile_fail("tests/refusals/helper_pattern_param.rs");
    refuse.compile_fail("tests/refusals/helper_accessor_name.rs");
}

/// A key position takes the vocabulary.
///
/// Whether a key is derivable is the walk's verdict, delivered at
/// expansion; whether its type could ever hash is the trait's, so a
/// string or a type of the author's own errs while it is typed — in
/// the editor, before the macro speaks.
#[test]
fn the_vocabulary_closes_the_key_positions() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/string_key.rs");
}

/// A vocabulary name is not shadowable.
///
/// The macro matches types by their last path segment — parameter
/// kinds, widening, the `Result` detection — so a local item under one
/// of those names would silently bind as the vocabulary's. Refused at
/// the item, which is the one place the mismatch is visible.
#[test]
fn the_macro_refuses_a_shadowed_vocabulary_name() {
    let refuse = TestCases::new();
    refuse.compile_fail("tests/refusals/shadowed_vocabulary.rs");
}

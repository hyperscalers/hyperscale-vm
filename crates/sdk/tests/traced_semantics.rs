//! What the parity fixtures cannot cover.
//!
//! `stdlib_parity` proves the SDK reaches the authored form on four real
//! packages — but none of them uses `for-each`, none nests, and none of
//! them can say anything about the handle order a guest bridge needs.
//! Those are exactly the parts of the design carrying risk, so they are
//! checked here against the real evaluator rather than against a fixture.

use hyperscale_vm_effects::vocabulary::{CONFIG, VAULT};
use hyperscale_vm_effects::{
    Clause, Declaration, EvalBudget, EvalInputs, Hash32, InstanceMeta, MAX_FOREACH_ELEMENTS,
    ManifestHash, MethodSignature, ModeExpr, PackageHash, ParamType, PresentedGrants, TargetExpr,
    TestHasher, Value, child_key, evaluate_declaration, evaluate_effects,
};
use hyperscale_vm_sdk::sym::{Addr, Bucket, Seq, Sym, U128, eq};
use hyperscale_vm_sdk::{Blueprint, Trace};
use hyperscale_vm_types::{
    Address, AddressClass, Effect, EffectSet, EffectTarget, Mode, ModeKind, Moves, SubstateKey,
};

const BASKET: Address = Address::new([0x50; 31], AddressClass::Component);
const RES_X: Address = Address::new([0xE1; 31], AddressClass::Component);
const RES_Y: Address = Address::new([0xE2; 31], AddressClass::Component);
const RES_Z: Address = Address::new([0xE3; 31], AddressClass::Component);

const fn identity() -> ManifestHash {
    ManifestHash(Hash32([0x1D; 32]))
}

fn vault(owner: Address, resource: Address) -> SubstateKey {
    child_key(
        &TestHasher,
        owner,
        VAULT,
        &[Value::Address(resource).canonical_bytes()],
    )
}

/// The creation-fixed record evaluation resolves the target with.
fn record_of(config: &[Value]) -> InstanceMeta {
    InstanceMeta {
        package: PackageHash(Hash32([1; 32])),
        config: config.to_vec(),
        salt: Hash32([2; 32]),
    }
}

/// Evaluate a traced signature the way routing would.
fn declared(signature: &MethodSignature, args: &[Value], config: &[Value]) -> EffectSet {
    let record = record_of(config);
    let budget = EvalBudget::default();
    let inputs = EvalInputs {
        self_addr: BASKET,
        args,
        record: &record,
        node_index: 0,
        identity: identity(),
        grants: PresentedGrants::none(),
        budget: &budget,
    };
    evaluate_effects(&signature.effects, &inputs, &TestHasher)
        .expect("the traced signature evaluates")
}

/// Both views of a traced signature's evaluation: the folded set that
/// scheduling reads and the clause order that materialization reads.
fn evaluated(signature: &MethodSignature, args: &[Value], config: &[Value]) -> Declaration {
    let record = record_of(config);
    let budget = EvalBudget::default();
    let inputs = EvalInputs {
        self_addr: BASKET,
        args,
        record: &record,
        node_index: 0,
        identity: identity(),
        grants: PresentedGrants::none(),
        budget: &budget,
    };
    evaluate_declaration(&signature.effects, &inputs, &TestHasher)
        .expect("the traced signature evaluates")
}

/// A basket whose `rebalance` touches one vault per configured resource —
/// the shape `for-each` exists for, and the shape no stdlib fixture has.
fn basket() -> Blueprint {
    Blueprint::builder()
        .method("rebalance", &[], |t: &mut Trace| {
            let holdings: Sym<Seq> = t.config(0);
            let owner = t.self_addr();

            t.point(&owner.child(CONFIG, &[])).read();
            t.for_each(&holdings, |t, resource| {
                let owner = t.self_addr();
                t.point(&owner.child(VAULT, &[resource])).write();
            });
        })
        .build()
}

#[test]
fn a_for_each_declares_one_effect_per_configured_element() {
    let blueprint = basket();
    let signature = blueprint.method("rebalance").unwrap().signature();

    let config = vec![Value::List(vec![
        Value::Address(RES_X),
        Value::Address(RES_Y),
        Value::Address(RES_Z),
    ])];
    let set = declared(signature, &[], &config);

    // The config leaf, plus one write per holding — at exactly the keys
    // `child_key` computes, which is what lets another shard name them.
    assert_eq!(set.len(), 4);
    for resource in [RES_X, RES_Y, RES_Z] {
        assert!(
            set.contains(&Effect {
                target: EffectTarget::Point(vault(BASKET, resource)),
                mode: Mode::Write { moves: Moves::Both },
            }),
            "no write declared on the {resource:?} vault"
        );
    }
}

#[test]
fn the_same_declaration_scales_with_configuration_alone() {
    // The point of tracing a signature rather than enumerating effects: one
    // declaration, and the instance's config decides the width.
    let blueprint = basket();
    let signature = blueprint.method("rebalance").unwrap().signature();

    for width in [0_usize, 1, 8, 64] {
        let holdings: Vec<Value> = (0..width)
            .map(|i| {
                Value::Address(Address::new(
                    [u8::try_from(i).unwrap(); 31],
                    AddressClass::Component,
                ))
            })
            .collect();
        let set = declared(signature, &[], &[Value::List(holdings)]);
        assert_eq!(set.len(), width + 1, "width {width}");
    }
}

#[test]
fn nested_binders_survive_evaluation() {
    // The de Bruijn conversion is structural, so the test that matters is
    // whether both binders reach the evaluator meaning what the author
    // wrote: the key is built from the inner member and the outer group's
    // tag, and the two must not be swapped.
    let blueprint = Blueprint::builder()
        .method("sweep", &[], |t: &mut Trace| {
            let groups: Sym<Seq> = t.config(0);
            t.for_each(&groups, |t, group| {
                let members: Sym<Seq> = group.clone().field(1).cast();
                t.for_each(&members, |t, member| {
                    let owner = t.self_addr();
                    let tag = group.clone().field(0);
                    t.point(&owner.child(VAULT, &[member, tag])).delta();
                });
            });
        })
        .build();
    let signature = blueprint.method("sweep").unwrap().signature();

    let group = |tag: Address, members: &[Address]| {
        Value::Tuple(vec![
            Value::Address(tag),
            Value::List(members.iter().copied().map(Value::Address).collect()),
        ])
    };
    let config = vec![Value::List(vec![
        group(RES_X, &[RES_Y, RES_Z]),
        group(RES_Y, &[RES_Z]),
    ])];
    let set = declared(signature, &[], &config);

    // Three (member, tag) pairs, all distinct.
    assert_eq!(set.len(), 3);
    let expect = |member: Address, tag: Address| {
        child_key(
            &TestHasher,
            BASKET,
            VAULT,
            &[
                Value::Address(member).canonical_bytes(),
                Value::Address(tag).canonical_bytes(),
            ],
        )
    };
    for (member, tag) in [(RES_Y, RES_X), (RES_Z, RES_X), (RES_Z, RES_Y)] {
        assert!(
            set.contains(&Effect {
                target: EffectTarget::Point(expect(member, tag)),
                mode: Mode::Delta { moves: Moves::Both },
            }),
            "member {member:?} under tag {tag:?} was not declared — binders may be swapped"
        );
    }
}

/// One handle the guest export receives, derived locally from the clause
/// tree: the kernel materializes per clause in declaration order, so the
/// clauses are the plan and nothing beside the metadata carries one.
struct Planned {
    mode: ModeKind,
    point: bool,
    repeat_depth: usize,
}

fn planned(clauses: &[Clause], depth: usize) -> Vec<Planned> {
    let mut shapes = Vec::new();
    for clause in clauses {
        match clause {
            Clause::Effect {
                reach: _,
                target,
                mode,
                ..
            } => shapes.push(Planned {
                mode: match mode {
                    ModeExpr::Read => ModeKind::Read,
                    ModeExpr::Delta { .. } => ModeKind::Delta,
                    ModeExpr::Reserve(_) => ModeKind::Reserve,
                    ModeExpr::Write { .. } => ModeKind::Write,
                },
                point: matches!(target, TargetExpr::Point(_)),
                repeat_depth: depth,
            }),
            Clause::ForEach { body, .. } => shapes.extend(planned(body, depth + 1)),
            Clause::Requires { .. } | Clause::Mints { .. } => {}
        }
    }
    shapes
}

#[test]
fn the_handle_plan_matches_what_the_kernel_materializes() {
    // The correspondence the whole SDK rests on: the order `HandlePlan`
    // reports is the order `KernelSession::materialize` builds its table
    // in, so a generated guest's positional parameters line up with the
    // handles it is given.
    //
    // The evaluated `EffectSet` cannot serve that role. It is canonical by
    // (target, mode), which is a comparison over child-key hashes — stable
    // but arbitrary, and it moves with the hasher. This test asserts the
    // plan tracks `Declaration::ordered` and, separately, that the set
    // order genuinely differs somewhere, so the correspondence is a
    // property rather than a coincidence.
    //
    // The witness is statistical, so the sample has to be wide. Only the
    // two vault keys move with the configuration; the configuration key
    // is the same one every time, and where it happens to sort below
    // every vault key drawn, the set agrees with the plan throughout and
    // there is no witness at all. A sample of a few keys can lose that
    // way on a hasher that means nothing by it.
    let pool = Blueprint::builder()
        .method(
            "swap",
            &[ParamType::Bucket, ParamType::U128],
            |t: &mut Trace| {
                let x: Sym<Addr> = t.config(0);
                let y: Sym<Addr> = t.config(1);
                let pool = t.self_addr();
                t.point(&pool.child(CONFIG, &[])).read();
                t.point(&pool.child(VAULT, &[x.cast()])).write();
                t.point(&pool.child(VAULT, &[y.cast()])).write();
            },
        )
        .build();
    let method = pool.method("swap").unwrap();

    let plan = planned(&method.signature().effects, 0);
    assert!(
        plan.iter().all(|s| s.repeat_depth == 0),
        "no clause is under a for-each"
    );
    let planned: Vec<ModeKind> = plan.iter().map(|s| s.mode).collect();
    assert_eq!(
        planned,
        vec![ModeKind::Read, ModeKind::Write, ModeKind::Write],
        "the plan follows the author's order"
    );
    assert!(plan.iter().all(|s| s.point));

    let mut set_order_differed = 0;
    for x in 0..64_u8 {
        for y in 0..64_u8 {
            if x == y {
                continue; // a degenerate pair collapses; see the test below
            }
            let config = vec![
                Value::Address(Address::new([x; 31], AddressClass::Component)),
                Value::Address(Address::new([y; 31], AddressClass::Component)),
            ];
            let declaration = evaluated(method.signature(), &[], &config);

            // What the kernel will materialize, in table order.
            let materialized: Vec<ModeKind> = declaration
                .ordered
                .iter()
                .map(|access| access.effect.mode.kind())
                .collect();
            assert_eq!(
                materialized, planned,
                "the plan must predict the materialization order for every config"
            );

            if declaration
                .set
                .iter()
                .map(|e| e.mode.kind())
                .ne(planned.iter().copied())
            {
                set_order_differed += 1;
            }
        }
    }
    assert!(
        set_order_differed > 0,
        "if set order always agreed, this correspondence would be untested luck"
    );
}

#[test]
fn a_degenerate_config_collapses_the_set_below_the_plan() {
    // The second finding, and the sharper of the two. `EffectSet` is a set:
    // two clauses that evaluate to the same (target, mode) become one entry.
    // A pool configured with the same resource on both sides is nonsense,
    // but it is nonsense the *declaration* cannot rule out — the resources
    // are creation-fixed config, and the tracer never sees them.
    //
    // So the handle count is not a function of the clause count. A bridge
    // that lowered "three clauses" to "three parameters" and let the kernel
    // fill them from the evaluated set would be handed two, and the
    // mismatch would surface at instantiation of one particular instance
    // rather than at publish. Either the kernel materializes per clause
    // rather than per set entry, or instance creation has to reject
    // configurations that make two clauses coincide.
    let pool = Blueprint::builder()
        .method("swap", &[], |t: &mut Trace| {
            let x: Sym<Addr> = t.config(0);
            let y: Sym<Addr> = t.config(1);
            let pool = t.self_addr();
            t.point(&pool.child(CONFIG, &[])).read();
            t.point(&pool.child(VAULT, &[x.cast()])).write();
            t.point(&pool.child(VAULT, &[y.cast()])).write();
        })
        .build();
    let method = pool.method("swap").unwrap();
    assert_eq!(planned(&method.signature().effects, 0).len(), 3);

    let distinct = vec![Value::Address(RES_X), Value::Address(RES_Y)];
    assert_eq!(declared(method.signature(), &[], &distinct).len(), 3);

    let degenerate = vec![Value::Address(RES_X), Value::Address(RES_X)];
    assert_eq!(
        declared(method.signature(), &[], &degenerate).len(),
        2,
        "the two writes fold onto one target"
    );
}

#[test]
fn a_dynamic_plan_reports_itself_as_dynamic() {
    let blueprint = basket();
    let plan = planned(
        &blueprint.method("rebalance").unwrap().signature().effects,
        0,
    );
    assert!(
        plan.iter().any(|s| s.repeat_depth > 0),
        "a for-each clause makes the handle count configuration-dependent"
    );
    assert_eq!(plan[0].repeat_depth, 0, "the config leaf is fixed");
    assert_eq!(plan[1].repeat_depth, 1, "the vault write repeats");
}

#[test]
fn the_worst_case_is_reported_where_it_can_exceed_the_bound() {
    // Two nested for-each clauses reach 1024^2 effects, past the 4096 a
    // signature may declare. The SDK cannot reject this — whether it happens
    // is a property of the config an instance is created with, not of the
    // declaration — but it can refuse to let the author find out from a
    // production routing failure.
    let deep = Blueprint::builder()
        .method("sweep", &[], |t: &mut Trace| {
            let groups: Sym<Seq> = t.config(0);
            t.for_each(&groups, |t, group| {
                let members: Sym<Seq> = group.cast();
                t.for_each(&members, |t, member| {
                    let owner = t.self_addr();
                    t.point(&owner.child(VAULT, &[member])).delta();
                });
            });
        })
        .build();
    let method = deep.method("sweep").unwrap();
    assert_eq!(method.worst_case_effects(), MAX_FOREACH_ELEMENTS.pow(2));
    assert!(!method.worst_case_fits());

    // The single-level basket is safely inside it.
    assert!(basket().method("rebalance").unwrap().worst_case_fits());
}

#[test]
#[should_panic(expected = "for-each nests")]
fn nesting_past_the_clause_bound_fails_the_build() {
    // Five levels, one past MAX_CLAUSE_DEPTH. Better here than at routing
    // time, where the package is published and every call to the method
    // fails.
    fn nest(t: &mut Trace, left: usize) {
        let list: Sym<Seq> = t.config(0);
        if left == 0 {
            let owner = t.self_addr();
            t.point(&owner.child(VAULT, &[])).write();
        } else {
            t.for_each(&list, |t, _| nest(t, left - 1));
        }
    }
    let _ = Blueprint::builder().method("deep", &[], |t: &mut Trace| nest(t, 5));
}

#[test]
#[should_panic(expected = "configuration-dependent number of clauses")]
fn a_verdict_from_inside_a_for_each_fails_the_build() {
    // A verdict occupies a fixed export parameter, and a branch inside a
    // `for-each` reaches one clause per element — so there is no single
    // verdict to hand over. The lowering declines to bind one there, and
    // this is the tracer holding a hand-written declaration to the same
    // thing.
    let _ = Blueprint::builder().method("pick", &[], |t: &mut Trace| {
        let list: Sym<Seq> = t.config(0);
        t.for_each(&list, |t, item| {
            let owner = t.self_addr();
            let chosen = eq(&item, &owner);
            t.when(&chosen, |t| {
                t.point(&owner.child(VAULT, &[])).write();
            });
            t.bind_guard();
        });
    });
}

#[test]
#[should_panic(expected = "escaped its closure")]
fn a_smuggled_binder_fails_the_build() {
    // Rust's ownership does not stop a `for-each` element being captured out
    // of its closure — that would need an invariant lifetime brand the API
    // does not carry yet. The tracer catches it instead: a binder used where
    // fewer binders are in scope than bound it cannot be lowered, and the
    // build stops rather than emitting a signature with a wild index.
    let mut escaped: Option<Sym<_>> = None;
    let _ = Blueprint::builder().method("leak", &[], |t: &mut Trace| {
        let list: Sym<Seq> = t.config(0);
        t.for_each(&list, |_, item| escaped = Some(item));
        let owner = t.self_addr();
        let key = owner.child(VAULT, &[escaped.take().unwrap()]);
        t.point(&key).write();
    });
}

#[test]
#[should_panic(expected = "declared bucket but read as u128")]
fn a_parameter_read_at_the_wrong_kind_fails_the_build() {
    // The one field of a signature that is independently checkable — params
    // against the component's own type section — is also the one the tracer
    // can check the effect expressions against.
    let _ = Blueprint::builder().method("swap", &[ParamType::Bucket], |t: &mut Trace| {
        let _: Sym<U128> = t.arg(0);
    });
}

#[test]
fn an_output_resource_is_a_declaration_not_an_inference() {
    // `-> Bucket` says an edge comes out, never which resource it carries.
    // For a wrapper it is a projection of an input; for a pool it is a
    // config field. Both spellings reach the same `outputs` slot.
    let wrapper = Blueprint::builder()
        .method("wrap", &[ParamType::Bucket], |t: &mut Trace| {
            let funds: Sym<Bucket> = t.arg(0);
            t.output(&funds.resource());
        })
        .build();
    let pool = Blueprint::builder()
        .method("swap", &[ParamType::Bucket], |t: &mut Trace| {
            let other: Sym<Addr> = t.config(1);
            t.output(&other);
        })
        .build();

    assert_eq!(wrapper.method("wrap").unwrap().signature().outputs.len(), 1);
    assert_eq!(pool.method("swap").unwrap().signature().outputs.len(), 1);
    assert_ne!(
        wrapper.method("wrap").unwrap().signature().outputs,
        pool.method("swap").unwrap().signature().outputs,
        "the same return type, two different declared resources"
    );
}

/// A body that only receives, and one that only sends, each holding the
/// same leaf exclusively.
fn one_way() -> Blueprint {
    Blueprint::builder()
        .method("receive", &[], |t: &mut Trace| {
            let owner = t.self_addr();
            t.point(&owner.child(VAULT, &[])).inbound();
        })
        .method("send", &[], |t: &mut Trace| {
            let owner = t.self_addr();
            t.point(&owner.child(VAULT, &[])).outbound();
        })
        .build()
}

/// An exclusive hold says which way value goes, and both ways are
/// authorable.
///
/// The direction is what the resource's own movement entries are read
/// against: a body that only receives is not asked for the credential a
/// sender needs, and one that only sends is not asked for the receiver's.
/// A hold that could only say `Both` would have to answer for a movement
/// it never makes.
#[test]
fn an_exclusive_hold_declares_the_direction_it_moves_value() {
    let blueprint = one_way();
    let leaf = child_key(&TestHasher, BASKET, VAULT, &[]);

    for (method, moves) in [("receive", Moves::In), ("send", Moves::Out)] {
        let signature = blueprint.method(method).unwrap().signature();
        let set = declared(signature, &[], &[]);
        assert!(
            set.contains(&Effect {
                target: EffectTarget::Point(leaf),
                mode: Mode::Write { moves },
            }),
            "{method} declares a {moves:?} write"
        );
    }
}

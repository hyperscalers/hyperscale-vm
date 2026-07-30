//! The restricted access DSL and its evaluator.
//!
//! An effect signature is a total function from a method's typed inputs to
//! its declared `(key, mode)` set, written in this DSL: field projections,
//! keyed lookups over input values, canonical-address computation, bounded
//! collection mapping, point and range targets. No loops, no recursion, no
//! reads of state — the evaluator takes arguments, instance configuration,
//! and a hasher, and nothing else, so evaluation is pure by construction
//! and identical on every node.

use crate::hash::{Hash32, Hasher};
use crate::manifest::ManifestHash;
use crate::types::{
    Address, Effect, EffectSet, EffectTarget, LocalKey, Mode, ReserveOverflow, RoleId, SubstateKey,
    Value, Window, child_key,
};

/// The bound on any collection a `for-each` clause maps over. Keeps
/// signature evaluation O(manifest size) whatever the metadata declares.
pub const MAX_FOREACH_ELEMENTS: usize = 1024;

/// An expression over a method's inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expr {
    /// A literal value.
    Literal(Value),
    /// The n-th manifest argument bound to this call.
    Arg(u32),
    /// The n-th field of the target instance's creation-fixed
    /// configuration — a locked substate, readable without a declared
    /// effect.
    Config(u32),
    /// The current `for-each` element; `0` names the innermost binding.
    Binding(u32),
    /// The target instance's own address.
    SelfAddr,
    /// Tuple field projection.
    Field(Box<Self>, u32),
    /// The static resource type of a bucket edge.
    ResourceOf(Box<Self>),
    /// Keyed lookup over a list of `(key, value)` pair tuples; yields the
    /// value of the first pair whose key matches.
    Lookup {
        /// The list of pairs to search.
        map: Box<Self>,
        /// The key to match against each pair's first field.
        key: Box<Self>,
    },
    /// The canonical child key `owner | H(role, material…)`.
    ChildKey {
        /// The owning address.
        owner: Box<Self>,
        /// The child's role under the owner.
        role: RoleId,
        /// The address material, canonically encoded into the hash.
        material: Vec<Self>,
    },
    /// A deterministic fresh 64-bit id, from the manifest hash, the node
    /// index, and the slot. Slots must be unique within a node's
    /// transitive signature.
    FreshId {
        /// The creation slot within this node.
        slot: u32,
    },
    /// The key of an object this call creates: a fresh 16-byte local id
    /// under the target instance's own prefix, from the same derivation as
    /// [`Expr::FreshId`].
    FreshKey {
        /// The creation slot within this node.
        slot: u32,
    },
    /// A 128-bit order key packed from two 64-bit halves.
    Pack {
        /// The high half — the primary sort dimension (a price).
        hi: Box<Self>,
        /// The low half — the tiebreaker (a sequence id).
        lo: Box<Self>,
    },
}

/// A snapshot window expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowExpr {
    /// A declared staleness bound, in versions.
    Bounded(Expr),
    /// A permanently locked substate; no proof obligation.
    Unbounded,
}

/// A mode with its parameters still unevaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModeExpr {
    /// Fresh coherent read.
    Read,
    /// Pinned read within a window.
    Snapshot(WindowExpr),
    /// Commutative increment or decrement; no declared amount.
    Delta,
    /// Conditional decrement of the evaluated amount.
    Reserve(Expr),
    /// Exclusive read-modify-write.
    Write,
}

/// An access target expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TargetExpr {
    /// A single substate leaf; the expression must evaluate to a key.
    Point(Expr),
    /// One ordered-collection entry at a computed order key.
    Entry {
        /// The collection's owner.
        owner: Expr,
        /// The collection's role under the owner.
        collection: RoleId,
        /// The entry's order key.
        order: Expr,
    },
    /// A declared interval of a collection's order-key space.
    Range {
        /// The collection's owner.
        owner: Expr,
        /// The collection's role under the owner.
        collection: RoleId,
        /// Inclusive lower bound.
        lo: Expr,
        /// Inclusive upper bound.
        hi: Expr,
        /// The maximum entries execution may touch.
        cap: u32,
    },
}

/// One clause of an effect signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Clause {
    /// A single declared access.
    Effect {
        /// What is accessed.
        target: TargetExpr,
        /// How it is accessed.
        mode: ModeExpr,
    },
    /// One access set per element of a bounded input collection; inside
    /// the body, the element is the innermost [`Expr::Binding`].
    ForEach {
        /// The collection to map over; must evaluate to a list.
        list: Expr,
        /// The clauses evaluated per element.
        body: Vec<Self>,
    },
}

/// Why signature evaluation rejected its inputs. Deterministic: the same
/// signature over the same inputs fails identically on every node.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EvalError {
    /// An argument index past the bound inputs.
    #[error("argument {0} out of range")]
    ArgOutOfRange(u32),
    /// A configuration index past the instance's configuration.
    #[error("configuration field {0} out of range")]
    ConfigOutOfRange(u32),
    /// A binding index with no enclosing `for-each`.
    #[error("binding {0} out of range")]
    BindingOutOfRange(u32),
    /// A value of the wrong kind.
    #[error("expected {expected}, found {found}")]
    TypeMismatch {
        /// The kind the expression required.
        expected: &'static str,
        /// The kind the value had.
        found: &'static str,
    },
    /// A tuple projection past the tuple's arity.
    #[error("tuple field {index} out of range (arity {arity})")]
    FieldOutOfRange {
        /// The projected index.
        index: u32,
        /// The tuple's arity.
        arity: usize,
    },
    /// A lookup key matching no pair.
    #[error("lookup key not present")]
    LookupMiss,
    /// A lookup list element that is not a `(key, value)` pair.
    #[error("lookup list element is not a pair")]
    LookupNotPairs,
    /// A `for-each` collection past [`MAX_FOREACH_ELEMENTS`].
    #[error("for-each over {len} elements exceeds the {MAX_FOREACH_ELEMENTS} bound")]
    ForEachTooLong {
        /// The collection's length.
        len: usize,
    },
    /// A range whose lower bound exceeds its upper bound.
    #[error("range bounds inverted: lo > hi")]
    InvalidRange,
    /// Folded reserve amounts overflowing `u128`.
    #[error("declared reserve amounts overflow")]
    ReserveOverflow,
}

impl From<ReserveOverflow> for EvalError {
    fn from(_overflow: ReserveOverflow) -> Self {
        Self::ReserveOverflow
    }
}

/// Everything a signature evaluates over. Note what is absent: state.
#[derive(Clone, Copy, Debug)]
pub struct EvalInputs<'a> {
    /// The target instance's own address.
    pub self_addr: Address,
    /// The call's bound arguments, in parameter order.
    pub args: &'a [Value],
    /// The target instance's creation-fixed configuration.
    pub config: &'a [Value],
    /// The invoking manifest node's index; namespaces fresh IDs.
    pub node_index: u32,
    /// The manifest's identity; roots fresh-ID derivation.
    pub manifest_hash: ManifestHash,
}

const DOMAIN_FRESH: &[u8] = b"hyperscale-vm/fresh-id";

fn fresh_digest(
    hasher: &dyn Hasher,
    manifest_hash: ManifestHash,
    node_index: u32,
    slot: u32,
) -> Hash32 {
    hasher.hash(
        DOMAIN_FRESH,
        &[
            &manifest_hash.0.0,
            &node_index.to_le_bytes(),
            &slot.to_le_bytes(),
        ],
    )
}

/// The deterministic fresh 64-bit id for `(manifest, node, slot)`.
///
/// This is the value [`Expr::FreshId`] evaluates to; the kernel derives
/// created-object ids the same way, so declaration and execution agree on
/// every fresh key.
#[must_use]
pub fn fresh_id(
    hasher: &dyn Hasher,
    manifest_hash: ManifestHash,
    node_index: u32,
    slot: u32,
) -> u64 {
    let digest = fresh_digest(hasher, manifest_hash, node_index, slot);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.0[..8]);
    u64::from_le_bytes(bytes)
}

/// The deterministic fresh local key for `(manifest, node, slot)` — the
/// local half [`Expr::FreshKey`] places under the creating instance's
/// prefix.
#[must_use]
pub fn fresh_local(
    hasher: &dyn Hasher,
    manifest_hash: ManifestHash,
    node_index: u32,
    slot: u32,
) -> LocalKey {
    let digest = fresh_digest(hasher, manifest_hash, node_index, slot);
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.0[..16]);
    LocalKey(bytes)
}

/// Evaluate a signature's clauses to its declared effect set.
///
/// # Errors
///
/// Any [`EvalError`]; verdicts are deterministic and identical on every
/// node.
pub fn evaluate_effects(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
) -> Result<EffectSet, EvalError> {
    let mut set = EffectSet::new();
    let mut bindings = Vec::new();
    eval_clauses(clauses, inputs, hasher, &mut bindings, &mut set)?;
    Ok(set)
}

/// Evaluate one expression with no enclosing `for-each` bindings.
///
/// # Errors
///
/// Any [`EvalError`]; verdicts are deterministic and identical on every
/// node.
pub fn evaluate_expr(
    expr: &Expr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
) -> Result<Value, EvalError> {
    eval_expr(expr, inputs, hasher, &[])
}

fn eval_clauses(
    clauses: &[Clause],
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &mut Vec<Value>,
    out: &mut EffectSet,
) -> Result<(), EvalError> {
    for clause in clauses {
        match clause {
            Clause::Effect { target, mode } => {
                let target = eval_target(target, inputs, hasher, bindings)?;
                let mode = eval_mode(mode, inputs, hasher, bindings)?;
                out.insert(Effect { target, mode })?;
            }
            Clause::ForEach { list, body } => {
                let items = as_list(eval_expr(list, inputs, hasher, bindings)?)?;
                if items.len() > MAX_FOREACH_ELEMENTS {
                    return Err(EvalError::ForEachTooLong { len: items.len() });
                }
                for item in items {
                    bindings.push(item);
                    let result = eval_clauses(body, inputs, hasher, bindings, out);
                    bindings.pop();
                    result?;
                }
            }
        }
    }
    Ok(())
}

fn eval_target(
    target: &TargetExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<EffectTarget, EvalError> {
    match target {
        TargetExpr::Point(expr) => {
            let key = as_key(eval_expr(expr, inputs, hasher, bindings)?)?;
            Ok(EffectTarget::Point(key))
        }
        TargetExpr::Entry {
            owner,
            collection,
            order,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings)?)?;
            let order = as_u128(eval_expr(order, inputs, hasher, bindings)?)?;
            Ok(EffectTarget::Entry {
                owner,
                collection: *collection,
                order,
            })
        }
        TargetExpr::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings)?)?;
            let lo = as_u128(eval_expr(lo, inputs, hasher, bindings)?)?;
            let hi = as_u128(eval_expr(hi, inputs, hasher, bindings)?)?;
            if lo > hi {
                return Err(EvalError::InvalidRange);
            }
            Ok(EffectTarget::Range {
                owner,
                collection: *collection,
                lo,
                hi,
                cap: *cap,
            })
        }
    }
}

fn eval_mode(
    mode: &ModeExpr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<Mode, EvalError> {
    match mode {
        ModeExpr::Read => Ok(Mode::Read),
        ModeExpr::Snapshot(window) => {
            let window = match window {
                WindowExpr::Bounded(expr) => {
                    Window::Bounded(as_u64(eval_expr(expr, inputs, hasher, bindings)?)?)
                }
                WindowExpr::Unbounded => Window::Unbounded,
            };
            Ok(Mode::Snapshot { window })
        }
        ModeExpr::Delta => Ok(Mode::Delta),
        ModeExpr::Reserve(expr) => {
            let amount = as_u128(eval_expr(expr, inputs, hasher, bindings)?)?;
            Ok(Mode::Reserve { amount })
        }
        ModeExpr::Write => Ok(Mode::Write),
    }
}

fn eval_expr(
    expr: &Expr,
    inputs: &EvalInputs<'_>,
    hasher: &dyn Hasher,
    bindings: &[Value],
) -> Result<Value, EvalError> {
    match expr {
        Expr::Literal(value) => Ok(value.clone()),
        Expr::Arg(index) => indexed(inputs.args, *index)
            .cloned()
            .ok_or(EvalError::ArgOutOfRange(*index)),
        Expr::Config(index) => indexed(inputs.config, *index)
            .cloned()
            .ok_or(EvalError::ConfigOutOfRange(*index)),
        Expr::Binding(index) => usize::try_from(*index)
            .ok()
            .and_then(|back| bindings.len().checked_sub(back + 1))
            .and_then(|position| bindings.get(position))
            .cloned()
            .ok_or(EvalError::BindingOutOfRange(*index)),
        Expr::SelfAddr => Ok(Value::Address(inputs.self_addr)),
        Expr::Field(tuple, index) => {
            let fields = as_tuple(eval_expr(tuple, inputs, hasher, bindings)?)?;
            let arity = fields.len();
            indexed(&fields, *index)
                .cloned()
                .ok_or(EvalError::FieldOutOfRange {
                    index: *index,
                    arity,
                })
        }
        Expr::ResourceOf(bucket) => match eval_expr(bucket, inputs, hasher, bindings)? {
            Value::Bucket { resource } => Ok(Value::Address(resource)),
            other => Err(EvalError::TypeMismatch {
                expected: "bucket",
                found: other.kind(),
            }),
        },
        Expr::Lookup { map, key } => {
            let pairs = as_list(eval_expr(map, inputs, hasher, bindings)?)?;
            let key = eval_expr(key, inputs, hasher, bindings)?;
            for pair in pairs {
                let Value::Tuple(fields) = pair else {
                    return Err(EvalError::LookupNotPairs);
                };
                let [pair_key, pair_value] = fields.as_slice() else {
                    return Err(EvalError::LookupNotPairs);
                };
                if *pair_key == key {
                    return Ok(pair_value.clone());
                }
            }
            Err(EvalError::LookupMiss)
        }
        Expr::ChildKey {
            owner,
            role,
            material,
        } => {
            let owner = as_address(eval_expr(owner, inputs, hasher, bindings)?)?;
            let mut encoded = Vec::with_capacity(material.len());
            for expr in material {
                encoded.push(eval_expr(expr, inputs, hasher, bindings)?.canonical_bytes());
            }
            Ok(Value::Key(child_key(hasher, owner, *role, &encoded)))
        }
        Expr::FreshId { slot } => Ok(Value::U64(fresh_id(
            hasher,
            inputs.manifest_hash,
            inputs.node_index,
            *slot,
        ))),
        Expr::FreshKey { slot } => Ok(Value::Key(SubstateKey {
            owner: inputs.self_addr,
            local: fresh_local(hasher, inputs.manifest_hash, inputs.node_index, *slot),
        })),
        Expr::Pack { hi, lo } => {
            let hi = as_u64(eval_expr(hi, inputs, hasher, bindings)?)?;
            let lo = as_u64(eval_expr(lo, inputs, hasher, bindings)?)?;
            Ok(Value::U128((u128::from(hi) << 64) | u128::from(lo)))
        }
    }
}

fn indexed<T>(slice: &[T], index: u32) -> Option<&T> {
    usize::try_from(index)
        .ok()
        .and_then(|index| slice.get(index))
}

fn as_u64(value: Value) -> Result<u64, EvalError> {
    match value {
        Value::U64(v) => Ok(v),
        other => Err(EvalError::TypeMismatch {
            expected: "u64",
            found: other.kind(),
        }),
    }
}

fn as_u128(value: Value) -> Result<u128, EvalError> {
    match value {
        Value::U64(v) => Ok(u128::from(v)),
        Value::U128(v) => Ok(v),
        other => Err(EvalError::TypeMismatch {
            expected: "u128",
            found: other.kind(),
        }),
    }
}

fn as_address(value: Value) -> Result<Address, EvalError> {
    match value {
        Value::Address(addr) => Ok(addr),
        other => Err(EvalError::TypeMismatch {
            expected: "address",
            found: other.kind(),
        }),
    }
}

fn as_key(value: Value) -> Result<SubstateKey, EvalError> {
    match value {
        Value::Key(key) => Ok(key),
        other => Err(EvalError::TypeMismatch {
            expected: "key",
            found: other.kind(),
        }),
    }
}

fn as_tuple(value: Value) -> Result<Vec<Value>, EvalError> {
    match value {
        Value::Tuple(fields) => Ok(fields),
        other => Err(EvalError::TypeMismatch {
            expected: "tuple",
            found: other.kind(),
        }),
    }
}

fn as_list(value: Value) -> Result<Vec<Value>, EvalError> {
    match value {
        Value::List(items) => Ok(items),
        other => Err(EvalError::TypeMismatch {
            expected: "list",
            found: other.kind(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Clause, EvalError, EvalInputs, Expr, MAX_FOREACH_ELEMENTS, ModeExpr, TargetExpr,
        WindowExpr, evaluate_effects, evaluate_expr, fresh_id, fresh_local,
    };
    use crate::hash::{Hash32, TestHasher};
    use crate::manifest::ManifestHash;
    use crate::types::{Address, Effect, EffectTarget, Mode, RoleId, Value, Window, child_key};

    fn inputs<'a>(args: &'a [Value], config: &'a [Value]) -> EvalInputs<'a> {
        EvalInputs {
            self_addr: Address([7; 16]),
            args,
            config,
            node_index: 3,
            manifest_hash: ManifestHash(Hash32([9; 32])),
        }
    }

    #[test]
    fn projections_and_lookup() {
        let args = [
            Value::Tuple(vec![Value::U64(1), Value::Address(Address([2; 16]))]),
            Value::List(vec![
                Value::Tuple(vec![Value::U64(10), Value::U64(100)]),
                Value::Tuple(vec![Value::U64(20), Value::U64(200)]),
            ]),
        ];
        let ins = inputs(&args, &[]);
        let field = Expr::Field(Box::new(Expr::Arg(0)), 1);
        assert_eq!(
            evaluate_expr(&field, &ins, &TestHasher),
            Ok(Value::Address(Address([2; 16])))
        );
        let hit = Expr::Lookup {
            map: Box::new(Expr::Arg(1)),
            key: Box::new(Expr::Literal(Value::U64(20))),
        };
        assert_eq!(evaluate_expr(&hit, &ins, &TestHasher), Ok(Value::U64(200)));
        let miss = Expr::Lookup {
            map: Box::new(Expr::Arg(1)),
            key: Box::new(Expr::Literal(Value::U64(30))),
        };
        assert_eq!(
            evaluate_expr(&miss, &ins, &TestHasher),
            Err(EvalError::LookupMiss)
        );
    }

    #[test]
    fn pack_and_fresh_derivations() {
        let ins = inputs(&[], &[]);
        let packed = Expr::Pack {
            hi: Box::new(Expr::Literal(Value::U64(5))),
            lo: Box::new(Expr::Literal(Value::U64(6))),
        };
        assert_eq!(
            evaluate_expr(&packed, &ins, &TestHasher),
            Ok(Value::U128((5u128 << 64) | 6))
        );

        let id = evaluate_expr(&Expr::FreshId { slot: 0 }, &ins, &TestHasher).unwrap();
        assert_eq!(
            id,
            Value::U64(fresh_id(&TestHasher, ins.manifest_hash, 3, 0))
        );
        assert_ne!(
            fresh_id(&TestHasher, ins.manifest_hash, 3, 0),
            fresh_id(&TestHasher, ins.manifest_hash, 3, 1)
        );
        assert_ne!(
            fresh_id(&TestHasher, ins.manifest_hash, 3, 0),
            fresh_id(&TestHasher, ins.manifest_hash, 4, 0)
        );

        let key = evaluate_expr(&Expr::FreshKey { slot: 2 }, &ins, &TestHasher).unwrap();
        let Value::Key(key) = key else { panic!() };
        assert_eq!(key.owner, ins.self_addr);
        assert_eq!(key.local, fresh_local(&TestHasher, ins.manifest_hash, 3, 2));
    }

    #[test]
    fn foreach_binds_innermost_first() {
        // For each recipient (a list of (owner, resource) pairs): a delta on
        // the recipient's vault for that resource.
        let args = [Value::List(vec![
            Value::Tuple(vec![
                Value::Address(Address([1; 16])),
                Value::Address(Address([0xAA; 16])),
            ]),
            Value::Tuple(vec![
                Value::Address(Address([2; 16])),
                Value::Address(Address([0xBB; 16])),
            ]),
        ])];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            list: Expr::Arg(0),
            body: vec![Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::Field(Box::new(Expr::Binding(0)), 0)),
                    role: RoleId(1),
                    material: vec![Expr::Field(Box::new(Expr::Binding(0)), 1)],
                }),
                mode: ModeExpr::Delta,
            }],
        }];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        assert_eq!(set.len(), 2);
        for (owner, resource) in [([1u8; 16], [0xAAu8; 16]), ([2; 16], [0xBB; 16])] {
            let key = child_key(
                &TestHasher,
                Address(owner),
                RoleId(1),
                &[Value::Address(Address(resource)).canonical_bytes()],
            );
            assert!(set.contains(&Effect {
                target: EffectTarget::Point(key),
                mode: Mode::Delta,
            }));
        }
    }

    #[test]
    fn foreach_is_bounded() {
        let args = [Value::List(vec![Value::U64(0); MAX_FOREACH_ELEMENTS + 1])];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::ForEach {
            list: Expr::Arg(0),
            body: vec![],
        }];
        assert_eq!(
            evaluate_effects(&clauses, &ins, &TestHasher),
            Err(EvalError::ForEachTooLong {
                len: MAX_FOREACH_ELEMENTS + 1
            })
        );
    }

    #[test]
    fn ranges_and_windows_evaluate_from_inputs() {
        let args = [Value::U64(100), Value::U64(110), Value::U64(8)];
        let ins = inputs(&args, &[]);
        let clauses = [
            Clause::Effect {
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: RoleId(4),
                    lo: Expr::Arg(0),
                    hi: Expr::Arg(1),
                    cap: 16,
                },
                mode: ModeExpr::Write,
            },
            Clause::Effect {
                target: TargetExpr::Point(Expr::ChildKey {
                    owner: Box::new(Expr::SelfAddr),
                    role: RoleId(9),
                    material: vec![],
                }),
                mode: ModeExpr::Snapshot(WindowExpr::Bounded(Expr::Arg(2))),
            },
        ];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        assert!(set.contains(&Effect {
            target: EffectTarget::Range {
                owner: ins.self_addr,
                collection: RoleId(4),
                lo: 100,
                hi: 110,
                cap: 16,
            },
            mode: Mode::Write,
        }));
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(child_key(&TestHasher, ins.self_addr, RoleId(9), &[])),
            mode: Mode::Snapshot {
                window: Window::Bounded(8),
            },
        }));

        let inverted = [Clause::Effect {
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: RoleId(4),
                lo: Expr::Arg(1),
                hi: Expr::Arg(0),
                cap: 16,
            },
            mode: ModeExpr::Write,
        }];
        assert_eq!(
            evaluate_effects(&inverted, &ins, &TestHasher),
            Err(EvalError::InvalidRange)
        );
    }

    #[test]
    fn reserve_amount_comes_from_arguments() {
        let args = [Value::Address(Address([0xCC; 16])), Value::U128(75)];
        let ins = inputs(&args, &[]);
        let clauses = [Clause::Effect {
            target: TargetExpr::Point(Expr::ChildKey {
                owner: Box::new(Expr::SelfAddr),
                role: RoleId(1),
                material: vec![Expr::Arg(0)],
            }),
            mode: ModeExpr::Reserve(Expr::Arg(1)),
        }];
        let set = evaluate_effects(&clauses, &ins, &TestHasher).unwrap();
        let expected = child_key(
            &TestHasher,
            ins.self_addr,
            RoleId(1),
            &[args[0].canonical_bytes()],
        );
        assert!(set.contains(&Effect {
            target: EffectTarget::Point(expected),
            mode: Mode::Reserve { amount: 75 },
        }));
    }
}

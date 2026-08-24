//! A package's declaration, rendered for someone to read.
//!
//! Everything a method declares is already in its signature, and none of
//! it is legible: a slot is a number, a role is a number, a claim is a
//! tree of boxed variants, and the one form that prints all of it is
//! `Debug`. So the half of the language an author writes is visible and
//! the half the macro derives is not.
//!
//! This renders the derived half in the vocabulary the authored half is
//! written in. The names come from the metadata's own tables — the state
//! table turns a slot into `vault` or `entries`, the configuration table
//! turns `config 0` into `config.x`, the role table turns `16` into
//! `admin` — so nothing here is a second statement of what a package
//! declares, and a package that renames a field renames it here.
//!
//! # What the rendering is held to
//!
//! Every match over an enum of the vocabulary lists all its arms, and
//! every struct variant is destructured field by field with no `..`.
//! That is what makes the rendering lossless by construction: a clause,
//! an expression or a target that grows a field does not quietly stop
//! being rendered — it fails to compile. The two open matches are over
//! slot and role *numbers*, which are integers rather than a closed set,
//! and both fall through to the number itself.
//!
//! Clauses are numbered by the preorder a clause index names, which is
//! the walk [`check_declarations`] judges them in, so the numbers a
//! reader matches an ABI binding against are the numbers the binding
//! means.
//!
//! [`check_declarations`]: crate::publish::check_declarations

use std::fmt::Write as _;

use hyperscale_hbor::{ShapeField, ShapeVariant, TypeShape};
use hyperscale_vm_types::{Address, Presence, SubstateKey};

use crate::auth::{CONFIRMATION, PACKAGE_ROLE_BASE, PRIMARY, RECOVERY, RoleId};
use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr};
use crate::envelope::NULLIFIER_SLOT;
use crate::metadata::{LeafForm, PACKAGE_SLOT, PackageMetadata, SlotKind, SlotShape};
use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};
use crate::rule::{GrantClaim, GrantRuleExpr, Rule, RuleExpr, RuleLeaf, always, never};
use crate::signature::{AbiParam, Issuance, MethodSignature, Totality};
use crate::types::{EdgeContent, SlotId, Value, u256_decimal};
use crate::vocabulary::{AUTH, CLAIMS, CONFIG, INSTANCE, NF_VAULT, RESOURCE, VAULT};

/// The whole package: its tables, then every method it declares.
#[must_use]
pub fn explain(metadata: &PackageMetadata) -> String {
    let names = Names(metadata);
    let mut out = String::new();
    names.tables(&mut out);
    for (name, signature) in &metadata.methods {
        out.push('\n');
        names.method(name, signature, &mut out);
    }
    out
}

/// One method, with the package's tables resolving its names.
///
/// `None` where the package declares no method under that name.
#[must_use]
pub fn explain_method(metadata: &PackageMetadata, method: &str) -> Option<String> {
    let signature = metadata.methods.get(method)?;
    let mut out = String::new();
    Names(metadata).method(method, signature, &mut out);
    Some(out)
}

/// The tables a rendering resolves names through.
struct Names<'a>(&'a PackageMetadata);

/// Binding strength, so a rendered expression reparses as the tree it
/// came from with no parentheses nothing needed.
///
/// `SELECT` is below every operator, which is what parenthesizes a
/// selection wherever one is an operand.
const SELECT: u8 = 0;
const OR: u8 = 1;
const AND: u8 = 2;
const COMPARE: u8 = 3;
const SUM: u8 = 4;
const UNARY: u8 = 5;
const ATOM: u8 = 6;

impl Names<'_> {
    /// The package's own tables, each omitted where it is empty.
    fn tables(&self, out: &mut String) {
        if !self.0.state.is_empty() {
            out.push_str("state\n");
            for (slot, shape) in &self.0.state {
                let SlotShape {
                    name,
                    kind,
                    element,
                } = shape;
                let _ = writeln!(
                    out,
                    "  {:>5}  {name} — {}, {}",
                    slot.0,
                    slot_kind(*kind),
                    leaf_form(element)
                );
            }
        }
        name_table("config", &self.0.config, 0, out);
        name_table("roles", &self.0.roles, PACKAGE_ROLE_BASE, out);
        name_table("events", &self.0.events, 0, out);
        name_table("errors", &self.0.errors, 0, out);
        if !self.0.types.is_empty() {
            out.push_str("types\n");
            for (name, shape) in &self.0.types {
                let _ = writeln!(out, "  {name} = {}", shape_of(shape));
            }
        }
    }

    /// One method: what it takes, what it declares, and what it hands
    /// back.
    fn method(&self, name: &str, signature: &MethodSignature, out: &mut String) {
        let MethodSignature {
            totality,
            issues,
            params,
            outputs,
            answers,
            denominations,
            effects,
            abi,
        } = signature;
        let kinds: Vec<&str> = params.iter().map(|param| param.name()).collect();
        let _ = write!(out, "{name}({}) — {}", kinds.join(", "), returns(*totality));
        if *answers {
            out.push_str(", answers");
        }
        out.push('\n');

        for (position, denomination) in denominations.iter().enumerate() {
            let Some(resource) = denomination else {
                continue;
            };
            let _ = writeln!(
                out,
                "  takes    arg{position} carrying {}",
                self.expr(resource, ATOM)
            );
        }
        if let Some(issuance) = issues {
            let Issuance { mark, kind, grants } = issuance;
            let _ = writeln!(
                out,
                "  issues   {} {}{}",
                bytes(mark),
                resource_kind(*kind),
                grants_of(grants)
            );
        }
        if !effects.is_empty() {
            out.push_str("  declares\n");
            let mut index = 0u32;
            for clause in effects {
                self.clause(clause, &mut index, 4, out);
            }
        }
        for (edge, output) in outputs.iter().enumerate() {
            let _ = writeln!(out, "  yields   edge {edge} = {}", self.expr(output, ATOM));
        }
        if !abi.is_empty() {
            let bound: Vec<String> = abi.iter().map(|param| self.abi_param(param)).collect();
            let _ = writeln!(out, "  exports  {}", bound.join(", "));
        }
    }

    /// One clause and, for a loop, its body — numbering in the preorder a
    /// clause index names.
    fn clause(&self, clause: &Clause, index: &mut u32, indent: usize, out: &mut String) {
        let number = *index;
        *index += 1;
        let pad = " ".repeat(indent);
        let guard = |guard: &Option<Box<Expr>>| {
            guard.as_ref().map_or_else(String::new, |condition| {
                format!("when {} → ", self.expr(condition, SELECT))
            })
        };
        match clause {
            Clause::Effect {
                guard: condition,
                target,
                mode,
                denomination,
            } => {
                let held = denomination.as_ref().map_or_else(String::new, |resource| {
                    format!(" holding {}", self.expr(resource, ATOM))
                });
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}{} {}{held}",
                    guard(condition),
                    self.mode(mode),
                    self.target(target)
                );
            }
            Clause::ForEach {
                guard: condition,
                list,
                body,
            } => {
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}for each of {}",
                    guard(condition),
                    self.expr(list, ATOM)
                );
                for nested in body {
                    self.clause(nested, index, indent + 2, out);
                }
            }
            Clause::Requires {
                guard: condition,
                rule,
            } => {
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}requires {}",
                    guard(condition),
                    self.rule(rule)
                );
            }
            Clause::Mints {
                guard: condition,
                claim,
            } => {
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}mints {}",
                    guard(condition),
                    self.expr(claim, ATOM)
                );
            }
        }
    }

    /// A declared rule: a threshold over leaves a caller must present.
    fn rule(&self, rule: &RuleExpr) -> String {
        match rule {
            Rule::Require(leaf) => match leaf {
                RuleLeaf::Claim(claim) => format!("claim {}", self.expr(claim, ATOM)),
                RuleLeaf::Stored { cell, role } => format!(
                    "the {} rule stored at {}",
                    self.role(*role),
                    self.expr(cell, ATOM)
                ),
                RuleLeaf::Presence { target, expect } => format!(
                    "{} is {}",
                    self.target(target),
                    match expect {
                        Presence::Either => "there or not",
                        Presence::Absent => "absent",
                        Presence::Present => "present",
                    }
                ),
                RuleLeaf::Granted {
                    resource,
                    behaviour,
                } => format!(
                    "the {} rule {} grants",
                    behaviour_name(*behaviour),
                    self.expr(resource, ATOM)
                ),
            },
            Rule::CountOf { count, rules } => {
                let branches: Vec<String> = rules.iter().map(|rule| self.rule(rule)).collect();
                format!("{count} of ({})", branches.join(", "))
            }
        }
    }

    /// How a cell is reached.
    fn mode(&self, mode: &ModeExpr) -> String {
        match mode {
            ModeExpr::Read => "read".to_owned(),
            ModeExpr::Delta => "delta".to_owned(),
            ModeExpr::Credit => "credit".to_owned(),
            ModeExpr::Reserve(amount) => format!("reserve {}", self.expr(amount, ATOM)),
            ModeExpr::Write => "write".to_owned(),
        }
    }

    /// What is reached: one leaf, one entry, or an interval of them.
    fn target(&self, target: &TargetExpr) -> String {
        match target {
            TargetExpr::Point(key) => self.expr(key, ATOM),
            TargetExpr::Entry {
                owner,
                collection,
                material,
                order,
            } => format!(
                "{} at {}",
                self.collection(owner, *collection, material),
                self.expr(order, ATOM)
            ),
            TargetExpr::Range {
                owner,
                collection,
                material,
                lo,
                hi,
                cap,
            } => format!(
                "{} over {}..={}, at most {} entries",
                self.collection(owner, *collection, material),
                self.expr(lo, ATOM),
                self.expr(hi, ATOM),
                self.expr(cap, ATOM)
            ),
        }
    }

    /// A collection under an owner, at the material separating it from
    /// the slot's others.
    fn collection(&self, owner: &Expr, slot: SlotId, material: &[Expr]) -> String {
        format!(
            "{}.{}{}",
            self.expr(owner, ATOM),
            self.slot(slot),
            self.material(material)
        )
    }

    /// The material a child key or a collection identity folds, where
    /// there is any.
    fn material(&self, material: &[Expr]) -> String {
        if material.is_empty() {
            return String::new();
        }
        let parts: Vec<String> = material
            .iter()
            .map(|part| self.expr(part, SELECT))
            .collect();
        format!("[{}]", parts.join(", "))
    }

    /// An expression, parenthesized exactly where `outer` binds tighter
    /// than it does.
    fn expr(&self, expr: &Expr, outer: u8) -> String {
        let (rendered, strength) = self.term(expr);
        if strength < outer {
            format!("({rendered})")
        } else {
            rendered
        }
    }

    /// One expression node and how tightly it binds.
    #[allow(clippy::too_many_lines)] // one arm per vocabulary term
    fn term(&self, expr: &Expr) -> (String, u8) {
        match expr {
            Expr::Literal(value) => (value_text(value), ATOM),
            Expr::Arg(position) => (format!("arg{position}"), ATOM),
            Expr::Config(field) => (self.config(*field), ATOM),
            // Zero names the innermost binding, so the caret counts
            // levels outward from the loop the term sits in.
            Expr::Binding(0) => ("element".to_owned(), ATOM),
            Expr::Binding(level) => (format!("element^{level}"), ATOM),
            Expr::SelfAddr => ("self".to_owned(), ATOM),
            Expr::SelfRecord => ("self.record".to_owned(), ATOM),
            Expr::Field(inner, field) => (format!("{}.{field}", self.expr(inner, ATOM)), ATOM),
            Expr::ResourceOf(edge) => (format!("resource-of({})", self.expr(edge, SELECT)), ATOM),
            Expr::IdsOf(edge) => (format!("ids-of({})", self.expr(edge, SELECT)), ATOM),
            Expr::Len(list) => (format!("len({})", self.expr(list, SELECT)), ATOM),
            Expr::Only(list) => (format!("only({})", self.expr(list, SELECT)), ATOM),
            Expr::List(elements) => (format!("[{}]", self.list(elements)), ATOM),
            Expr::Tuple(fields) => (format!("({})", self.list(fields)), ATOM),
            Expr::NfBucket { resource, ids } => (
                format!(
                    "edge({} × {})",
                    self.expr(resource, SELECT),
                    self.expr(ids, SELECT)
                ),
                ATOM,
            ),
            Expr::Lookup { map, key } => (
                format!("{}[{}]", self.expr(map, ATOM), self.expr(key, SELECT)),
                ATOM,
            ),
            Expr::SelfResource {
                kind,
                material,
                grants,
            } => (
                format!(
                    "self-issued({}{}){}",
                    resource_kind(*kind),
                    self.material(material),
                    grants_of(grants)
                ),
                ATOM,
            ),
            Expr::ChildKey {
                owner,
                slot,
                material,
            } => (
                format!(
                    "{}.{}{}",
                    self.expr(owner, ATOM),
                    self.slot(*slot),
                    self.material(material)
                ),
                ATOM,
            ),
            Expr::FreshId { slot } => (format!("fresh-id({slot})"), ATOM),
            Expr::FreshKey { slot } => (format!("fresh-key({slot})"), ATOM),
            Expr::Pack { hi, lo } => (
                format!("pack({}, {})", self.expr(hi, SELECT), self.expr(lo, SELECT)),
                ATOM,
            ),
            Expr::OrderKey {
                owner,
                slot,
                material,
            } => (
                format!("order-key({})", self.collection(owner, *slot, material)),
                ATOM,
            ),
            Expr::Add(left, right) => (
                format!("{} + {}", self.expr(left, SUM), self.expr(right, SUM + 1)),
                SUM,
            ),
            Expr::Not(judgment) => (format!("!{}", self.expr(judgment, UNARY)), UNARY),
            Expr::And(left, right) => (
                format!("{} and {}", self.expr(left, AND), self.expr(right, AND + 1)),
                AND,
            ),
            Expr::Or(left, right) => (
                format!("{} or {}", self.expr(left, OR), self.expr(right, OR + 1)),
                OR,
            ),
            Expr::Eq(left, right) => (
                format!(
                    "{} == {}",
                    self.expr(left, COMPARE + 1),
                    self.expr(right, COMPARE + 1)
                ),
                COMPARE,
            ),
            Expr::Lt(left, right) => (
                format!(
                    "{} < {}",
                    self.expr(left, COMPARE + 1),
                    self.expr(right, COMPARE + 1)
                ),
                COMPARE,
            ),
            Expr::Contains { map, key } => (
                format!(
                    "{} in {}",
                    self.expr(key, COMPARE + 1),
                    self.expr(map, COMPARE + 1)
                ),
                COMPARE,
            ),
            Expr::If {
                cond,
                then,
                otherwise,
            } => (
                format!(
                    "if {} then {} else {}",
                    self.expr(cond, SELECT),
                    self.expr(then, SELECT),
                    self.expr(otherwise, SELECT)
                ),
                SELECT,
            ),
        }
    }

    /// A comma-separated run of expressions, each free to be anything.
    fn list(&self, elements: &[Expr]) -> String {
        let rendered: Vec<String> = elements
            .iter()
            .map(|element| self.expr(element, SELECT))
            .collect();
        rendered.join(", ")
    }

    /// How one ABI parameter is built.
    fn abi_param(&self, param: &AbiParam) -> String {
        match param {
            AbiParam::Handle(clause) => format!("handle for clause {clause}"),
            AbiParam::Bucket(position) => format!("edge arg{position}"),
            AbiParam::Issuer => "the issuer".to_owned(),
            AbiParam::Guard(clause) => format!("whether clause {clause} was declared"),
            AbiParam::Run { clause, site } => format!("the run over clause {clause} site {site}"),
            AbiParam::Derived(expr) => self.expr(expr, SELECT),
        }
    }

    /// A configuration field, by the name its author spelled.
    fn config(&self, field: u32) -> String {
        usize::try_from(field)
            .ok()
            .and_then(|index| self.0.config.get(index))
            .map_or_else(
                || format!("config[{field}]"),
                |name| format!("config.{name}"),
            )
    }

    /// A role, by the reserved name or the package's own.
    fn role(&self, role: RoleId) -> String {
        match role {
            PRIMARY => return "primary".to_owned(),
            RECOVERY => return "recovery".to_owned(),
            CONFIRMATION => return "confirmation".to_owned(),
            _ => {}
        }
        role.0
            .checked_sub(PACKAGE_ROLE_BASE)
            .and_then(|offset| self.0.roles.get(offset as usize))
            .map_or_else(|| format!("role {}", role.0), Clone::clone)
    }

    /// A slot, by the protocol's name for it or the package's own.
    fn slot(&self, slot: SlotId) -> String {
        let vocabulary = match slot {
            VAULT => Some("vault"),
            CLAIMS => Some("claims"),
            CONFIG => Some("config"),
            AUTH => Some("auth"),
            RESOURCE => Some("resource"),
            NF_VAULT => Some("nf-vault"),
            INSTANCE => Some("instance"),
            PACKAGE_SLOT => Some("package"),
            NULLIFIER_SLOT => Some("nullifier"),
            _ => None,
        };
        if let Some(name) = vocabulary {
            return name.to_owned();
        }
        self.0
            .state
            .get(&slot)
            .map_or_else(|| format!("slot {}", slot.0), |shape| shape.name.clone())
    }
}

/// One index-to-name table, numbered from the band it is indexed in.
fn name_table(title: &str, names: &[String], base: u16, out: &mut String) {
    if names.is_empty() {
        return;
    }
    let _ = writeln!(out, "{title}");
    for (index, name) in names.iter().enumerate() {
        let number = base as usize + index;
        let _ = writeln!(out, "  {number:>5}  {name}");
    }
}

/// The rules a resource's own address grants, where it grants any.
fn grants_of(grants: &GrantsExpr) -> String {
    if grants.is_empty() {
        return String::new();
    }
    let granted: Vec<String> = grants
        .iter()
        .map(|(behaviour, entry)| {
            format!(
                "{} to {}",
                behaviour_name(behaviour),
                grant_entry(behaviour, entry)
            )
        })
        .collect();
    format!(", granting {}", granted.join(" and "))
}

/// A literal, in the form the kind reads best in.
fn value_text(value: &Value) -> String {
    match value {
        // The saturated widths are named rather than spelled: a
        // range over the whole order space is a common declaration,
        // and thirty-nine digits of it says less than the name does.
        Value::U64(u64::MAX) => "u64::MAX".to_owned(),
        Value::U64(number) => number.to_string(),
        Value::U128(u128::MAX) => "u128::MAX".to_owned(),
        Value::U128(number) => number.to_string(),
        // A stored rate reads as the scaled integer it is: the scale is
        // the type's and a reader who knows the type knows it.
        Value::U256(scaled) => u256_decimal(*scaled),
        Value::Bytes(raw) => bytes(raw),
        Value::Address(address) => address_text(*address),
        Value::Key(SubstateKey { owner, local }) => {
            format!("{}/{}", address_text(*owner), hex(&local.0))
        }
        Value::Bucket { resource, content } => {
            let carried = match content {
                EdgeContent::Fungible => "an amount".to_owned(),
                EdgeContent::NonFungible { ids } => {
                    let listed: Vec<String> = ids.iter().map(ToString::to_string).collect();
                    format!("[{}]", listed.join(", "))
                }
            };
            format!(
                "edge({} × {carried})",
                address_text(Address::from(*resource))
            )
        }
        Value::Tuple(fields) => {
            let rendered: Vec<String> = fields.iter().map(value_text).collect();
            format!("({})", rendered.join(", "))
        }
        Value::List(elements) => {
            let rendered: Vec<String> = elements.iter().map(value_text).collect();
            format!("[{}]", rendered.join(", "))
        }
        Value::Bool(judgment) => judgment.to_string(),
    }
}

/// What one leaf of a slot holds.
fn leaf_form(form: &LeafForm) -> String {
    match form {
        LeafForm::Value(shape) => format!("holding {}", shape_of(shape)),
        LeafForm::Bytes => "holding its own bytes".to_owned(),
    }
}

/// A granted rule, whose leaves name what the resource's own derivation
/// commits to and nothing a caller supplies.
/// What one granted entry admits, as a reader of the resource sees it.
///
/// Which side a leaf asks about is the behaviour's, so the reading is
/// too: a holder question is answered by what the moving party holds, an
/// actor question by what a caller presents.
fn grant_entry(behaviour: GrantedBehaviour, rule: &GrantRuleExpr) -> String {
    if *rule == always() {
        return "anyone".to_owned();
    }
    if *rule == never() {
        return "nobody".to_owned();
    }
    let rendered = grant_rule(rule);
    if behaviour.asks_about_the_actor() {
        rendered
    } else {
        format!("whoever holds {rendered}")
    }
}

/// What one declared claim names.
fn grant_claim(claim: &GrantClaim) -> String {
    match claim {
        GrantClaim::SelfAddr => "the issuer".to_owned(),
        GrantClaim::SelfBadge { mark, .. } => format!("the issuer's {} badge", bytes(mark)),
        GrantClaim::SelfInstance { mark, id, .. } => {
            format!("instance {id} of the issuer's {} badge", bytes(mark))
        }
        GrantClaim::Config(field) => format!("configuration field {field}"),
    }
}

fn grant_rule(rule: &GrantRuleExpr) -> String {
    match rule {
        Rule::Require(claim) => grant_claim(claim),
        Rule::CountOf { count, rules } => {
            let branches: Vec<String> = rules.iter().map(grant_rule).collect();
            format!("{count} of ({})", branches.join(", "))
        }
    }
}

/// A type, in the vocabulary the encoding admits.
fn shape_of(shape: &TypeShape) -> String {
    match shape {
        TypeShape::Bool => "bool".to_owned(),
        TypeShape::U8 => "u8".to_owned(),
        TypeShape::U16 => "u16".to_owned(),
        TypeShape::U32 => "u32".to_owned(),
        TypeShape::U64 => "u64".to_owned(),
        TypeShape::U128 => "u128".to_owned(),
        TypeShape::I8 => "i8".to_owned(),
        TypeShape::I16 => "i16".to_owned(),
        TypeShape::I32 => "i32".to_owned(),
        TypeShape::I64 => "i64".to_owned(),
        TypeShape::I128 => "i128".to_owned(),
        TypeShape::Text => "text".to_owned(),
        TypeShape::ByteArray(width) => format!("[u8; {width}]"),
        TypeShape::Seq(element) => format!("[{}]", shape_of(element)),
        TypeShape::Set(element) => format!("set[{}]", shape_of(element)),
        TypeShape::Map { key, value } => format!("map[{} → {}]", shape_of(key), shape_of(value)),
        TypeShape::Option(inner) => format!("{}?", shape_of(inner)),
        TypeShape::Tuple(fields) => {
            let rendered: Vec<String> = fields.iter().map(shape_of).collect();
            format!("({})", rendered.join(", "))
        }
        TypeShape::Struct(fields) => {
            let rendered: Vec<String> = fields
                .iter()
                .map(|ShapeField { name, shape }| format!("{name}: {}", shape_of(shape)))
                .collect();
            format!("{{ {} }}", rendered.join(", "))
        }
        TypeShape::Enum(variants) => {
            let rendered: Vec<String> = variants
                .iter()
                .map(
                    |ShapeVariant {
                         name,
                         discriminant,
                         content,
                     }| {
                        format!("{discriminant} {name}{}", shape_of(content))
                    },
                )
                .collect();
            format!("< {} >", rendered.join(" | "))
        }
        TypeShape::Ref(name) => name.clone(),
    }
}

/// What shape of state a slot holds.
const fn slot_kind(kind: SlotKind) -> &'static str {
    match kind {
        SlotKind::Cell => "one leaf",
        SlotKind::Keyed => "a leaf per key",
        SlotKind::Ordered => "an ordered collection",
        SlotKind::Unordered => "an unordered collection",
    }
}

/// How completely a method returns.
const fn returns(totality: Totality) -> &'static str {
    match totality {
        Totality::Fallible => "fallible",
        Totality::Infallible => "infallible",
        Totality::Total => "total",
    }
}

/// What a resource is, folded into its derivation.
const fn resource_kind(kind: ResourceKind) -> &'static str {
    match kind {
        ResourceKind::Fungible => "fungible",
        ResourceKind::NonFungible => "non-fungible",
    }
}

/// What a granted rule governs.
const fn behaviour_name(behaviour: GrantedBehaviour) -> &'static str {
    match behaviour {
        GrantedBehaviour::Mint => "mint",
        GrantedBehaviour::Burn => "burn",
        GrantedBehaviour::Withdraw => "withdraw",
        GrantedBehaviour::Deposit => "deposit",
        GrantedBehaviour::Freeze => "freeze",
        GrantedBehaviour::Recall => "recall",
    }
}

/// A byte string as its author most likely wrote it: a mark is a name,
/// and anything that is not printable text is its own bytes.
fn bytes(raw: &[u8]) -> String {
    match core::str::from_utf8(raw) {
        Ok(text) if !text.is_empty() && text.chars().all(|c| !c.is_control()) => {
            format!("{text:?}")
        }
        _ => format!("0x{}", hex(raw)),
    }
}

/// An address as its class and its whole body: a declaration's literals
/// are few, and a truncated one names something a reader cannot check.
fn address_text(address: Address) -> String {
    format!("{}:{}", address.class(), hex(&address.to_bytes()))
}

/// Lowercase hex, with no separator.
fn hex(raw: &[u8]) -> String {
    raw.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::TypeShape;
    use hyperscale_vm_types::Presence;

    use super::{explain, explain_method};
    use crate::auth::{PRIMARY, RoleId, package_role};
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr, self_child};
    use crate::metadata::{LeafForm, PackageMetadata, SlotKind, SlotShape};
    use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};
    use crate::rule::{GrantClaim, GrantRuleExpr, Rule, RuleLeaf};
    use crate::signature::{MethodSignature, ParamType, Totality};
    use crate::types::{SlotId, Value, package_slot};
    use crate::vocabulary::VAULT;

    /// A package declaring one method, so a rendering has a name table
    /// to resolve through.
    fn package(method: &str, signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata {
            config: vec!["x".to_owned(), "y".to_owned()],
            roles: vec!["admin".to_owned()],
            events: vec!["traded".to_owned()],
            errors: vec!["underfunded".to_owned()],
            ..PackageMetadata::default()
        };
        metadata.state.insert(
            package_slot(0),
            SlotShape {
                name: "entries".to_owned(),
                kind: SlotKind::Ordered,
                element: LeafForm::Value(TypeShape::U128),
            },
        );
        metadata.methods.insert(method.to_owned(), signature);
        metadata
    }

    /// A method declaring `effects` and nothing else.
    fn declaring(effects: Vec<Clause>) -> MethodSignature {
        MethodSignature {
            effects,
            ..MethodSignature::default()
        }
    }

    /// One read declared under `condition`, so a rendering has a
    /// position that takes an expression of any binding strength.
    fn guarded(condition: Expr) -> Clause {
        Clause::Effect {
            guard: Some(Box::new(condition)),
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        }
    }

    /// One read of a point target.
    fn read(target: Expr) -> Clause {
        Clause::Effect {
            guard: None,
            target: TargetExpr::Point(target),
            mode: ModeExpr::Read,
            denomination: None,
        }
    }

    fn rendered(method: &str, signature: MethodSignature) -> String {
        let metadata = package(method, signature);
        explain_method(&metadata, method).expect("the method it was built around")
    }

    #[test]
    fn a_slot_is_named_by_the_protocol_or_by_the_package_that_declared_it() {
        let text = rendered(
            "reads",
            declaring(vec![
                read(self_child(VAULT, vec![Expr::Config(0)])),
                read(self_child(package_slot(0), vec![])),
                read(self_child(SlotId(999), vec![])),
            ]),
        );
        assert!(text.contains("read self.vault[config.x]"), "{text}");
        assert!(text.contains("read self.entries"), "{text}");
        assert!(text.contains("read self.slot 999"), "{text}");
    }

    #[test]
    fn an_index_past_its_table_renders_as_the_index() {
        let text = rendered("reads", declaring(vec![read(Expr::Config(7))]));
        assert!(text.contains("read config[7]"), "{text}");
    }

    #[test]
    fn a_role_is_named_by_the_reserved_set_or_the_packages_own_band() {
        let stored = |role| Clause::Requires {
            guard: None,
            rule: Rule::Require(RuleLeaf::Stored {
                cell: Expr::SelfAddr,
                role,
            }),
        };
        let text = rendered(
            "gated",
            declaring(vec![
                stored(PRIMARY),
                stored(package_role(0)),
                stored(RoleId(9)),
            ]),
        );
        assert!(text.contains("the primary rule stored at self"), "{text}");
        assert!(text.contains("the admin rule stored at self"), "{text}");
        assert!(text.contains("the role 9 rule stored at self"), "{text}");
    }

    #[test]
    fn an_operand_is_parenthesized_exactly_where_it_binds_looser() {
        let sum = |left, right| Expr::Add(Box::new(left), Box::new(right));
        let arg = Expr::Arg;
        // `(arg0 + arg1) + arg2` needs no parentheses to reparse as
        // itself, and `arg0 + (arg1 + arg2)` is a different tree that does.
        let left_nested = rendered(
            "l",
            declaring(vec![guarded(sum(sum(arg(0), arg(1)), arg(2)))]),
        );
        let right_nested = rendered(
            "r",
            declaring(vec![guarded(sum(arg(0), sum(arg(1), arg(2))))]),
        );
        assert!(
            left_nested.contains("when arg0 + arg1 + arg2 →"),
            "{left_nested}"
        );
        assert!(
            right_nested.contains("when arg0 + (arg1 + arg2) →"),
            "{right_nested}"
        );
    }

    #[test]
    fn a_selection_is_parenthesized_wherever_it_is_an_operand() {
        let selection = Expr::If {
            cond: Box::new(Expr::Eq(
                Box::new(Expr::Arg(0)),
                Box::new(Expr::Literal(Value::U64(1))),
            )),
            then: Box::new(Expr::Config(0)),
            otherwise: Box::new(Expr::Config(1)),
        };
        let text = rendered(
            "chooses",
            declaring(vec![guarded(Expr::Add(
                Box::new(selection),
                Box::new(Expr::Arg(1)),
            ))]),
        );
        assert!(
            text.contains("when (if arg0 == 1 then config.x else config.y) + arg1 →"),
            "{text}"
        );
    }

    #[test]
    fn clauses_are_numbered_in_the_preorder_a_clause_index_names() {
        let signature = declaring(vec![
            read(Expr::SelfAddr),
            Clause::ForEach {
                guard: None,
                list: Expr::IdsOf(Box::new(Expr::Arg(0))),
                body: vec![read(Expr::Binding(0)), read(Expr::Binding(1))],
            },
            Clause::Mints {
                guard: None,
                claim: Expr::SelfAddr,
            },
        ]);
        let flat = signature.effects.iter().flat_map(Clause::effects).count();
        let text = rendered("loops", signature);
        let numbers: Vec<&str> = text
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .filter(|word| word.parse::<u32>().is_ok())
            .collect();
        assert_eq!(numbers, ["0", "1", "2", "3", "4"]);
        assert_eq!(numbers.len(), flat, "the walk the index names");
        assert!(text.contains("2  read element"), "{text}");
        assert!(text.contains("3  read element^1"), "{text}");
    }

    #[test]
    fn a_guard_reads_as_the_condition_the_clause_is_declared_under() {
        let text = rendered(
            "guarded",
            declaring(vec![Clause::Effect {
                guard: Some(Box::new(Expr::Lt(
                    Box::new(Expr::Arg(0)),
                    Box::new(Expr::Config(0)),
                ))),
                target: TargetExpr::Point(Expr::SelfAddr),
                mode: ModeExpr::Reserve(Expr::Arg(1)),
                denomination: Some(Box::new(Expr::Config(1))),
            }]),
        );
        assert!(
            text.contains("when arg0 < config.x → reserve arg1 self holding config.y"),
            "{text}"
        );
    }

    #[test]
    fn a_presence_condition_says_which_way_it_is_feasible() {
        let holds = |presence| Clause::Requires {
            guard: None,
            rule: Rule::Require(RuleLeaf::Presence {
                target: Box::new(TargetExpr::Point(Expr::SelfAddr)),
                expect: presence,
            }),
        };
        let text = rendered(
            "held",
            declaring(vec![holds(Presence::Present), holds(Presence::Absent)]),
        );
        assert!(text.contains("requires self is present"), "{text}");
        assert!(text.contains("requires self is absent"), "{text}");
    }

    #[test]
    fn a_threshold_names_its_count_and_every_branch() {
        let text = rendered(
            "threshold",
            declaring(vec![Clause::Requires {
                guard: None,
                rule: Rule::CountOf {
                    count: 2,
                    rules: vec![
                        Rule::Require(RuleLeaf::Claim(Expr::Config(0))),
                        Rule::Require(RuleLeaf::Granted {
                            resource: Expr::Arg(0),
                            behaviour: GrantedBehaviour::Recall,
                        }),
                        Rule::Require(RuleLeaf::Stored {
                            cell: Expr::SelfAddr,
                            role: PRIMARY,
                        }),
                    ],
                },
            }]),
        );
        assert!(
            text.contains(
                "requires 2 of (claim config.x, the recall rule arg0 grants, \
                 the primary rule stored at self)"
            ),
            "{text}"
        );
    }

    #[test]
    fn an_issued_resource_carries_the_rules_its_address_grants() {
        let mut grants = GrantsExpr::new();
        grants.set(
            GrantedBehaviour::Deposit,
            GrantRuleExpr::Require(GrantClaim::SelfBadge {
                mark: b"owner-badge".to_vec(),
                rules: GrantsExpr::new(),
            }),
        );
        let text = rendered(
            "issues",
            declaring(vec![read(Expr::SelfResource {
                kind: ResourceKind::NonFungible,
                material: vec![Expr::Literal(Value::Bytes(b"ticket".to_vec()))],
                grants,
            })]),
        );
        assert!(
            text.contains(
                "read self-issued(non-fungible[\"ticket\"]), \
                 granting deposit to whoever holds the issuer's \"owner-badge\" badge"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_range_names_its_bounds_and_what_it_may_touch() {
        let text = rendered(
            "sweeps",
            declaring(vec![Clause::Effect {
                guard: None,
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: package_slot(0),
                    material: vec![Expr::Arg(0)],
                    lo: Expr::Literal(Value::U128(0)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Len(Box::new(Expr::Arg(1))),
                },
                mode: ModeExpr::Read,
                denomination: None,
            }]),
        );
        assert!(
            text.contains("read self.entries[arg0] over 0..=u128::MAX, at most len(arg1) entries"),
            "{text}"
        );
    }

    #[test]
    fn the_package_rendering_carries_every_table_it_declares() {
        let mut signature = declaring(vec![]);
        signature.params = vec![ParamType::Bucket];
        signature.totality = Totality::Total;
        let text = explain(&package("deposit", signature));
        assert!(text.contains("     16  entries — an ordered collection, holding u128"));
        assert!(text.contains("      0  x"));
        assert!(text.contains("     16  admin"));
        assert!(text.contains("      0  traded"));
        assert!(text.contains("      0  underfunded"));
        assert!(text.contains("deposit(bucket) — total"), "{text}");
    }

    #[test]
    fn a_method_the_package_does_not_declare_renders_as_nothing() {
        let metadata = package("deposit", declaring(vec![]));
        assert!(explain_method(&metadata, "withdraw").is_none());
    }
}

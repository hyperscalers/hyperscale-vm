//! A package's declaration, rendered for someone to read.
//!
//! Everything a method declares is already in its signature, and none of
//! it is legible: a slot is a number, a claim is a tree of boxed
//! variants, and the one form that prints all of it is `Debug`. So the
//! half of the language an author writes is visible and the half the
//! macro derives is not.
//!
//! This renders the derived half in the vocabulary the authored half is
//! written in. The names come from the metadata's own tables — the state
//! table turns a slot into `vault` or `entries`, the configuration table
//! turns `config 0` into `config.x` — so nothing here is a second
//! statement of what a package declares, and a package that renames a
//! field renames it here.
//!
//! # What the rendering is held to
//!
//! Every match over an enum of the vocabulary lists all its arms, and
//! every struct variant is destructured field by field with no `..`.
//! That is what makes the rendering lossless by construction: a clause,
//! an expression or a target that grows a field does not quietly stop
//! being rendered — it fails to compile. The one open match is over
//! slot *numbers*, which are integers rather than a closed set, and it
//! falls through to the number itself.
//!
//! A self-issued resource is spelled once. The tables carry a
//! `resources` line for every derivation the methods reach, grants and
//! all, and a mention whose kind and mark name exactly one of those
//! lines renders without them. Two derivations one mark cannot separate
//! stay fully spelled, everywhere.
//!
//! A denomination the target's key already shows is not written again:
//! `credit self.till[config.asset]` moves what its key names, and a
//! trailer restating it would say nothing. The one reading this folds
//! is a read's — whether a bare `read` of a keyed cell declared its
//! denomination is answered by the state table rather than the clause
//! line.
//!
//! Clauses are numbered by the preorder a clause index names, which is
//! the walk [`check_declarations`] judges them in and the numbering a
//! refusal's clause index counts in. An ABI binding names a top-level
//! clause and a site of its body; the exports line converts that
//! coordinate to the listed number of the exact line it covers, so the
//! numbers a reader matches a binding against are the listing's own.
//!
//! [`check_declarations`]: crate::publish::check_declarations

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use hyperscale_hbor::{ShapeField, ShapeVariant, TypeShape};
use hyperscale_vm_types::{
    Address, AddressClass, EffectTarget, Moves, Presence, SubstateKey, UnmetCondition,
};

use crate::admission::{AdmissionError, Admitted, Asks, Injected, IntentView, Placed, interleave};
use crate::claim::Claim;
use crate::dsl::{Clause, Expr, ModeExpr, SlotRef, TargetExpr, preorder_len};
use crate::envelope::{EnvelopeTree, NULLIFIER_SLOT};
use crate::graph::{GraphArg, GraphNode, ManifestGraph};
use crate::hash::Hasher;
use crate::manifest::JudgedLeaf;
use crate::metadata::{LeafForm, PACKAGE_SLOT, PackageMetadata, SlotKind, SlotShape};
use crate::records::ChainRecords;
use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind, ResourceMeta};
use crate::rule::{
    GrantRuleExpr, GrantSubject, Holding, Judged, Rule, RuleExpr, RuleLeaf, SealedLeaf, StoredRule,
    always, never,
};
use crate::signature::{AbiParam, Issuance, Issued, MethodSignature, ParamType, Totality};
use crate::types::{EdgeContent, Value, u256_decimal};
use crate::vocabulary::{AUTH, CONFIG, HALT, INSTANCE, NF_VAULT, RESOURCE, VAULT};

/// The whole package: its tables, then every method it declares.
#[must_use]
pub fn explain(metadata: &PackageMetadata) -> String {
    let names = Names::new(metadata);
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
    Names::new(metadata).method(method, signature, &mut out);
    Some(out)
}

/// What a resource's own record says about moving it, for whoever is
/// deciding whether to accept it.
///
/// The tier where the questions are settled. A package's declaration
/// says `withdraw = config.registrar` and cannot say what that field
/// will name; a record has the instance's answer folded into it, so
/// every entry here reads as one of exactly two questions — **a holding**,
/// a standing fact about the party whose cell moves, or **an approval**,
/// which is about this transaction and nothing about that party.
///
/// Each entry also says when its verdict lands, which is what a holder
/// needs and what the sealed leaves already decide: an approval is
/// answered before the transaction exists and costs a refused sender
/// nothing; a holding is answered before any body runs; an entry asking
/// both lands inside the call, where a caller may already have committed.
///
/// The addresses render as themselves. A record is what a resource's own
/// address is the hash of, so there is no package here to name anything
/// through — which is the honest limit of reading a resource rather than
/// a declaration.
#[must_use]
pub fn explain_resource(record: &ResourceMeta, hasher: &dyn Hasher) -> String {
    let address = record.address(hasher);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "resource {}  {}",
        address_text(address.address()),
        resource_kind(record.kind)
    );
    let _ = writeln!(out, "  issued by  {}", address_text(record.namespace));
    let _ = writeln!(
        out,
        "  class      {}",
        match address.address().class() {
            AddressClass::Restricted =>
                "restricted — an entry here can stop a movement of it, so a transfer \
                 presents this record",
            _ => "plain — nothing here can stop a movement, so a transfer pays for none of it",
        }
    );
    // What the issuing frame speaks for, asked through the door
    // admission injects through — so what this says demands nothing is
    // exactly what nothing is demanded for.
    let issuer = Claim::of_address(record.namespace);
    for behaviour in GrantedBehaviour::ALL {
        let Some(entry) = record.rules.get(behaviour) else {
            continue;
        };
        let asks = match behaviour.demanded(entry, issuer) {
            Err(_) => "unreadable".to_owned(),
            Ok(None) => "the issuer's own code, which proves nothing to itself".to_owned(),
            // The constants answer without asking anything, so there is
            // no stage for a verdict to land at and nothing to hear.
            Ok(Some(rule)) if rule == always() => "anyone".to_owned(),
            Ok(Some(rule)) if rule == never() => "nobody, ever".to_owned(),
            Ok(Some(rule)) => format!(
                "{} — heard {}",
                sealed_rule(&rule, Some(record.namespace)),
                heard(rule.judged())
            ),
        };
        let _ = writeln!(out, "  {:<9}  {asks}", behaviour.word());
    }
    out
}

/// When a verdict reached at this stage lands, in what it costs the
/// party it lands on.
const fn heard(judged: Judged) -> &'static str {
    match judged {
        // Never included, so it costs a refused sender nothing at all.
        Judged::AtAdmission => "before it is a transaction",
        // The whole transaction aborts, and no caller committed on it.
        Judged::AtMaterialization => "before any body runs",
        // Inside the declaring node's own leg, which a caller may
        // already have committed without waiting for.
        Judged::InTheLeg => "inside the call, after a caller may have committed",
    }
}

/// One sealed rule, each leaf saying which of the two questions it is.
///
/// `issuer` is the record's own namespace, so an entry naming it reads as
/// the issuer rather than as an address a reader would have to compare by
/// eye. It still reads as an approval: a movement entry naming the issuer
/// asks whether *this transaction* carried a claim on them, and the party
/// whose cell moves is somebody else entirely.
fn sealed_rule(rule: &StoredRule, issuer: Option<Address>) -> String {
    match rule {
        Rule::Require(SealedLeaf::Claim(claim)) if issuer == Some(claim.subject) => {
            format!("approval on the issuer{}", instance_text(claim))
        }
        Rule::Require(SealedLeaf::Claim(claim)) => {
            format!("approval on {}", claim_text(claim))
        }
        Rule::Require(SealedLeaf::Held { badge, holding }) => format!(
            "the moving party holds {} of {}",
            match holding {
                Holding::Balance => "a balance".to_owned(),
                Holding::AnyInstance => "any instance".to_owned(),
                Holding::Instance(id) => format!("instance {id}"),
            },
            address_text(badge.address())
        ),
        Rule::CountOf { count, rules } => {
            let branches: Vec<String> = rules
                .iter()
                .map(|branch| sealed_rule(branch, issuer))
                .collect();
            format!("{count} of ({})", branches.join(", "))
        }
    }
}

/// What the protocol asked of a transaction, which no declaration
/// mentions.
///
/// Every requirement here comes from a resource rather than from a
/// signature — a package will not declare a rule it does not want, which
/// is what makes omission inexpressible — so none of it is visible in
/// [`explain`] and a reader of the packages a transaction calls would
/// conclude it is bound by nothing. Marked as the protocol's for that
/// reason, and each one names the entry it came from, because the rule
/// alone says what must hold and cannot say who asked.
///
/// A node the protocol asked nothing of is listed anyway. The absence is
/// the answer a reader came for, and leaving the line out would make it
/// indistinguishable from a node this forgot.
#[must_use]
pub fn explain_requirements(admitted: &Admitted) -> String {
    let mut out = String::new();
    out.push_str("required by the protocol, from the resources this transaction moves\n");
    for (index, node) in admitted.manifest().nodes.iter().enumerate() {
        let _ = writeln!(
            out,
            "  {index:>3}  {} {}",
            address_text(node.target),
            node.method
        );
        let injected = admitted
            .injected()
            .get(index)
            .map_or(&[][..], Vec::as_slice);
        if injected.is_empty() {
            out.push_str("         nothing — no resource this node moves governs it\n");
            continue;
        }
        for Injected {
            rule,
            asks,
            resource,
            behaviour,
        } in injected
        {
            let _ = writeln!(
                out,
                "         {} of {} — {}, heard {}",
                behaviour.word(),
                address_text(resource.address()),
                match asks {
                    Asks::Entry(entry) => sealed_rule(entry, None),
                    Asks::Unhalted => "the moving party is not halted".to_owned(),
                },
                heard(rule.judged())
            );
        }
    }
    out
}

/// Why a transaction refused, in the terms whoever it refused would read
/// it.
///
/// A verdict points and carries no rule — the declaration is
/// content-addressed with its package, so restating it in the receipt
/// would be paying to say twice what a reader can derive. What it points
/// at, for the condition that fires most, is a **key**: a hash of the
/// party and the badge that inverts to neither, so the verdict alone
/// says some leaf was missing and can never say whose or of what.
///
/// This is the derivation that reads it back. The verdict names the
/// node whose frame asked, so the requirements to match the key against
/// are that node's alone — every one of them built from something, with
/// that something beside it. So a refusal names the resource, the
/// behaviour, and the question, none of which the receipt carries.
///
/// **The node is what makes the answer exact rather than likely.** Two
/// frames moving one holder's holding of one resource read the same
/// leaf, so a search across every node would answer with whichever came
/// first — and a rule a package wrote on a leaf some other node happens
/// to be asked about would be read as the protocol's, which is the one
/// misattribution this whole derivation exists to avoid.
///
/// A condition matching nothing that node injected is the **package's
/// own**, and saying so is half the answer on its own: it separates a
/// rule the author wrote and a reader can find in [`explain`] from one
/// no declaration mentions.
#[must_use]
pub fn explain_refusal(admitted: &Admitted, unmet: &UnmetCondition) -> String {
    match unmet {
        UnmetCondition::Holds {
            target,
            required,
            node,
        } => unmet_presence(admitted, target, *required, *node),
        UnmetCondition::Satisfies { node } => unsatisfied_claims(admitted, *node),
        UnmetCondition::Unanswerable { node } => format!(
            "{}a condition nothing about committed state could have satisfied. The declaration \
             sent it to a judge that reads state, and it asks about something else — so it was \
             refused rather than waved through.",
            node.map_or_else(String::new, |node| format!("node {node}: "))
        ),
    }
}

/// The refusal a leaf of committed state reads back to.
fn unmet_presence(
    admitted: &Admitted,
    target: &EffectTarget,
    required: Presence,
    node: Option<u32>,
) -> String {
    // The asking node's own requirements and nobody else's. A
    // condition the verdict cannot place is one no injection
    // could have matched anyway, so the fallback below is the
    // same answer either way.
    let at = node.and_then(|node| usize::try_from(node).ok());
    // Every requirement the leaf could have come from, not whichever was
    // written first. Resolving a holding hashes the party and the badge
    // together, so a resource whose `withdraw` and `deposit` entries ask
    // about one holding produces two requirements over the same leaf —
    // the verdict cannot tell them apart, and a reading that named one
    // would be picking by declaration order.
    let matched: Vec<&Injected> = at
        .and_then(|at| admitted.injected().get(at))
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|injected| {
            injected.rule.leaves().any(|leaf| {
                matches!(leaf, JudgedLeaf::Presence { target: named, expect }
                    if named == target && *expect == required)
            })
        })
        .collect();
    if matched.is_empty() {
        return format!(
            "{}the package's own condition on {}: it must be {}, and it is not — a rule \
             its author wrote, so its declaration says what it is for",
            at.map_or_else(String::new, |at| format!("node {at}: ")),
            target_text(target),
            presence_text(required)
        );
    }
    let at = at.unwrap_or_default();
    let called = admitted.manifest().nodes.get(at);
    let entries = joined(matched.iter().map(|injected| {
        format!(
            "{} of {}",
            injected.behaviour.word(),
            address_text(injected.resource.address())
        )
    }));
    let asks = joined(matched.iter().map(|injected| match &injected.asks {
        Asks::Entry(entry) => sealed_rule(entry, None),
        Asks::Unhalted => "the moving party is not halted".to_owned(),
    }));
    format!(
        "{}: {entries} asks that {asks} — and it does not hold. Nothing declared this: it \
         is the resource's own entry, put on the call because the call moves it.",
        called.map_or_else(
            || format!("node {at}"),
            |called| format!(
                "node {at}, {} {}",
                address_text(called.target),
                called.method
            )
        ),
    )
}

/// Distinct renderings, in the order they were met, joined as
/// alternatives.
///
/// A tie is reported as a tie. Two requirements the verdict cannot
/// separate read as `withdraw of R or deposit of R`, and two that say the
/// same thing collapse to the one thing they say.
fn joined(parts: impl Iterator<Item = String>) -> String {
    let mut distinct: Vec<String> = Vec::new();
    for part in parts {
        if !distinct.contains(&part) {
            distinct.push(part);
        }
    }
    distinct.join(" or ")
}

/// The refusal a rule over presented claims reads back to.
fn unsatisfied_claims(admitted: &Admitted, node: u32) -> String {
    let at = usize::try_from(node).unwrap_or(usize::MAX);
    let asked: Vec<String> = admitted
        .injected()
        .get(at)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|injected| {
            injected
                .rule
                .leaves()
                .any(|leaf| matches!(leaf, JudgedLeaf::Claim(_)))
        })
        .map(|injected| {
            format!(
                "{} of {}",
                injected.behaviour.word(),
                address_text(injected.resource.address())
            )
        })
        .collect();
    let presented = admitted.manifest().nodes.get(at).map_or_else(
        || "nothing this can see".to_owned(),
        |node| {
            if node.evidence.is_empty() {
                "nothing".to_owned()
            } else {
                let claims: Vec<String> = node.evidence.iter().map(claim_text).collect();
                claims.join(", ")
            }
        },
    );
    if asked.is_empty() {
        return format!(
            "node {node} presented {presented}, and the package's own gate is not \
             satisfied by it"
        );
    }
    format!(
        "node {node} presented {presented}, and it does not satisfy what the protocol \
         asked for: {}",
        asked.join(", ")
    )
}

/// Every configuration field a resource's declared grants read.
///
/// What an author has to supply before a declaration can be sealed into
/// the record a holder reads. A grant naming no field seals against
/// nothing and is exact as written; one naming a field is a question only
/// an instance answers, and this says which question.
#[must_use]
pub fn grants_read_config(grants: &GrantsExpr) -> BTreeSet<u32> {
    fn walk(rule: &GrantRuleExpr, into: &mut BTreeSet<u32>) {
        match rule {
            GrantRuleExpr::Require(claim) => match claim {
                GrantSubject::Config(slot) => {
                    into.insert(*slot);
                }
                // A badge's own rules are folded into its address, so a
                // field they read is a field this set reads.
                GrantSubject::SelfBadge { rules, .. }
                | GrantSubject::SelfInstance { rules, .. } => {
                    for (_, nested) in rules.iter() {
                        walk(nested, into);
                    }
                }
                GrantSubject::SelfAddr => {}
            },
            GrantRuleExpr::CountOf { rules, .. } => {
                for branch in rules {
                    walk(branch, into);
                }
            }
        }
    }
    let mut read = BTreeSet::new();
    for (_, rule) in grants.iter() {
        walk(rule, &mut read);
    }
    read
}

/// A refusal at admitting a bare graph, with the place it points to
/// spelled out.
///
/// The sentence a composer gets carries indices — node 7, argument 2,
/// clause 4 — and an index means nothing without the thing it indexes.
/// `graph` is the composition as written, so a node index resolves to
/// the call the author wrote and an argument index to the argument they
/// put there. The clause resolves through the callee's own declaration,
/// which is the only place a clause number is a line. A refusal from a
/// composed tree goes through [`explain_admission_tree`], which holds
/// the tree's own node numbering.
///
/// Whatever cannot be resolved is left out rather than guessed at. A
/// refusal about the whole composition renders as its own sentence,
/// which is already the whole answer.
#[must_use]
pub fn explain_admission(
    graph: &ManifestGraph,
    records: &dyn ChainRecords,
    refusal: &AdmissionError,
) -> String {
    // A bare graph is one intent with no sockets, so the interleave
    // emits its nodes in author order and the flattened numbering is the
    // graph's own.
    explain_placed(&[graph], None, records, refusal)
}

/// A refusal at admitting an envelope tree, with the place it points to
/// spelled out on [`explain_admission`]'s terms.
///
/// A flattened node index numbers the emission order of the same
/// interleave admission ran — a subintent's node comes before the node
/// that consumes its socket, whichever intent wrote it — so the walk is
/// re-run here over the tree rather than guessed from concatenation.
/// The intents themselves are the tree's own: the root, then the
/// subintents in declaration order.
#[must_use]
pub fn explain_admission_tree(
    tree: &EnvelopeTree,
    records: &dyn ChainRecords,
    refusal: &AdmissionError,
) -> String {
    let mut views = Vec::with_capacity(1 + tree.subintents.len());
    views.push(IntentView {
        graph: &tree.root.graph,
        sockets: &tree.root.sockets,
        bindings: &tree.root_bindings,
        signer: None,
    });
    for subintent in &tree.subintents {
        views.push(IntentView {
            graph: &subintent.decl.graph,
            sockets: &subintent.decl.sockets,
            bindings: &subintent.bindings,
            signer: None,
        });
    }
    let total: usize = views.iter().map(|view| view.graph.nodes.len()).sum();
    // A tree the interleave cannot order has no flattened numbering to
    // resolve against, and its refusal says so on its own.
    let order = interleave(&views, total).ok().map(|(_, order)| order);
    let graphs: Vec<&ManifestGraph> = views.iter().map(|view| view.graph).collect();
    explain_placed(&graphs, order.as_deref(), records, refusal)
}

/// The shared rendering: resolve where the refusal points, and append
/// the call, the argument, and the clause it names.
fn explain_placed(
    intents: &[&ManifestGraph],
    order: Option<&[(usize, usize)]>,
    records: &dyn ChainRecords,
    refusal: &AdmissionError,
) -> String {
    let mut out = refusal.to_string();
    let at = refusal.at();
    let Some(node) = placed_node(intents, order, at) else {
        return out;
    };
    let _ = write!(
        out,
        "\n  {} {}",
        address_text(node.target.into()),
        node.method
    );
    if let Some(arg) = at.param.and_then(|param| node.args.get(param as usize)) {
        let _ = write!(
            out,
            "\n  argument {}: {}",
            at.param.unwrap_or_default(),
            arg_text(arg)
        );
    }
    if let Some(abi) = at.abi
        && let Some(described) = bound_abi(records, node, abi)
    {
        let _ = write!(out, "\n  binding {abi}: {described}");
    }
    if let Some(clause) = at.clause
        && let Some(listing) = declared_clause(records, node, clause)
    {
        let _ = write!(out, "\n  clause {clause}: {}", listing.trim_end());
    }
    if let AdmissionError::EvidenceUnsatisfied {
        rule: Some(rule),
        presented,
        ..
    } = refusal
    {
        out.push_str("\n  the gate requires:");
        judged_rule(rule, presented, &mut out, 0);
    }
    out
}

/// The rule an unsatisfied-evidence refusal was judged against, each
/// leaf beside what became of it: met by a presented claim, or the
/// party whose proving call could have met it. What turns the bare
/// verdict into something a composer can act on — the unmet leaf says
/// which sign-in or badge presentation the transaction is missing.
fn judged_rule(rule: &Rule<Claim>, presented: &[Claim], out: &mut String, depth: usize) {
    let pad = "  ".repeat(depth + 2);
    match rule {
        Rule::Require(claim) => {
            let met = presented.contains(claim);
            let word = if met { "met" } else { "unmet" };
            let _ = write!(out, "\n{pad}{word:>5}  claim {}", claim_text(claim));
            if !met {
                let _ = write!(out, " — {}", proven_by(claim));
            }
        }
        Rule::CountOf { count, rules } => {
            let _ = write!(out, "\n{pad}{count} of:");
            for branch in rules {
                judged_rule(branch, presented, out, depth + 1);
            }
        }
    }
}

/// The proving call that would meet an unmet claim leaf, read off the
/// claim's own class: an identity is signed into, a badge is presented
/// by whoever holds it.
fn proven_by(claim: &Claim) -> String {
    match (claim.subject.class(), claim.instance) {
        (AddressClass::Principal, _) => {
            format!("proven by signing in as {}", address_text(claim.subject))
        }
        (_, None) => "proven by a holder presenting the badge".to_owned(),
        (_, Some(id)) => format!("proven by a holder presenting instance {id}"),
    }
}

/// The ABI binding a refusal is about, described as the exports line
/// describes it — never as an argument, which is a different list.
fn bound_abi(records: &dyn ChainRecords, node: &GraphNode, abi: u32) -> Option<String> {
    let instance = records.instance(node.target)?;
    let metadata = records.package(instance.package)?;
    let signature = metadata.methods.get(&node.method)?;
    let param = signature.abi.get(usize::try_from(abi).ok()?)?;
    Some(Names::new(&metadata).abi_param(param, &signature.effects))
}

/// The node a refusal points at.
///
/// An intent-local index is that intent's own. A flattened one numbers
/// the interleave's emission order, resolved through `order` where the
/// composition has one; a lone intent's emission order is its author
/// order, so no map is needed to hold the two apart.
fn placed_node<'a>(
    intents: &[&'a ManifestGraph],
    order: Option<&[(usize, usize)]>,
    at: Placed,
) -> Option<&'a GraphNode> {
    let node = usize::try_from(at.node?).ok()?;
    if let Some(intent) = at.intent {
        return intents.get(usize::try_from(intent).ok()?)?.nodes.get(node);
    }
    if let Some(order) = order {
        let &(intent, local) = order.get(node)?;
        return intents.get(intent)?.nodes.get(local);
    }
    let [graph] = intents else {
        return None;
    };
    graph.nodes.get(node)
}

/// One argument as the composer wrote it.
fn arg_text(arg: &GraphArg) -> String {
    match arg {
        GraphArg::Literal(value) => format!("the literal {value:?}"),
        GraphArg::Edge { edge, .. } => format!(
            "output {} of node {} of its own intent",
            edge.output, edge.producer
        ),
        GraphArg::Socket(reference) => format!("socket {reference} of its own intent"),
    }
}

/// The preorder number the listing gives top-level clause `index` — or,
/// where `site` names a line of that clause's loop body, the body
/// line's own number. `None` for a coordinate the effects do not hold,
/// including a sited binding on a clause that is not a loop.
fn listed_line(effects: &[Clause], index: u32, site: Option<u32>) -> Option<u32> {
    let mut number = 0u32;
    for (position, clause) in effects.iter().enumerate() {
        if position == usize::try_from(index).ok()? {
            let Some(site) = site else {
                return Some(number);
            };
            let site = usize::try_from(site).ok()?;
            let Clause::ForEach { body, .. } = clause else {
                return (site == 0).then_some(number);
            };
            if site >= body.len() {
                return None;
            }
            return Some(
                number
                    .saturating_add(1)
                    .saturating_add(preorder_len(&body[..site])),
            );
        }
        number = number.saturating_add(1);
        if let Clause::ForEach { body, .. } = clause {
            number = number.saturating_add(preorder_len(body));
        }
    }
    None
}

/// One clause of the callee's declaration, rendered as `explain_method`
/// numbers it.
fn declared_clause(records: &dyn ChainRecords, node: &GraphNode, clause: u32) -> Option<String> {
    let instance = records.instance(node.target)?;
    let metadata = records.package(instance.package)?;
    let signature = metadata.methods.get(&node.method)?;
    let mut index = 0;
    let mut out = String::new();
    for declared in &signature.effects {
        let mut listing = String::new();
        let from = index;
        Names::new(&metadata).clause(declared, &mut index, 0, &mut listing);
        if (from..index).contains(&clause) {
            out = listing;
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

/// What a condition required of a leaf.
const fn presence_text(required: Presence) -> &'static str {
    match required {
        Presence::Present => "there",
        Presence::Absent => "not there",
        Presence::Either => "either way",
    }
}

/// One effect target, as far as a hash can be read.
///
/// Every arm destructured whole, on the same terms as everything else
/// here: a target that grows a field stops compiling rather than
/// quietly stops being rendered.
fn target_text(target: &EffectTarget) -> String {
    match target {
        EffectTarget::Point(key) => key_text(key),
        EffectTarget::Entry {
            owner,
            collection,
            order,
        } => format!(
            "{}'s collection {} at {order}",
            address_text(*owner),
            hex(&collection.0)
        ),
        EffectTarget::Range {
            owner,
            collection,
            lo,
            hi,
            cap,
        } => {
            let over = if *lo == 0 && *hi == u128::MAX {
                "the whole order space".to_owned()
            } else {
                format!("{lo}..={hi}")
            };
            format!(
                "{}'s collection {} over {over}, at most {cap} entries",
                address_text(*owner),
                hex(&collection.0)
            )
        }
    }
}

/// One substate key: the owner it sits under, which is an address, and
/// the local part, which is not.
fn key_text(key: &SubstateKey) -> String {
    format!("{}/{}", address_text(key.owner), hex(&key.local.0))
}

/// The tables a rendering resolves names through, and the census of
/// self-issued resources that lets a mention leave its grants to the
/// resources table.
struct Names<'a> {
    metadata: &'a PackageMetadata,
    /// Every self-issued resource the package's methods derive, keyed by
    /// its rendered kind and material, holding each distinct grants
    /// trailer seen under that key.
    ///
    /// A key with one trailer names one derivation, so a mention of it
    /// renders without the grants and the resources table says them
    /// once. A key with several is two resources a mark cannot tell
    /// apart, and every mention stays fully spelled.
    issued: BTreeMap<(String, String), BTreeSet<String>>,
}

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

impl<'a> Names<'a> {
    fn new(metadata: &'a PackageMetadata) -> Self {
        let mut names = Self {
            metadata,
            issued: BTreeMap::new(),
        };
        let mut issued: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for signature in metadata.methods.values() {
            for issuance in &signature.issues {
                let Issuance {
                    mark,
                    kind,
                    direction: _,
                    grants,
                } = issuance;
                issued
                    .entry((
                        resource_kind(*kind).to_owned(),
                        format!("[{}]", bytes(mark)),
                    ))
                    .or_default()
                    .insert(names.grants_of(grants));
            }
            for top in signature_exprs(signature) {
                let mut stack = vec![top];
                while let Some(expr) = stack.pop() {
                    stack.extend(expr.children());
                    if let Expr::SelfResource {
                        kind,
                        material,
                        grants,
                    } = expr
                    {
                        issued
                            .entry((resource_kind(*kind).to_owned(), names.material(material)))
                            .or_default()
                            .insert(names.grants_of(grants));
                    }
                }
            }
        }
        names.issued = issued;
        names
    }

    /// Whether one derivation answers to this kind and material, so a
    /// mention may leave its grants to the resources table.
    fn tabled(&self, kind: ResourceKind, material: &str) -> bool {
        self.issued
            .get(&(resource_kind(kind).to_owned(), material.to_owned()))
            .is_some_and(|grants| grants.len() == 1)
    }

    /// The package's own tables, each omitted where it is empty.
    fn tables(&self, out: &mut String) {
        if !self.metadata.state.is_empty() {
            out.push_str("state\n");
            for (slot, shape) in &self.metadata.state {
                let SlotShape {
                    name,
                    kind,
                    element,
                    denomination,
                } = shape;
                let holding = denomination
                    .as_ref()
                    .map(|resource| format!(", denominated in {}", self.expr(resource, SELECT)))
                    .unwrap_or_default();
                let _ = writeln!(
                    out,
                    "  {:>5}  {name} — {}, {}{holding}",
                    slot.0,
                    slot_kind(*kind),
                    leaf_form(element)
                );
            }
        }
        name_table("config", &self.metadata.config, out);
        // The census, spelled once: every mention below whose kind and
        // material name exactly one line here leaves its grants to it.
        if !self.issued.is_empty() {
            out.push_str("resources\n");
            for ((kind, material), grants) in &self.issued {
                for trailer in grants {
                    let granted = trailer
                        .strip_prefix(", ")
                        .map_or_else(String::new, |granted| format!(" — {granted}"));
                    let _ = writeln!(out, "  {kind}{material}{granted}");
                }
            }
        }
        name_table("events", &self.metadata.events, out);
        name_table("errors", &self.metadata.errors, out);
        if !self.metadata.types.is_empty() {
            out.push_str("types\n");
            for (name, shape) in &self.metadata.types {
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
            destroys,
            params,
            outputs,
            answers,
            denominations,
            effects,
            abi,
        } = signature;
        let kinds: Vec<String> = params
            .iter()
            .map(|param| match param {
                // The width is the signature's own statement; the
                // generic label would drop the one fact it fixes.
                ParamType::BytesExact(width) => format!("[u8; {width}]"),
                _ => param.name().to_owned(),
            })
            .collect();
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
        for issuance in issues {
            let Issuance {
                mark,
                kind,
                direction,
                grants,
            } = issuance;
            // The label is the direction: what a frame may do with its
            // grant is which of the resource's authority entries it
            // answers to, so a reader should not have to find it in a
            // clause further down.
            let material = format!("[{}]", bytes(mark));
            let granted = if self.tabled(*kind, &material) {
                String::new()
            } else {
                self.grants_of(grants)
            };
            let _ = writeln!(
                out,
                "  {}{} {}{granted}",
                match direction {
                    Issued::Minted => "mints    ",
                    Issued::Burned => "burns    ",
                    Issued::Either => "issues   ",
                },
                bytes(mark),
                resource_kind(*kind)
            );
        }
        // What a caller hands over to be destroyed, which is the other
        // way supply leaves — named by parameter because the resource is
        // the edge's rather than one this instance derives.
        for param in destroys {
            let _ = writeln!(out, "  destroys arg{param}, if its own rule admits it");
        }
        if !effects.is_empty() {
            out.push_str("  declares\n");
            let mut index = 0u32;
            for clause in effects {
                self.clause(clause, &mut index, 4, out);
            }
        }
        for (edge, output) in outputs.iter().enumerate() {
            // What an edge carries, on the same word `takes` uses. The
            // line already says it is an edge, so a constructed bucket
            // sheds its wrapper: the resource and, for a non-fungible,
            // the ids beside it.
            let carried = match output {
                Expr::NfBucket { resource, ids } => {
                    format!("{} × {}", self.expr(resource, ATOM), self.expr(ids, ATOM))
                }
                _ => self.expr(output, ATOM),
            };
            let _ = writeln!(out, "  yields   edge {edge} carrying {carried}");
        }
        if !abi.is_empty() {
            let _ = writeln!(
                out,
                "  exports  {}",
                self.abi_params(abi, effects).join(", ")
            );
        }
    }

    /// The exports line's entries, with an unbroken run of clause
    /// handles said once — `handles for clauses 0–6` rather than seven
    /// spellings of one word. A run of two stays spelled out: the
    /// compression pays only where the counting does.
    fn abi_params(&self, abi: &[AbiParam], effects: &[Clause]) -> Vec<String> {
        fn flush(bound: &mut Vec<String>, run: &mut Vec<u32>) {
            match run.as_slice() {
                [] => {}
                &[first, .., last] if run.len() >= 3 => {
                    bound.push(format!("handles for clauses {first}–{last}"));
                }
                lines => {
                    bound.extend(lines.iter().map(|line| format!("handle for clause {line}")));
                }
            }
            run.clear();
        }
        let mut bound: Vec<String> = Vec::new();
        let mut run: Vec<u32> = Vec::new();
        for param in abi {
            if let AbiParam::Handle { clause, site } = param
                && let Some(line) = listed_line(effects, *clause, Some(*site))
            {
                if run.last().is_some_and(|last| line != last + 1) {
                    flush(&mut bound, &mut run);
                }
                run.push(line);
                continue;
            }
            flush(&mut bound, &mut run);
            bound.push(self.abi_param(param, effects));
        }
        flush(&mut bound, &mut run);
        bound
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
                reach,
                guard: condition,
                target,
                mode,
                denomination,
            } => {
                // A vault-like cell is keyed by the resource it holds, so
                // its denomination is its key restated — written once, as
                // the key. Only a denomination the key does not already
                // show is worth a trailer.
                let held = denomination.as_ref().map_or_else(String::new, |resource| {
                    let restated = key_material(target)
                        .iter()
                        .any(|material| self.expr(material, SELECT) == self.expr(resource, SELECT));
                    if restated {
                        String::new()
                    } else {
                        format!(" holding {}", self.expr(resource, ATOM))
                    }
                });
                // A reach names whose authority lets it name somebody
                // else's cell, which is the first thing a reader of the
                // clause needs and the only reason the target is not the
                // declaring instance's own.
                let under = reach.map_or_else(String::new, |behaviour| {
                    format!(", reaching under {}", behaviour.word())
                });
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}{} {}{held}{under}",
                    guard(condition),
                    self.mode(mode, target, denomination.is_some()),
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
            Clause::Proves {
                guard: condition,
                claim,
            } => {
                let _ = writeln!(
                    out,
                    "{pad}{number:>3}  {}proves {}",
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
                RuleLeaf::Stored { cell } => {
                    format!("the rule stored at {}", self.expr(cell, ATOM))
                }
                RuleLeaf::Presence { target, expect } => format!(
                    "{} is {}",
                    self.target(target),
                    match expect {
                        Presence::Either => "there or not",
                        Presence::Absent => "absent",
                        Presence::Present => "present",
                    }
                ),
            },
            Rule::CountOf { count, rules } => {
                let branches: Vec<String> = rules.iter().map(|rule| self.rule(rule)).collect();
                format!("{count} of ({})", branches.join(", "))
            }
        }
    }

    /// How a cell is reached.
    ///
    /// An exclusive write says which way value moves under it, and the
    /// verb that says so is the cell's: a balance is credited and
    /// debited, a collection is filed into and taken from. Rendered
    /// only where the cell holds value at all — a direction on a byte
    /// cell moves nothing and the kernel drops it, so writing it down
    /// would be the rendering saying more than the declaration means.
    fn mode(&self, mode: &ModeExpr, target: &TargetExpr, holds_value: bool) -> String {
        match mode {
            ModeExpr::Read => "read".to_owned(),
            ModeExpr::Delta { moves: Moves::Both } => "delta".to_owned(),
            ModeExpr::Delta { moves: Moves::In } => "credit".to_owned(),
            ModeExpr::Delta { moves: Moves::Out } => "debit".to_owned(),
            ModeExpr::Reserve(amount) => format!("reserve {}", self.expr(amount, ATOM)),
            ModeExpr::Write { moves } => match (moves, holds_value) {
                (Moves::Both, _) | (_, false) => "write".to_owned(),
                (Moves::In, true) => match target {
                    TargetExpr::Point(_) => "credit-only".to_owned(),
                    TargetExpr::Entry { .. } | TargetExpr::Range { .. } => "file".to_owned(),
                },
                (Moves::Out, true) => match target {
                    TargetExpr::Point(_) => "debit-only".to_owned(),
                    TargetExpr::Entry { .. } | TargetExpr::Range { .. } => "take".to_owned(),
                },
            },
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
                self.collection(owner, collection, material),
                self.expr(order, ATOM)
            ),
            TargetExpr::Range {
                owner,
                collection,
                material,
                lo,
                hi,
                cap,
            } => {
                let over = if is_least(lo) && is_greatest(hi) {
                    "the whole order space".to_owned()
                } else {
                    format!("{}..={}", self.expr(lo, ATOM), self.expr(hi, ATOM))
                };
                format!(
                    "{} over {over}, at most {} entries",
                    self.collection(owner, collection, material),
                    self.expr(cap, ATOM)
                )
            }
        }
    }

    /// A collection under an owner, at the material separating it from
    /// the slot's others.
    fn collection(&self, owner: &Expr, slot: &SlotRef, material: &[Expr]) -> String {
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
            } => {
                let material = self.material(material);
                let grants = if self.tabled(*kind, &material) {
                    String::new()
                } else {
                    self.grants_of(grants)
                };
                (
                    format!("self-issued({}{material}){grants}", resource_kind(*kind)),
                    ATOM,
                )
            }
            Expr::ChildKey {
                owner,
                slot,
                material,
            } => (
                format!(
                    "{}.{}{}",
                    self.expr(owner, ATOM),
                    self.slot(slot),
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
                format!(
                    "order-key({})",
                    self.collection(owner, &SlotRef::Fixed(*slot), material)
                ),
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
    ///
    /// A binding names a top-level clause, and for a loop one site of
    /// its body; the listing numbers every line in preorder. What is
    /// rendered is the listed number of the exact line the binding
    /// covers — the body line for a sited binding — so the number a
    /// reader matches against the listing is the number printed here.
    fn abi_param(&self, param: &AbiParam, effects: &[Clause]) -> String {
        match param {
            AbiParam::Handle { clause, site } => listed_line(effects, *clause, Some(*site))
                .map_or_else(
                    || format!("handle for clause {clause} site {site}"),
                    |line| format!("handle for clause {line}"),
                ),
            AbiParam::Bucket(position) => format!("edge arg{position}"),
            AbiParam::Guard(clause) => listed_line(effects, *clause, None).map_or_else(
                || format!("whether clause {clause} was declared"),
                |line| format!("whether clause {line} was declared"),
            ),
            AbiParam::Derived(expr) => self.expr(expr, SELECT),
        }
    }

    /// What a resource's declared entries grant, as a trailer on the
    /// derivation that folds them.
    fn grants_of(&self, grants: &GrantsExpr) -> String {
        if grants.is_empty() {
            return String::new();
        }
        let granted: Vec<String> = grants
            .iter()
            .map(|(behaviour, entry)| {
                format!(
                    "{} to {}",
                    behaviour.word(),
                    self.grant_entry(behaviour, entry)
                )
            })
            .collect();
        format!(", granting {}", granted.join(" and "))
    }

    /// What one declared entry admits, as a reader of the resource sees
    /// it.
    ///
    /// **Which question an entry asks is the subject's answer, not the
    /// behaviour's.** An actor question always reads a claim, so it says
    /// who must approve. A holder question reads whichever its subject
    /// can be asked: a resource can be held, so naming one asks a
    /// standing fact about the party whose cell moves; an identity
    /// cannot, so naming one asks whether this transaction carried a
    /// claim on it.
    ///
    /// A configuration field carries an address and no class until an
    /// instance supplies one, so this cannot say which of the two it
    /// will be, and does not pretend to — the record's own rendering is
    /// where the answer is settled.
    fn grant_entry(&self, behaviour: GrantedBehaviour, rule: &GrantRuleExpr) -> String {
        if *rule == always() {
            return "anyone".to_owned();
        }
        if *rule == never() {
            return "nobody".to_owned();
        }
        if behaviour.asks_about_the_actor() {
            return self.grant_rule(rule);
        }
        match rule {
            Rule::Require(GrantSubject::SelfAddr) => {
                "whatever transaction the issuer approves".to_owned()
            }
            Rule::Require(GrantSubject::Config(field)) => {
                format!("whoever answers for {}", self.config(*field))
            }
            Rule::Require(GrantSubject::SelfBadge { .. } | GrantSubject::SelfInstance { .. }) => {
                format!("whoever holds {}", self.grant_rule(rule))
            }
            // A threshold over subjects that need not agree about which
            // question they ask, so each branch says for itself.
            Rule::CountOf { count, rules } => {
                let branches: Vec<String> = rules
                    .iter()
                    .map(|branch| self.grant_entry(behaviour, branch))
                    .collect();
                format!("{count} of ({})", branches.join(", "))
            }
        }
    }

    /// An actor question's entry, which always names who must approve.
    fn grant_rule(&self, rule: &GrantRuleExpr) -> String {
        match rule {
            Rule::Require(claim) => self.grant_claim(claim),
            Rule::CountOf { count, rules } => {
                let branches: Vec<String> =
                    rules.iter().map(|rule| self.grant_rule(rule)).collect();
                format!("{count} of ({})", branches.join(", "))
            }
        }
    }

    /// What one declared claim names.
    fn grant_claim(&self, claim: &GrantSubject) -> String {
        match claim {
            GrantSubject::SelfAddr => "the issuer".to_owned(),
            GrantSubject::SelfBadge { mark, .. } => format!("the issuer's {} badge", bytes(mark)),
            GrantSubject::SelfInstance { mark, id, .. } => {
                format!("instance {id} of the issuer's {} badge", bytes(mark))
            }
            GrantSubject::Config(field) => self.config(*field),
        }
    }

    /// A configuration field, by the name its author spelled.
    fn config(&self, field: u32) -> String {
        usize::try_from(field)
            .ok()
            .and_then(|index| self.metadata.config.get(index))
            .map_or_else(
                || format!("config[{field}]"),
                |name| format!("config.{name}"),
            )
    }

    /// A slot the declaration wrote down, by the name it goes under —
    /// or, where an argument names it, that argument, since a reach is
    /// told which slot it is reaching and the reader is told the same
    /// way.
    fn slot(&self, slot: &SlotRef) -> String {
        let slot = match slot {
            SlotRef::Fixed(slot) => *slot,
            SlotRef::Reached(expr) => return self.expr(expr, ATOM),
        };
        let vocabulary = match slot {
            VAULT => Some("vault"),
            HALT => Some("halt"),
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
        self.metadata
            .state
            .get(&slot)
            .map_or_else(|| format!("slot {}", slot.0), |shape| shape.name.clone())
    }
}

/// Every expression a signature holds at top level, wherever the
/// declaration puts one — the walk the resource census descends from.
///
/// Destructured whole, on the module's own terms: a signature, clause,
/// target or rule that grows an expression-bearing field stops compiling
/// rather than quietly escaping the census.
fn signature_exprs(signature: &MethodSignature) -> Vec<&Expr> {
    let MethodSignature {
        totality: _,
        issues: _,
        destroys: _,
        params: _,
        outputs,
        answers: _,
        denominations,
        effects,
        abi,
    } = signature;
    let mut exprs: Vec<&Expr> = Vec::new();
    exprs.extend(denominations.iter().flatten());
    exprs.extend(outputs);
    for param in abi {
        match param {
            AbiParam::Handle { .. } | AbiParam::Bucket(_) | AbiParam::Guard(_) => {}
            AbiParam::Derived(expr) => exprs.push(expr),
        }
    }
    for clause in effects.iter().flat_map(Clause::effects) {
        clause_exprs(clause, &mut exprs);
    }
    exprs
}

/// One clause's own expressions — a loop's body is walked by the caller,
/// which iterates the preorder.
fn clause_exprs<'a>(clause: &'a Clause, into: &mut Vec<&'a Expr>) {
    match clause {
        Clause::Effect {
            guard,
            target,
            mode,
            denomination,
            reach: _,
        } => {
            into.extend(guard.as_deref());
            target_exprs(target, into);
            match mode {
                ModeExpr::Read | ModeExpr::Delta { .. } | ModeExpr::Write { .. } => {}
                ModeExpr::Reserve(amount) => into.push(amount),
            }
            into.extend(denomination.as_deref());
        }
        Clause::ForEach {
            guard,
            list,
            body: _,
        } => {
            into.extend(guard.as_deref());
            into.push(list);
        }
        Clause::Requires { guard, rule } => {
            into.extend(guard.as_deref());
            rule_exprs(rule, into);
        }
        Clause::Proves { guard, claim } => {
            into.extend(guard.as_deref());
            into.push(claim);
        }
    }
}

/// Whether an order bound is the bottom of the whole space, however
/// spelled: `0` and `pack(0, 0)` name one bound, and a range over the
/// whole space says less as sixty digits than as the phrase — the same
/// judgment the saturated literals get.
fn is_least(bound: &Expr) -> bool {
    match bound {
        Expr::Literal(Value::U64(0) | Value::U128(0)) => true,
        Expr::Pack { hi, lo } => is_least(hi) && is_least(lo),
        _ => false,
    }
}

/// Whether an order bound is the top of the whole space, on
/// [`is_least`]'s terms.
fn is_greatest(bound: &Expr) -> bool {
    match bound {
        Expr::Literal(Value::U64(u64::MAX) | Value::U128(u128::MAX)) => true,
        Expr::Pack { hi, lo } => is_greatest(hi) && is_greatest(lo),
        _ => false,
    }
}

/// The material a target's rendered key shows, against which a
/// denomination is judged already visible.
fn key_material(target: &TargetExpr) -> &[Expr] {
    match target {
        TargetExpr::Point(Expr::ChildKey { material, .. })
        | TargetExpr::Entry { material, .. }
        | TargetExpr::Range { material, .. } => material,
        TargetExpr::Point(_) => &[],
    }
}

/// A target's expressions: the owner, whatever names the slot, the
/// material, and the bounds.
fn target_exprs<'a>(target: &'a TargetExpr, into: &mut Vec<&'a Expr>) {
    match target {
        TargetExpr::Point(key) => into.push(key),
        TargetExpr::Entry {
            owner,
            collection,
            material,
            order,
        } => {
            into.push(owner);
            into.extend(collection.reached());
            into.extend(material);
            into.push(order);
        }
        TargetExpr::Range {
            owner,
            collection,
            material,
            lo,
            hi,
            cap,
        } => {
            into.push(owner);
            into.extend(collection.reached());
            into.extend(material);
            into.push(lo);
            into.push(hi);
            into.push(cap);
        }
    }
}

/// A declared rule's expressions, leaf by leaf.
fn rule_exprs<'a>(rule: &'a RuleExpr, into: &mut Vec<&'a Expr>) {
    match rule {
        Rule::Require(leaf) => match leaf {
            RuleLeaf::Claim(claim) => into.push(claim),
            RuleLeaf::Stored { cell } => into.push(cell),
            RuleLeaf::Presence { target, expect: _ } => target_exprs(target, into),
        },
        Rule::CountOf { count: _, rules } => {
            for branch in rules {
                rule_exprs(branch, into);
            }
        }
    }
}

/// One index-to-name table.
fn name_table(title: &str, names: &[String], out: &mut String) {
    if names.is_empty() {
        return;
    }
    let _ = writeln!(out, "{title}");
    for (index, name) in names.iter().enumerate() {
        let _ = writeln!(out, "  {index:>5}  {name}");
    }
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
        // An instance family's entry: the id is the entry's own order
        // key, so the leaf has nothing left to hold.
        LeafForm::Value(TypeShape::Tuple(parts)) if parts.is_empty() => {
            "holding nothing".to_owned()
        }
        LeafForm::Value(shape) => format!("holding {}", shape_of(shape)),
        LeafForm::Bytes => "holding its own bytes".to_owned(),
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
///
/// Public because it is the one spelling every rendering uses, and the
/// one a test matching rendered text should build expectations with.
#[must_use]
pub fn address_text(address: Address) -> String {
    format!("{}:{}", address.class(), hex(&address.to_bytes()))
}

/// One claim, subject and instance both.
///
/// The instance is half of what a claim names: an approval on instance 3
/// and one on instance 7 are two different claims about one badge, and a
/// rendering that drops it says the right badge was presented and
/// mysteriously refused.
#[must_use]
pub fn claim_text(claim: &Claim) -> String {
    format!("{}{}", address_text(claim.subject), instance_text(claim))
}

/// The instance half of a claim, where it names one.
fn instance_text(claim: &Claim) -> String {
    claim
        .instance
        .map_or_else(String::new, |id| format!(", instance {id}"))
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
    use hyperscale_vm_types::{Address, AddressClass, Moves, Presence};

    use super::{SlotRef, explain, explain_method, joined};
    use crate::dsl::{Clause, Expr, ModeExpr, TargetExpr, self_child};
    use crate::metadata::{LeafForm, PackageMetadata, SlotKind, SlotShape};
    use crate::resource::{GrantedBehaviour, GrantsExpr, ResourceKind};
    use crate::rule::{GrantRuleExpr, GrantSubject, Rule, RuleLeaf};
    use crate::signature::{AbiParam, MethodSignature, ParamType, Totality};
    use crate::types::{SlotId, Value, package_slot};
    use crate::vocabulary::VAULT;

    /// A refusal the verdict cannot attribute reads as every entry it
    /// could have come from.
    ///
    /// Resolving a holding hashes the party and the badge together, so
    /// two entries of one resource asking the same thing of the same
    /// party land on one leaf and the receipt carries no way back to
    /// which. One access moving both directions earns both entries —
    /// `GrantedBehaviour::earned_by(Moves::Both)` is `[Withdraw,
    /// Deposit]` — so the pair arrives on one node, and reporting
    /// whichever came first would be picking by declaration order.
    ///
    /// Latent in the corpus rather than reachable from it: no guest
    /// declares a both-direction access on a restricted resource today,
    /// which is why the first-match reading went unnoticed.
    #[test]
    fn requirements_one_leaf_cannot_separate_read_as_alternatives() {
        assert_eq!(
            joined(["withdraw of R".to_owned(), "deposit of R".to_owned()].into_iter()),
            "withdraw of R or deposit of R"
        );
        // Two entries asking the same thing are one thing asked.
        assert_eq!(
            joined(["not halted".to_owned(), "not halted".to_owned()].into_iter()),
            "not halted"
        );
        // And one is itself, so the common case reads as it always did.
        assert_eq!(
            joined(["withdraw of R".to_owned()].into_iter()),
            "withdraw of R"
        );
    }

    /// The verb a directional write reads as is the cell's own, and a
    /// cell that holds no value has no direction to read.
    ///
    /// A balance is credited and debited; a collection is filed into
    /// and taken from. The one thing both give up is the other
    /// direction, and the rendering has to say which — a declaration
    /// that gave up the debit is asked for the receiving credential
    /// alone, and a reader deciding whether to call it needs to see
    /// that before the entry does.
    #[test]
    fn a_directional_write_reads_as_the_verb_its_cell_takes() {
        let resource = || {
            Expr::Literal(Value::Address(Address::new(
                [0xE1; 31],
                AddressClass::Resource,
            )))
        };
        let clause = |target, moves, held: bool| Clause::Effect {
            reach: None,
            guard: None,
            target,
            mode: ModeExpr::Write { moves },
            denomination: held.then(|| Box::new(resource())),
        };
        let balance = || TargetExpr::Point(self_child(VAULT, vec![resource()]));
        let entries = || TargetExpr::Range {
            owner: Expr::SelfAddr,
            collection: SlotRef::Fixed(package_slot(0)),
            material: vec![resource()],
            lo: Expr::Literal(Value::U128(0)),
            hi: Expr::Literal(Value::U128(1)),
            cap: Expr::Literal(Value::U64(1)),
        };
        let rendered = |target: TargetExpr, moves, held| {
            explain_method(
                &package("m", declaring(vec![clause(target, moves, held)])),
                "m",
            )
            .expect("the method renders")
        };

        assert!(rendered(balance(), Moves::In, true).contains("credit-only"));
        assert!(rendered(balance(), Moves::Out, true).contains("debit-only"));
        assert!(rendered(entries(), Moves::In, true).contains("file"));
        assert!(rendered(entries(), Moves::Out, true).contains("take"));

        // Both directions is what a write saying nothing means, and so
        // is a cell holding no value: the kernel drops the direction
        // there, so the rendering says no more than the declaration.
        for target in [balance(), entries()] {
            assert!(rendered(target.clone(), Moves::Both, true).contains("write"));
            for moves in [Moves::In, Moves::Out, Moves::Both] {
                assert!(
                    rendered(target.clone(), moves, false).contains("write"),
                    "a byte cell has no direction to read"
                );
            }
        }
    }

    /// An unbroken run of clause handles is counted once; a pair is
    /// spelled out.
    #[test]
    fn a_run_of_clause_handles_is_counted_once() {
        let handle = |clause| AbiParam::Handle { clause, site: 0 };
        let mut signature = declaring(vec![
            read(Expr::SelfAddr),
            read(Expr::SelfAddr),
            read(Expr::SelfAddr),
            read(Expr::SelfAddr),
        ]);
        signature.abi = vec![
            handle(0),
            handle(1),
            handle(2),
            handle(3),
            AbiParam::Derived(Expr::Arg(0)),
        ];
        let text = rendered("runs", signature);
        assert!(
            text.contains("exports  handles for clauses 0–3, arg0"),
            "{text}"
        );

        let mut signature = declaring(vec![read(Expr::SelfAddr), read(Expr::SelfAddr)]);
        signature.abi = vec![handle(0), handle(1)];
        let text = rendered("pair", signature);
        assert!(
            text.contains("exports  handle for clause 0, handle for clause 1"),
            "{text}"
        );
    }

    /// A denomination the key already shows is the key restated, and
    /// only one the key does not show earns a trailer.
    #[test]
    fn a_denomination_the_key_shows_is_not_written_twice() {
        let keyed = |denomination: Expr| Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Point(self_child(VAULT, vec![Expr::Config(0)])),
            mode: ModeExpr::Delta { moves: Moves::In },
            denomination: Some(Box::new(denomination)),
        };
        let text = rendered("keeps", declaring(vec![keyed(Expr::Config(0))]));
        assert!(text.contains("credit self.vault[config.x]\n"), "{text}");
        let text = rendered("keeps", declaring(vec![keyed(Expr::Config(1))]));
        assert!(
            text.contains("credit self.vault[config.x] holding config.y"),
            "{text}"
        );
    }

    /// A package declaring one method, so a rendering has a name table
    /// to resolve through.
    fn package(method: &str, signature: MethodSignature) -> PackageMetadata {
        let mut metadata = PackageMetadata {
            config: vec!["x".to_owned(), "y".to_owned()],
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
                denomination: None,
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
            reach: None,
            guard: Some(Box::new(condition)),
            target: TargetExpr::Point(Expr::SelfAddr),
            mode: ModeExpr::Read,
            denomination: None,
        }
    }

    /// One read of a point target.
    fn read(target: Expr) -> Clause {
        Clause::Effect {
            reach: None,
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
            Clause::Proves {
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
                reach: None,
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
                        Rule::Require(RuleLeaf::Claim(Expr::Arg(0))),
                        Rule::Require(RuleLeaf::Stored {
                            cell: Expr::SelfAddr,
                        }),
                    ],
                },
            }]),
        );
        assert!(
            text.contains("requires 2 of (claim config.x, claim arg0, the rule stored at self)"),
            "{text}"
        );
    }

    /// A mention of a self-issued resource leaves its grants to the
    /// resources table, which spells them once — unless two derivations
    /// share a mark, in which case no mention leaves anything implicit.
    #[test]
    fn an_issued_resource_spells_its_grants_in_the_resources_table() {
        let granting = |badge: &[u8]| {
            let mut grants = GrantsExpr::new();
            grants.set(
                GrantedBehaviour::Deposit,
                GrantRuleExpr::Require(GrantSubject::SelfBadge {
                    mark: badge.to_vec(),
                    kind: ResourceKind::Fungible,
                    rules: GrantsExpr::new(),
                }),
            );
            grants
        };
        let ticket = |grants| Expr::SelfResource {
            kind: ResourceKind::NonFungible,
            material: vec![Expr::Literal(Value::Bytes(b"ticket".to_vec()))],
            grants,
        };
        let text = explain(&package(
            "issues",
            declaring(vec![read(ticket(granting(b"owner-badge")))]),
        ));
        assert!(
            text.contains(
                "resources\n  non-fungible[\"ticket\"] — granting deposit to whoever \
                 holds the issuer's \"owner-badge\" badge"
            ),
            "{text}"
        );
        assert!(
            text.contains("read self-issued(non-fungible[\"ticket\"])\n"),
            "{text}"
        );

        // Two grant sets under one mark are two resources a reader
        // cannot tell apart by name, so every mention stays whole.
        let text = explain(&package(
            "issues",
            declaring(vec![
                read(ticket(granting(b"owner-badge"))),
                read(ticket(granting(b"court-badge"))),
            ]),
        ));
        assert!(
            text.contains(
                "read self-issued(non-fungible[\"ticket\"]), granting deposit to \
                 whoever holds the issuer's \"owner-badge\" badge"
            ),
            "{text}"
        );
    }

    #[test]
    fn a_range_names_its_bounds_and_what_it_may_touch() {
        let text = rendered(
            "sweeps",
            declaring(vec![Clause::Effect {
                reach: None,
                guard: None,
                target: TargetExpr::Range {
                    owner: Expr::SelfAddr,
                    collection: SlotRef::Fixed(package_slot(0)),
                    material: vec![Expr::Arg(0)],
                    lo: Expr::Literal(Value::U128(3)),
                    hi: Expr::Literal(Value::U128(u128::MAX)),
                    cap: Expr::Len(Box::new(Expr::Arg(1))),
                },
                mode: ModeExpr::Read,
                denomination: None,
            }]),
        );
        assert!(
            text.contains("read self.entries[arg0] over 3..=u128::MAX, at most len(arg1) entries"),
            "{text}"
        );
    }

    /// A range over the whole order space is named rather than spelled,
    /// whichever way its bounds are written.
    #[test]
    fn a_range_over_the_whole_space_is_named_rather_than_spelled() {
        let range = |lo, hi| Clause::Effect {
            reach: None,
            guard: None,
            target: TargetExpr::Range {
                owner: Expr::SelfAddr,
                collection: SlotRef::Fixed(package_slot(0)),
                material: vec![],
                lo,
                hi,
                cap: Expr::Literal(Value::U64(8)),
            },
            mode: ModeExpr::Read,
            denomination: None,
        };
        let text = rendered(
            "whole",
            declaring(vec![range(
                Expr::Literal(Value::U128(0)),
                Expr::Literal(Value::U128(u128::MAX)),
            )]),
        );
        assert!(
            text.contains("read self.entries over the whole order space, at most 8 entries"),
            "{text}"
        );

        let half = |part: u64| Box::new(Expr::Literal(Value::U64(part)));
        let text = rendered(
            "whole",
            declaring(vec![range(
                Expr::Pack {
                    hi: half(0),
                    lo: half(0),
                },
                Expr::Pack {
                    hi: half(u64::MAX),
                    lo: half(u64::MAX),
                },
            )]),
        );
        assert!(text.contains("over the whole order space"), "{text}");
    }

    #[test]
    fn the_package_rendering_carries_every_table_it_declares() {
        let mut signature = declaring(vec![]);
        signature.params = vec![ParamType::Bucket];
        signature.totality = Totality::Total;
        let text = explain(&package("deposit", signature));
        assert!(text.contains("     16  entries — an ordered collection, holding u128"));
        assert!(text.contains("      0  x"));
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

//! The `#[blueprint]` macro: one module is the package.
//!
//! Applied to a module, so the macro sees the component's state, its
//! configuration, and every method together — which is what lets a body
//! written as ordinary Rust yield the access declaration routing needs
//! *and* the component that executes it, without the author writing
//! either.
//!
//! ```ignore
//! #[blueprint]
//! mod account {
//!     #[state]
//!     struct Account {}
//!
//!     impl Account {
//!         pub fn deposit(&mut self, funds: Bucket) {
//!             self.vault(funds.resource()).put(funds);
//!             self.claims(funds.resource()).declared();
//!         }
//!     }
//! }
//! ```
//!
//! The two deltas above are declared because `put` is a commutative
//! movement and `declared` is one stated without making it, and because
//! the key of each is `ResourceOf(Arg(0))` — all of it read off the body.
//! Nothing was written twice.
//!
//! # The two halves
//!
//! A host build gets `blueprint()`: the declaration, traced. A
//! `wasm32` build gets the world, the bindings, and the `impl Guest`
//! whose bodies are the bodies above with each state access rewritten to
//! the kernel call its mode names. The export's parameter list and the
//! signature's ABI binding are the same object seen from two sides, which
//! is why neither is authored: what reaches an export is what the body
//! could not compute, and that is a residue of the body rather than a
//! second declaration of it.
//!
//! # What the macro refuses
//!
//! Routing evaluates a declaration before execution and never reads state,
//! so a key the body computes from a substate value arrives too late to
//! route on. That is not a limitation the macro could engineer away, and
//! the macro stops with an error on the offending line rather than
//! guessing. The same applies to a range's bounds and entry cap, which
//! evaluate with the declaration: an argument or a configured value
//! serves, a substate value does not.
//!
//! The walk is exhaustive: an expression form the lowering does not model
//! is a compile error, never a skip, because a skipped form is a
//! declaration missing whatever the body did inside it. Concretely that
//! refuses closures, macros outside the assert and panic family (whose
//! arguments are walked like any expression), calls that pass the
//! component on — including `self.other_method(…)` — and an early `return`
//! carrying a produced value edge, which the tail's exact output list
//! cannot absorb. Reassigning a local forgets what it held, so a key used
//! after a conditional reassignment is refused at the use site. One handle
//! declares one mode: a read beside a movement, or a second reservation,
//! is refused where it is recorded.
//!
//! Conditionals — `if` and `match` alike — are fine: every arm is
//! declared, giving a superset of what any one execution touches. The VM
//! prices that superset through `footprint` rather than rejecting it.
//!
//! Loops are fine too, and what a `for` means is read off what it ranges
//! over: a configured collection makes it a `for-each` clause, anything
//! else makes it a `while` that binds a name. Walking the entries of an
//! interval the body already declared is the common case, and the range
//! clause covered them before the loop started.
//!
//! A body whose *declaration* is sound but whose executing half the
//! emission cannot write — a `for-each`, whose handle count depends on
//! configuration, or an unordered entry, which sits at a hash the kernel
//! derives — is a compile error on the guest build alone. The declaration
//! still stands, and the package's component is then written the long way:
//! the publish gate judges artifacts, never authorship.
//!
//! # What it does not do
//!
//! It does not build `Expr` literals. Every declaration it derives is
//! emitted as calls into `hyperscale_vm_sdk::Trace`, so the tracer stays
//! the single implementation of what a declaration means and the macro's
//! correctness reduces to whether it called the tracer the way a human
//! would.

// `syn`'s AST is matched by fully-qualified variant path throughout. Pulling
// `Expr::`, `Item::`, or `Type::` into scope would collide with this crate's
// own `Term` and `Val` variants and, worse, read as though it were them —
// the prefix is the only thing distinguishing "the contract's syntax" from
// "the macro's model of it".
#![allow(clippy::absolute_paths)]

mod mode;
use crate::mode::HandleMode;
mod bind;
mod client;
mod emit;
mod guest;
mod host;
mod lower;
mod syntax;
mod term;
mod wit;

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::vocabulary::{
    AUTH, CLAIMS, CONFIG, INSTANCE, NF_VAULT, RESOURCE, VAULT,
};
use hyperscale_vm_effects::{
    MAX_RULE_DEPTH, PACKAGE_SLOT_BASE, ResourceKind, Rule, SlotId, well_formed,
};
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::spanned::Spanned;

use crate::lower::{Field, FieldKind, Lowerer, Target};
use crate::term::{Op, emit_kind};

/// Derive a contract's package from its module: the declaration routing
/// reads, and the component that executes it.
///
/// See the crate docs for the shape and for what the lowering refuses.
///
/// # Panics
///
/// Never; every rejection is a `compile_error!` on the offending span.
#[proc_macro_attribute]
pub fn blueprint(attr: TokenStream, item: TokenStream) -> TokenStream {
    let module = syn::parse_macro_input!(item as syn::ItemMod);
    let attr = TokenStream2::from(attr);
    match serves(&attr).and_then(|serves| expand(module, serves)) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

/// Which addresses the package answers, as its attribute says.
///
/// A package serves instances of itself unless it says otherwise, and
/// exactly one says otherwise: the account, which the instance registry
/// binds to every principal address by class. That is not something the
/// module could be read for — a principal's address folds in no package
/// hash — so it is stated.
fn serves(attr: &TokenStream2) -> syn::Result<client::Serves> {
    if attr.is_empty() {
        return Ok(client::Serves::Instances);
    }
    let ident: syn::Ident = syn::parse2(attr.clone())?;
    if ident == "principals" {
        Ok(client::Serves::Principals)
    } else {
        Err(syn::Error::new(
            ident.span(),
            "`#[blueprint]` takes `principals` or nothing — the first is the package an \
             instance registry serves to every principal address by class, and no other \
             package can be one",
        ))
    }
}

/// A Rust name as the protocol spells it: the published form of a method,
/// an event, or an error code.
fn kebab(name: &str) -> String {
    let mut out = String::new();
    for (index, ch) in name.char_indices() {
        if ch == '_' {
            out.push('-');
        } else if ch.is_uppercase() {
            if index > 0 {
                out.push('-');
            }
            out.extend(ch.to_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

/// The names one declared band spells, refused where two of them
/// collide.
///
/// Every band resolves by position and renders by name — an event's
/// index, an error's code, a role's band offset, a resource's mark — so
/// two entries spelling one name are two claims on one number, and the
/// second is the one nothing reaches. [`kebab`] maps more than one
/// identifier onto a name, which is what makes this something an author
/// can write without seeing it.
fn distinct_band<'a>(
    band: &str,
    declared: impl IntoIterator<Item = &'a syn::Ident>,
) -> syn::Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for ident in declared {
        let name = kebab(&ident.to_string());
        if names.contains(&name) {
            return Err(syn::Error::new(
                ident.span(),
                format!(
                    "`{name}` already names one of this package's {band}, and a band \
                     resolves by position — so this one is an entry nothing can reach"
                ),
            ));
        }
        names.push(name);
    }
    Ok(names)
}

/// The single type argument of a generic state field, which is the value
/// its leaves hold.
fn element_of(ty: &syn::Type) -> Option<syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let syn::PathArguments::AngleBracketed(args) = &path.path.segments.last()?.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty.clone()),
        _ => None,
    })
}

/// The state field's slot and shape, read off its declaration.
fn parse_field(field: &syn::Field, next: u16) -> syn::Result<(String, Field)> {
    let name = field
        .ident
        .as_ref()
        .ok_or_else(|| syn::Error::new(field.span(), "a state field must be named"))?
        .to_string();

    let mut pinned = None;
    let mut denomination = None;
    for attr in &field.attrs {
        if attr.path().is_ident("slot") {
            let literal: syn::LitInt = attr.parse_args()?;
            pinned = Some(literal.base10_parse::<u16>()?);
        }
        if attr.path().is_ident("denomination") {
            denomination = Some(attr.parse_args::<syn::Expr>()?);
        }
    }
    // A slot an author does not pin is the next of the package's own, in
    // declaration order. Safe because a user package is immutable and its
    // instance addresses commit to its hash: reordering fields produces a
    // different package at a different address rather than relocating
    // anything live. A system package upgrades in place under one address
    // and pins every slot, which is what `#[slot(n)]` is left for — and
    // the field walk holds each struct to one discipline or the other.
    let slot = pinned.unwrap_or(next);

    let syn::Type::Path(path) = &field.ty else {
        return Err(syn::Error::new(field.ty.span(), "unsupported state type"));
    };
    let outer = path
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    let kind = match outer.as_str() {
        "Config" => FieldKind::Config,
        "Cell" => FieldKind::Cell,
        "Keyed" => FieldKind::Keyed,
        "Ordered" => FieldKind::Ordered,
        "Unordered" => FieldKind::Unordered,
        _ => {
            return Err(syn::Error::new(
                field.ty.span(),
                "a state field must be `Config<_>`, `Cell<_>`, `Keyed<_>`, `Ordered<_>`, or \
                 `Unordered<_>` — state is reachable only through these, which is what makes \
                 the access mode derivable from the body",
            ));
        }
    };
    // The holdings element is the accessor's alone: a package's own
    // non-fungible collection is not a shape the protocol slots support,
    // and a holder's instances are reached through `holdings(resource)`.
    if matches!(&element_of(&field.ty), Some(ty) if is_named(ty, "NfVault")) {
        return Err(syn::Error::new(
            field.ty.span(),
            "`NfVault` is the holdings element and only the accessor names it — a holder's \
             instances are reached by `holdings(resource)`, not declared as a field",
        ));
    }
    // A vault holds one resource and has to say which. A keyed family is
    // denominated by whatever key a body names it at, so an attribute
    // there would be a second answer to a question the key already
    // settles; a single leaf has no key, so the attribute is the only
    // place it can be said.
    let vault = matches!(&element_of(&field.ty), Some(ty) if is_named(ty, "Vault"));
    match (kind, vault, denomination.is_some()) {
        (FieldKind::Cell, true, false) => {
            return Err(syn::Error::new(
                field.span(),
                "a single vault holds one resource and nothing names which: add \
                 `#[denomination(config.<field>)]`, or `#[denomination(issued(<Resource>))]` \
                 for a declared resource the instance issues",
            ));
        }
        (FieldKind::Keyed, true, true) => {
            return Err(syn::Error::new(
                field.span(),
                "a keyed vault family is denominated by the key a body names it at, so it \
                 cannot also declare one",
            ));
        }
        (_, false, true) => {
            return Err(syn::Error::new(
                field.span(),
                "only a vault is denominated — this field holds no value",
            ));
        }
        _ => {}
    }
    if let Err(refusal) = protocol_band(slot) {
        return Err(syn::Error::new(field.span(), refusal));
    }
    Ok((
        name,
        Field {
            slot,
            kind,
            element: element_of(&field.ty),
            denomination,
        },
    ))
}

/// Refuse a field in the protocol's own band.
///
/// The cells below the base exist under every owner and an engine derives
/// their keys without consulting any metadata, so they are reached by
/// accessor and declared by nobody. A field that lands on one is a
/// package putting its own value where a protocol read will look for
/// something else — and the shape is no defence, because `VAULT` and
/// `CLAIMS` are both a keyed vault, so the band check could see nothing
/// in a misnumbered pool side to disagree with. Refusing the band
/// outright is what makes the claims cell unreachable except through
/// `claims()`.
fn protocol_band(slot: u16) -> Result<(), String> {
    if slot >= PACKAGE_SLOT_BASE {
        return Ok(());
    }
    let cell = match SlotId(slot) {
        VAULT => "a fungible balance cell, reached by `vault(resource)`",
        CLAIMS => "the delivery fallback beside a vault, reached by `claims(resource)`",
        CONFIG => "the creation-fixed configuration leaf, reached by `config()`",
        AUTH => "the stored authority cell, reached by `auth()`",
        RESOURCE => "a resource's record under its issuer",
        NF_VAULT => "a holder's non-fungible instances, reached by `holdings(resource)`",
        INSTANCE => "a non-fungible instance's data",
        _ => "unassigned",
    };
    Err(format!(
        "slot {slot} is the protocol's own — {cell} — and every owner has it already. A \
         package's own slots start at {PACKAGE_SLOT_BASE} and are numbered by declaration \
         order, so this field needs no slot at all"
    ))
}

/// Whether a type's last path segment is `name`.
pub(crate) fn is_named(ty: &syn::Type, name: &str) -> bool {
    matches!(ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == name))
}

/// The address vocabulary: every Rust type that crosses the boundary as
/// the world's own address record, paired with the [`ParamType`] variant
/// naming the classes it admits.
///
/// The one spelling of the family. The binding walk narrows by
/// membership, the signature derivation declares by the paired kind, and
/// the client wrapper widens everything past the wide type — so a class
/// newtype added here is added everywhere at once.
///
/// [`ParamType`]: hyperscale_vm_effects::ParamType
pub(crate) const ADDRESS_FAMILY: [(&str, &str); 6] = [
    ("Address", "Address"),
    ("CallTarget", "CallTarget"),
    ("ComponentAddr", "Component"),
    ("PackageAddr", "Package"),
    ("PrincipalAddr", "Principal"),
    ("ResourceAddr", "Resource"),
];

/// Whether a type is one of the address family's.
pub(crate) fn is_address(ty: &syn::Type) -> bool {
    ADDRESS_FAMILY.iter().any(|(name, _)| is_named(ty, name))
}

/// The parameter kind a Rust type binds as in a manifest.
fn param_type(ty: &syn::Type) -> syn::Result<TokenStream2> {
    let syn::Type::Path(path) = ty else {
        return Err(syn::Error::new(ty.span(), "unsupported parameter type"));
    };
    // An address type declares its classes in the kind, so a wrong-class
    // argument is admission's refusal — which is what lets the generated
    // prologue narrow with no failure arm.
    if let Some((_, kind)) = ADDRESS_FAMILY.iter().find(|(name, _)| is_named(ty, name)) {
        let kind = format_ident!("{kind}");
        return Ok(quote!(::hyperscale_vm_sdk::ParamType::#kind));
    }
    let name = path
        .path
        .segments
        .last()
        .map(|s| s.ident.to_string())
        .unwrap_or_default();
    let variant = match name.as_str() {
        "Bucket" => quote!(Bucket),
        "NfBucket" => quote!(NfBucket),
        "Ids" => quote!(Ids),
        // A quantity is a `u128` at the boundary: the tag is the
        // guest's and erases here, where a manifest binds a number.
        "u128" | "Quantity" => quote!(U128),
        "u64" => quote!(U64),
        "Vec" | "Bytes" => quote!(Bytes),
        "Rule" => quote!(Rule),
        "RoleTable" => quote!(RoleTable),
        _ => {
            return Err(syn::Error::new(
                ty.span(),
                "a contract parameter must be one of `Bucket`, `NfBucket`, `Ids`, \
                 `Quantity`, `u128`, `u64`, `Address`, or bytes — these are the kinds a \
                 manifest can bind",
            ));
        }
    };
    Ok(quote!(::hyperscale_vm_sdk::ParamType::#variant))
}

/// The published name of a method: its Rust name as the protocol spells
/// names, unless `#[name("…")]` says otherwise.
///
/// Kebab by default because every other published name already is — the
/// module's world, its events, its errors — so a method was the one
/// place an author restated a rule the macro applies everywhere else.
/// The attribute stays for the rename that is not a respelling: a
/// published name outlives the Rust identifier that happened to derive
/// it, and a package whose method reads better under another name says
/// so once.
fn method_name(method: &syn::ImplItemFn) -> syn::Result<String> {
    for attr in &method.attrs {
        if attr.path().is_ident("name") {
            let literal: syn::LitStr = attr.parse_args()?;
            let published = literal.value();
            if published == kebab(&method.sig.ident.to_string()) {
                return Err(syn::Error::new_spanned(
                    attr,
                    "this is the name the method already publishes — a `#[name]` that \
                     restates the derivation says nothing, and one that stops agreeing \
                     with it silently renames the method",
                ));
            }
            return Ok(published);
        }
    }
    Ok(kebab(&method.sig.ident.to_string()))
}

/// The macro's own attributes, which are read and then removed so what it
/// emits is ordinary Rust.
const OWN: &[&str] = &[
    "slot",
    "denomination",
    "state",
    "config",
    "name",
    "event",
    "error",
    "record",
    "resource",
    "roles",
    "requires",
    "proves",
    "total",
];

/// The attributes that name a gate, whose method may have no body of
/// its own.
const GATES: &[&str] = &["requires", "proves"];

fn strip(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|attr| !OWN.iter().any(|own| attr.path().is_ident(own)));
}

/// Whose authority naming a method requires, as its own attribute says.
enum Gate {
    /// Anyone may name it.
    Public,
    /// A rule over identities the target itself names.
    Guarded {
        /// The rule, as a tracer call answering a `Requirement`.
        rule: TokenStream2,
        /// Whether the rule is the target's own address and nothing
        /// else, which is what lets a call take its target from the
        /// proof presented.
        on_self: bool,
        /// Whether meeting it can take more than one claim, so a caller
        /// presents a set rather than a proof.
        threshold: bool,
    },
    /// The target's own stored rule, read at the named field's cell.
    Authorizing(u16),
    /// One of the target's stored roles.
    RoleGated(TokenStream2),
    /// One of the package's own stored roles, at a declared table field.
    TableGated {
        /// The slot of the state field holding the table.
        slot: u16,
        /// The role's package-band offset.
        role: u16,
    },
    /// The target's rule and its possession of the badge a parameter
    /// names: the field the rule is stored at, and the parameter's index.
    Custodial {
        /// The slot of the state field holding the target's stored rule.
        rule: u16,
        /// The parameter naming the badge.
        badge: u32,
        /// The parameter naming which instance of it, where the badge is
        /// non-fungible. Absent for a fungible badge, whose possession
        /// is an amount rather than a named thing.
        id: Option<u32>,
    },
}

/// The rule a `#[guarded]` method requires, as a tracer call answering a
/// `Requirement`.
///
/// Rust's own operators carry the algebra: `||` is a count of one, `&&`
/// a count of every branch, and `n_of(k, …)` the threshold no operator
/// expresses. Precedence and grouping are the language's, so an author
/// reads a gate the way they read any other condition — and a chain of
/// one operator flattens into one threshold rather than nesting, because
/// depth is the cap that binds first.
///
/// Answers the rule, whether it is the target's own address alone, and
/// whether meeting it can take more than one claim.
fn guarded_rule(
    expr: &syn::Expr,
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
    params: &[(String, syn::Type)],
    depth: usize,
) -> syn::Result<(TokenStream2, bool, bool)> {
    match expr {
        syn::Expr::Paren(inner) => {
            guarded_rule(&inner.expr, config_fields, resources, params, depth)
        }
        syn::Expr::Binary(binary) => {
            let all = match binary.op {
                syn::BinOp::Or(_) => false,
                syn::BinOp::And(_) => true,
                _ => {
                    return Err(syn::Error::new(
                        binary.op.span(),
                        "a gate combines claims with `||`, `&&`, or `n_of(k, …)`",
                    ));
                }
            };
            let branches = flatten(expr, &binary.op);
            let lowered = threshold(
                expr.span(),
                &branches,
                config_fields,
                resources,
                params,
                depth,
            )?;
            // `||` is a count of one and `&&` a count of every branch, so
            // neither can be a threshold nobody meant: a chain has at
            // least two branches, and both counts sit inside them.
            let count = if all {
                u8::try_from(lowered.len()).unwrap_or(u8::MAX)
            } else {
                1
            };
            check_threshold_node(expr.span(), count, lowered.len())?;
            Ok((
                quote!(__t.n_of(#count, ::std::vec![#(#lowered),*])),
                false,
                true,
            ))
        }
        // A threshold no operator expresses: `n_of(2, a, b, c)`.
        syn::Expr::Call(call) if named(&call.func, "n_of") => {
            let mut args = call.args.iter();
            let count = args.next().and_then(count_literal).ok_or_else(|| {
                syn::Error::new(
                    call.span(),
                    "`n_of` takes a literal count and then the claims it counts",
                )
            })?;
            let branches: Vec<_> = args.collect();
            let lowered = threshold(
                call.span(),
                &branches,
                config_fields,
                resources,
                params,
                depth,
            )?;
            check_threshold_node(call.span(), count, lowered.len())?;
            Ok((
                quote!(__t.n_of(#count, ::std::vec![#(#lowered),*])),
                false,
                true,
            ))
        }
        // `recalls(resource)` — the rule the resource's own address
        // seals for recall, resolved at admission from the presented
        // record. The other sealed behaviours get their spellings when
        // something consumes them.
        syn::Expr::Call(call) if named(&call.func, "recalls") => {
            let Some(arg) = call.args.first() else {
                return Err(syn::Error::new(
                    call.span(),
                    "`recalls` names the resource whose sealed recall rule governs",
                ));
            };
            // A caller may name the resource, unlike an authority: the
            // rule is the address's own commitment, so naming the
            // resource chooses which sealed rule governs and can never
            // choose what it says.
            let resource = sealed_subject(arg, config_fields, params)?;
            Ok((
                quote!(__t.sealed(::hyperscale_vm_sdk::SealedBehaviour::Recall, &#resource)),
                false,
                true,
            ))
        }
        leaf => {
            let (identity, on_self) = guarded_identity(leaf, config_fields, resources, params)?;
            Ok((quote!(__t.claim(&#identity)), on_self, false))
        }
    }
}

/// One threshold node's shape, judged by the vocabulary's own predicate
/// — the same one the tracer's `n_of` and the stored rule's decode gate
/// apply — so what the macro refuses cannot fork from what they refuse.
/// The span is the one thing this side adds: the line that wrote the
/// gate, rather than the tracer's panic inside a generated `blueprint()`.
fn check_threshold_node(span: Span, count: u8, width: usize) -> syn::Result<()> {
    let node = Rule::CountOf {
        count,
        rules: vec![Rule::Require(()); width],
    };
    well_formed(&node).map_err(|reason| syn::Error::new(span, reason))
}

/// The branches of one threshold, lowered, held to the depth the
/// vocabulary admits.
///
/// The cap is read from the vocabulary rather than restated, and it is
/// checked here rather than at the tracer's own assertion: both refuse
/// the same trees — a threshold at the deepest level would put its
/// branches past the cap, which is what `within_caps` walks into — but
/// only this one can point at the line that wrote it. Depth is a
/// property of the shape alone, so a gate whose leaves nobody has
/// evaluated is still answerable for it; the node's count and width are
/// judged where each arm knows its count, through the shared predicate.
fn threshold(
    span: Span,
    branches: &[&syn::Expr],
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
    params: &[(String, syn::Type)],
    depth: usize,
) -> syn::Result<Vec<TokenStream2>> {
    if depth + 1 >= MAX_RULE_DEPTH {
        return Err(syn::Error::new(
            span,
            format!("a gate nests past the {MAX_RULE_DEPTH} levels the vocabulary admits"),
        ));
    }
    branches
        .iter()
        .map(|branch| {
            guarded_rule(branch, config_fields, resources, params, depth + 1)
                .map(|(rule, _, _)| rule)
        })
        .collect()
}

/// One operator's whole chain as a flat branch list.
///
/// `a || b || c` parses left-nested, and nesting is what the depth cap
/// binds first — so a chain of one operator is one threshold over three
/// branches rather than two over two.
fn flatten<'a>(expr: &'a syn::Expr, op: &syn::BinOp) -> Vec<&'a syn::Expr> {
    let same = |other: &syn::BinOp| {
        matches!(
            (op, other),
            (syn::BinOp::Or(_), syn::BinOp::Or(_)) | (syn::BinOp::And(_), syn::BinOp::And(_))
        )
    };
    match expr {
        syn::Expr::Binary(binary) if same(&binary.op) => {
            let mut out = flatten(&binary.left, op);
            out.extend(flatten(&binary.right, op));
            out
        }
        other => vec![other],
    }
}

/// Whether a call names `name`, by its last path segment.
fn named(func: &syn::Expr, name: &str) -> bool {
    matches!(func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == name))
}

/// A `u8` count written as a literal.
fn count_literal(expr: &syn::Expr) -> Option<u8> {
    match expr {
        syn::Expr::Lit(lit) => match &lit.lit {
            syn::Lit::Int(int) => int.base10_parse().ok(),
            _ => None,
        },
        _ => None,
    }
}

/// The identity a `#[guarded]` method requires, as a tracer call.
///
/// Every identity a method can require is one the target itself names.
/// A caller who names the identity they must present can always present
/// it, so a gate over an argument reads as guarded and admits everyone —
/// which is the refusal `check_abi` makes at publish, made here on the
/// line that wrote it.
/// The resource a sealed leaf governs by: a parameter or a configured
/// field, resolved to the expression admission evaluates.
///
/// Caller-named on purpose, where an authority never may be: the sealed
/// rule is the address's own commitment, verified by re-derivation, so
/// the namer picks which resource's rule applies and nothing about what
/// it admits.
fn sealed_subject(
    subject: &syn::Expr,
    config_fields: &[(String, syn::Type)],
    params: &[(String, syn::Type)],
) -> syn::Result<TokenStream2> {
    let refuse = || {
        syn::Error::new(
            subject.span(),
            "a sealed rule's resource is a method parameter or one of the component's \
             configuration fields",
        )
    };
    let syn::Expr::Path(path) = subject else {
        return Err(refuse());
    };
    let Some(name) = path.path.get_ident().map(ToString::to_string) else {
        return Err(refuse());
    };
    if let Some(index) = params.iter().position(|(p, _)| *p == name) {
        let index = u32::try_from(index).expect("a parameter list is shorter than u32");
        return Ok(quote!(__t.arg::<::hyperscale_vm_sdk::Addr>(#index)));
    }
    if let Some(slot) = config_fields.iter().position(|(f, _)| *f == name) {
        let slot = u32::try_from(slot).unwrap_or(u32::MAX);
        return Ok(quote!(__t.config::<::hyperscale_vm_sdk::Addr>(#slot)));
    }
    Err(refuse())
}

fn guarded_identity(
    identity: &syn::Expr,
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
    params: &[(String, syn::Type)],
) -> syn::Result<(TokenStream2, bool)> {
    // Possession has its own authoring surface, and `#[requires]` is
    // not it: a rule is a match over presented claims, and a `holds`
    // anywhere in one — beside a rule under a conjunction as much as
    // within it under a disjunction — would make authority a predicate
    // engine, which is the fence this grammar keeps.
    if let syn::Expr::Call(call) = identity
        && matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("holds"))
    {
        return Err(syn::Error::new(
            identity.span(),
            "a `#[requires]` rule names claims only; possession is spelled \
             `#[proves(badge)]`",
        ));
    }
    let refuse = || {
        syn::Error::new(
            identity.span(),
            "a guarded method names `self`, a badge it issues, or one of the \
             component's configuration fields",
        )
    };
    match identity {
        syn::Expr::Path(path) if path.path.is_ident("self") => Ok((quote!(__t.self_addr()), true)),
        syn::Expr::Path(path) if path.path.get_ident().is_some() => {
            let name = path.path.get_ident().expect("checked").to_string();
            if params.iter().any(|(p, _)| *p == name) {
                return Err(syn::Error::new(
                    identity.span(),
                    "the authority this method requires is one its caller names, so \
                     the gate would admit everyone — name `self`, a badge it issues, \
                     or a configuration field instead",
                ));
            }
            let issued = resources.iter().find(|r| r.name == name);
            let configured = config_fields.iter().position(|(f, _)| *f == name);
            // The two are different authorities — a badge this instance
            // issues, an address fixed where it was created — so a name
            // that is both says nothing about which the gate means.
            if issued.is_some() && configured.is_some() {
                return Err(syn::Error::new(
                    identity.span(),
                    "this names both a resource the package issues and a configuration \
                     field, so which authority the gate means is not written — rename one",
                ));
            }
            // A resource the package declares is one this instance
            // issues, so holding it is operating this instance and the
            // mark is the item's rather than a literal repeated at every
            // gate that names it.
            if let Some(issued) = issued {
                let kind = emit_kind(issued.kind);
                let mark = syn::LitByteStr::new(&issued.mark, identity.span());
                return Ok((quote!(__t.self_resource(#kind, #mark)), false));
            }
            // Creation-fixed, so the claim is the target's own: an
            // object whose address derives from no key admits somebody
            // by naming them where it was created.
            let Some(slot) = configured else {
                return Err(refuse());
            };
            let slot = u32::try_from(slot).unwrap_or(u32::MAX);
            Ok((
                quote!(__t.config::<::hyperscale_vm_sdk::Addr>(#slot)),
                false,
            ))
        }
        // A badge the instance issues: holding it is operating the
        // instance, and it derives from the address rather than from
        // anything a caller supplies. `issued(Name)` names a declared
        // `#[resource]` struct, because the derivation folds the kind
        // and the declaration is where a kind is stated.
        syn::Expr::Call(call) => {
            let named = match &*call.func {
                syn::Expr::Path(path) => path
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "issued"),
                _ => false,
            };
            let resolved = call
                .args
                .first()
                .and_then(|arg| match arg {
                    syn::Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
                    _ => None,
                })
                .and_then(|name| resources.iter().find(|r| r.name == name));
            match (named, resolved) {
                (true, Some(issued)) => {
                    let kind = emit_kind(issued.kind);
                    let mark = syn::LitByteStr::new(&issued.mark, identity.span());
                    Ok((quote!(__t.self_resource(#kind, #mark)), false))
                }
                _ => Err(refuse()),
            }
        }
        _ => Err(refuse()),
    }
}

/// The `#[requires(<rule>)]` grammar: the stored-rule form `auth[role]`,
/// or a rule over claims the declaration names.
fn parse_requires(
    attr: &syn::Attribute,
    declared: &Declared<'_>,
    params: &[(String, syn::Type)],
) -> syn::Result<Gate> {
    let written: syn::Expr = attr.parse_args()?;
    // The stored-rule form: `auth[primary]` names the protocol table,
    // `<field>[Role]` a package's own — each with the role the caller
    // must satisfy there.
    if let syn::Expr::Index(index) = &written {
        let syn::Expr::Path(base) = index.expr.as_ref() else {
            return Err(syn::Error::new(
                index.span(),
                "a stored-rule condition is written `auth[role]` or `<field>[Role]`",
            ));
        };
        let syn::Expr::Path(role) = index.index.as_ref() else {
            return Err(syn::Error::new(
                index.index.span(),
                "a stored role is named, not computed",
            ));
        };
        if base.path.is_ident("auth") {
            let named = match role.path.get_ident().map(ToString::to_string).as_deref() {
                Some("primary") => quote!(PRIMARY),
                Some("recovery") => quote!(RECOVERY),
                Some("confirmation") => quote!(CONFIRMATION),
                _ => {
                    return Err(syn::Error::new(
                        role.span(),
                        "a stored role is `primary`, `recovery`, or `confirmation`",
                    ));
                }
            };
            return Ok(Gate::RoleGated(quote!(::hyperscale_vm_sdk::#named)));
        }
        // A package's own table: the field holding it, indexed by a
        // declared role name. The field's type is what says it holds a
        // rule table, and the `#[roles]` enum is where the name gets its
        // band offset.
        let Some(field) = base
            .path
            .get_ident()
            .and_then(|ident| declared.fields.get(&ident.to_string()))
        else {
            return Err(syn::Error::new(
                base.span(),
                "a stored table is `auth`, or a declared field holding the package's \
                 own role table",
            ));
        };
        if !holds_role_table(field) {
            return Err(syn::Error::new(
                base.span(),
                "this field does not hold a role table — a package's stored roles live \
                 in a `Cell<Option<AuthCell>>` field",
            ));
        }
        let named = role
            .path
            .get_ident()
            .map(|ident| kebab(&ident.to_string()))
            .and_then(|name| declared.roles.iter().position(|r| *r == name));
        let Some(offset) = named else {
            return Err(syn::Error::new(
                role.span(),
                "not a declared role — name a variant of the package's `#[roles]` enum",
            ));
        };
        let slot = field.slot;
        let role = u16::try_from(offset).expect("a role enum is shorter than u16");
        return Ok(Gate::TableGated { slot, role });
    }
    let (rule, on_self, threshold) = guarded_rule(
        &written,
        declared.config_fields,
        declared.resources,
        params,
        0,
    )?;
    Ok(Gate::Guarded {
        rule,
        on_self,
        threshold,
    })
}

/// Read a method's gate off its attributes.
fn parse_gate(
    method: &syn::ImplItemFn,
    declared: &Declared<'_>,
    params: &[(String, syn::Type)],
) -> syn::Result<Gate> {
    // A gate names the cell its rule lives in the way a body would, and a
    // body reaches the protocol's own cells by accessor.
    let cell = |name: &syn::Ident| {
        declared
            .fields
            .get(&name.to_string())
            .or_else(|| declared.accessors.get(&name.to_string()))
            .map(|f| f.slot)
            .ok_or_else(|| {
                syn::Error::new(
                    name.span(),
                    "not a cell of the component's state — name a declared field or one of \
                     the protocol's own cells",
                )
            })
    };
    for attr in &method.attrs {
        if attr.path().is_ident("requires") {
            return parse_requires(attr, declared, params);
        }
        if attr.path().is_ident("proves") {
            let claim: syn::Expr = attr.parse_args()?;
            // `proves(self)`: satisfying one's own stored rule, minting
            // one's own identity.
            if let syn::Expr::Path(path) = &claim
                && path.path.is_ident("self")
            {
                let auth = syn::Ident::new("auth", claim.span());
                return Ok(Gate::Authorizing(cell(&auth)?));
            }
            let auth = syn::Ident::new("auth", claim.span());
            let rule = cell(&auth)?;
            let position = |named: &syn::Ident| {
                params
                    .iter()
                    .position(|(p, _)| named == p.as_str())
                    .map(|index| {
                        u32::try_from(index).expect("a parameter list is shorter than u32")
                    })
                    .ok_or_else(|| syn::Error::new(named.span(), "not a parameter of this method"))
            };
            // `proves(badge)` and `proves(badge[id])`: the stored rule,
            // possession of the badge, and the badge's mint.
            return match &claim {
                syn::Expr::Path(badge) => {
                    let badge = badge.path.require_ident()?;
                    Ok(Gate::Custodial {
                        rule,
                        badge: position(badge)?,
                        id: None,
                    })
                }
                syn::Expr::Index(index) => {
                    let (syn::Expr::Path(badge), syn::Expr::Path(id)) =
                        (index.expr.as_ref(), index.index.as_ref())
                    else {
                        return Err(syn::Error::new(
                            index.span(),
                            "an instance claim is written `badge[id]`, both parameters of \
                             this method",
                        ));
                    };
                    Ok(Gate::Custodial {
                        rule,
                        badge: position(badge.path.require_ident()?)?,
                        id: Some(position(id.path.require_ident()?)?),
                    })
                }
                _ => Err(syn::Error::new(
                    claim.span(),
                    "a call proves `self`, a badge parameter, or `badge[id]`",
                )),
            };
        }
    }
    Ok(Gate::Public)
}

/// The protocol's own cells, as a body reaches them.
///
/// These exist under every owner and an engine derives their keys without
/// consulting any metadata, so declaring them asks every package to
/// re-declare the same universals correctly — and a package that gets one
/// wrong puts its value where a protocol read will look for something
/// else. They are accessors instead, and the shape each takes here is the
/// field shape it replaces, so a body reaching one lands on the clause
/// the field lowered to.
fn accessors(config: Option<&syn::Ident>) -> BTreeMap<String, Field> {
    let vault = || Field {
        slot: VAULT.0,
        kind: FieldKind::Keyed,
        element: Some(syn::parse_quote!(::hyperscale_vm_sdk::state::Vault)),
        denomination: None,
    };
    let mut cells = BTreeMap::from([
        ("vault".to_owned(), vault()),
        (
            "claims".to_owned(),
            Field {
                slot: CLAIMS.0,
                ..vault()
            },
        ),
        (
            "holdings".to_owned(),
            Field {
                slot: NF_VAULT.0,
                kind: FieldKind::Ordered,
                // The instance's id is the entry's own order key, so an
                // entry has nothing left to hold — the element is the
                // name the derivation reads to know the interval holds
                // value and is narrowed by a resource.
                element: Some(syn::parse_quote!(::hyperscale_vm_sdk::state::NfVault)),
                denomination: None,
            },
        ),
        (
            "auth".to_owned(),
            Field {
                slot: AUTH.0,
                kind: FieldKind::Cell,
                element: Some(syn::parse_quote!(
                    ::core::option::Option<::hyperscale_vm_sdk::AuthCell>
                )),
                denomination: None,
            },
        ),
    ]);
    // A package with no configuration struct has no configuration to
    // read, and `config()` is a name it never gets rather than one that
    // answers nothing.
    if let Some(config) = config {
        cells.insert(
            "config".to_owned(),
            Field {
                slot: CONFIG.0,
                kind: FieldKind::Config,
                element: Some(syn::parse_quote!(#config)),
                denomination: None,
            },
        );
    }
    cells
}

/// The `#[state]` struct: its name, its fields by slot and shape, and the
/// configuration struct its `Config<_>` field names, if it has one.
fn parse_state(
    items: &[syn::Item],
    span: Span,
) -> syn::Result<(syn::Ident, BTreeMap<String, Field>, Option<syn::Ident>)> {
    // Named before the state is read, so the refusal below can name every
    // accessor a field would shadow — including `config`, which exists
    // exactly when the package declares a configuration struct.
    let reserved = accessors(None);
    let mut fields = BTreeMap::new();
    let mut state_name = None;
    let mut config_name = None;
    for item in items {
        if let syn::Item::Struct(item) = item
            && item.attrs.iter().any(|a| a.path().is_ident("config"))
        {
            config_name = Some(item.ident.clone());
        }
    }
    // What a field would name a leaf by: its slot, and the material the
    // field itself fixes. Two fields agreeing on both are one leaf under
    // two names, which no accessor can tell apart afterwards.
    let mut named: BTreeMap<(u16, String), String> = BTreeMap::new();
    // The package band's next free slot. A pinned slot advances it too,
    // so an unpinned field never lands on one a later pin also names —
    // the collision that remains is a pin *below* the counter, which the
    // duplicate check below reports on the line that wrote it.
    let mut next = PACKAGE_SLOT_BASE;
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if !item.attrs.iter().any(|a| a.path().is_ident("state")) {
            continue;
        }
        state_name = Some(item.ident.clone());
        // Whether this struct pins its slots, decided by its first field
        // and held to by the rest. Declaration order numbers the
        // unpinned, so a mix would let an insertion renumber the fields
        // below it — under an in-place upgrade, that is a read of the
        // wrong leaf.
        let mut pinning: Option<(bool, String)> = None;
        for field in &item.fields {
            let (name, parsed) = parse_field(field, next)?;
            let pins = field.attrs.iter().any(|a| a.path().is_ident("slot"));
            match &pinning {
                None => pinning = Some((pins, name.clone())),
                Some((discipline, holder)) if *discipline != pins => {
                    return Err(syn::Error::new(
                        field.span(),
                        format!(
                            "a `#[state]` struct pins every slot or none: `{holder}` and \
                             `{name}` disagree, and a mix lets an insertion renumber the \
                             unpinned fields under an in-place upgrade"
                        ),
                    ));
                }
                Some(_) => {}
            }
            if reserved.contains_key(&name) {
                return Err(syn::Error::new(
                    field.span(),
                    format!(
                        "`{name}` is the accessor for one of the protocol's own cells, which \
                         exists under every owner — a field of that name would shadow it"
                    ),
                ));
            }
            if parsed.slot >= PACKAGE_SLOT_BASE {
                next = next.max(parsed.slot + 1);
            }
            let material = parsed
                .denomination
                .as_ref()
                .map_or_else(String::new, |expr| quote!(#expr).to_string());
            if let Some(held) = named.insert((parsed.slot, material), name.clone()) {
                return Err(syn::Error::new(
                    field.span(),
                    format!(
                        "`{held}` already holds slot {} under the same material, so both fields \
                         name one leaf",
                        parsed.slot
                    ),
                ));
            }
            fields.insert(name, parsed);
        }
    }
    let state_name = state_name.ok_or_else(|| {
        syn::Error::new(
            span,
            "`#[blueprint]` needs one `#[state]` struct — it names the slots every key in \
             the package sits under",
        )
    })?;
    Ok((state_name, fields, config_name))
}

/// The configuration struct's fields in declaration order — which is what
/// fixes each one's config slot index, and what a guest reading one gets
/// handed.
fn config_slots(items: &[syn::Item], config_name: Option<&syn::Ident>) -> Vec<(String, syn::Type)> {
    let Some(config_name) = config_name else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.ident == *config_name => Some(&item.fields),
            _ => None,
        })
        .flatten()
        .filter_map(|field| {
            field
                .ident
                .as_ref()
                .map(|name| (name.to_string(), field.ty.clone()))
        })
        .collect()
}

/// The package's event names, in the declaration order an emitted index
/// refers to.
fn event_names(items: &[syn::Item]) -> syn::Result<Vec<(syn::Ident, String)>> {
    let declared: Vec<&syn::Ident> = items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Struct(item) if item.attrs.iter().any(|a| a.path().is_ident("event")) => {
                Some(&item.ident)
            }
            _ => None,
        })
        .collect();
    let names = distinct_band("events", declared.iter().copied())?;
    Ok(declared.into_iter().cloned().zip(names).collect())
}

/// The package's error names, in the order a declined invocation's code
/// refers to.
fn error_names(items: &[syn::Item]) -> syn::Result<Vec<String>> {
    distinct_band(
        "errors",
        items
            .iter()
            .filter_map(|item| match item {
                syn::Item::Enum(item) if item.attrs.iter().any(|a| a.path().is_ident("error")) => {
                    Some(&item.variants)
                }
                _ => None,
            })
            .flatten()
            .map(|variant| &variant.ident),
    )
}

/// The `#[total]` attribute, where a method claims the mark the publish
/// gate then checks against the artifact the claim rides on.
///
/// Returned rather than reduced to a flag so a refusal can point at the
/// claim: the mark is one attribute an author adds or removes, and an
/// error on the method's name asks them to work out which of the lines
/// above it is the one being complained about.
fn total_attr(method: &syn::ImplItemFn) -> Option<&syn::Attribute> {
    method
        .attrs
        .iter()
        .find(|attr| attr.path().is_ident("total"))
}

/// Whether a method's return type carries an error arm, which is the whole
/// of what its totality mark is.
fn declines(method: &syn::ImplItemFn) -> bool {
    let syn::ReturnType::Type(_, ty) = &method.sig.output else {
        return false;
    };
    matches!(&**ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "Result"))
}

/// One public method, lowered to its declaration and its two executing
/// halves.
struct Lowered {
    /// The `.method(…)` builder call.
    declaration: TokenStream2,
    /// The export and the `impl Guest` body behind it, or why there is
    /// none.
    guest: Result<guest::Method, TokenStream2>,
    /// The arm this method takes in the package's native dispatch.
    ///
    /// Emitted whether or not the guest half is, because what the two
    /// refuse over is the component the emission cannot build — never
    /// the body, which is the same text either way.
    host: TokenStream2,
    /// What the method contributes to the package's calling surface.
    ///
    /// Emitted whether or not the guest half is, for the same reason the
    /// declaration is: a package written the long way is still called
    /// through the declaration it publishes.
    client: client::Method,
}

#[allow(clippy::too_many_lines)] // one pass over a method: name, params, gate, body, export
fn lower_method(
    method: &syn::ImplItemFn,
    declared: &Declared<'_>,
    serves: client::Serves,
) -> syn::Result<Lowered> {
    let published = method_name(method)?;
    let mut params = Vec::new();
    let mut idents = Vec::new();
    let mut kinds = Vec::new();
    for arg in &method.sig.inputs {
        let syn::FnArg::Typed(arg) = arg else {
            continue; // the receiver
        };
        let syn::Pat::Ident(ident) = &*arg.pat else {
            return Err(syn::Error::new(
                arg.pat.span(),
                "a contract parameter must be a plain name — the declaration refers \
                 to arguments positionally, and a pattern has no one position",
            ));
        };
        idents.push(ident.ident.clone());
        params.push((ident.ident.to_string(), (*arg.ty).clone()));
        kinds.push(param_type(&arg.ty)?);
    }

    let gate = parse_gate(method, declared, &params)?;
    client::check_names(&idents, client::Shape::of(&gate), serves)?;
    let returns = !matches!(method.sig.output, syn::ReturnType::Default);
    let claims_total = total_attr(method).is_some();
    let lowered = Lowerer::new(declared, &params, returns, claims_total)
        .run(&method.block)
        .map_err(|errors| {
            errors
                .into_iter()
                .reduce(|mut all, error| {
                    all.combine(error);
                    all
                })
                .unwrap_or_else(|| syn::Error::new(method.span(), "lowering failed"))
        })?;
    check_gate_shape(&gate, &lowered, method)?;

    let declining = declines(method);
    let claim = total_attr(method);
    // What the mark promises is that a caller committing against this
    // method has nothing to hear back. Three things could break that, and
    // the macro can see two of them: an error arm the method declines
    // through, and a gate that turns callers away before the body runs.
    // The third is a trap, which is a property of compiled code the macro
    // has not emitted yet — so that one is the publish gate's, read off
    // the artifact. Refusing the two that are visible here is what keeps
    // an author from meeting them later as a metadata error about a
    // package rather than as a mistake on a line.
    if let Some(claim) = claim {
        if declining {
            return Err(syn::Error::new_spanned(
                claim,
                "a method carrying an error arm can refuse, and a total method cannot: the \
                 two marks describe the same signature and only one of them is true",
            ));
        }
        if !matches!(gate, Gate::Public) {
            return Err(syn::Error::new_spanned(
                claim,
                "a total method admits every caller, and a gate turns some away before the \
                 body runs: drop the mark, or drop the gate",
            ));
        }
    }
    let total = claim.is_some();
    let closure = emit::declaration(
        &lowered,
        &gate_calls(&gate, &lowered),
        declining,
        total,
        &sealed_registrations(declared.resources),
    );
    let declaration = quote!(
        .method(#published, &[#(#kinds),*], #closure)
    );
    let name = published.clone();

    let guest = lowered.refusal.as_ref().map_or_else(
        || {
            Ok(guest::method(
                &name,
                &lowered,
                &params,
                declared.config_fields,
                declining,
            ))
        },
        |(span, why)| Err(guest::refusal(&name, *span, why)),
    );
    let host = host::arm(&name, &lowered, &params, declared.config_fields, declining);
    let client = client::Method {
        rust: method.sig.ident.clone(),
        published,
        shape: client::Shape::of(&gate),
        outputs: lowered.outputs.len(),
        docs: method
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("doc"))
            .cloned()
            .collect(),
        params,
    };
    Ok(Lowered {
        declaration,
        guest,
        host,
        client,
    })
}

/// The tracer calls a gate becomes.
///
/// An authorizing method's clause is the gate's, not the body's: the
/// kernel reads the stored rule before the export runs, so the read is
/// declared here and no handle is bound for it.
fn gate_calls(gate: &Gate, lowered: &lower::Lowered) -> TokenStream2 {
    match gate {
        Gate::Public => quote!(),
        Gate::Guarded { rule, .. } => quote!({
            let __rule = #rule;
            __t.guarded_by(__rule);
        }),
        Gate::Authorizing(slot) => quote!({
            let __owner = __t.self_addr();
            let __key = __owner.child(::hyperscale_vm_sdk::SlotId(#slot), &[]);
            __t.point(&__key).read();
            __t.authorizing();
        }),
        Gate::RoleGated(role) => quote!(__t.role_gated(#role);),
        // A package-table gate declares its own read — unless the body
        // already reaches the table, in which case the gate rides the
        // body's own clause exactly as the protocol table's rewrites do:
        // one cell is one clause, and two declarations of it would be a
        // self-conflict.
        Gate::TableGated { slot, role } => {
            if lowered.point_site(*slot).is_some() {
                quote!(__t.role_gated(::hyperscale_vm_sdk::package_role(#role));)
            } else {
                quote!({
                    let __owner = __t.self_addr();
                    let __key = __owner.child(::hyperscale_vm_sdk::SlotId(#slot), &[]);
                    __t.point(&__key).read();
                    __t.table_gated(::hyperscale_vm_sdk::package_role(#role));
                })
            }
        }
        // A custody gate is two reads and neither is the body's: the
        // kernel judges the holder's stored rule and their possession of
        // the badge before the export runs, so what the clauses do is
        // provision the cells it reads. The possession read is pinned to
        // the protocol's own slot, keyed by exactly the expressions the
        // mint names — which is what ties what is minted to what is
        // held. It says what it holds too: a vault is a value cell in
        // every mode it is reached in, and a read that said nothing
        // would be a read of bytes.
        Gate::Custodial {
            rule,
            badge,
            id: None,
        } => quote!({
            let __owner = __t.self_addr();
            let __badge = __t.arg::<::hyperscale_vm_sdk::Addr>(#badge);
            let __material = [__badge.clone().cast::<::hyperscale_vm_sdk::Opaque>()];
            let __rule = __owner.child(::hyperscale_vm_sdk::SlotId(#rule), &[]);
            __t.point(&__rule).read();
            let __vault = __owner.child(::hyperscale_vm_sdk::VAULT, &__material);
            __t.point(&__vault).holding(&__badge).read();
            __t.custodial(&__badge);
        }),
        Gate::Custodial {
            rule,
            badge,
            id: Some(id),
        } => quote!({
            let __owner = __t.self_addr();
            let __badge = __t.arg::<::hyperscale_vm_sdk::Addr>(#badge);
            let __id = __t
                .arg::<::hyperscale_vm_sdk::Num>(#id)
                .cast::<::hyperscale_vm_sdk::Amount>();
            let __material = [__badge.clone().cast::<::hyperscale_vm_sdk::Opaque>()];
            let __rule = __owner.child(::hyperscale_vm_sdk::SlotId(#rule), &[]);
            __t.point(&__rule).read();
            // The entry at the instance's own id: holding that one, not
            // holding any.
            __t.entry(
                &__owner,
                ::hyperscale_vm_sdk::NF_VAULT,
                &__material,
                &__id,
            )
            .holding(&__badge)
            .read();
            __t.custodial_instance(&__badge, &__id);
        }),
    }
}

/// Hold a gate to the declaration shape the publish gate pins for it.
///
/// The same rules `hyperscale_vm_effects::check_abi` applies to a
/// published artifact, applied to the body that would produce one — so an
/// author hears about it on the offending line rather than at the moment
/// they try to publish.
fn check_gate_shape(
    gate: &Gate,
    lowered: &lower::Lowered,
    method: &syn::ImplItemFn,
) -> syn::Result<()> {
    let refuse = |message: &str| Err(syn::Error::new(method.sig.ident.span(), message));
    match gate {
        Gate::Public | Gate::Guarded { .. } => Ok(()),
        Gate::Authorizing(_) => {
            if lowered.sites.is_empty() {
                Ok(())
            } else {
                refuse(
                    "an authorizing method declares exactly one point read — the cell its \
                     stored rule lives in, which the kernel reads before the export runs. \
                     The body has nothing left to say, so it must be empty",
                )
            }
        }
        Gate::RoleGated(_) => match lowered.sites.as_slice() {
            [site]
                if matches!(site.target, Target::Point { .. })
                    && site.resource() == Some(HandleMode::WriteCell) =>
            {
                Ok(())
            }
            _ => refuse(
                "a role-gated method declares exactly one point write — the cell its \
                 stored roles live in. The write is where the gate's cell comes from, \
                 and it serializes role rewrites against concurrent sign-ins",
            ),
        },
        // A table-gated method's body is its own: the gate declares the
        // read it judges where the body does not reach the table. Where
        // it does, the rewrite must read what it rewrites — `existing()`
        // — so an unfounded component's rotation refuses as the routed
        // absence rather than creating a table out of nowhere.
        Gate::TableGated { slot, .. } => {
            let Some(site) = lowered.point_site(*slot) else {
                return Ok(());
            };
            if !site.ops.iter().any(|(op, _)| *op == Op::Existing) {
                return refuse(
                    "a role-gated rewrite of its own table reads what it rewrites — \
                     `existing()` — so an unfounded component refuses as the routed \
                     absence rather than seeding a table its founding never wrote",
                );
            }
            // Where the body reaches the table the gate rides the body's
            // own clause, and the cell it reads the rule from is the one
            // write it finds — so a second write beside it would leave
            // two cells answering for one role.
            let writes = lowered
                .sites
                .iter()
                .filter(|site| site.resource() == Some(HandleMode::WriteCell))
                .count();
            if writes > 1 {
                return refuse(
                    "a method gated on its own stored table rewrites that table and \
                     nothing else: the gate reads its rule from the body's own write, \
                     so a second write leaves two cells answering for one role",
                );
            }
            Ok(())
        }
        Gate::Custodial { .. } => {
            if lowered.sites.is_empty() {
                Ok(())
            } else {
                refuse(
                    "a custodial method declares two reads — its rule cell, and the \
                     badge-keyed vault or holdings entry its claim names — and the \
                     kernel makes both before the export runs. The body has nothing \
                     left to say, so it must be empty",
                )
            }
        }
    }
}

/// Every public method of the state struct's inherent impls, lowered.
fn lower_methods(
    items: &[syn::Item],
    state_name: &syn::Ident,
    declared: &Declared<'_>,
    serves: client::Serves,
) -> syn::Result<Vec<Lowered>> {
    let mut lowered = Vec::new();
    for item in items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        if !matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name)) {
            continue;
        }
        for item in &block.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if matches!(method.vis, syn::Visibility::Public(_)) {
                if matches!(serves, client::Serves::Instances) && method.sig.ident == "instantiate"
                {
                    return Err(syn::Error::new(
                        method.sig.ident.span(),
                        "`instantiate` is the generated seal: the macro derives it for \
                         every instance-serving package, so an authored method cannot \
                         take the name",
                    ));
                }
                lowered.push(lower_method(method, declared, serves)?);
            }
        }
    }
    if matches!(serves, client::Serves::Instances) {
        lowered.push(lower_method(
            &instantiate_method(declared.resources, instantiation_gate(items)),
            declared,
            serves,
        )?);
    }
    Ok(lowered)
}

/// The generated `instantiate` — the seal that makes a component actual,
/// beside the record of every resource it declares.
///
/// Synthesized rather than authored: the statements lower to the
/// `CONFIG` write and one `RESOURCE` write per declared mark, each under
/// its own absence door, and the method is never emitted into the module
/// — only its lowered halves exist.
///
/// The records ride the seal rather than a call of their own because a
/// record is an ordinary declared write and needs no issuance grant, so
/// the node that makes the component actual is the node that says what
/// it issues. A package declaring no resource comes up in this one node
/// and nothing else.
fn instantiate_method(resources: &[Resource], gate: Option<&syn::Attribute>) -> syn::ImplItemFn {
    let records = resources.iter().map(|resource| {
        let name = syn::Ident::new(&resource.name, Span::call_site());
        let stated = match resource.kind {
            ResourceKind::Fungible => {
                let divisibility = resource.divisibility;
                quote!(#divisibility)
            }
            ResourceKind::NonFungible => quote!(),
        };
        quote!(#name::__record(#stated);)
    });
    // The supply, where a mark states one: the node that makes the
    // component actual is the node that issues what it comes up
    // holding, so the two are one invocation and the edge leaves with
    // whoever composed the bring-up.
    let supplied = resources
        .iter()
        .find_map(|resource| Some((resource, resource.initial.as_ref()?)));
    let (returns, supply) = match supplied {
        Some((resource, initial)) => {
            let name = syn::Ident::new(&resource.name, Span::call_site());
            let edge = match resource.kind {
                ResourceKind::Fungible => quote!(::hyperscale_vm_sdk::state::Bucket),
                ResourceKind::NonFungible => quote!(::hyperscale_vm_sdk::state::NfBucket),
            };
            (quote!(-> #edge), quote!(#name::mint(#initial)))
        }
        None => (quote!(), quote!()),
    };
    syn::parse_quote!(
        /// Makes this component actual: seals its creation-fixed record
        /// into the configuration leaf, writes the record of every
        /// resource it issues, and issues the supply it comes up
        /// holding — each write refused where its leaf is already there.
        #gate
        pub fn instantiate(&mut self) #returns {
            self.__seal();
            #(#records)*
            #supply
        }
    )
}

/// The `#[requires(..)]` a `#[config]` struct carries, if any: who may
/// bring a component of this package up.
///
/// A property of the configuration rather than of the state, because the
/// configuration is where the founder is named — a pool's `founder`
/// field is what makes one address's bring-up different from another's,
/// and the gate is what holds the two together. Inherited by the
/// generated `instantiate`, which is the whole of bringing up.
fn instantiation_gate(items: &[syn::Item]) -> Option<&syn::Attribute> {
    items.iter().find_map(|item| {
        let syn::Item::Struct(item) = item else {
            return None;
        };
        if !item.attrs.iter().any(|a| a.path().is_ident("config")) {
            return None;
        }
        item.attrs.iter().find(|a| a.path().is_ident("requires"))
    })
}

/// Remove the macro's own attributes, so what it emits is ordinary Rust.
///
/// The state struct's inherent impl is also held to the host build. Its
/// bodies are what the export bodies were rewritten from, so they are
/// read on every target and run on none — and compiling them on a guest
/// build would ask for the authoring half of a vocabulary that has only
/// its executing half there.
fn strip_macro_attrs(items: &mut [syn::Item], state_name: &syn::Ident) {
    for item in items {
        if let syn::Item::Impl(block) = item
            && matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name))
        {
            block
                .attrs
                .push(syn::parse_quote!(#[cfg(not(target_arch = "wasm32"))]));
        }
        match item {
            syn::Item::Struct(item) => {
                strip(&mut item.attrs);
                for field in &mut item.fields {
                    strip(&mut field.attrs);
                }
            }
            syn::Item::Enum(item) => {
                // A `#[roles]` enum is names for the gates and the
                // metadata table; nothing constructs a variant, and the
                // lint would be describing the design.
                if item.attrs.iter().any(|a| a.path().is_ident("roles")) {
                    item.attrs.push(syn::parse_quote!(#[allow(dead_code)]));
                }
                strip(&mut item.attrs);
                for variant in &mut item.variants {
                    strip(&mut variant.attrs);
                }
            }
            syn::Item::Impl(block) => {
                for item in &mut block.items {
                    if let syn::ImplItem::Fn(method) = item {
                        // A method whose gate is its whole declaration
                        // has an empty body, and the parameters its gate
                        // names are the kernel's to read before the
                        // export runs — so the body never sees them, and
                        // the lint describes the gate rather than a
                        // parameter nobody meant.
                        let gated = method.block.stmts.is_empty()
                            && method
                                .attrs
                                .iter()
                                .any(|attr| GATES.iter().any(|g| attr.path().is_ident(g)));
                        strip(&mut method.attrs);
                        if gated {
                            method
                                .attrs
                                .push(syn::parse_quote!(#[allow(unused_variables)]));
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

/// The protocol cells as the authoring half sees them.
///
/// The `#[state]` struct's own inherent impl is compiled on the host and
/// run nowhere: it is the text the executing halves are rewritten from,
/// so it has to type-check even though nothing calls it. A field spelling
/// type-checked because the field was there; an accessor needs the method
/// to be, and these are it — the same off-host stubs the state vocabulary
/// is made of, at the types each accessor's field spelling had.
fn authoring_accessors(state: &syn::Ident, config: Option<&syn::Ident>) -> TokenStream2 {
    let configured = config.map(|config| {
        quote!(
            /// The instance's creation-fixed configuration.
            fn config(&self) -> &::hyperscale_vm_sdk::state::Config<#config> {
                ::core::unimplemented!("a contract body runs on the guest")
            }
        )
    });
    quote!(
        #[cfg(not(target_arch = "wasm32"))]
        #[allow(dead_code, clippy::unused_self)] // authoring stubs, run nowhere
        impl #state {
            #configured

            /// The holder's fungible balance in `resource`.
            fn vault<K>(&self, resource: K) -> ::hyperscale_vm_sdk::state::Slot<
                ::hyperscale_vm_sdk::state::Vault,
            > {
                let _ = resource;
                ::core::unimplemented!("a contract body runs on the guest")
            }

            /// The guaranteed-delivery cell beside that balance.
            fn claims<K>(&self, resource: K) -> ::hyperscale_vm_sdk::state::Slot<
                ::hyperscale_vm_sdk::state::Vault,
            > {
                let _ = resource;
                ::core::unimplemented!("a contract body runs on the guest")
            }

            /// The holder's instances of `resource`.
            fn holdings<K>(&self, resource: K) -> ::hyperscale_vm_sdk::state::Ordered<
                ::hyperscale_vm_sdk::state::NfVault,
            > {
                let _ = resource;
                ::core::unimplemented!("a contract body runs on the guest")
            }

            /// The stored authority cell, absent until the holder
            /// securifies.
            fn auth(&self) -> ::hyperscale_vm_sdk::state::Cell<
                ::core::option::Option<::hyperscale_vm_sdk::AuthCell>,
            > {
                ::core::unimplemented!("a contract body runs on the guest")
            }
        }
    )
}

/// Open the configuration struct and its fields to whoever creates an
/// instance.
///
/// The visibility is the macro's rather than the author's, and so is the
/// documentation obligation that would come with it: a field an author
/// did not write `pub` on is not one they undertook to document, and a
/// slot's meaning is the declaration's — which is where a reader should
/// find it. An author who has something to say about a slot still says
/// it, and the allow costs them nothing.
fn publish_config(items: &mut [syn::Item], config: &syn::Ident) {
    for item in items {
        if let syn::Item::Struct(item) = item
            && item.ident == *config
        {
            item.vis = syn::parse_quote!(pub);
            item.attrs.push(syn::parse_quote!(#[allow(missing_docs)]));
            for field in &mut item.fields {
                field.vis = syn::parse_quote!(pub);
            }
        }
    }
}

/// One inherent `emit` per event type, at the index the name table fixes.
///
/// The index is the macro's, never the author's: a constant beside a name
/// table is the one thing in the old four-document shape that nothing
/// checked. What crosses is the event's own encoding, so the payload's
/// shape and the type declaring it cannot drift.
fn event_emitters(events: &[(syn::Ident, String)]) -> Vec<syn::Item> {
    events
        .iter()
        .enumerate()
        .map(|(index, (ident, _))| {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
            syn::parse_quote!(
                impl #ident {
                    /// Record that this happened.
                    ///
                    /// The type index is this package's own, fixed by the
                    /// declaration order of its event structs, and the
                    /// payload is the event's own encoding — so a
                    /// consumer decodes the type this package declared
                    /// rather than a layout it was told about.
                    ///
                    /// The payload is built on the stack, in a buffer
                    /// the event's own bound sizes. Nothing here
                    /// allocates, because a method marked total may not:
                    /// growing a heap buffer can fail, and the failure
                    /// is the `unreachable` that costs the mark. So
                    /// nothing an event names may carry a length — the
                    /// event itself, and every declaration reachable
                    /// through its fields — and the widths are the
                    /// event's to state.
                    pub fn emit(&self) {
                        use ::hyperscale_vm_sdk::hbor::HborInfallible as _;
                        let mut buf = [0u8; <Self as ::hyperscale_vm_sdk::hbor::HborInfallible>
                            ::MAX_ENCODED_LEN];
                        let payload =
                            ::hyperscale_vm_sdk::hbor::to_slice_infallible(self, &mut buf);
                        #[cfg(target_arch = "wasm32")]
                        ::hyperscale_vm_sdk::guest::emit(#index, payload);
                        #[cfg(not(target_arch = "wasm32"))]
                        ::hyperscale_vm_sdk::host::emit(#index, payload);
                    }
                }
            )
        })
        .collect()
}

/// The resources a package issues, by the name each is declared under.
///
/// A resource address is its minter over the material that separates one
/// of its resources from another, and that material is a hash preimage:
/// a mark typed one character differently is a different, perfectly
/// valid address that nothing holds and no gate can open. Naming it
/// makes the mark the item's, derived once, so a typo is an unresolved
/// path rather than a method unreachable for the life of an immutable
/// package.
///
/// The mark is the name as the protocol spells names everywhere else, so
/// what an author reads in a gate and what a consumer reads off the
/// emitted constant are one string derived once.
fn resources(items: &[syn::Item], config_fields: &[String]) -> syn::Result<Vec<Resource>> {
    let mut structs = Vec::new();
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        let Some(attr) = item.attrs.iter().find(|a| a.path().is_ident("resource")) else {
            continue;
        };
        let ResourceAttr {
            kind,
            divisibility,
            initial,
            seals,
        } = resource_attr(attr)?;
        // Fields are an instance's data, and a fungible resource has no
        // instances — so a fielded fungible declaration states a schema
        // nothing could ever hold.
        if kind == ResourceKind::Fungible && !item.fields.is_empty() {
            return Err(syn::Error::new(
                item.fields.span(),
                "a fungible resource has no instances, so these fields describe nothing \
                 — drop them, or declare the resource `non_fungible`",
            ));
        }
        // A mark carrying a schema founds its instances through a method
        // that takes the record: what one holds is runtime data, and an
        // attribute is not the place for it.
        if initial.is_some() && !item.fields.is_empty() {
            return Err(syn::Error::new(
                item.fields.span(),
                "a mark carrying a schema states no initial supply — what its instance \
                 holds is runtime data, so it is founded through a method that takes \
                 the record",
            ));
        }
        structs.push((
            &item.ident,
            kind,
            divisibility,
            initial,
            seals,
            !item.fields.is_empty(),
        ));
    }
    // Rendered in a second pass, against the whole declared set: a
    // sealed leaf names another of the package's own marks, so what its
    // kind is and whether it seals rules of its own are answers only the
    // full set has.
    let named: Vec<(&syn::Ident, ResourceKind, bool)> = structs
        .iter()
        .map(|(ident, kind, _, _, seals, _)| (*ident, *kind, seals.is_some()))
        .collect();
    let rendered: Vec<(TokenStream2, bool)> = structs
        .iter()
        .map(|(_, _, _, _, seals, _)| {
            seals.as_ref().map_or_else(
                || Ok((quote!(::hyperscale_vm_sdk::SealedRulesExpr::new()), false)),
                |list| sealed_rules(list, &named, config_fields),
            )
        })
        .collect::<syn::Result<_>>()?;
    let marks = distinct_band("resources", structs.iter().map(|(ident, ..)| *ident))?;
    let declared: Vec<Resource> = structs
        .into_iter()
        .zip(marks)
        .zip(rendered)
        .map(
            |(((ident, kind, divisibility, initial, _, schema), mark), (seals, seals_config))| {
                Resource {
                    name: ident.to_string(),
                    mark: mark.into_bytes(),
                    kind,
                    divisibility,
                    initial,
                    seals,
                    seals_config,
                    schema,
                }
            },
        )
        .collect();
    // The kernel grants one issuance per invocation, and bringing a
    // component up is one invocation — so a component brings one thing
    // into existence, and a second initial supply is a second grant the
    // node it would ride has no room for.
    let mut supplied = declared.iter().filter(|r| r.initial.is_some());
    if let (Some(first), Some(second)) = (supplied.next(), supplied.next()) {
        return Err(syn::Error::new(
            second
                .initial
                .as_ref()
                .expect("filtered on a stated supply")
                .span(),
            format!(
                "`{}` already states the supply this component comes up holding, and \
                 a body brings one thing into existence. Mint `{}` through a method \
                 of your own, called once the component is actual",
                first.name, second.name,
            ),
        ));
    }
    Ok(declared)
}

/// What a declaration registers before it declares anything: the rules
/// each of the package's own marks seals.
///
/// Emitted once per method rather than at each site naming a resource,
/// because the address folds these rules — so one registration is what
/// keeps a gate, a key and a mint from deriving three addresses. A
/// package that seals nothing emits nothing.
fn sealed_registrations(resources: &[Resource]) -> TokenStream2 {
    let registered = resources.iter().filter(|r| !r.seals.is_empty()).map(|r| {
        let mark = syn::LitByteStr::new(&r.mark, Span::call_site());
        let seals = &r.seals;
        quote!(__t.seals(#mark, #seals);)
    });
    quote!(#(#registered)*)
}

/// Whether a call's callee is the free function `name`.
fn calls(func: &syn::Expr, name: &str) -> bool {
    matches!(func, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|last| last.ident == name))
}

/// The sealed-rule grammar: a behaviour, and the rule its resource's
/// address commits for it.
///
/// The same combinators `#[requires(..)]` takes — `||`, `&&`,
/// `n_of(k, …)` — over a closed leaf set, because a sealed rule is
/// folded into an address rather than judged against a cell. What a leaf
/// may name is what the address already knows: the issuing instance,
/// a badge that instance also issues, or a configuration field.
fn sealed_rules(
    attr: &syn::MetaList,
    resources: &[(&syn::Ident, ResourceKind, bool)],
    config_fields: &[String],
) -> syn::Result<(TokenStream2, bool)> {
    let entries = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::MetaNameValue, syn::Token![,]>::parse_terminated,
    )?;
    let mut sealed = Vec::new();
    let mut named: Vec<String> = Vec::new();
    // Whether any leaf names configuration, which is what decides
    // whether the address is derivable from the handle alone.
    let mut reads_config = false;
    for entry in &entries {
        let behaviour = match entry.path.get_ident().map(ToString::to_string).as_deref() {
            Some("recall") => quote!(Recall),
            Some("freeze") => quote!(Freeze),
            Some("deposit") => quote!(Deposit),
            _ => {
                return Err(syn::Error::new(
                    entry.path.span(),
                    "a sealed behaviour is `recall`, `freeze`, or `deposit` — the set an \
                     address cannot answer by arithmetic, since who may mint is the \
                     derivation's",
                ));
            }
        };
        let name = behaviour.to_string();
        if named.contains(&name) {
            return Err(syn::Error::new(
                entry.path.span(),
                format!(
                    "`{}` is sealed twice, and a resource seals one rule for each \
                         behaviour",
                    entry.path.get_ident().expect("matched an ident")
                ),
            ));
        }
        named.push(name);
        let rule = sealed_rule(&entry.value, resources, config_fields, 0)?;
        reads_config |= names_config(&entry.value, config_fields);
        sealed.push(quote!(
            __seals.set(::hyperscale_vm_sdk::SealedBehaviour::#behaviour, #rule);
        ));
    }
    let rendered = quote!({
        let mut __seals = ::hyperscale_vm_sdk::SealedRulesExpr::new();
        #(#sealed)*
        __seals
    });
    Ok((rendered, reads_config))
}

/// Whether a sealed rule names a configuration field anywhere in it.
///
/// What it decides is a signature: a resource whose rules name
/// configuration has an address that is a function of the instance's
/// own, and the handle alone cannot recover it — an address is a hash.
/// So the helper that derives one asks for the configuration, and the
/// helper that does not, does not.
fn names_config(expr: &syn::Expr, config_fields: &[String]) -> bool {
    match expr {
        syn::Expr::Paren(inner) => names_config(&inner.expr, config_fields),
        syn::Expr::Binary(binary) => {
            names_config(&binary.left, config_fields) || names_config(&binary.right, config_fields)
        }
        syn::Expr::Call(call) if calls(&call.func, "n_of") => {
            call.args.iter().any(|arg| names_config(arg, config_fields))
        }
        syn::Expr::Path(path) if !path.path.is_ident("self") => path
            .path
            .get_ident()
            .is_some_and(|ident| config_fields.contains(&ident.to_string())),
        _ => false,
    }
}

fn sealed_rule(
    expr: &syn::Expr,
    resources: &[(&syn::Ident, ResourceKind, bool)],
    config_fields: &[String],
    depth: usize,
) -> syn::Result<TokenStream2> {
    match expr {
        syn::Expr::Paren(inner) => sealed_rule(&inner.expr, resources, config_fields, depth),
        syn::Expr::Binary(binary) => {
            let all = match binary.op {
                syn::BinOp::Or(_) => false,
                syn::BinOp::And(_) => true,
                _ => {
                    return Err(syn::Error::new(
                        binary.op.span(),
                        "a sealed rule combines claims with `||`, `&&`, or `n_of(k, …)`",
                    ));
                }
            };
            let branches = flatten(expr, &binary.op);
            let lowered = sealed_branches(expr.span(), &branches, resources, config_fields, depth)?;
            let count = if all {
                u8::try_from(lowered.len()).unwrap_or(u8::MAX)
            } else {
                1u8
            };
            check_threshold_node(expr.span(), count, lowered.len())?;
            Ok(quote!(::hyperscale_vm_sdk::SealedRuleExpr::CountOf {
                count: #count,
                rules: ::std::vec![#(#lowered),*],
            }))
        }
        syn::Expr::Call(call) if calls(&call.func, "n_of") => {
            let mut args = call.args.iter();
            let count = match args.next() {
                Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Int(int),
                    ..
                })) => int.base10_parse::<u8>()?,
                _ => {
                    return Err(syn::Error::new(
                        call.span(),
                        "a threshold states its count first: `n_of(2, a, b, c)`",
                    ));
                }
            };
            let branches: Vec<&syn::Expr> = args.collect();
            let lowered = sealed_branches(call.span(), &branches, resources, config_fields, depth)?;
            check_threshold_node(call.span(), count, lowered.len())?;
            Ok(quote!(::hyperscale_vm_sdk::SealedRuleExpr::CountOf {
                count: #count,
                rules: ::std::vec![#(#lowered),*],
            }))
        }
        other => {
            let claim = sealed_claim(other, resources, config_fields)?;
            Ok(quote!(::hyperscale_vm_sdk::SealedRuleExpr::Require(#claim)))
        }
    }
}

fn sealed_branches(
    span: Span,
    branches: &[&syn::Expr],
    resources: &[(&syn::Ident, ResourceKind, bool)],
    config_fields: &[String],
    depth: usize,
) -> syn::Result<Vec<TokenStream2>> {
    if depth + 1 >= MAX_RULE_DEPTH {
        return Err(syn::Error::new(
            span,
            format!("a sealed rule nests past the {MAX_RULE_DEPTH} levels the vocabulary admits"),
        ));
    }
    branches
        .iter()
        .map(|branch| sealed_rule(branch, resources, config_fields, depth + 1))
        .collect()
}

/// One sealed leaf, as the closed vocabulary spells it.
fn sealed_claim(
    expr: &syn::Expr,
    resources: &[(&syn::Ident, ResourceKind, bool)],
    config_fields: &[String],
) -> syn::Result<TokenStream2> {
    let refuse = |span| {
        syn::Error::new(
            span,
            "a sealed claim is `self`, `issued(<Resource>)` for a fungible badge, \
             `issued(<Resource>, <id>)` for one instance of a non-fungible one, or a \
             configuration field by name — a derivation the address already knows, \
             never anything a caller supplies",
        )
    };
    match expr {
        // The issuing instance, acting as itself.
        syn::Expr::Path(path) if path.path.is_ident("self") => {
            Ok(quote!(::hyperscale_vm_sdk::SealedClaim::SelfAddr))
        }
        // A configuration field, whose address class says which claim.
        syn::Expr::Path(path) => {
            let name = path
                .path
                .get_ident()
                .map(ToString::to_string)
                .ok_or_else(|| refuse(path.span()))?;
            let slot = config_fields
                .iter()
                .position(|field| *field == name)
                .ok_or_else(|| {
                    syn::Error::new(
                        path.span(),
                        format!("`{name}` is not a configuration field of this package"),
                    )
                })?;
            let slot = u32::try_from(slot).unwrap_or(u32::MAX);
            Ok(quote!(::hyperscale_vm_sdk::SealedClaim::Config(#slot)))
        }
        // A badge the issuing instance also issues.
        syn::Expr::Call(call) if calls(&call.func, "issued") => {
            let mut args = call.args.iter();
            let named = match args.next() {
                Some(syn::Expr::Path(path)) => path.path.get_ident().map(ToString::to_string),
                _ => None,
            }
            .ok_or_else(|| refuse(call.span()))?;
            let Some((ident, kind, seals)) = resources.iter().find(|(ident, ..)| **ident == named)
            else {
                return Err(syn::Error::new(
                    call.span(),
                    format!("`{named}` is not a `#[resource]` of this package"),
                ));
            };
            // The well-foundedness rule, said where the author wrote it:
            // a leaf derives through the unsealed form, so naming a mark
            // that seals its own rules would name an address nothing is
            // ever minted at.
            if *seals {
                return Err(syn::Error::new(
                    call.span(),
                    format!(
                        "`{named}` seals rules of its own, and a sealed rule names only \
                         resources that seal none — a leaf derives through the unsealed \
                         form, so this would name an address nothing is minted at"
                    ),
                ));
            }
            let mark = syn::LitByteStr::new(kebab(&named).as_bytes(), ident.span());
            match (kind, args.next()) {
                (ResourceKind::Fungible, None) => Ok(quote!(
                    ::hyperscale_vm_sdk::SealedClaim::SelfBadge { mark: #mark.to_vec() }
                )),
                (ResourceKind::NonFungible, Some(id)) => Ok(quote!(
                    ::hyperscale_vm_sdk::SealedClaim::SelfInstance {
                        mark: #mark.to_vec(),
                        id: #id,
                    }
                )),
                (ResourceKind::Fungible, Some(id)) => Err(syn::Error::new(
                    id.span(),
                    format!("`{named}` is fungible, and a balance has no instance to name"),
                )),
                (ResourceKind::NonFungible, None) => Err(syn::Error::new(
                    call.span(),
                    format!(
                        "`{named}` is non-fungible, so a claim on it names which instance: \
                         `issued({named}, <id>)`"
                    ),
                )),
            }
        }
        other => Err(refuse(other.span())),
    }
}

/// One `#[resource]` declaration, as everything downstream reads it.
#[derive(Clone)]
struct Resource {
    /// The struct's own name, which is what a body and a gate call it.
    name: String,
    /// The material separating it from the package's other resources.
    mark: Vec<u8>,
    /// The kind its attribute states.
    kind: ResourceKind,
    /// The display quantization its record carries. Meaningless on a
    /// non-fungible mark, where it is never read.
    divisibility: u8,
    /// The supply the component comes up holding, where its attribute
    /// states one: a quantity for a fungible mark, an instance id for a
    /// non-fungible one — the same split the mint itself takes.
    initial: Option<syn::LitInt>,
    /// The rules its address commits, as the expression that builds
    /// them. Rendered once here because three sites emit it — a gate
    /// naming the resource, a term over it, and the grant that mints it
    /// — and an address they disagreed about would be three resources.
    seals: TokenStream2,
    /// Whether those rules name configuration, which decides whether the
    /// address is derivable from a handle alone.
    seals_config: bool,
    /// Whether the struct has fields, which is what makes it an
    /// instance's data schema and not only a bare mark.
    schema: bool,
}

/// The display quantization a fungible resource carries where its
/// attribute states none.
///
/// The width the protocol's own fee resource is recorded at, so a
/// package that says nothing is recorded like the one resource every
/// network already holds. Nothing on-chain consults it — a divisibility
/// is what a client renders with — which is why a default is a default
/// and not a guess with consequences.
const DEFAULT_DIVISIBILITY: u8 = 18;

/// What a `#[resource]` attribute states about the resource beside its
/// name.
///
/// Stated in the source because the derivation and the record both fold
/// it: the mark constant a gate evaluates and the address a host derives
/// need the kind, and the record `instantiate` writes needs the
/// divisibility. The attribute is the one place all three read from.
struct ResourceAttr {
    kind: ResourceKind,
    divisibility: u8,
    initial: Option<syn::LitInt>,
    seals: Option<syn::MetaList>,
}

fn resource_attr(attr: &syn::Attribute) -> syn::Result<ResourceAttr> {
    let mut kind = None;
    let mut divisibility = None;
    let mut initial = None;
    let mut seals = None;
    if matches!(attr.meta, syn::Meta::List(_)) {
        let terms = attr.parse_args_with(
            syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
        )?;
        for term in &terms {
            match term {
                syn::Meta::Path(path) => {
                    let stated = match path.get_ident().map(ToString::to_string).as_deref() {
                        Some("fungible") => ResourceKind::Fungible,
                        Some("non_fungible") => ResourceKind::NonFungible,
                        _ => return Err(unknown_resource_term(path)),
                    };
                    if kind.replace(stated).is_some() {
                        return Err(syn::Error::new(
                            path.span(),
                            "a resource is one kind — the derivation folds it, so two \
                             spellings would be two addresses",
                        ));
                    }
                }
                syn::Meta::List(list) if list.path.is_ident("seals") => {
                    if seals.replace(list.clone()).is_some() {
                        return Err(syn::Error::new(list.path.span(), "seals, twice"));
                    }
                }
                syn::Meta::List(list) if list.path.is_ident("initial") => {
                    if initial.replace(list.parse_args::<syn::LitInt>()?).is_some() {
                        return Err(syn::Error::new(list.path.span(), "initial, twice"));
                    }
                }
                syn::Meta::NameValue(nv) if nv.path.is_ident("divisibility") => {
                    let syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(int),
                        ..
                    }) = &nv.value
                    else {
                        return Err(syn::Error::new(
                            nv.value.span(),
                            "a divisibility is a literal count of subunit digits",
                        ));
                    };
                    if divisibility.replace(int.base10_parse::<u8>()?).is_some() {
                        return Err(syn::Error::new(nv.path.span(), "divisibility, twice"));
                    }
                }
                other => return Err(unknown_resource_term(other)),
            }
        }
    }
    let kind = kind.unwrap_or(ResourceKind::Fungible);
    // Instances are whole by construction, so there is no quantity for a
    // quantization to be about.
    if kind == ResourceKind::NonFungible && divisibility.is_some() {
        return Err(syn::Error::new(
            attr.span(),
            "a non-fungible resource has no divisibility — its instances are whole, \
             and what a client renders is an id",
        ));
    }
    Ok(ResourceAttr {
        kind,
        divisibility: divisibility.unwrap_or(DEFAULT_DIVISIBILITY),
        initial,
        seals,
    })
}

fn unknown_resource_term(at: &impl Spanned) -> syn::Error {
    syn::Error::new(
        at.span(),
        "a resource states `fungible` (the default) or `non_fungible`, the supply \
         its component comes up holding as `initial(<n>)`, the rules its address \
         commits as `seals(<behaviour> = <rule>, …)`, and — where it is fungible — \
         `divisibility = <digits>`",
    )
}

/// The constant naming each declared resource's mark.
///
/// Emitted rather than asked for, and read by everything outside the
/// package that has to derive the same address — so the mark a gate
/// evaluates and the mark a host names are one declaration rather than
/// two that agree by inspection.
fn resource_marks(declared: &[Resource]) -> Vec<syn::Item> {
    declared
        .iter()
        .flat_map(
            |Resource {
                 name,
                 mark,
                 kind,
                 schema,
                 ..
             }| {
                let ident = syn::Ident::new(&screaming(name), Span::call_site());
                let bytes = syn::LitByteStr::new(mark, Span::call_site());
                let doc =
                    format!("The mark separating `{name}` from this package's other resources.");
                let mark_const: syn::Item = syn::parse_quote!(
                    #[doc = #doc]
                    pub const #ident: &[u8] = #bytes;
                );
                let struct_ident = syn::Ident::new(name, Span::call_site());
                [mark_const, issuance(name, *kind, *schema, &struct_ident)]
            },
        )
        .collect()
}

/// The issuance surface a mark carries: what bringing this resource into
/// existence, and taking it back out, is spelled as.
///
/// One word for both kinds, because the declaration already states which
/// one it is, and the shape the word takes is the shape that declaration
/// implies — a quantity for a fungible mark, an instance id for a
/// non-fungible one. Emitted per mark rather than offered as one generic
/// function, which is what makes the wrong shape a type error on the
/// argument rather than a refusal the macro has to phrase.
///
/// One instance per call, because one call is one declared cell — which
/// is what the lowering opens either way. Several at once is the edge
/// merge `NfBucket::put` already performs, so the batch the surface does
/// not offer costs a line rather than a vocabulary.
///
/// Bodies are the off-host stubs every contract surface has, and they sit
/// where the author's own `impl` block sits: off the guest. Every call is
/// rewritten by the lowering before either half of the emission sees one,
/// so what a guest build would compile here is an unreachable panic and
/// whatever that drags in.
fn issuance(name: &str, kind: ResourceKind, schema: bool, mark: &syn::Ident) -> syn::Item {
    let stub = quote!(::core::unimplemented!("a contract body runs on the guest"));
    let create_doc = format!("Bring `{name}` itself into existence, by writing its record.");
    let mint_doc = format!("Bring `{name}` into existence, as an edge.");
    let burn_doc = format!("Destroy `{name}`, which is `funds`' own resource.");
    let at_doc = format!("The record filed for `{name}` instance `id`, where one was minted.");
    let mut methods: Vec<syn::ImplItemFn> = Vec::new();

    // The record states only what the address cannot carry, which for a
    // fungible resource is its display quantization and for a
    // non-fungible one is nothing at all.
    methods.push(match kind {
        ResourceKind::Fungible => syn::parse_quote!(
            #[doc = #create_doc]
            pub fn create(divisibility: u8) {
                let _ = divisibility;
                #stub
            }
        ),
        ResourceKind::NonFungible => syn::parse_quote!(
            #[doc = #create_doc]
            pub fn create() {
                #stub
            }
        ),
    });

    match kind {
        // Value in, and value out under the same authority.
        ResourceKind::Fungible => {
            methods.push(syn::parse_quote!(
                #[doc = #mint_doc]
                #[must_use]
                pub fn mint(
                    quantity: ::hyperscale_vm_sdk::state::Quantity,
                ) -> ::hyperscale_vm_sdk::state::Bucket {
                    let _ = quantity;
                    #stub
                }
            ));
            methods.push(syn::parse_quote!(
                #[doc = #burn_doc]
                pub fn burn(funds: ::hyperscale_vm_sdk::state::Bucket) {
                    let _ = &funds;
                    #stub
                }
            ));
        }
        // A fielded mark's instance carries a record, so the mint takes
        // one and the mark can answer with it. A bare mark's cell holds
        // the presence byte, which is nothing to hand over and nothing
        // to read back.
        ResourceKind::NonFungible if schema => {
            methods.push(syn::parse_quote!(
                #[doc = #mint_doc]
                #[must_use]
                pub fn mint(id: u64, data: Self) -> ::hyperscale_vm_sdk::state::NfBucket {
                    let _ = (id, data);
                    #stub
                }
            ));
            methods.push(syn::parse_quote!(
                #[doc = #at_doc]
                #[must_use]
                pub fn at(id: u64) -> ::core::option::Option<Self> {
                    let _ = id;
                    #stub
                }
            ));
        }
        ResourceKind::NonFungible => {
            methods.push(syn::parse_quote!(
                #[doc = #mint_doc]
                #[must_use]
                pub fn mint(id: u64) -> ::hyperscale_vm_sdk::state::NfBucket {
                    let _ = id;
                    #stub
                }
            ));
        }
    }

    syn::parse_quote!(
        #[cfg(not(target_arch = "wasm32"))]
        impl #mark {
            #(#methods)*
        }
    )
}

/// Everything a package declares by name, gathered once and read by the
/// gate parser and the lowering alike.
struct Declared<'a> {
    /// The state fields, by name.
    fields: &'a BTreeMap<String, Field>,
    /// The protocol cells reached by accessor.
    accessors: &'a BTreeMap<String, Field>,
    /// The `#[roles]` enum's names, in band order.
    roles: &'a [String],
    /// The configuration struct's fields, in slot order.
    config_fields: &'a [(String, syn::Type)],
    /// The `#[resource]` structs: name, mark, kind.
    resources: &'a [Resource],
}

/// Whether a state field holds the package's own role table: the same
/// cell shape the protocol auth cell has, at a package-band slot.
///
/// The absence is what the shape turns on, so the `Option` is read as
/// well as the element under it — a table that cannot be absent has no
/// founding door to be behind.
pub(crate) fn holds_role_table(field: &Field) -> bool {
    field.element.as_ref().is_some_and(|ty| {
        is_named(ty, "Option") && element_of(ty).is_some_and(|held| is_named(&held, "AuthCell"))
    })
}

/// The package's role names, in the band order a `#[roles]` enum
/// declares them.
///
/// One enum, because the band is one sequence: two enums would be two
/// claims about where the numbering starts.
fn role_names(items: &[syn::Item]) -> syn::Result<Vec<String>> {
    let mut declared: Option<&syn::ItemEnum> = None;
    for item in items {
        let syn::Item::Enum(item) = item else {
            continue;
        };
        if !item.attrs.iter().any(|a| a.path().is_ident("roles")) {
            continue;
        }
        if declared.is_some() {
            return Err(syn::Error::new(
                item.ident.span(),
                "a package declares one `#[roles]` enum — the band is one sequence, and \
                 a second enum would be a second claim about where it starts",
            ));
        }
        declared = Some(item);
    }
    let Some(item) = declared else {
        return Ok(Vec::new());
    };
    for variant in &item.variants {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new(
                variant.ident.span(),
                "a role is a name — the rule it selects lives in the stored table",
            ));
        }
    }
    distinct_band("roles", item.variants.iter().map(|variant| &variant.ident))
}

/// A Rust type name as the constant naming it: `OwnerBadge` is
/// `OWNER_BADGE`.
fn screaming(name: &str) -> String {
    kebab(name).replace('-', "_").to_uppercase()
}

/// The declared structs an emit encodes: the events, and everything
/// they name in turn.
///
/// The bound follows the payload rather than the attribute that declared
/// it. An event composed of a record is the ordinary shape — the event
/// *is* the thing just stored — so a record one names is written into
/// the same stack buffer and is held to the same widths. A record no
/// event reaches is only ever a cell, and a cell's encode allocates.
fn emit_closure(items: &[syn::Item]) -> BTreeSet<String> {
    let mut named: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut frontier: Vec<String> = Vec::new();
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        let marked = |name: &str| item.attrs.iter().any(|a| a.path().is_ident(name));
        if !marked("record") && !marked("event") && !marked("resource") {
            continue;
        }
        if marked("event") {
            frontier.push(item.ident.to_string());
        }
        named.insert(
            item.ident.to_string(),
            item.fields.iter().flat_map(|f| type_names(&f.ty)).collect(),
        );
    }
    let mut reached = BTreeSet::new();
    while let Some(name) = frontier.pop() {
        if !reached.insert(name.clone()) {
            continue;
        }
        if let Some(fields) = named.get(&name) {
            frontier.extend(fields.iter().cloned());
        }
    }
    reached
}

/// Every type name a field's type mentions, generic arguments included.
///
/// Names rather than paths, because what this answers against is the
/// module's own declarations, and a package names those unqualified.
fn type_names(ty: &syn::Type) -> Vec<String> {
    let mut found = Vec::new();
    walk_type_names(ty, &mut found);
    found
}

fn walk_type_names(ty: &syn::Type, found: &mut Vec<String>) {
    match ty {
        syn::Type::Path(path) => {
            for segment in &path.path.segments {
                found.push(segment.ident.to_string());
                if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                    for arg in &args.args {
                        if let syn::GenericArgument::Type(inner) = arg {
                            walk_type_names(inner, found);
                        }
                    }
                }
            }
        }
        syn::Type::Array(array) => walk_type_names(&array.elem, found),
        syn::Type::Tuple(tuple) => {
            for elem in &tuple.elems {
                walk_type_names(elem, found);
            }
        }
        syn::Type::Reference(reference) => walk_type_names(&reference.elem, found),
        _ => {}
    }
}

/// The codec every declared record and event carries.
///
/// Pushed onto the author's own struct rather than asked for, on the same
/// terms as every other fact this macro derives: the encoding is the
/// protocol's, so naming it is the protocol's job. The path routes
/// through the SDK, which is the one crate a contract depends on.
fn encode_declared(items: &mut [syn::Item]) -> Vec<syn::Item> {
    let emitted = emit_closure(items);
    let mut records = Vec::new();
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        let marked = |name: &str| item.attrs.iter().any(|a| a.path().is_ident(name));
        let (record, event) = (marked("record"), marked("event"));
        // A `#[resource]` struct with fields is an instance's data
        // schema, and its cell is read and written as the record it is.
        // A bare mark declares no fields and encodes nothing.
        let instance = marked("resource") && !item.fields.is_empty();
        let stored = record || instance;
        if !stored && !event {
            continue;
        }
        item.attrs.push(syn::parse_quote!(
            #[derive(::core::fmt::Debug, ::core::cmp::PartialEq, ::core::cmp::Eq)]
        ));
        item.attrs
            .push(syn::parse_quote!(#[derive(::hyperscale_vm_sdk::hbor::Hbor)]));
        // Fixed width where an emit spends it. The payload goes into a
        // buffer on the stack sized from this bound, because a method
        // marked total may not allocate and a heap buffer that grows can
        // fail — so nothing an event names may carry a length.
        //
        // A cell claims no such thing. Every one is written through an
        // allocating encode whatever it holds, so a record no event
        // reaches is held to what the encoding carries rather than to
        // what a stack buffer could.
        if emitted.contains(&item.ident.to_string()) {
            item.attrs.push(syn::parse_quote!(
                #[hbor(crate = ::hyperscale_vm_sdk::hbor, infallible)]
            ));
        } else {
            item.attrs
                .push(syn::parse_quote!(#[hbor(crate = ::hyperscale_vm_sdk::hbor)]));
        }
        // Named by whoever reads it: a record by the reader of its cell,
        // an event by the decoder of its payload. Both are the package's
        // own surface, so both are open the way the configuration struct
        // is.
        item.vis = syn::parse_quote!(pub);
        item.attrs.push(syn::parse_quote!(#[allow(missing_docs)]));
        for field in &mut item.fields {
            field.vis = syn::parse_quote!(pub);
        }
        if stored {
            let name = &item.ident;
            records.push(syn::parse_quote!(
                impl ::hyperscale_vm_sdk::state::Record for #name {}
            ));
        }
    }
    records
}

/// The lints that describe the off-host stubs rather than the contract.
///
/// Every contract method takes the receiver its declaration is read from
/// whether its body reads it; none can be `const`, because off-guest
/// every accessor it calls is unimplemented; and a value a contract
/// stores is consumed on the guest and dropped by the stub. Each would
/// otherwise be typed per method, on every package, for a lint saying
/// nothing about the code it sits on.
fn stub_allows(attrs: &mut Vec<syn::Attribute>) {
    attrs.push(syn::parse_quote!(
        #[allow(
            clippy::unused_self,
            clippy::missing_const_for_fn,
            clippy::needless_pass_by_value
        )]
    ));
}

/// The lints an expanded module carries, each about the emission rather
/// than about anything an author wrote.
fn module_allows(attrs: &mut Vec<syn::Attribute>) {
    // Nothing in a package constructs its own state: the struct names
    // the slots the kernel materializes storage under, and the
    // configuration record is an instance's, not the code's. On a guest
    // build the authoring half is held back too, so the vocabulary those
    // are written against is read by nothing there either.
    attrs.push(syn::parse_quote!(#[allow(dead_code)]));
    // `&mut self` is a contract's own statement that a method mutates
    // component state, which is what the declaration is read from. That
    // the host-side stubs it calls happen to take `&self` is an artifact
    // of their being unimplemented off-guest, not a reason to narrow a
    // signature the derivation depends on.
    attrs.push(syn::parse_quote!(#[allow(clippy::needless_pass_by_ref_mut)]));
    // Every struct field is re-emitted as `name: value`, because the
    // value is the lowering's rewrite of the author's expression and not
    // their token. Shorthand would be legible only where that rewrite is
    // the identity, and reading a lint about the author's spelling back
    // into the emitter is a carve-out for one case in a walk that has no
    // others.
    attrs.push(syn::parse_quote!(#[allow(clippy::redundant_field_names)]));
    stub_allows(attrs);
    attrs.push(syn::parse_quote!(
        #[cfg_attr(target_arch = "wasm32", allow(unused_imports))]
    ));
}

fn expand(mut module: syn::ItemMod, serves: client::Serves) -> syn::Result<TokenStream2> {
    let span = module.span();
    let world = kebab(&module.ident.to_string());
    let Some((_, items)) = &mut module.content else {
        return Err(syn::Error::new(
            span,
            "`#[blueprint]` needs the module's body — it reads the state, the configuration, \
             and every method together",
        ));
    };

    let (state_name, fields, config_name) = parse_state(items, span)?;
    let config_fields = config_slots(items, config_name.as_ref());
    let events = event_names(items)?;
    let errors = error_names(items)?;
    let declared_resources = resources(
        items,
        &config_fields
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>(),
    )?;
    let declared_roles = role_names(items)?;
    let accessors = accessors(config_name.as_ref());
    let declared = Declared {
        fields: &fields,
        accessors: &accessors,
        roles: &declared_roles,
        config_fields: &config_fields,
        resources: &declared_resources,
    };
    let methods = lower_methods(items, &state_name, &declared, serves)?;
    let calls: Vec<_> = methods.iter().map(|m| &m.client).collect();
    let slots: BTreeMap<String, u16> = fields
        .iter()
        .map(|(name, field)| (name.clone(), field.slot))
        .collect();
    let client = client::module(
        &state_name,
        config_name.as_ref(),
        &config_fields,
        &slots,
        serves,
        &calls,
        &declared_resources,
    );

    let declarations = methods.iter().map(|m| &m.declaration);
    let event_table = events.iter().map(|(_, name)| quote!(.event(#name)));
    let error_table = errors.iter().map(|name| quote!(.error(#name)));
    let role_table = declared_roles.iter().map(|name| quote!(.role(#name)));

    let (exports, refusals): (Vec<_>, Vec<_>) =
        methods
            .iter()
            .fold((Vec::new(), Vec::new()), |(mut ok, mut no), method| {
                match &method.guest {
                    Ok(built) => ok.push(built),
                    Err(refusal) => no.push(refusal),
                }
                (ok, no)
            });
    // Both executing halves stand or fall together: what the emission
    // refuses is a body it cannot rewrite, and a package written the long
    // way brings its own component and its own way of being called.
    let (component, dispatch) = if refusals.is_empty() {
        let shapes: Vec<_> = exports.iter().map(|m| m.export.clone()).collect();
        let document = wit::document(&world, &shapes);
        let arms: Vec<_> = methods.iter().map(|method| method.host.clone()).collect();
        (
            guest::component(&world, &document, &exports),
            host::dispatch(&arms),
        )
    } else {
        (quote!(#(#refusals)*), quote!())
    };

    // Before the markers are stripped: `encode_declared` reads them, and
    // what it pushes has to survive the strip that follows.
    let records = encode_declared(items);
    strip_macro_attrs(items, &state_name);
    items.extend(records);
    // A configuration is by definition what a creator supplies, so a
    // private one is unfillable rather than deliberately closed. The
    // macro opens the struct it found rather than asking every author to
    // spell the visibility of a record only creation writes.
    if let Some(config) = &config_name {
        publish_config(items, config);
    }
    module_allows(&mut module.attrs);
    items.extend(resource_marks(&declared_resources));
    items.extend(event_emitters(&events));
    items.push(syn::parse_quote!(
        /// This package's metadata, as routing consumes it.
        ///
        /// Derived from the method bodies above; see the `#[blueprint]`
        /// docs for the grammar the derivation admits.
        #[cfg(not(target_arch = "wasm32"))]
        #[must_use]
        pub fn blueprint() -> ::hyperscale_vm_sdk::Blueprint {
            ::hyperscale_vm_sdk::Blueprint::builder()
                #(#declarations)*
                #(#event_table)*
                #(#error_table)*
                #(#role_table)*
                .build()
        }
    ));
    items.push(syn::Item::Verbatim(authoring_accessors(
        &state_name,
        config_name.as_ref(),
    )));
    items.push(syn::Item::Verbatim(component));
    items.push(syn::Item::Verbatim(dispatch));
    items.push(syn::Item::Verbatim(client));

    Ok(quote!(#module))
}

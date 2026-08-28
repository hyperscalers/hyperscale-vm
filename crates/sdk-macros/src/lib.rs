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
//! mod pool {
//!     #[state]
//!     struct Pool {
//!         till: Keyed<Vault>,
//!     }
//!
//!     impl Pool {
//!         pub fn deposit(&mut self, funds: Bucket) {
//!             self.till.at(funds.resource()).put(funds);
//!         }
//!     }
//! }
//! ```
//!
//! The delta above is declared because `put` is a commutative movement,
//! and its key is `ResourceOf(Arg(0))` — all of it read off the body.
//! Nothing was written twice.
//!
//! # One component, one name
//!
//! The component is the module: the world a package publishes under is
//! the module's name, so the `#[state]` struct carries that name in
//! `PascalCase` and a struct named anything else is refused. A package
//! that stores nothing of its own writes no `#[state]` struct at all —
//! the macro writes the one its module implies.
//!
//! # The state struct is the balance sheet
//!
//! Every value leaf an instance package holds is a field of its
//! `#[state]` struct, in one of two forms per kind: a named field
//! stating its resource — `Vault` or `Instances` under `#[holds(..)]`,
//! where the expression is `config.<field>` or `issued(<Resource>)` —
//! or an open family denominated by its key, `Keyed<Vault>` reached by
//! `at(resource)` and `Keyed<Instances>` by `of(resource)`.
//!
//! The protocol balances — `self.vault(resource)`,
//! `self.holdings(resource)` — are the principals blueprint's alone:
//! where the kernel asks what somebody holds, it reads their protocol
//! cells, so a badge in an account is a credential while the same badge
//! handed to a component is an asset on that component's own sheet. The
//! presenting gates (`#[proves(<badge>)]` and the custodial family)
//! are the principals' for the same reason. `auth()` and `config()`
//! remain accessors of every component.
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
//! # The attributes, and each one's shape
//!
//! An index, not a manual — the refusal messages teach the details, and
//! `guests/*` shows every one of these in use.
//!
//! On the module:
//! - `#[blueprint]` — the module is the package; `#[blueprint(principals)]`
//!   for the one package that serves principals.
//!
//! On items of the module:
//! - `#[state] struct <Module>` — the slots the package's keys sit under;
//!   optional, name-checked, at most one. Fields take `#[slot(<n>)]`
//!   (pin all or none) and `#[holds(<expr>)]` on a named `Vault` or
//!   `Instances`.
//! - `#[config] struct …` — the creation-fixed fields `config.<field>`
//!   resolves against; at most one.
//! - `#[resource(…)] struct …` — a resource the package issues:
//!   `non_fungible`, `initial(<n>)`, `display_digits = <n>`, and
//!   `grants(<behaviour> = <rule>, …)` over mint, burn, withdraw,
//!   deposit, recall, and halt.
//! - `#[error] enum …` — the refusal table: fieldless variants, crossing
//!   the boundary as codes.
//! - `#[event] struct …` / `#[record] struct …` — an emitted event's
//!   payload; a stored record's shape.
//!
//! On a `pub` method:
//! - `#[requires(<rule>)]` — the gate, over the leaves `self`,
//!   `config.<field>`, `issued(<Resource>)`, and `governs(<field>)`,
//!   combined with `||`, `&&`, and `n_of(<k>, …)`.
//! - `#[proves(self)]`, `#[proves(<badge>)]`, `#[proves(<badge>[<id>])]`
//!   — sign in as oneself, or prove possession of a badge parameter (an
//!   address; the id a `u64`).
//! - `#[total]` — the method cannot refuse or trap; the gate checks the
//!   claim against the artifact.
//! - `#[name("…")]` — publish under this name instead of the kebab-cased
//!   identifier.
//!
//! A method carries at most one gate attribute.
//!
//! `#[proves(self)]` is a component vouching for its own identity: only
//! this package's own code can mint its address's claim, so the method
//! *is* the gate. That means a **public** `#[proves(self)]` method whose
//! body always succeeds hands that claim to every caller — a gate keyed
//! on the component's identity opens to anyone who calls it first. Where
//! that is not intended, gate the proving method itself (`#[requires(…)]`)
//! or have its body decline on the paths that should not vouch. It reads
//! like "authenticate me"; it means "anyone who calls me speaks as me."
//!
//! # Names the generated client takes
//!
//! Every method gets a client wrapper, and the wrapper's own parameters
//! are named: `builder` on all of them, and `who` on a principal package's,
//! where its free functions name the caller. A method parameter of one of
//! those names would shadow it and is refused. Evidence is the builder's to
//! resolve from the scope, so no wrapper takes a proof parameter and none
//! is reserved.
//!
//! Beside those, the `__` prefix is reserved whole: the lowering emits
//! `__value_N`, `__capability_N` and their kin into the generated body, so
//! a parameter — or a body's own local — wearing one would shadow a
//! binding the lowered effects read, and is refused.
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
//! refuses closures, macros whose body does not parse as an expression
//! list (one that does is walked argument by argument, like any other
//! expression), calls that pass the component on — including `self.other_method(…)` — and an early `return`
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
mod bind;
mod client;
mod emit;
mod gate;
mod guest;
mod host;
mod inline;
mod lanes;
mod lower;
mod records;
mod resource;
mod role;
mod rule;
mod state;
mod syntax;
mod term;
mod wit;

use std::collections::{BTreeMap, BTreeSet};

use hyperscale_vm_effects::ResourceKind;
use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{format_ident, quote};
use syn::spanned::Spanned;

use crate::gate::{Gate, check_gate_shape, gate_calls, parse_gate};
use crate::lower::{Field, Lowerer};
use crate::records::{encode_declared, event_emitters};
use crate::resource::{Resource, grant_registrations, resource_marks, resources};
use crate::role::Role;
use crate::state::{accessors, distinct_band, parse_state, state_struct, state_table};

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
    author(attr, item, Role::Reader)
}

/// The same, for the crate that publishes this package as a component.
///
/// Reached through the SDK's `guest` feature rather than named by an
/// author: which crate publishes a package is a fact about the manifest,
/// and spelling it twice would let the two disagree.
#[proc_macro_attribute]
pub fn blueprint_publisher(attr: TokenStream, item: TokenStream) -> TokenStream {
    author(attr, item, Role::Publisher)
}

/// Run one test on every engine lane the crate was built with.
///
/// The body takes the chain it runs on and says nothing about what is
/// under it; each lane is a test of its own, named for the engine, so a
/// divergence names the engine that diverged.
///
/// # Panics
///
/// Never; a body the lanes cannot run is a `compile_error!` on its own
/// span.
#[proc_macro_attribute]
pub fn lanes(attr: TokenStream, item: TokenStream) -> TokenStream {
    let body = syn::parse_macro_input!(item as syn::ItemFn);
    match lanes::lanes(&attr.into()).and_then(|lanes| lanes::expand(&lanes, body)) {
        Ok(tokens) => tokens.into(),
        Err(error) => error.to_compile_error().into(),
    }
}

fn author(attr: TokenStream, item: TokenStream, role: Role) -> TokenStream {
    let module = syn::parse_macro_input!(item as syn::ItemMod);
    let recovered = module.clone();
    let attr = TokenStream2::from(attr);
    match serves(&attr).and_then(|serves| expand(module, serves, role)) {
        Ok(tokens) => tokens.into(),
        Err(error) => refused(recovered, role, &error).into(),
    }
}

/// What a refused module still emits: its items, stripped, with the
/// accessors and marks their bodies reach — beside the errors.
///
/// Emitting only the errors would erase every type in the module from
/// the editor's view on the first mistake, turning one refusal into a
/// cascade of `cannot find type` across the crate while the author fixes
/// the line the error names. Everything here is best-effort: whatever
/// the parse gets far enough to derive is emitted, and a module too
/// broken for a piece goes without it.
fn refused(mut module: syn::ItemMod, role: Role, error: &syn::Error) -> TokenStream2 {
    let errors = error.to_compile_error();
    let module_name = module.ident.clone();
    let Some((_, items)) = &mut module.content else {
        return errors;
    };
    let mut extras: Vec<syn::Item> = Vec::new();
    // On a state-name refusal, the accessors go on the struct the author
    // actually marked — an impl on the module's derived name would name a
    // type that does not exist, and every body would error on it.
    let state_name = state_struct(items, &module_name).unwrap_or_else(|_| {
        items
            .iter()
            .find_map(|item| match item {
                syn::Item::Struct(item)
                    if item.attrs.iter().any(|a| a.path().is_ident("state")) =>
                {
                    Some(item.ident.clone())
                }
                _ => None,
            })
            .unwrap_or_else(|| {
                syn::Ident::new(&pascal(&module_name.to_string()), Span::call_site())
            })
    });
    // By the attribute alone, not through `parse_state`: the state parse
    // may be the very thing that refused, and the accessors need only
    // the two names.
    let config_name = items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.attrs.iter().any(|a| a.path().is_ident("config")) => {
            Some(item.ident.clone())
        }
        _ => None,
    });
    extras.push(syn::Item::Verbatim(authoring_accessors(
        &state_name,
        config_name.as_ref(),
        role,
        None,
    )));
    let config_fields = config_slots(items, config_name.as_ref());
    let names: Vec<String> = config_fields.iter().map(|(name, _)| name.clone()).collect();
    if let Ok(resources) = resources(items, &names) {
        extras.extend(resource_marks(&resources, role));
    }
    if let Ok(events) = event_names(items) {
        extras.extend(event_emitters(&events, role));
    }
    let (records, _) = encode_declared(items);
    module_allows(&mut module.attrs, role);
    strip_macro_attrs(items, &state_name, role);
    items.extend(records);
    items.extend(extras);
    quote!(#module #errors)
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

/// A module's name as the struct standing for it: `flash_loan` is
/// `FlashLoan`.
fn pascal(name: &str) -> String {
    let mut out = String::new();
    let mut starting = true;
    for ch in name.chars() {
        if ch == '_' {
            starting = true;
        } else if starting {
            out.extend(ch.to_uppercase());
            starting = false;
        } else {
            out.push(ch);
        }
    }
    out
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
    // `[u8; N]` — bytes whose width is the signature's: admission holds
    // an argument to it, so the body reads the array as spelled. The
    // width is spliced as written, so a named constant resolves where
    // the generated signature compiles.
    if let syn::Type::Array(array) = ty {
        if matches!(&*array.elem, syn::Type::Path(p) if p.path.is_ident("u8")) {
            let width = &array.len;
            return Ok(quote!(::hyperscale_vm_sdk::ParamType::BytesExact(#width as u32)));
        }
        return Err(syn::Error::new(
            ty.span(),
            "the one array parameter is `[u8; N]` — bytes whose width the signature \
             fixes and admission refuses a mismatch of",
        ));
    }
    let syn::Type::Path(path) = ty else {
        return Err(syn::Error::new(
            ty.span(),
            "a contract parameter is a plain named type or `[u8; N]` — a reference or \
             tuple is not one a manifest can bind. The kinds are `Bucket`, `NfBucket`, \
             `Ids`, `Quantity`, `OrderKey`, `Fixed`, `SignedFixed`, `u128`, `u64`, \
             `Address`, and bytes",
        ));
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
        "u128" | "Quantity" | "OrderKey" => quote!(U128),
        // A stored rate crosses at its own width, carrying the scale the
        // type fixes — so an oracle posting one writes a rate rather
        // than an integer whose meaning lives in a doc comment. Signed or
        // not is the guest's reading of the same thirty-two bytes.
        "Fixed" | "SignedFixed" => quote!(U256),
        "u64" => quote!(U64),
        "Vec" | "Bytes" => quote!(Bytes),
        "Rule" | "RuleBytes" => quote!(Rule),
        _ => {
            return Err(syn::Error::new(
                ty.span(),
                "a contract parameter must be one of `Bucket`, `NfBucket`, `Ids`, \
                 `Quantity`, `OrderKey`, `Fixed`, `SignedFixed`, `u128`, `u64`, `Address`, \
                 bytes, or `[u8; N]` — these are the kinds a manifest can bind",
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
    let mut names = method.attrs.iter().filter(|a| a.path().is_ident("name"));
    let Some(attr) = names.next() else {
        return Ok(kebab(&method.sig.ident.to_string()));
    };
    // Reading the first and stopping would take one `#[name]`'s word while
    // a second vanished — the silently-renamed method this must not allow.
    if let Some(second) = names.next() {
        let mut refusal =
            syn::Error::new_spanned(second, "a method carries one `#[name]` — this repeats it");
        refusal.combine(syn::Error::new_spanned(
            attr,
            "the `#[name]` this method already carries",
        ));
        return Err(refusal);
    }
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
    Ok(published)
}

/// The macro's own attributes, which are read and then removed so what it
/// emits is ordinary Rust.
const OWN: &[&str] = &[
    "slot",
    "denomination",
    "holds",
    "state",
    "config",
    "name",
    "event",
    "error",
    "record",
    "resource",
    "requires",
    "proves",
    "total",
];

/// The attributes that name a gate, whose method may have no body of
/// its own.
const GATES: &[&str] = &["requires", "proves"];

/// The widest tuple the client tier binds: the most parameters a
/// published method takes, and the most fields a configuration struct
/// declares. A stated bound rather than a cliff — past it the generated
/// wrapper would fail to compile with nothing naming the cap.
const MAX_PARAMS: usize = 16;

/// Refuse a configuration struct wider than the tuple a creation binds.
fn check_config_width(config: Option<&syn::Ident>, fields: usize) -> syn::Result<()> {
    if fields > MAX_PARAMS
        && let Some(config) = config
    {
        return Err(syn::Error::new(
            config.span(),
            format!(
                "a configuration struct declares at most {MAX_PARAMS} fields — the widest \
                 tuple a creation binds"
            ),
        ));
    }
    Ok(())
}

fn strip(attrs: &mut Vec<syn::Attribute>) {
    attrs.retain(|attr| !OWN.iter().any(|own| attr.path().is_ident(own)));
}

/// The first of the macro's own attributes among `names`, with its name.
fn own_attr<'a>(
    attrs: &'a [syn::Attribute],
    names: &[&'static str],
) -> Option<(&'a syn::Attribute, &'static str)> {
    attrs.iter().find_map(|attr| {
        names
            .iter()
            .find(|name| attr.path().is_ident(name))
            .map(|name| (attr, *name))
    })
}

/// Hold each of the macro's own attributes to the placement its reader
/// scans.
///
/// The readers are kind- and place-filtered and `strip` is not, so a
/// misplaced attribute — `#[error]` on a struct, `#[slot]` on a config
/// field, `#[total]` on a helper function — would otherwise vanish
/// without declaring anything. Every refusal names where the attribute
/// is read.
fn check_marker_kinds(
    items: &[syn::Item],
    state_name: &syn::Ident,
    config_name: Option<&syn::Ident>,
) -> syn::Result<()> {
    for item in items {
        match item {
            syn::Item::Struct(item) => marker_kinds_on_struct(item, state_name, config_name)?,
            syn::Item::Enum(item) => marker_kinds_on_enum(item)?,
            syn::Item::Impl(block) => marker_kinds_on_impl(block)?,
            // The item kinds no reader scans at all: a marker on one is
            // a marker the strip would eat whole.
            syn::Item::Fn(syn::ItemFn { attrs, .. })
            | syn::Item::Const(syn::ItemConst { attrs, .. })
            | syn::Item::Static(syn::ItemStatic { attrs, .. })
            | syn::Item::Use(syn::ItemUse { attrs, .. })
            | syn::Item::Mod(syn::ItemMod { attrs, .. })
            | syn::Item::Type(syn::ItemType { attrs, .. })
            | syn::Item::Trait(syn::ItemTrait { attrs, .. })
            | syn::Item::Union(syn::ItemUnion { attrs, .. })
            | syn::Item::Macro(syn::ItemMacro { attrs, .. }) => {
                if let Some((attr, name)) = own_attr(attrs, OWN) {
                    return Err(syn::Error::new_spanned(
                        attr,
                        format!(
                            "nothing reads `#[{name}]` on this item — see the `#[blueprint]` \
                             docs for where each attribute is read"
                        ),
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Refuse a local item whose name the macro matches by last path
/// segment.
///
/// Parameter kinds, widening, and the `Result` detection all read a
/// type's final segment, so a module-local `Bucket` or a `Result` alias
/// would silently bind as the vocabulary's — the one mismatch the walk
/// cannot see, closed here at the item that would cause it.
fn check_vocabulary_shadows(items: &[syn::Item]) -> syn::Result<()> {
    const MATCHED: &[&str] = &[
        "Address",
        "CallTarget",
        "ComponentAddr",
        "PackageAddr",
        "PrincipalAddr",
        "ResourceAddr",
        "Bucket",
        "NfBucket",
        "Ids",
        "Quantity",
        "OrderKey",
        "Fixed",
        "SignedFixed",
        "Vec",
        "Bytes",
        "Rule",
        "RuleBytes",
        "Result",
    ];
    for item in items {
        if let syn::Item::Use(item) = item {
            check_use_shadows(&item.tree, MATCHED)?;
            continue;
        }
        let ident = match item {
            syn::Item::Struct(item) => &item.ident,
            syn::Item::Enum(item) => &item.ident,
            syn::Item::Type(item) => &item.ident,
            _ => continue,
        };
        if MATCHED.iter().any(|name| ident == name) {
            return Err(syn::Error::new(
                ident.span(),
                format!(
                    "`{ident}` is a name the macro matches by a type's last path segment, \
                     so a local `{ident}` would silently bind as the vocabulary's — \
                     rename it"
                ),
            ));
        }
    }
    Ok(())
}

/// Refuse a `use … as Alias` that binds some other type under a vocabulary
/// name: the macro matches by last path segment, so `NfBucket as Bucket`
/// would lower as the fungible `Bucket` the alias only spells. A plain
/// import of a vocabulary name is left alone — that is how the vocabulary
/// itself is brought into scope.
fn check_use_shadows(tree: &syn::UseTree, matched: &[&str]) -> syn::Result<()> {
    match tree {
        syn::UseTree::Path(path) => check_use_shadows(&path.tree, matched),
        syn::UseTree::Group(group) => group
            .items
            .iter()
            .try_for_each(|item| check_use_shadows(item, matched)),
        syn::UseTree::Rename(rename) => {
            let alias = &rename.rename;
            if alias != &rename.ident && matched.iter().any(|name| alias == name) {
                return Err(syn::Error::new(
                    alias.span(),
                    format!(
                        "`{alias}` is a name the macro matches by a type's last path \
                         segment, so aliasing `{}` to it would silently bind as the \
                         vocabulary's — drop the rename",
                        rename.ident
                    ),
                ));
            }
            Ok(())
        }
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => Ok(()),
    }
}

/// Refuse a `__`-prefixed name anywhere the module can author one.
///
/// Bindings first: the generated code emits `__value_N`,
/// `__capability_N` and their kin into a lowered body, so an author's
/// `let __value_0` would shadow the binding the lowered effect reads.
/// `check_names` reserves the prefix for parameters; this holds the rest
/// of a body to it.
///
/// Item names too, and these carry more than shadowing: the kernel
/// spellings `__found`, `__record` and `__seal` exist only as the
/// lowering's own emissions, and their gates assume no authored text can
/// spell them. An author supplying `fn __found` on a mark would hand the
/// reading build the stub that assumption rests on being absent — so the
/// whole prefix is refused where a name is declared, which is what makes
/// the assumption true by construction.
fn check_reserved_locals(items: &[syn::Item], state_name: &syn::Ident) -> syn::Result<()> {
    struct Reserved<'e> {
        errors: &'e mut Vec<syn::Error>,
    }
    impl<'ast> syn::visit::Visit<'ast> for Reserved<'_> {
        fn visit_pat_ident(&mut self, pat: &'ast syn::PatIdent) {
            if pat.ident.to_string().starts_with("__") {
                self.errors.push(syn::Error::new(
                    pat.ident.span(),
                    format!(
                        "`{}` starts with `__`, which the generated code reserves for its \
                         own bindings — name the binding without the leading underscores",
                        pat.ident
                    ),
                ));
            }
            syn::visit::visit_pat_ident(self, pat);
        }
    }
    let mut errors = Vec::new();
    let reserve_name = |ident: &syn::Ident, errors: &mut Vec<syn::Error>| {
        if ident.to_string().starts_with("__") {
            errors.push(syn::Error::new(
                ident.span(),
                format!(
                    "`{ident}` starts with `__`, which the generated code reserves for its own \
                     items — name the function without the leading underscores"
                ),
            ));
        }
    };
    for item in items {
        match item {
            syn::Item::Fn(function) => reserve_name(&function.sig.ident, &mut errors),
            syn::Item::Impl(block) => {
                for inner in &block.items {
                    let syn::ImplItem::Fn(method) = inner else {
                        continue;
                    };
                    reserve_name(&method.sig.ident, &mut errors);
                    let on_state = block.trait_.is_none()
                        && matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name));
                    if on_state {
                        syn::visit::Visit::visit_block(
                            &mut Reserved {
                                errors: &mut errors,
                            },
                            &method.block,
                        );
                    }
                }
            }
            _ => {}
        }
    }
    errors
        .into_iter()
        .reduce(|mut all, error| {
            all.combine(error);
            all
        })
        .map_or(Ok(()), Err)
}

/// The markers whose reader scans structs, and the two field pins.
const ON_A_STRUCT: &[&str] = &["state", "config", "event", "record", "resource"];
const ON_A_METHOD: &[&str] = &["proves", "total", "name"];
const ON_A_STATE_FIELD: &[&str] = &["slot", "holds", "denomination"];

fn marker_kinds_on_struct(
    item: &syn::ItemStruct,
    state_name: &syn::Ident,
    config_name: Option<&syn::Ident>,
) -> syn::Result<()> {
    if let Some((attr, _)) = own_attr(&item.attrs, &["error"]) {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[error]` marks an enum — the table it declares is the variants",
        ));
    }
    if let Some((attr, name)) = own_attr(&item.attrs, ON_A_METHOD) {
        return Err(syn::Error::new_spanned(
            attr,
            format!(
                "`#[{name}]` marks a method of `{state_name}`'s impl — a struct declares \
                 nothing with it"
            ),
        ));
    }
    if let Some((attr, name)) = own_attr(&item.attrs, ON_A_STATE_FIELD) {
        return Err(syn::Error::new_spanned(
            attr,
            format!("`#[{name}]` sits on a `#[state]` field, not on the struct"),
        ));
    }
    if config_name != Some(&item.ident)
        && let Some((attr, _)) = own_attr(&item.attrs, &["requires"])
    {
        return Err(syn::Error::new_spanned(
            attr,
            "`#[requires]` on a struct gates instantiation, and that gate is the \
             configuration's — it is read on the `#[config]` struct alone",
        ));
    }
    let allowed: &[&str] = if item.ident == *state_name {
        ON_A_STATE_FIELD
    } else {
        &[]
    };
    let misplaced: Vec<&'static str> = OWN
        .iter()
        .filter(|name| !allowed.contains(name))
        .copied()
        .collect();
    for field in &item.fields {
        if let Some((attr, name)) = own_attr(&field.attrs, &misplaced) {
            let read = if ON_A_STATE_FIELD.contains(&name) {
                format!(
                    " — it is read on the `#[state]` struct's fields, and `{}` is not it",
                    item.ident
                )
            } else {
                String::new()
            };
            return Err(syn::Error::new_spanned(
                attr,
                format!("nothing reads `#[{name}]` on this field{read}"),
            ));
        }
    }
    Ok(())
}

fn marker_kinds_on_enum(item: &syn::ItemEnum) -> syn::Result<()> {
    for &marker in ON_A_STRUCT {
        if let Some((attr, _)) = own_attr(&item.attrs, &[marker]) {
            return Err(syn::Error::new_spanned(
                attr,
                format!("`#[{marker}]` marks a struct — an enum declares nothing here"),
            ));
        }
    }
    if let Some((attr, name)) = own_attr(
        &item.attrs,
        &[
            "requires",
            "proves",
            "total",
            "name",
            "slot",
            "holds",
            "denomination",
        ],
    ) {
        return Err(syn::Error::new_spanned(
            attr,
            format!("nothing reads `#[{name}]` on an enum"),
        ));
    }
    for variant in &item.variants {
        if let Some((attr, name)) = own_attr(&variant.attrs, OWN) {
            return Err(syn::Error::new_spanned(
                attr,
                format!("nothing reads `#[{name}]` on a variant"),
            ));
        }
    }
    Ok(())
}

fn marker_kinds_on_impl(block: &syn::ItemImpl) -> syn::Result<()> {
    if let Some((attr, name)) = own_attr(&block.attrs, OWN) {
        return Err(syn::Error::new_spanned(
            attr,
            format!(
                "nothing reads `#[{name}]` on an impl block — the method attributes sit \
                 on the methods themselves"
            ),
        ));
    }
    let misplaced: Vec<&'static str> = OWN
        .iter()
        .filter(|name| !ON_A_METHOD.contains(name) && **name != "requires")
        .copied()
        .collect();
    for item in &block.items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        if let Some((attr, name)) = own_attr(&method.attrs, &misplaced) {
            return Err(syn::Error::new_spanned(
                attr,
                format!("nothing reads `#[{name}]` on a method"),
            ));
        }
    }
    Ok(())
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

/// The module's `#[error]` enums, in declaration order.
fn error_enums(items: &[syn::Item]) -> impl Iterator<Item = &syn::ItemEnum> + Clone {
    items.iter().filter_map(|item| match item {
        syn::Item::Enum(item) if item.attrs.iter().any(|a| a.path().is_ident("error")) => {
            Some(item)
        }
        _ => None,
    })
}

/// The package's error names, in the order a declined invocation's code
/// refers to.
fn error_names(items: &[syn::Item]) -> syn::Result<Vec<String>> {
    let variants = error_enums(items).flat_map(|item| &item.variants);
    // A refusal crosses the boundary as its code; the variant's name is
    // everything the table carries. Fields would silently vanish there,
    // and the generated cast would blame the `#[blueprint]` line — so a
    // fielded variant is refused where it was written.
    for variant in variants.clone() {
        if !matches!(variant.fields, syn::Fields::Unit) {
            return Err(syn::Error::new(
                variant.ident.span(),
                format!(
                    "`{}` carries fields, and a refusal crosses the boundary as a bare \
                     code — the error table holds names alone",
                    variant.ident
                ),
            ));
        }
        if variant.discriminant.is_some() {
            return Err(syn::Error::new(
                variant.ident.span(),
                format!(
                    "`{}` names its own code, and a variant's code is its place in the \
                     error table — drop the discriminant",
                    variant.ident
                ),
            ));
        }
    }
    distinct_band("errors", variants.map(|variant| &variant.ident))
}

/// One `Declines` impl per `#[error]` enum.
///
/// A variant's code is its place in the package's one error table, which
/// spans the module's error enums in declaration order — a figure only
/// the whole module knows, so it is written here rather than read off
/// the enum's own discriminants.
fn decline_impls(items: &[syn::Item]) -> TokenStream2 {
    let mut code = 0u32;
    let mut impls = TokenStream2::new();
    for item in error_enums(items) {
        let name = &item.ident;
        let arms: Vec<TokenStream2> = item
            .variants
            .iter()
            .map(|variant| {
                let ident = &variant.ident;
                let arm = quote!(Self::#ident => #code);
                code += 1;
                arm
            })
            .collect();
        let names = item.variants.iter().map(|variant| {
            let ident = &variant.ident;
            let published = kebab(&ident.to_string());
            quote!(Self::#ident => #published)
        });
        impls.extend(quote!(
            #[automatically_derived]
            impl ::hyperscale_vm_sdk::Declines for #name {
                fn code(&self) -> u32 {
                    match *self { #(#arms,)* }
                }
            }
            // Off the artifact: a name is for whoever reads a receipt,
            // and the component crosses the boundary with the code alone.
            #[automatically_derived]
            #[cfg(not(target_arch = "wasm32"))]
            impl ::hyperscale_vm_sdk::DeclinesAs for #name {
                fn declined_as(self) -> &'static str {
                    match self { #(#names,)* }
                }
            }
        ));
    }
    impls
}

/// Hold a method's decline arm to the enums the error table is built
/// from.
///
/// The generated halves ask the arm for its table code, so an arm that
/// is no `#[error]` enum of this package would surface as an opaque
/// trait error inside generated code — refused here instead, at the type
/// the author wrote.
fn check_decline_arm(arm: &syn::Type, declines: &BTreeSet<String>) -> syn::Result<()> {
    let named = match arm {
        syn::Type::Path(path) => path.path.segments.last().map(|last| last.ident.to_string()),
        _ => None,
    };
    if named.is_some_and(|name| declines.contains(&name)) {
        return Ok(());
    }
    Err(syn::Error::new_spanned(
        arm,
        "a refusal crosses the boundary as a code from the error table, and this arm is \
         not one of the package's `#[error]` enums — decline with one of those",
    ))
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

/// The type a method answers with, at the tail position the lowering
/// took it from.
///
/// Its own return type, less the error arm a fallible one wears and less
/// the edges travelling beside it. Which element was the answer is the
/// lowering's finding rather than this function's: a method hands back
/// any number of edges and at most one value, and reading the tuple a
/// second time to decide which was which is the classification that
/// drifts from the one that declared the outputs.
fn answered(method: &syn::ImplItemFn, at: usize) -> Option<syn::Type> {
    let syn::ReturnType::Type(_, ty) = &method.sig.output else {
        return None;
    };
    let held = match &**ty {
        syn::Type::Path(path) if path.path.segments.last()?.ident == "Result" => {
            let syn::PathArguments::AngleBracketed(args) = &path.path.segments.last()?.arguments
            else {
                return None;
            };
            match args.args.first()? {
                syn::GenericArgument::Type(held) => held.clone(),
                _ => return None,
            }
        }
        other => other.clone(),
    };
    match held {
        syn::Type::Tuple(tuple) => tuple.elems.into_iter().nth(at),
        one => Some(one),
    }
}

/// The error arm a method's return type carries, which is the whole of
/// what its totality mark is judged against.
///
/// The type rather than the fact of one, because both halves run the
/// author's body inside a closure and a body that only ever propagates —
/// `?` on a helper that made the judgment — never names its own error
/// anywhere the closure's type could be read off. Annotating the closure
/// is what keeps that a shape an author may write.
fn declined_with(method: &syn::ImplItemFn) -> Option<syn::Type> {
    let syn::ReturnType::Type(_, ty) = &method.sig.output else {
        return None;
    };
    let syn::Type::Path(path) = &**ty else {
        return None;
    };
    let last = path.path.segments.last()?;
    if last.ident != "Result" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &last.arguments else {
        return None;
    };
    match args.args.iter().nth(1)? {
        syn::GenericArgument::Type(arm) => Some(arm.clone()),
        _ => None,
    }
}

/// One public method, lowered to its declaration and its two executing
/// halves.
struct Lowered {
    /// The `.method(…)` builder call.
    declaration: TokenStream2,
    /// The export and the `impl Guest` body behind it.
    guest: guest::Method,
    /// The arm this method takes in the package's native dispatch.
    host: TokenStream2,
    /// What the method contributes to the package's calling surface.
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
    if params.len() > MAX_PARAMS {
        return Err(syn::Error::new(
            method.sig.inputs.span(),
            format!(
                "a published method takes at most {MAX_PARAMS} parameters — the widest \
                 argument tuple the client tier binds"
            ),
        ));
    }

    let gate = parse_gate(method, declared, &params)?;
    // Presentation is the principals blueprint's: a badge in an account
    // is a credential, and a badge handed to a component is an asset —
    // authority must not travel with custody. A component acts as
    // itself through `#[proves(self)]`, or names identities with
    // `#[requires(..)]`.
    if matches!(gate, Gate::Custodial { .. })
        && matches!(serves, client::Serves::Instances)
        && let Some((attr, _)) = own_attr(&method.attrs, &["proves"])
    {
        return Err(syn::Error::new_spanned(
            attr,
            "presenting a badge is the account's: a badge held by a component is an \
             asset, not a credential, so an instance package gates with \
             `#[proves(self)]` or `#[requires(..)]`",
        ));
    }
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
                .unwrap_or_else(|| {
                    syn::Error::new(
                        method.span(),
                        format!(
                            "`{}` failed to lower with no line recorded — a defect of the \
                             macro, not of this body",
                            method.sig.ident
                        ),
                    )
                })
        })?;
    check_gate_shape(&gate, &lowered, method)?;

    let declining = declined_with(method);
    if let Some(arm) = &declining {
        check_decline_arm(arm, declared.declines)?;
    }
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
        if declining.is_some() {
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
        &gate_calls(&gate, &lowered, serves),
        declining.is_some(),
        total,
        &grant_registrations(declared.resources),
    );
    let declaration = quote!(
        .method(#published, &[#(#kinds),*], #closure)
    );
    let name = published.clone();

    let guest = guest::method(
        &name,
        &lowered,
        &params,
        declared.config_fields,
        declining.as_ref(),
    );
    let host = host::arm(
        &name,
        &lowered,
        &params,
        declared.config_fields,
        declining.as_ref(),
    );
    let client = client::Method {
        rust: method.sig.ident.clone(),
        published,
        shape: client::Shape::of(&gate),
        outputs: lowered.outputs.len(),
        answers: lowered
            .answer
            .is_some()
            .then(|| answered(method, lowered.answer_at))
            .flatten(),
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

/// Refuse a gate or a published-method mark on methods that publish
/// nothing, with `because` saying why these do not.
fn refuse_unpublished_marks<'a>(
    items: impl Iterator<Item = &'a syn::ImplItem>,
    because: &str,
) -> syn::Result<()> {
    for item in items {
        let syn::ImplItem::Fn(method) = item else {
            continue;
        };
        if let Some((attr, _)) = own_attr(&method.attrs, GATES) {
            return Err(syn::Error::new_spanned(
                attr,
                format!("a gate guards a published method, and {because}, or drop the attribute"),
            ));
        }
        if let Some((attr, _)) = own_attr(&method.attrs, &["total", "name"]) {
            return Err(syn::Error::new_spanned(
                attr,
                format!("this describes a published method, and {because}, or drop the attribute"),
            ));
        }
    }
    Ok(())
}

/// Every public method of the state struct's inherent impls, lowered.
fn lower_methods(
    items: &[syn::Item],
    state_name: &syn::Ident,
    declared: &Declared<'_>,
    serves: client::Serves,
) -> syn::Result<Vec<Lowered>> {
    let mut lowered = Vec::new();
    let mut published: Vec<String> = Vec::new();
    let helpers = inline::helpers(items, state_name, declared.accessors)?;
    for item in items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        if !matches!(&*block.self_ty, syn::Type::Path(p) if p.path.is_ident(state_name)) {
            // Another type's impl publishes nothing, and `strip` removes
            // the macro's attributes from every fn — so a gate or a mark
            // here would vanish without a word, exactly like one on a
            // private method.
            refuse_unpublished_marks(
                block.items.iter(),
                &format!(
                    "only `{state_name}`'s own methods publish — move the method into its impl"
                ),
            )?;
            continue;
        }
        for item in &block.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            // Only `pub` methods publish, and `strip` removes the
            // macro's attributes from every fn — a gate on a private
            // method would vanish while its body keeps inlining into
            // callers whose own gates govern. Forgetting `pub` is still
            // the classic slip, and the refusal names the fix.
            if !matches!(method.vis, syn::Visibility::Public(_)) {
                refuse_unpublished_marks(
                    std::iter::once(item),
                    "a private method inlines into its callers and publishes nothing — \
                     make the method `pub`",
                )?;
            }
            if matches!(method.vis, syn::Visibility::Public(_)) {
                // The published name, not the Rust one: `#[name(..)]`
                // reaches the same collisions, and the builder would
                // catch them as a panic from inside a generated
                // `blueprint()` rather than at the line that wrote them.
                let name = method_name(method)?;
                let at = || {
                    method
                        .attrs
                        .iter()
                        .find(|attr| attr.path().is_ident("name"))
                        .map_or_else(|| method.sig.ident.span(), Spanned::span)
                };
                if matches!(serves, client::Serves::Instances) && name == INSTANTIATE {
                    return Err(syn::Error::new(
                        at(),
                        "`instantiate` is the generated seal: the macro derives it for \
                         every instance-serving package, so an authored method cannot \
                         publish under the name",
                    ));
                }
                if published.contains(&name) {
                    return Err(syn::Error::new(
                        at(),
                        format!(
                            "another method already publishes as `{name}`, and a \
                             published name names one export"
                        ),
                    ));
                }
                published.push(name);
                let method = inline::splice(method, &helpers)?;
                lowered.push(lower_method(&method, declared, serves)?);
            }
        }
    }
    if matches!(serves, client::Serves::Instances) {
        lowered.push(lower_method(
            &instantiate_method(declared.resources, instantiation_gate(items)?),
            declared,
            serves,
        )?);
    } else if let Some(attr) = instantiation_gate(items)? {
        // A principals package instantiates nothing — the registry serves
        // it to every principal address by class — so an instantiation gate
        // has no call to gate. Read only in the branch above, it would be
        // stripped in silence rather than enforced, so it is refused here.
        return Err(syn::Error::new_spanned(
            attr,
            "`#[requires]` on the configuration gates instantiation, and a package serving \
             principals is never instantiated — the gate would bind nothing; remove it",
        ));
    }
    Ok(lowered)
}

/// The name a package's generated seal publishes under.
///
/// One declaration because two sites read it: the refusal that keeps an
/// authored method off the name, and the method the macro synthesizes to
/// take it.
pub(crate) const INSTANTIATE: &str = "instantiate";

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
                let display_digits = resource.display_digits;
                quote!(#display_digits)
            }
            ResourceKind::NonFungible => quote!(),
        };
        quote!(#name::__record(#stated);)
    });
    // The supply each mark states: the node that makes the component
    // actual is the node that founds what it comes up holding, so every
    // one of them is this invocation's and their edges leave with
    // whoever composed the bring-up.
    //
    // Founding is not minting — the record write beside each is the
    // creation, and no `Mint` entry governs it — which is what lets a
    // component come up holding a supply nothing may ever add to.
    let supplied: Vec<_> = resources
        .iter()
        .filter_map(|resource| Some((resource, resource.initial.as_ref()?)))
        .collect();
    let edges = supplied.iter().map(|(resource, _)| match resource.kind {
        ResourceKind::Fungible => quote!(::hyperscale_vm_sdk::state::Bucket),
        ResourceKind::NonFungible => quote!(::hyperscale_vm_sdk::state::NfBucket),
    });
    let founds = supplied.iter().map(|(resource, initial)| {
        let name = syn::Ident::new(&resource.name, Span::call_site());
        // A balance is founded in subunits and an instance by its id, so
        // the literal a mark states means whichever its kind takes.
        match resource.kind {
            ResourceKind::Fungible => quote!(#name::__found(
                ::hyperscale_vm_sdk::state::Quantity::from_subunits(#initial)
            )),
            ResourceKind::NonFungible => quote!(#name::__found(#initial)),
        }
    });
    let (returns, supply) = match supplied.len() {
        0 => (quote!(), quote!()),
        1 => (quote!(-> #(#edges)*), quote!(#(#founds)*)),
        // Several leave as a tuple, the shape any method handing back
        // more than one edge already takes.
        _ => (quote!(-> (#(#edges),*)), quote!((#(#founds),*))),
    };
    let name = syn::Ident::new(INSTANTIATE, Span::call_site());
    syn::parse_quote!(
        /// Makes this component actual: seals its creation-fixed record
        /// into the configuration leaf, writes the record of every
        /// resource it issues, and issues the supply it comes up
        /// holding — each write refused where its leaf is already there.
        #gate
        pub fn #name(&mut self) #returns {
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
fn instantiation_gate(items: &[syn::Item]) -> syn::Result<Option<&syn::Attribute>> {
    for item in items {
        let syn::Item::Struct(item) = item else {
            continue;
        };
        if !item.attrs.iter().any(|a| a.path().is_ident("config")) {
            continue;
        }
        // Reading the first and stopping would take a second attribute's
        // word for nothing while `strip` removed it, and a gate silently
        // weaker than what the author wrote is the failure this
        // derivation must not have.
        let mut gates = item.attrs.iter().filter(|a| a.path().is_ident("requires"));
        let Some(first) = gates.next() else {
            return Ok(None);
        };
        if let Some(second) = gates.next() {
            let mut refusal = syn::Error::new_spanned(
                second,
                "a configuration carries one instantiation gate — combine what it asks into a \
                 single `#[requires(…)]`",
            );
            refusal.combine(syn::Error::new_spanned(
                first,
                "the gate this configuration already carries",
            ));
            return Err(refusal);
        }
        return Ok(Some(first));
    }
    Ok(None)
}

/// Remove the macro's own attributes, so what it emits is ordinary Rust.
///
/// The state struct's inherent impl is also held to the host build. Its
/// bodies are what the export bodies were rewritten from, so they are
/// read on every target and run on none — and compiling them on a guest
/// build would ask for the authoring half of a vocabulary that has only
/// its executing half there.
fn strip_macro_attrs(items: &mut [syn::Item], state_name: &syn::Ident, role: Role) {
    for item in items {
        if role.publishes()
            && let syn::Item::Impl(block) = item
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
            // The kinds no reader scans. A marker on one is refused, so
            // a successful expansion never strips here — the refused
            // module does, so the marker rustc cannot resolve is not
            // re-reported behind the refusal that already named it.
            syn::Item::Fn(syn::ItemFn { attrs, .. })
            | syn::Item::Const(syn::ItemConst { attrs, .. })
            | syn::Item::Static(syn::ItemStatic { attrs, .. })
            | syn::Item::Use(syn::ItemUse { attrs, .. })
            | syn::Item::Mod(syn::ItemMod { attrs, .. })
            | syn::Item::Type(syn::ItemType { attrs, .. })
            | syn::Item::Trait(syn::ItemTrait { attrs, .. })
            | syn::Item::Union(syn::ItemUnion { attrs, .. })
            | syn::Item::Macro(syn::ItemMacro { attrs, .. }) => strip(attrs),
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
fn authoring_accessors(
    state: &syn::Ident,
    config: Option<&syn::Ident>,
    role: Role,
    serves: Option<client::Serves>,
) -> TokenStream2 {
    let configured = config.map(|config| {
        quote!(
            /// The instance's creation-fixed configuration.
            fn config(&self) -> #config {
                ::core::unimplemented!("a contract body runs on the guest")
            }
        )
    });
    // The protocol balance is the principals': an instance package's
    // reserves are declared fields of its own state, so the anonymous
    // accessors exist only where the funds are the protocol cells by
    // identity. A refused module keeps them, so the analyzer holds
    // whatever the author wrote alive while they fix it.
    let protocol_balances = matches!(serves, None | Some(client::Serves::Principals)).then(|| {
        quote!(
            /// The holder's fungible balance in `resource`.
            fn vault<K: ::hyperscale_vm_sdk::state::KeyShape>(
                &self,
                resource: K,
            ) -> ::hyperscale_vm_sdk::state::Slot<::hyperscale_vm_sdk::state::Vault> {
                let _ = resource;
                ::core::unimplemented!("a contract body runs on the guest")
            }

            /// The holder's instances of `resource`.
            fn holdings<K: ::hyperscale_vm_sdk::state::KeyShape>(
                &self,
                resource: K,
            ) -> ::hyperscale_vm_sdk::state::Ordered<::hyperscale_vm_sdk::state::NfVault>
            {
                let _ = resource;
                ::core::unimplemented!("a contract body runs on the guest")
            }
        )
    });
    let reading = role.reading();
    quote!(
        #reading
        #[allow(dead_code, clippy::unused_self)] // authoring stubs, run nowhere
        impl #state {
            #configured

            #protocol_balances

            /// The rule governing this address, absent until the holder
            /// securifies.
            fn auth(&self) -> ::hyperscale_vm_sdk::state::Cell<
                ::core::option::Option<::hyperscale_vm_sdk::RuleBytes>,
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

/// Open the `#[error]` enums to whoever asserts on a decline.
///
/// The visibility is the macro's rather than the author's, on the
/// configuration's terms: a refusal is by definition what a caller is
/// handed, so a private table is unreadable rather than deliberately
/// closed — and the documentation obligation that would come with `pub`
/// stays the macro's too.
fn publish_errors(items: &mut [syn::Item]) {
    for item in items {
        if let syn::Item::Enum(item) = item
            && item.attrs.iter().any(|a| a.path().is_ident("error"))
        {
            item.vis = syn::parse_quote!(pub);
            item.attrs.push(syn::parse_quote!(#[allow(missing_docs)]));
        }
    }
}

/// Everything a package declares by name, gathered once and read by the
/// gate parser and the lowering alike.
struct Declared<'a> {
    /// The state fields, by name.
    fields: &'a BTreeMap<String, Field>,
    /// The protocol cells reached by accessor.
    accessors: &'a BTreeMap<String, Field>,
    /// The configuration struct's own name, where the package has one.
    config_record: Option<&'a syn::Ident>,
    /// The configuration struct's fields, in slot order.
    config_fields: &'a [(String, syn::Type)],
    /// The `#[resource]` structs: name, mark, kind.
    resources: &'a [Resource],
    /// The `#[error]` enums' names: what a decline arm may name.
    declines: &'a BTreeSet<String>,
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
fn module_allows(attrs: &mut Vec<syn::Attribute>, role: Role) {
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
    // Key material is a list of symbolic values whatever its length, and
    // each is cloned into it because a term may key more than one
    // clause. A one-element list is a borrow of the single term wearing
    // that shape, which reads as a clone that a slice would not need.
    attrs.push(syn::parse_quote!(#[allow(clippy::cloned_ref_to_slice_refs)]));
    stub_allows(attrs);
    if role.publishes() {
        attrs.push(syn::parse_quote!(
            #[cfg_attr(target_arch = "wasm32", allow(unused_imports))]
        ));
    }
}

/// The component this package publishes, and its native dispatch.
///
/// A reader builds no component: the declaration and the calling surface
/// the same text yields are what it came for, and it runs the bodies
/// through the dispatch rather than through wasm.
fn executing(world: &str, methods: &[Lowered], role: Role) -> (TokenStream2, TokenStream2) {
    let arms: Vec<_> = methods.iter().map(|method| method.host.clone()).collect();
    let component = if role.publishes() {
        let shapes: Vec<_> = methods
            .iter()
            .map(|method| method.guest.export.clone())
            .collect();
        let document = wit::document(world, &shapes);
        let exports: Vec<_> = methods.iter().map(|method| &method.guest).collect();
        guest::component(world, &document, &exports)
    } else {
        quote!()
    };
    (component, host::dispatch(&arms, role))
}

/// The denominated vault fields, as the client module's markers carry
/// them: field name, slot, and the configuration index the denomination
/// names.
///
/// A vault field's client marker is its pascal-cased name, emitted into
/// a module that glob-imports the author's items — a module type
/// wearing that name would be silently shadowed there, so the collision
/// is refused where the field is named.
/// A field naming `#[holds(issued(<Resource>))]` holds a resource whose
/// kind its own shape can carry.
///
/// A vault is a fungible balance cell and an instance family is
/// non-fungible custody, so a field naming a resource of the other kind is
/// a declaration that cannot mean what it says. Caught here, on the
/// attribute, rather than at a later `put`/`file` that would pin a
/// wrong-kind bucket and fail with an admission error naming neither the
/// field nor the line. Only `issued(<Resource>)` names a compile-time
/// resource whose kind is known; `config.<field>` is a runtime address.
/// What a `#[holds(..)]` denomination may spell, stated for the refusal
/// that names it.
const HOLDS_GRAMMAR: &str = "a denomination is `config.<field>` for a configured resource, or \
     `issued(<Resource>)` for a declared one the instance derives from its own address";

fn check_holds_kinds(
    fields: &BTreeMap<String, Field>,
    config_fields: &[(String, syn::Type)],
    resources: &[Resource],
) -> syn::Result<()> {
    for field in fields.values() {
        let Some(expr) = &field.denomination else {
            continue;
        };
        // The `config.<field>` arm resolves nowhere until a body reaches
        // the field, so a typo or a wrong base would drop the holding from
        // the balance sheet with no diagnostic. Validate the grammar here,
        // where every declared holding passes through, so the attribute is
        // refused rather than silently emptied.
        let call = match expr {
            syn::Expr::Field(access) => {
                // The base is the fixed `config` accessor, or a Config-kind
                // state field named directly — the two `field_denomination`
                // resolves through `state()`.
                let base_names_config = matches!(&*access.base, syn::Expr::Path(base)
                if base.path.get_ident().is_some_and(|ident| {
                    ident == "config"
                        || fields
                            .get(&ident.to_string())
                            .is_some_and(|f| f.kind == lower::FieldKind::Config)
                }));
                let member_is_a_slot = match &access.member {
                    syn::Member::Named(name) => {
                        let name = name.to_string();
                        config_fields.iter().any(|(f, _)| *f == name)
                    }
                    syn::Member::Unnamed(_) => false,
                };
                if !base_names_config || !member_is_a_slot {
                    return Err(syn::Error::new(expr.span(), HOLDS_GRAMMAR));
                }
                continue;
            }
            syn::Expr::Call(call) => call,
            _ => return Err(syn::Error::new(expr.span(), HOLDS_GRAMMAR)),
        };
        if !matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("issued")) {
            return Err(syn::Error::new(expr.span(), HOLDS_GRAMMAR));
        }
        let Some(name) = call.args.first().and_then(|arg| match arg {
            syn::Expr::Path(path) => path.path.get_ident().map(ToString::to_string),
            _ => None,
        }) else {
            return Err(syn::Error::new(expr.span(), HOLDS_GRAMMAR));
        };
        let Some(resource) = resources.iter().find(|r| r.name == name) else {
            return Err(syn::Error::new(expr.span(), HOLDS_GRAMMAR));
        };
        let non_fungible = field.kind == lower::FieldKind::Ordered;
        let fits = if non_fungible {
            resource.kind == ResourceKind::NonFungible
        } else {
            resource.kind == ResourceKind::Fungible
        };
        if !fits {
            let (shape, wanted) = if non_fungible {
                ("an instance family", "non-fungible")
            } else {
                ("a vault", "fungible")
            };
            return Err(syn::Error::new(
                expr.span(),
                format!(
                    "{shape} holds a {wanted} resource, and this names one of the other \
                     kind — spell the field the shape its resource wants, or name a \
                     {wanted} resource here"
                ),
            ));
        }
    }
    Ok(())
}

fn vault_markers(
    items: &[syn::Item],
    fields: &BTreeMap<String, Field>,
    config_fields: &[(String, syn::Type)],
) -> syn::Result<Vec<(String, u16, u32)>> {
    let vaults: Vec<(String, u16, u32)> = fields
        .iter()
        // One leaf holding an amount: a named `Instances` family also
        // carries a denomination, but its marker would promise a balance
        // where there are entries.
        .filter(|(_, field)| matches!(field.kind, lower::FieldKind::Cell))
        .filter_map(|(name, field)| {
            let index = state::config_index(field.denomination.as_ref()?, config_fields)?;
            Some((name.clone(), field.slot, index))
        })
        .collect();
    for (name, ..) in &vaults {
        let marker = pascal(name);
        if let Some(item) = items.iter().find(|item| match item {
            syn::Item::Struct(it) => it.ident == marker,
            syn::Item::Enum(it) => it.ident == marker,
            syn::Item::Type(it) => it.ident == marker,
            _ => false,
        }) {
            return Err(syn::Error::new(
                item.span(),
                format!(
                    "the `{name}` vault's client marker is `{marker}`, and this item \
                     would be shadowed by it in the generated client — rename the \
                     field or the type"
                ),
            ));
        }
    }
    Ok(vaults)
}

#[allow(clippy::too_many_lines)] // linear assembly: parse, check, then emit
fn expand(
    mut module: syn::ItemMod,
    serves: client::Serves,
    role: Role,
) -> syn::Result<TokenStream2> {
    let span = module.span();
    let module_name = module.ident.clone();
    let world = kebab(&module_name.to_string());
    let Some((_, items)) = &mut module.content else {
        return Err(syn::Error::new(
            span,
            "`#[blueprint]` needs the module's body — it reads the state, the configuration, \
             and every method together",
        ));
    };

    let state_name = state_struct(items, &module_name)?;
    let (fields, config_name) = parse_state(items)?;
    check_marker_kinds(items, &state_name, config_name.as_ref())?;
    check_vocabulary_shadows(items)?;
    check_reserved_locals(items, &state_name)?;
    let config_fields = config_slots(items, config_name.as_ref());
    check_config_width(config_name.as_ref(), config_fields.len())?;
    let events = event_names(items)?;
    let errors = error_names(items)?;
    let declines: BTreeSet<String> = error_enums(items)
        .map(|item| item.ident.to_string())
        .collect();
    let declines_impls = decline_impls(items);
    let declared_resources = resources(
        items,
        &config_fields
            .iter()
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>(),
    )?;
    check_holds_kinds(&fields, &config_fields, &declared_resources)?;
    let accessors = accessors(config_name.as_ref(), serves);
    let declared = Declared {
        fields: &fields,
        accessors: &accessors,
        config_record: config_name.as_ref(),
        config_fields: &config_fields,
        resources: &declared_resources,
        declines: &declines,
    };
    let methods = lower_methods(items, &state_name, &declared, serves)?;
    let calls: Vec<_> = methods.iter().map(|m| &m.client).collect();
    let slots: BTreeMap<String, u16> = fields
        .iter()
        .map(|(name, field)| (name.clone(), field.slot))
        .collect();
    let reading = role.reading();
    let vaults = vault_markers(items, &fields, &config_fields)?;
    let client = client::module(&client::Surface {
        handle: &state_name,
        config: config_name.as_ref(),
        config_fields: &config_fields,
        fields: &slots,
        serves,
        methods: &calls,
        resources: &declared_resources,
        vaults: &vaults,
    });

    let declarations = methods.iter().map(|m| &m.declaration);
    let event_table = events.iter().map(|(ident, _)| quote!(.event::<#ident>()));
    let error_table = errors.iter().map(|name| quote!(.error(#name)));
    let state_table = state_table(&fields, &config_fields);
    let config_table = config_fields.iter().map(|(name, _)| quote!(.config(#name)));

    let (component, dispatch) = executing(&world, &methods, role);

    // Before the markers are stripped: `encode_declared` reads them, and
    // what it pushes has to survive the strip that follows.
    let (records, stored_types) = encode_declared(items);
    let stored_table = stored_types
        .iter()
        .map(|ident| quote!(.declares::<#ident>()));
    publish_errors(items);
    strip_macro_attrs(items, &state_name, role);
    items.extend(records);
    // A configuration is by definition what a creator supplies, so a
    // private one is unfillable rather than deliberately closed. The
    // macro opens the struct it found rather than asking every author to
    // spell the visibility of a record only creation writes.
    if let Some(config) = &config_name {
        publish_config(items, config);
    }
    module_allows(&mut module.attrs, role);
    items.extend(resource_marks(&declared_resources, role));
    items.extend(event_emitters(&events, role));
    items.push(syn::parse_quote!(
        /// This package's metadata, as routing consumes it.
        ///
        /// Derived from the method bodies above; see the `#[blueprint]`
        /// docs for the grammar the derivation admits.
        #reading
        #[must_use]
        pub fn blueprint() -> ::hyperscale_vm_sdk::Blueprint {
            ::hyperscale_vm_sdk::Blueprint::builder()
                #(#declarations)*
                #(#event_table)*
                #(#error_table)*
                #(#stored_table)*
                #(#state_table)*
                #(#config_table)*
                .build()
        }
    ));
    items.push(syn::Item::Verbatim(authoring_accessors(
        &state_name,
        config_name.as_ref(),
        role,
        Some(serves),
    )));
    items.push(syn::Item::Verbatim(declines_impls));
    items.push(syn::Item::Verbatim(component));
    items.push(syn::Item::Verbatim(dispatch));
    items.push(syn::Item::Verbatim(quote!(#reading #client)));

    Ok(quote!(#module))
}

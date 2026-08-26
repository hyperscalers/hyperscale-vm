//! The state struct, read as a slot table.
//!
//! What `#[state]` declares: one field per slot, each in the band a
//! package numbers its own state in, and each with an element type the
//! vocabulary can name. The accessors a body reaches state through are
//! derived from the same table, so what a package declares and what its
//! bodies can touch are one text.

use std::collections::BTreeMap;

use hyperscale_vm_effects::vocabulary::{AUTH, CONFIG, HALT, INSTANCE, NF_VAULT, RESOURCE, VAULT};
use hyperscale_vm_effects::{PACKAGE_SLOT_BASE, SlotId};
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::spanned::Spanned as _;

use crate::lower::{Field, FieldKind};
use crate::{is_named, kebab, pascal};

/// The names one declared band spells, refused where two of them
/// collide.
///
/// Every band resolves by position and renders by name — an event's
/// index, an error's code, a role's band offset, a resource's mark — so
/// two entries spelling one name are two claims on one number, and the
/// second is the one nothing reaches. [`kebab`] maps more than one
/// identifier onto a name, which is what makes this something an author
/// can write without seeing it.
pub fn distinct_band<'a>(
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
pub fn element_of(ty: &syn::Type) -> Option<syn::Type> {
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
pub fn parse_field(field: &syn::Field, next: u16) -> syn::Result<(String, Field)> {
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
/// something else — and the shape is no defence, because a package's own
/// keyed vault is the same shape as the protocol's, so the band check
/// would find nothing in a misnumbered pool side to disagree with.
/// Refusing the band outright is what makes the difference legible.
pub fn protocol_band(slot: u16) -> Result<(), String> {
    if slot >= PACKAGE_SLOT_BASE {
        return Ok(());
    }
    let cell = match SlotId(slot) {
        VAULT => "a fungible balance cell, reached by `vault(resource)`",
        CONFIG => "the creation-fixed configuration leaf, reached by `config()`",
        AUTH => "the stored authority cell, reached by `auth()`",
        RESOURCE => "a resource's record under its issuer",
        NF_VAULT => "a holder's non-fungible instances, reached by `holdings(resource)`",
        INSTANCE => "a non-fungible instance's data",
        HALT => "a holder's halt flag, written by an issuer the resource admits",
        _ => "unassigned",
    };
    Err(format!(
        "slot {slot} is the protocol's own — {cell} — and every owner has it already. A \
         package's own slots start at {PACKAGE_SLOT_BASE} and are numbered by declaration \
         order, so this field needs no slot at all"
    ))
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
pub fn accessors(config: Option<&syn::Ident>) -> BTreeMap<String, Field> {
    let vault = || Field {
        slot: VAULT.0,
        kind: FieldKind::Keyed,
        element: Some(syn::parse_quote!(::hyperscale_vm_sdk::state::Vault)),
        denomination: None,
    };
    let mut cells = BTreeMap::from([
        ("vault".to_owned(), vault()),
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
                    ::core::option::Option<::hyperscale_vm_sdk::RuleBytes>
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

/// The `#[state]` struct's fields by slot and shape, and the
/// configuration struct its `Config<_>` field names, if it has one.
pub fn parse_state(
    items: &[syn::Item],
) -> syn::Result<(BTreeMap<String, Field>, Option<syn::Ident>)> {
    // Named before the state is read, so the refusal below can name every
    // accessor a field would shadow — including `config`, which exists
    // exactly when the package declares a configuration struct.
    let reserved = accessors(None);
    let mut fields = BTreeMap::new();
    let mut config_name = None;
    for item in items {
        if let syn::Item::Struct(item) = item
            && item.attrs.iter().any(|a| a.path().is_ident("config"))
        {
            config_name = Some(item.ident.clone());
        }
    }
    // The slot each field claims, which is one field's. A denomination
    // separates two leaves in the store, because it is hashed into the
    // key beside the slot — but it is hashed, so a stored leaf carries
    // the slot and nothing of the material, and a slot naming two fields
    // is two leaves a reader could not tell apart. Which is also what
    // the declared state table is keyed by.
    let mut named: BTreeMap<u16, String> = BTreeMap::new();
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
            if let Some(held) = named.insert(parsed.slot, name.clone()) {
                return Err(syn::Error::new(
                    field.span(),
                    format!(
                        "`{held}` already declares slot {}, and a slot names one field: a \
                         stored leaf carries its slot and never the material hashed into its \
                         key, so a reader that found one could not tell which field it holds",
                        parsed.slot
                    ),
                ));
            }
            fields.insert(name, parsed);
        }
    }
    Ok((fields, config_name))
}

/// The struct the component is, named for the module it lives in.
///
/// `#[state]` states the slots a package's keys sit under, and a package
/// with no state of its own has none to state — so the attribute is
/// optional and the macro writes the struct its module name implies. A
/// stated one is held to that name: the world a package publishes under
/// is the module's, so a struct named anything else is one thing an
/// author holds under two names with nothing keeping them in step.
pub fn state_struct(items: &mut Vec<syn::Item>, module: &syn::Ident) -> syn::Result<syn::Ident> {
    let expected = pascal(&module.to_string());
    let stated = items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.attrs.iter().any(|a| a.path().is_ident("state")) => {
            Some(&item.ident)
        }
        _ => None,
    });
    let Some(stated) = stated else {
        let ident = syn::Ident::new(&expected, module.span());
        items.insert(0, syn::parse_quote!(#[state] struct #ident;));
        return Ok(ident);
    };
    if stated == &expected {
        return Ok(stated.clone());
    }
    Err(syn::Error::new(
        stated.span(),
        format!(
            "`{stated}` is the state of `{module}`, so it is named `{expected}` — one \
             component, one name, and the package publishes under the module's"
        ),
    ))
}

/// The `.slot(…)` builder call each declared state field contributes.
///
/// A configuration is a leaf per field under its own slot rather than
/// one this table's key reaches, so it contributes none.
pub fn state_table(fields: &BTreeMap<String, Field>) -> Vec<TokenStream2> {
    fields
        .iter()
        .filter_map(|(name, field)| {
            let kind = match field.kind {
                FieldKind::Config => return None,
                FieldKind::Cell => quote!(Cell),
                FieldKind::Keyed => quote!(Keyed),
                FieldKind::Ordered => quote!(Ordered),
                FieldKind::Unordered => quote!(Unordered),
            };
            let element = field.element.as_ref()?;
            let slot = field.slot;
            Some(quote!(.slot::<#element>(
                #slot,
                #name,
                ::hyperscale_vm_sdk::SlotKind::#kind,
            )))
        })
        .collect()
}

/// Whether a state field holds the package's own role table: the same
/// cell shape the protocol auth cell has, at a package-band slot.
///
/// The absence is what the shape turns on, so the `Option` is read as
/// well as the element under it — a table that cannot be absent has no
/// one-way door to be behind.
pub fn holds_rule(field: &Field) -> bool {
    field.element.as_ref().is_some_and(|ty| {
        is_named(ty, "Option") && element_of(ty).is_some_and(|held| is_named(&held, "RuleBytes"))
    })
}

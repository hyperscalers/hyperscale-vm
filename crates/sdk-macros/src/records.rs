//! What a declared type or event turns into.
//!
//! The codec push: a `#[record]` gains the encoding the vocabulary
//! decodes it with, an `#[event]` gains the emitter that stamps it with
//! its own table index, and the shapes both of them name are walked out
//! of the module so the declaration can carry them.

use std::collections::{BTreeMap, BTreeSet};

use quote::quote;
use syn::spanned::Spanned as _;

use crate::role::Role;

/// The type to write where a bare collection was, or `None` where the
/// type is not one.
///
/// Read syntactically, as every type reading in this macro is. A cap
/// behind an alias is one the macro cannot see, and the type system
/// refuses that too — a shaped type cannot name an uncapped collection,
/// and a configured one has no cap for a `for-each` to be priced at.
pub fn uncapped(ty: &syn::Type) -> Option<&'static str> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let held = |name: &str| {
        let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
            return false;
        };
        matches!(args.args.first(), Some(syn::GenericArgument::Type(inner))
            if matches!(inner, syn::Type::Path(p) if p.path.is_ident(name)))
    };
    match segment.ident.to_string().as_str() {
        "Vec" if held("u8") => Some("Bytes<N>"),
        "Vec" => Some("Capped<Vec<_>, N>"),
        "String" => Some("Text<N>"),
        "BTreeSet" => Some("Capped<BTreeSet<_>, N>"),
        "BTreeMap" => Some("Capped<BTreeMap<_, _>, N>"),
        _ => None,
    }
}

/// Whether `ty` is many values under one name.
///
/// What a slot kind carries and a leaf does not: the properties a
/// collection has — many leaves, per entry routing, independent writers
/// — are exactly the ones a cell loses. Opaque bytes are one value a
/// package moves without reading, so they are not one of these.
pub fn is_collection(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    let holds_bytes = matches!(uncapped(ty), Some("Bytes<N>"));
    matches!(
        segment.ident.to_string().as_str(),
        "Vec" | "BTreeSet" | "BTreeMap" | "Capped"
    ) && !holds_bytes
}

/// Refuse a collection whose type does not say how much of it there can
/// be, in every position a package declares one.
///
/// The width of what a package writes is what the publish gate holds to
/// the kernel's caps, and a collection with no cap has none: the type
/// system says so too, since a shaped type cannot name one, but it says
/// it on a generated line. This says it on the field.
///
/// # Errors
///
/// On the first field carrying one, naming the type to write instead.
pub fn refuse_uncapped(items: &[syn::Item]) -> syn::Result<()> {
    for item in items {
        let Some(declared) = Declared::of(item) else {
            continue;
        };
        let marked = ["record", "event", "resource", "config"]
            .into_iter()
            .find(|mark| declared.marked(mark));
        let Some(mark) = marked else {
            continue;
        };
        for field in declared.fields() {
            let Some(write) = uncapped(&field.ty) else {
                continue;
            };
            return Err(syn::Error::new(
                field.ty.span(),
                format!(
                    "a `#[{mark}]` field carries its cap in its own type, because the width \
                     of what a package writes is what its declaration states — write `{write}`"
                ),
            ));
        }
    }
    Ok(())
}

/// One inherent `emit` per event type, at the index the name table fixes.
///
/// The index is the macro's, never the author's: a constant written
/// beside a name table is a number nothing checks. What crosses is the
/// event's own encoding, so the payload's shape and the type declaring
/// it cannot drift.
pub fn event_emitters(events: &[(syn::Ident, String)], role: Role) -> Vec<syn::Item> {
    events
        .iter()
        .enumerate()
        .map(|(index, (ident, _))| {
            let index = u32::try_from(index).expect("an event table is shorter than u32");
            // The one kernel call an author reaches without an accessor.
            // A publisher carries both routings and the target picks;
            // everybody else has only the session to emit into.
            let emit = if role.publishes() {
                quote!(
                    #[cfg(target_arch = "wasm32")]
                    ::hyperscale_vm_sdk::guest::emit(#index, payload);
                    #[cfg(not(target_arch = "wasm32"))]
                    ::hyperscale_vm_sdk::host::emit(#index, payload);
                )
            } else {
                quote!(::hyperscale_vm_sdk::host::emit(#index, payload);)
            };
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
                        let mut buf = [0u8; <Self as ::hyperscale_vm_sdk::hbor::HborBound>
                            ::MAX_ENCODED_LEN];
                        let payload =
                            ::hyperscale_vm_sdk::hbor::to_slice_infallible(self, &mut buf);
                        #emit
                    }
                }
            )
        })
        .collect()
}

/// Everything `seeds` reach: the declared structs named through their
/// fields, and through those in turn.
///
/// The property follows the payload rather than the attribute that
/// declared it. An event composed of a record is the ordinary shape —
/// the event *is* the thing just stored — so a record one names is
/// written into the same buffer and is held to the same terms.
pub fn reached_by(items: &[syn::Item], seeds: &BTreeSet<String>) -> BTreeSet<String> {
    let mut named: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut frontier: Vec<String> = seeds.iter().cloned().collect();
    for item in items {
        let Some(declared) = Declared::of(item) else {
            continue;
        };
        if !declared.marked("record") && !declared.marked("event") && !declared.marked("resource") {
            continue;
        }
        named.insert(
            declared.ident.to_string(),
            declared
                .fields()
                .iter()
                .flat_map(|f| type_names(&f.ty))
                .collect(),
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
pub fn type_names(ty: &syn::Type) -> Vec<String> {
    let mut found = Vec::new();
    walk_type_names(ty, &mut found);
    found
}

pub fn walk_type_names(ty: &syn::Type, found: &mut Vec<String>) {
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

/// A struct or an enum the module declares, read one way.
///
/// A record may be either: a struct where one shape is stored, an enum
/// where the cell holds one of several — a proposal that replaces the
/// factors or the roles, never both. An event and a resource are structs
/// alone; the enum is admitted where a codec is all the marker asks for.
struct Declared<'a> {
    attrs: &'a [syn::Attribute],
    ident: &'a syn::Ident,
    item: &'a syn::Item,
}

impl<'a> Declared<'a> {
    fn of(item: &'a syn::Item) -> Option<Self> {
        match item {
            syn::Item::Struct(it) => Some(Self {
                attrs: &it.attrs,
                ident: &it.ident,
                item,
            }),
            syn::Item::Enum(it) => Some(Self {
                attrs: &it.attrs,
                ident: &it.ident,
                item,
            }),
            _ => None,
        }
    }

    fn marked(&self, name: &str) -> bool {
        self.attrs.iter().any(|a| a.path().is_ident(name))
    }

    /// Every field the wire carries: a struct's own, or each variant's.
    fn fields(&self) -> Vec<&'a syn::Field> {
        match self.item {
            syn::Item::Struct(it) => it.fields.iter().collect(),
            syn::Item::Enum(it) => it.variants.iter().flat_map(|v| v.fields.iter()).collect(),
            _ => Vec::new(),
        }
    }
}

/// The codec every declared record and event carries.
///
/// Pushed onto the author's own type rather than asked for, on the same
/// terms as every other fact this macro derives: the encoding is the
/// protocol's, so naming it is the protocol's job. The path routes
/// through the SDK, which is the one crate a contract depends on.
pub fn encode_declared(
    items: &mut [syn::Item],
    length_free: &BTreeSet<String>,
) -> (Vec<syn::Item>, Vec<syn::Ident>) {
    let length_free = reached_by(items, length_free);
    let mut records = Vec::new();
    let mut stored_types = Vec::new();
    for item in items {
        let Some(declared) = Declared::of(item) else {
            continue;
        };
        let (record, event) = (declared.marked("record"), declared.marked("event"));
        // A `#[resource]` struct with fields is an instance's data
        // schema, and its cell is read and written as the record it is.
        // A bare mark declares no fields and encodes nothing.
        let instance = declared.marked("resource") && !declared.fields().is_empty();
        let ident = declared.ident.clone();
        let (attrs, vis): (&mut Vec<syn::Attribute>, &mut syn::Visibility) = match item {
            syn::Item::Struct(it) => (&mut it.attrs, &mut it.vis),
            syn::Item::Enum(it) => (&mut it.attrs, &mut it.vis),
            _ => continue,
        };
        let stored = record || instance;
        if !stored && !event {
            continue;
        }
        attrs.push(syn::parse_quote!(
            #[derive(
                ::core::clone::Clone,
                ::core::fmt::Debug,
                ::core::cmp::PartialEq,
                ::core::cmp::Eq
            )]
        ));
        attrs.push(syn::parse_quote!(
            #[derive(::hyperscale_vm_sdk::hbor::Hbor, ::hyperscale_vm_sdk::hbor::HborShape)]
        ));
        // A total body may not fault, so what a method under the mark
        // emits carries no length anywhere: the claim is asked for here
        // and checked field by field, which puts the refusal on the
        // field that carries one.
        //
        // No other declaration claims it. Every event's payload is
        // written into a stack buffer its own bound sizes, whatever it
        // holds, and every cell through an allocating encode — so a
        // length is a thing to refuse only where the mark is.
        if length_free.contains(&ident.to_string()) {
            attrs.push(syn::parse_quote!(
                #[hbor(crate = ::hyperscale_vm_sdk::hbor, length_free)]
            ));
        } else {
            attrs.push(syn::parse_quote!(#[hbor(crate = ::hyperscale_vm_sdk::hbor)]));
        }
        // Named by whoever reads it: a record by the reader of its cell,
        // an event by the decoder of its payload. Both are the package's
        // own surface, so both are open the way the configuration struct
        // is.
        *vis = syn::parse_quote!(pub);
        attrs.push(syn::parse_quote!(#[allow(missing_docs)]));
        // A variant's fields share the enum's visibility and refuse a
        // qualifier of their own.
        if let syn::Item::Struct(it) = item {
            for field in &mut it.fields {
                field.vis = syn::parse_quote!(pub);
            }
        }
        if stored {
            records.push(syn::parse_quote!(
                impl ::hyperscale_vm_sdk::state::Record for #ident {}
            ));
            records.push(syn::parse_quote!(
                impl ::hyperscale_vm_sdk::state::LeafShape for #ident {
                    const LEAF: &'static ::hyperscale_vm_sdk::hbor::ShapeNode =
                        <Self as ::hyperscale_vm_sdk::hbor::HborShape>::NODE;
                }
            ));
            stored_types.push(ident);
        }
    }
    (records, stored_types)
}

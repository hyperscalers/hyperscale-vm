//! What a declared type or event turns into.
//!
//! The codec push: a `#[record]` gains the encoding the vocabulary
//! decodes it with, an `#[event]` gains the emitter that stamps it with
//! its own table index, and the shapes both of them name are walked out
//! of the module so the declaration can carry them.

use std::collections::{BTreeMap, BTreeSet};

use quote::quote;

use crate::role::Role;

/// One inherent `emit` per event type, at the index the name table fixes.
///
/// The index is the macro's, never the author's: a constant beside a name
/// table is the one thing in the old four-document shape that nothing
/// checked. What crosses is the event's own encoding, so the payload's
/// shape and the type declaring it cannot drift.
pub fn event_emitters(events: &[(syn::Ident, String)], role: Role) -> Vec<syn::Item> {
    events
        .iter()
        .enumerate()
        .map(|(index, (ident, _))| {
            let index = u32::try_from(index).unwrap_or(u32::MAX);
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
                        use ::hyperscale_vm_sdk::hbor::HborInfallible as _;
                        let mut buf = [0u8; <Self as ::hyperscale_vm_sdk::hbor::HborInfallible>
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

/// The declared structs an emit encodes: the events, and everything
/// they name in turn.
///
/// The bound follows the payload rather than the attribute that declared
/// it. An event composed of a record is the ordinary shape — the event
/// *is* the thing just stored — so a record one names is written into
/// the same stack buffer and is held to the same widths. A record no
/// event reaches is only ever a cell, and a cell's encode allocates.
pub fn emit_closure(items: &[syn::Item]) -> BTreeSet<String> {
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

/// The codec every declared record and event carries.
///
/// Pushed onto the author's own struct rather than asked for, on the same
/// terms as every other fact this macro derives: the encoding is the
/// protocol's, so naming it is the protocol's job. The path routes
/// through the SDK, which is the one crate a contract depends on.
pub fn encode_declared(items: &mut [syn::Item]) -> (Vec<syn::Item>, Vec<syn::Ident>) {
    let emitted = emit_closure(items);
    let mut records = Vec::new();
    let mut stored_types = Vec::new();
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
        item.attrs.push(syn::parse_quote!(
            #[derive(::hyperscale_vm_sdk::hbor::Hbor, ::hyperscale_vm_sdk::hbor::HborShape)]
        ));
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
            records.push(syn::parse_quote!(
                impl ::hyperscale_vm_sdk::state::LeafShape for #name {
                    fn leaf_form(
                        types: &mut ::hyperscale_vm_sdk::hbor::ShapeRegistry,
                    ) -> ::hyperscale_vm_sdk::LeafForm {
                        ::hyperscale_vm_sdk::LeafForm::Value(
                            <Self as ::hyperscale_vm_sdk::hbor::HborShape>::shape(types),
                        )
                    }
                }
            ));
            stored_types.push(name.clone());
        }
    }
    (records, stored_types)
}

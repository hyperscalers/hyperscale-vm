//! Emission of `HborShape` bodies.
//!
//! The shape is read off the same declaration the codec is, in the same
//! order, so what a consumer is told and what the encoder writes are one
//! derivation. Where the codec descends, the shape nests; where the codec
//! skips a field, the shape has nothing to say about it.
//!
//! What is emitted is a static tree: one `const` naming the fields' own
//! constants, which is the form a generic impl can state and a type that
//! reaches itself cannot.
//!
//! A declared name is the identifier that declared it. Rust names a
//! type's members once each, so two of them cannot reach one name — where
//! a rendering that folded case would let them, and would need a refusal
//! to say so. Rust admits identifiers the protocol does not, though, so
//! each one is held to what a name is made of beside the node it names,
//! in a `const` on its own span: the rule is the decoder's own, asserted
//! where the word is written rather than restated here.

use proc_macro2::TokenStream;
use quote::{quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Error, Fields, Ident, Result};

use crate::attrs::{FieldAttrs, TypeAttrs};
use crate::codec::{bounds, variant_tags};

/// Emit the `HborShape` impl for `input`.
///
/// # Errors
///
/// On a malformed attribute, a duplicate discriminant, or a `transparent`
/// type with anything other than one field.
pub fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let attrs = TypeAttrs::parse(&input.attrs)?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let shape_bounds = bounds(input, &quote!(__hbor::HborShape));

    let mut spelled = Vec::new();
    let node = match &input.data {
        Data::Struct(data) => {
            if attrs.transparent {
                transparent(&data.fields)?
            } else {
                let content = fields(&data.fields, &mut spelled)?;
                let declared = name.to_string();
                spelled.push(spellable(name));
                quote! {
                    &__hbor::ShapeNode::Named {
                        name: #declared,
                        shape: #content,
                    }
                }
            }
        }
        Data::Enum(data) => {
            if attrs.transparent {
                return Err(Error::new(
                    name.span(),
                    "`transparent` needs exactly one field; an enum has a discriminant of its own",
                ));
            }
            let mut variants = TokenStream::new();
            for (variant, tag) in data.variants.iter().zip(variant_tags(data)?) {
                let variant_name = variant.ident.to_string();
                let content = fields(&variant.fields, &mut spelled)?;
                spelled.push(spellable(&variant.ident));
                variants.extend(quote!((#variant_name, #tag, #content),));
            }
            let declared = name.to_string();
            spelled.push(spellable(name));
            quote! {
                &__hbor::ShapeNode::Named {
                    name: #declared,
                    shape: &__hbor::ShapeNode::Enum(&[#variants]),
                }
            }
        }
        Data::Union(_) => {
            return Err(Error::new(
                name.span(),
                "a union has no field the decoder could know to read",
            ));
        }
    };

    let krate = &attrs.crate_path;
    Ok(quote! {
        const _: () = {
        use #krate as __hbor;

        #(#spelled)*

        #[automatically_derived]
        impl #impl_generics __hbor::HborShape for #name #type_generics
        #where_clause #shape_bounds {
            const NODE: &'static __hbor::ShapeNode = #node;
        }
        };
    })
}

/// A wrapper is a name and not a layer on the wire, so it describes as
/// the one field it holds.
fn transparent(fields: &Fields) -> Result<TokenStream> {
    let mut held = fields.iter();
    let (Some(field), None) = (held.next(), held.next()) else {
        return Err(Error::new(
            fields.span(),
            "`transparent` needs exactly one field",
        ));
    };
    let ty = &field.ty;
    Ok(quote!(<#ty as __hbor::HborShape>::NODE))
}

/// The node of a set of fields: named, positional, or none at all.
///
/// A skipped field is not on the wire, so it is not in the shape either —
/// a consumer told about one would read a value the bytes do not hold.
fn fields(fields: &Fields, spelled: &mut Vec<TokenStream>) -> Result<TokenStream> {
    let mut on_the_wire = Vec::new();
    for field in fields {
        if !FieldAttrs::parse(&field.attrs)?.skip {
            if let Some(ident) = &field.ident {
                spelled.push(spellable(ident));
            }
            on_the_wire.push(field);
        }
    }
    let nodes = on_the_wire
        .iter()
        .map(|field| {
            let ty = &field.ty;
            quote!(<#ty as __hbor::HborShape>::NODE)
        })
        .collect::<Vec<_>>();
    Ok(match fields {
        Fields::Named(_) => {
            let entries = on_the_wire.iter().zip(nodes).map(|(field, node)| {
                let name = field
                    .ident
                    .as_ref()
                    .map_or_else(String::new, ToString::to_string);
                quote!((#name, #node))
            });
            quote!(&__hbor::ShapeNode::Struct(&[#(#entries),*]))
        }
        Fields::Unnamed(_) | Fields::Unit => {
            quote!(&__hbor::ShapeNode::Tuple(&[#(#nodes),*]))
        }
    })
}

/// Hold `ident` to what the protocol spells a name with, on its own span.
///
/// The published name is the identifier, so an identifier Rust admits and
/// the protocol does not — a non-ASCII one, or one past the bytes a name
/// may occupy — would travel to every consumer that renders it. The
/// decoder holds an arriving name to the same rule; this is the tier that
/// says which word to change, and it asks the decoder's own question
/// rather than asking a second one that could answer differently.
fn spellable(ident: &Ident) -> TokenStream {
    let spelling = ident.to_string();
    quote_spanned! { ident.span() =>
        const _: () = assert!(
            __hbor::is_name(#spelling),
            concat!(
                "`",
                #spelling,
                "` is published as it is written, and the protocol spells a name as an \
                 ASCII identifier no longer than a name may be"
            )
        );
    }
}

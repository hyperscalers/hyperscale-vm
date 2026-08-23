//! Emission of `HborShape` bodies.
//!
//! The shape is read off the same declaration the codec is, in the same
//! order, so what a consumer is told and what the encoder writes are one
//! derivation. Where the codec descends, the shape nests; where the codec
//! skips a field, the shape has nothing to say about it.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Error, Fields, Result};

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

    let body = match &input.data {
        Data::Struct(data) => {
            if attrs.transparent {
                transparent(&data.fields)?
            } else {
                let content = fields(&data.fields)?;
                let declared = kebab(&name.to_string());
                quote! {
                    types.nominal(
                        #declared,
                        ::core::any::type_name::<Self>(),
                        |types| #content,
                    )
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
                let variant_name = kebab(&variant.ident.to_string());
                let content = fields(&variant.fields)?;
                variants.extend(quote! {
                    __hbor::ShapeVariant {
                        name: ::std::string::ToString::to_string(#variant_name),
                        discriminant: #tag,
                        content: #content,
                    },
                });
            }
            let declared = kebab(&name.to_string());
            quote! {
                types.nominal(
                    #declared,
                    ::core::any::type_name::<Self>(),
                    |types| __hbor::TypeShape::Enum(::std::vec![#variants]),
                )
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

        #[automatically_derived]
        impl #impl_generics __hbor::HborShape for #name #type_generics
        #where_clause #shape_bounds {
            fn shape(types: &mut __hbor::ShapeRegistry) -> __hbor::TypeShape {
                #body
            }
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
    Ok(quote!(<#ty as __hbor::HborShape>::shape(types)))
}

/// The shape of a set of fields: named, positional, or none at all.
///
/// A skipped field is not on the wire, so it is not in the shape either —
/// a consumer told about one would read a value the bytes do not hold.
fn fields(fields: &Fields) -> Result<TokenStream> {
    let mut on_the_wire = Vec::new();
    for field in fields {
        if !FieldAttrs::parse(&field.attrs)?.skip {
            on_the_wire.push(field);
        }
    }
    let shapes = on_the_wire
        .iter()
        .map(|field| {
            let ty = &field.ty;
            quote!(<#ty as __hbor::HborShape>::shape(types))
        })
        .collect::<Vec<_>>();
    Ok(match fields {
        Fields::Named(_) => {
            let entries = on_the_wire.iter().zip(shapes).map(|(field, shape)| {
                let name = field
                    .ident
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                quote! {
                    __hbor::ShapeField {
                        name: ::std::string::ToString::to_string(#name),
                        shape: #shape,
                    }
                }
            });
            quote!(__hbor::TypeShape::Struct(::std::vec![#(#entries),*]))
        }
        Fields::Unnamed(_) | Fields::Unit => {
            quote!(__hbor::TypeShape::Tuple(::std::vec![#(#shapes),*]))
        }
    })
}

/// A Rust type or variant name as the name a package declares it under:
/// `ValidatorRegistered` is `validator-registered`.
///
/// The same rendering the metadata's own name tables use, so a table
/// entry and the type it describes agree on what to call it.
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

//! Emission of the `Chunked` impl.

use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{Data, DataEnum, DeriveInput, Error, Fields, Index, Result};

use crate::attrs::{FieldAttrs, TypeAttrs, reject_unencodable};
use crate::codec::{bounds, variant_tags};

/// Emit `Chunked` for `input`: one leaf per field, in declaration order.
///
/// # Errors
///
/// On a shape whose leaves are not well defined, or a field with no
/// canonical encoding.
pub fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let attrs = TypeAttrs::parse(&input.attrs)?;
    if attrs.transparent {
        return Err(Error::new(
            input.ident.span(),
            "a transparent wrapper is its inner type on the wire; chunk the inner type",
        ));
    }

    let body = match &input.data {
        Data::Struct(data) => struct_chunks(&data.fields)?,
        Data::Enum(data) => enum_chunks(data)?,
        Data::Union(_) => {
            return Err(Error::new(
                input.ident.span(),
                "a union has no field the tree could know to cover",
            ));
        }
    };

    let Some(domain) = attrs.merkle_domain.as_ref() else {
        return Err(Error::new(
            input.ident.span(),
            "a merkle root binds a type through its domain; declare \
             `#[hbor(merkle_domain = \"...\")]` so two types over identical bytes cannot \
             share a root",
        ));
    };
    if domain.value().is_empty() {
        return Err(Error::new(
            domain.span(),
            "a merkle domain must not be empty; it is what keeps a proof gathered against one \
             type from verifying against another",
        ));
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let encode_bounds = bounds(input, &quote!(::hyperscale_hbor::HborEncode));

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::hyperscale_hbor::merkle::Chunked for #name #type_generics
        #where_clause #encode_bounds {
            const MERKLE_DOMAIN: &'static [u8] = #domain.as_bytes();

            fn chunks(
                &self,
            ) -> ::core::result::Result<
                ::std::vec::Vec<::std::vec::Vec<u8>>,
                ::hyperscale_hbor::EncodeError,
            > {
                let mut leaves = ::std::vec::Vec::new();
                #body
                ::core::result::Result::Ok(leaves)
            }
        }
    })
}

fn struct_chunks(fields: &Fields) -> Result<TokenStream> {
    if fields.is_empty() {
        return Err(Error::new(
            fields.span_or_call_site(),
            "a type with no fields has no leaves, and its root would be shared by every value",
        ));
    }
    let mut out = TokenStream::new();
    for (index, field) in fields.iter().enumerate() {
        if FieldAttrs::parse(&field.attrs)?.skip {
            continue;
        }
        reject_unencodable(&field.ty)?;
        let access = field.ident.as_ref().map_or_else(
            || {
                let index = Index::from(index);
                quote!(&self.#index)
            },
            |name| quote!(&self.#name),
        );
        out.extend(quote! {
            leaves.push(::hyperscale_hbor::to_vec(#access)?);
        });
    }
    Ok(out)
}

fn enum_chunks(data: &DataEnum) -> Result<TokenStream> {
    let mut arms = TokenStream::new();
    for (variant, tag) in data.variants.iter().zip(variant_tags(data)?) {
        let variant_name = &variant.ident;
        let bindings: Vec<_> = variant
            .fields
            .iter()
            .enumerate()
            .map(|(position, field)| {
                field
                    .ident
                    .as_ref()
                    .map_or_else(|| quote::format_ident!("field_{position}"), Clone::clone)
            })
            .collect();
        let pattern = match &variant.fields {
            Fields::Named(_) => quote!(Self::#variant_name { #(#bindings),* }),
            Fields::Unnamed(_) => quote!(Self::#variant_name ( #(#bindings),* )),
            Fields::Unit => quote!(Self::#variant_name),
        };
        for field in &variant.fields {
            reject_unencodable(&field.ty)?;
        }
        // The discriminant is its own leaf, so which variant this is can be
        // proven without revealing the variant's content.
        arms.extend(quote! {
            #pattern => {
                leaves.push(::hyperscale_hbor::to_vec(&#tag)?);
                #(leaves.push(::hyperscale_hbor::to_vec(#bindings)?);)*
            }
        });
    }
    Ok(quote! {
        match self {
            #arms
        }
    })
}

/// `Fields::span` is not available on `Fields::Unit`, which is the case this
/// diagnostic is for.
trait SpanOrCallSite {
    fn span_or_call_site(&self) -> Span;
}

impl SpanOrCallSite for Fields {
    fn span_or_call_site(&self) -> Span {
        use syn::spanned::Spanned;
        match self {
            Self::Unit => Span::call_site(),
            other => other.span(),
        }
    }
}

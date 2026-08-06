//! Emission of the `HborSigned` impl.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{Data, DeriveInput, Error, Result};

use crate::attrs::{FieldAttrs, TypeAttrs};
use crate::codec::{Include, SelfAccess, bounds, encode_fields};

/// Emit `HborSigned` when the type declares a signing domain, and refuse the
/// combinations where a preimage would not mean what it looks like.
///
/// # Errors
///
/// When `unsigned` appears without a domain, when a domain is asked of a
/// shape that cannot carry one, or when nothing would be covered.
pub fn derive(input: &DeriveInput, attrs: &TypeAttrs) -> Result<TokenStream> {
    let fields = match &input.data {
        Data::Struct(data) => Some(&data.fields),
        _ => None,
    };

    let Some(domain) = attrs.signing_domain.as_ref() else {
        if let Some(context) = attrs.signing_context.as_ref() {
            return Err(Error::new(
                context.span(),
                "`signing_context` names what a preimage mixes in, and this type declares no \
                 `signing_domain`, so there is no preimage to mix it into",
            ));
        }
        reject_orphan_unsigned(input)?;
        return Ok(TokenStream::new());
    };

    let Some(fields) = fields else {
        return Err(Error::new(
            input.ident.span(),
            "`signing_domain` needs a struct; an enum's variants would each cover different \
             content under one domain",
        ));
    };
    if attrs.transparent {
        return Err(Error::new(
            input.ident.span(),
            "a transparent wrapper is its inner type on the wire; give the inner type the domain",
        ));
    }

    let mut covered = 0usize;
    for field in fields {
        if !FieldAttrs::parse(&field.attrs)?.unsigned {
            covered += 1;
        }
    }
    if covered == 0 {
        return Err(Error::new(
            input.ident.span(),
            "every field is `unsigned`, so the preimage would cover no content and every value \
             of this type would share one signature",
        ));
    }

    if domain.value().is_empty() {
        return Err(Error::new(
            domain.span(),
            "a signing domain must not be empty; it is what stops a signature for one message \
             from verifying against another",
        ));
    }

    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();
    let encode_bounds = bounds(input, &quote!(::hyperscale_hbor::HborEncode));
    let body = encode_fields(fields, &SelfAccess, Include::Signed)?;

    if let Some(context) = attrs.signing_context.as_ref() {
        return Ok(quote! {
            #[automatically_derived]
            impl #impl_generics ::hyperscale_hbor::HborSignedWith for #name #type_generics
            #where_clause #encode_bounds {
                type Context = #context;

                const SIGNING_DOMAIN: &'static [u8] = #domain.as_bytes();

                fn signing_bytes(
                    &self,
                    context: &Self::Context,
                ) -> ::core::result::Result<::std::vec::Vec<u8>, ::hyperscale_hbor::EncodeError>
                {
                    let mut buffer = ::std::vec::Vec::new();
                    // The default cap, whatever the consumer's decoder uses:
                    // depth charges write no bytes, so the cap decides only
                    // whether a too-deep value has a preimage at all — never
                    // which bytes it has.
                    let mut encoder = ::hyperscale_hbor::Encoder::new(
                        &mut buffer,
                        ::hyperscale_hbor::DEFAULT_MAX_DEPTH,
                    );
                    // Framed, not concatenated: an unframed domain that is a
                    // prefix of another collides with it once the content
                    // begins with the remaining bytes.
                    encoder.write_sized(
                        <Self as ::hyperscale_hbor::HborSignedWith>::SIGNING_DOMAIN,
                    )?;
                    // The context is a leading field in all but storage: a
                    // fixed type, encoded ahead of the signed fields,
                    // charging one level like any other.
                    encoder.nested(context)?;
                    #body
                    ::core::result::Result::Ok(buffer)
                }
            }
        });
    }

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::hyperscale_hbor::HborSigned for #name #type_generics
        #where_clause #encode_bounds {
            const SIGNING_DOMAIN: &'static [u8] = #domain.as_bytes();

            fn signing_bytes(
                &self,
            ) -> ::core::result::Result<::std::vec::Vec<u8>, ::hyperscale_hbor::EncodeError> {
                let mut buffer = ::std::vec::Vec::new();
                // The default cap, whatever the consumer's decoder uses:
                // depth charges write no bytes, so the cap decides only
                // whether a too-deep value has a preimage at all — never
                // which bytes it has.
                let mut encoder = ::hyperscale_hbor::Encoder::new(
                    &mut buffer,
                    ::hyperscale_hbor::DEFAULT_MAX_DEPTH,
                );
                // Framed, not concatenated: an unframed domain that is a
                // prefix of another collides with it once the content
                // begins with the remaining bytes.
                encoder.write_sized(<Self as ::hyperscale_hbor::HborSigned>::SIGNING_DOMAIN)?;
                #body
                ::core::result::Result::Ok(buffer)
            }
        }
    })
}

fn reject_orphan_unsigned(input: &DeriveInput) -> Result<()> {
    let fields = match &input.data {
        Data::Struct(data) => data.fields.iter().collect::<Vec<_>>(),
        Data::Enum(data) => data.variants.iter().flat_map(|v| v.fields.iter()).collect(),
        Data::Union(_) => Vec::new(),
    };
    for field in fields {
        if FieldAttrs::parse(&field.attrs)?.unsigned {
            return Err(Error::new(
                field.span(),
                "`unsigned` holds a field out of a signing preimage, and this type declares no \
                 `signing_domain`, so it would do nothing",
            ));
        }
    }
    Ok(())
}

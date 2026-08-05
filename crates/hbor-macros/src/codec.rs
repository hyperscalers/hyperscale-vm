//! Emission of `HborEncode` and `HborDecode` bodies.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Data, DataEnum, DeriveInput, Error, Expr, Fields, GenericArgument, Ident, Index, PathArguments,
    Result, Type,
};

use crate::attrs::{FieldAttrs, Shape, TypeAttrs, VariantAttrs, reject_unencodable, shape};
use crate::signing;

/// Emit both impls for `input`.
///
/// # Errors
///
/// On a malformed attribute, a type with no canonical encoding, a cap the
/// emitter cannot place, or a duplicate discriminant.
pub fn derive(input: &DeriveInput) -> Result<TokenStream> {
    let attrs = TypeAttrs::parse(&input.attrs)?;
    let name = &input.ident;
    let (impl_generics, type_generics, where_clause) = input.generics.split_for_impl();

    let width_bounds = bounds(input, &quote!(::hyperscale_hbor::HborWidth));
    let encode_bounds = bounds(input, &quote!(::hyperscale_hbor::HborEncode));
    let decode_bounds = bounds(input, &quote!(::hyperscale_hbor::HborDecode));

    let (encode_body, decode_body, min_len) = match &input.data {
        Data::Struct(data) => {
            if attrs.transparent {
                transparent(&data.fields)?
            } else {
                let encode = encode_fields(&data.fields, &SelfAccess, Include::All)?;
                let decode = decode_fields(&data.fields, &quote!(Self))?;
                let min = min_encoded_len(&data.fields);
                (encode, decode, min)
            }
        }
        Data::Enum(data) => {
            if attrs.transparent {
                return Err(Error::new(
                    input.ident.span(),
                    "`transparent` needs exactly one field; an enum has a discriminant of its own",
                ));
            }
            enumeration(name, data)?
        }
        Data::Union(_) => {
            return Err(Error::new(
                input.ident.span(),
                "a union has no field the decoder could know to read",
            ));
        }
    };

    let validate = attrs.validate.as_ref().map(|path| {
        quote! {
            #path(&value).map_err(::hyperscale_hbor::DecodeError::FailedValidation)?;
        }
    });
    let signed = signing::derive(input, &attrs)?;

    Ok(quote! {
        #[automatically_derived]
        impl #impl_generics ::hyperscale_hbor::HborWidth for #name #type_generics
        #where_clause #width_bounds {
            const MIN_ENCODED_LEN: usize = #min_len;
        }

        #[automatically_derived]
        impl #impl_generics ::hyperscale_hbor::HborEncode for #name #type_generics
        #where_clause #encode_bounds {
            fn encode(
                &self,
                encoder: &mut ::hyperscale_hbor::Encoder<'_>,
            ) -> ::core::result::Result<(), ::hyperscale_hbor::EncodeError> {
                #encode_body
                ::core::result::Result::Ok(())
            }
        }

        #[automatically_derived]
        impl #impl_generics ::hyperscale_hbor::HborDecode for #name #type_generics
        #where_clause #decode_bounds {
            fn decode(
                decoder: &mut ::hyperscale_hbor::Decoder<'_>,
            ) -> ::core::result::Result<Self, ::hyperscale_hbor::DecodeError> {
                let value = #decode_body;
                #validate
                ::core::result::Result::Ok(value)
            }
        }

        #signed
    })
}

/// How a field is reached in the encode body.
pub trait Access {
    fn get(&self, index: usize, name: Option<&Ident>) -> TokenStream;
}

/// Fields of the value itself: `&self.name` or `&self.0`.
pub struct SelfAccess;

impl Access for SelfAccess {
    fn get(&self, index: usize, name: Option<&Ident>) -> TokenStream {
        name.map_or_else(
            || {
                let index = Index::from(index);
                quote!(&self.#index)
            },
            |name| quote!(&self.#name),
        )
    }
}

/// Fields bound by a match arm: the binding, by name or position.
struct BindingAccess;

impl Access for BindingAccess {
    fn get(&self, index: usize, name: Option<&Ident>) -> TokenStream {
        let binding = binding(index, name);
        quote!(#binding)
    }
}

fn binding(index: usize, name: Option<&Ident>) -> Ident {
    name.map_or_else(|| format_ident!("field_{index}"), Clone::clone)
}

/// Which fields an encode body covers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Include {
    /// Every field — the wire form.
    All,
    /// Every field but those held out of what a signature covers.
    Signed,
}

pub fn encode_fields(
    fields: &Fields,
    access: &dyn Access,
    include: Include,
) -> Result<TokenStream> {
    let mut out = TokenStream::new();
    for (index, field) in fields.iter().enumerate() {
        reject_unencodable(&field.ty)?;
        let attrs = FieldAttrs::parse(&field.attrs)?;
        if include == Include::Signed && attrs.unsigned {
            continue;
        }
        let value = access.get(index, field.ident.as_ref());
        let label = field
            .ident
            .as_ref()
            .map_or_else(|| index.to_string(), ToString::to_string);

        if let Some(max) = &attrs.max {
            if shape(&field.ty) == Shape::Opaque {
                return Err(capped_opaque(&field.ty));
            }
            out.extend(quote! {
                ::hyperscale_hbor::bounded::check_encoded_len(#label, (#value).len(), #max)?;
            });
        }

        out.extend(if shape(&field.ty) == Shape::Bytes {
            quote! {
                encoder.descend(|encoder| {
                    ::hyperscale_hbor::bounded::encode_bytes(encoder, #value)
                })?;
            }
        } else {
            quote!(encoder.nested(#value)?;)
        });
    }
    Ok(out)
}

fn decode_fields(fields: &Fields, constructor: &TokenStream) -> Result<TokenStream> {
    let mut reads = TokenStream::new();
    let mut names = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        reject_unencodable(&field.ty)?;
        let attrs = FieldAttrs::parse(&field.attrs)?;
        let name = binding(index, field.ident.as_ref());
        let ty = &field.ty;
        let read = read_expression(ty, attrs.max.as_ref())?;
        reads.extend(quote! { let #name: #ty = #read; });
        names.push(name);
    }

    // Fields are read in declaration order, by explicit bindings rather than
    // in-place construction, so the read order is the wire order whatever
    // the constructor's shape.
    let build = match fields {
        Fields::Named(_) => quote!(#constructor { #(#names),* }),
        Fields::Unnamed(_) => quote!(#constructor ( #(#names),* )),
        Fields::Unit => quote!(#constructor),
    };
    Ok(quote! {{ #reads #build }})
}

fn read_expression(ty: &Type, max: Option<&Expr>) -> Result<TokenStream> {
    let Some(max) = max else {
        return Ok(if shape(ty) == Shape::Bytes {
            quote!(decoder.descend(::hyperscale_hbor::bounded::decode_bytes)?)
        } else {
            quote!(decoder.nested()?)
        });
    };

    let reader = match shape(ty) {
        Shape::Bytes => quote!(decode_bounded_bytes),
        Shape::Sequence => quote!(decode_bounded_vec),
        Shape::Text => quote!(decode_bounded_string),
        Shape::Set => quote!(decode_bounded_btree_set),
        Shape::Map => quote!(decode_bounded_btree_map),
        Shape::Opaque => return Err(capped_opaque(ty)),
    };
    Ok(quote! {
        decoder.descend(|decoder| ::hyperscale_hbor::bounded::#reader(decoder, #max))?
    })
}

fn capped_opaque(ty: &Type) -> Error {
    Error::new(
        ty.span(),
        "`max` needs a field written as Vec, String, BTreeSet, or BTreeMap; \
         a type that hides one behind an alias or a newtype carries its own bound instead",
    )
}

/// Whether `ty`'s minimum width references `this` type's own.
///
/// The width formula recurses through exactly two shapes: a `Box`, which
/// forwards its contents' width, and a tuple, which sums its components'.
/// `Vec`, `Option`, maps, and sets have constant minimums whatever they
/// hold, so `Vec<Self>` recurses in memory but not in the constant.
/// Anything unrecognized is treated as non-recursive: a false negative is
/// a loud const-evaluation cycle at compile time, never a wrong constant.
fn width_reaches(ty: &Type, this: &Ident) -> bool {
    match ty {
        Type::Path(path) => {
            let Some(segment) = path.path.segments.last() else {
                return false;
            };
            if segment.ident == *this || segment.ident == "Self" {
                return true;
            }
            if segment.ident == "Box"
                && let PathArguments::AngleBracketed(bracketed) = &segment.arguments
            {
                return bracketed.args.iter().any(
                    |arg| matches!(arg, GenericArgument::Type(inner) if width_reaches(inner, this)),
                );
            }
            false
        }
        Type::Tuple(tuple) => tuple.elems.iter().any(|elem| width_reaches(elem, this)),
        _ => false,
    }
}

fn min_encoded_len(fields: &Fields) -> TokenStream {
    let terms = fields.iter().map(|field| {
        let ty = &field.ty;
        quote!(<#ty as ::hyperscale_hbor::HborWidth>::MIN_ENCODED_LEN)
    });
    quote!(0 #(+ #terms)*)
}

fn transparent(fields: &Fields) -> Result<(TokenStream, TokenStream, TokenStream)> {
    let mut iter = fields.iter();
    let (Some(field), None) = (iter.next(), iter.next()) else {
        return Err(Error::new(
            fields.span(),
            "`transparent` needs exactly one field",
        ));
    };
    if FieldAttrs::parse(&field.attrs)?.max.is_some() {
        return Err(Error::new(
            field.span(),
            "a transparent wrapper is its inner type on the wire; put `max` on the field that \
             holds the wrapper",
        ));
    }
    reject_unencodable(&field.ty)?;

    let ty = &field.ty;
    let access = SelfAccess.get(0, field.ident.as_ref());
    // No `descend`: a transparent wrapper is not a level, it is a name. The
    // inner type still charges for whatever it nests.
    let encode = quote! { ::hyperscale_hbor::HborEncode::encode(#access, encoder)?; };
    let inner = quote!(<#ty as ::hyperscale_hbor::HborDecode>::decode(decoder)?);
    let decode = field.ident.as_ref().map_or_else(
        || quote!(Self(#inner)),
        |name| quote!(Self { #name: #inner }),
    );
    let min = quote!(<#ty as ::hyperscale_hbor::HborWidth>::MIN_ENCODED_LEN);
    Ok((encode, decode, min))
}

/// The wire byte of every variant, in declaration order.
///
/// The single place discriminants are resolved: the codec and the merkle
/// chunking both read from here, so a variant cannot carry one tag on the
/// wire and another in its tree.
///
/// # Errors
///
/// On a duplicate discriminant, or an enum too large to index by byte.
pub fn variant_tags(data: &DataEnum) -> Result<Vec<u8>> {
    let mut seen: Vec<(u8, Span)> = Vec::new();
    for (index, variant) in data.variants.iter().enumerate() {
        let attrs = VariantAttrs::parse(&variant.attrs)?;
        let tag = match attrs.discriminant {
            Some(explicit) => explicit,
            None => u8::try_from(index).map_err(|_| {
                Error::new(
                    variant.ident.span(),
                    "an enum past 256 variants needs discriminants of its own",
                )
            })?,
        };
        if let Some((_, first)) = seen.iter().find(|(other, _)| *other == tag) {
            let mut error = Error::new(
                variant.ident.span(),
                format!("discriminant {tag} is already taken"),
            );
            error.combine(Error::new(*first, format!("{tag} is used here")));
            return Err(error);
        }
        seen.push((tag, variant.ident.span()));
    }
    Ok(seen.into_iter().map(|(tag, _)| tag).collect())
}

fn enumeration(name: &Ident, data: &DataEnum) -> Result<(TokenStream, TokenStream, TokenStream)> {
    let mut arms = TokenStream::new();
    let mut branches = TokenStream::new();
    let mut candidates = Vec::new();

    for (variant, tag) in data.variants.iter().zip(variant_tags(data)?) {
        let variant_name = &variant.ident;
        let bindings = variant.fields.iter().enumerate().map(|(position, field)| {
            let name = binding(position, field.ident.as_ref());
            field
                .ident
                .as_ref()
                .map_or_else(|| quote!(#name), |ident| quote!(#ident))
        });
        let pattern = match &variant.fields {
            Fields::Named(_) => quote!(Self::#variant_name { #(#bindings),* }),
            Fields::Unnamed(_) => quote!(Self::#variant_name ( #(#bindings),* )),
            Fields::Unit => quote!(Self::#variant_name),
        };
        let writes = encode_fields(&variant.fields, &BindingAccess, Include::All)?;
        arms.extend(quote! {
            #pattern => {
                encoder.write_u8(#tag);
                #writes
            }
        });

        let reads = decode_fields(&variant.fields, &quote!(#name::#variant_name))?;
        branches.extend(quote! { #tag => #reads, });
        // A self-recursive variant embeds a whole `Self` beside its
        // discriminant, so it is strictly wider than the enum's minimum:
        // leaving it out of the candidates changes the answer not at all
        // and breaks the const cycle its width would otherwise be.
        if !variant
            .fields
            .iter()
            .any(|field| width_reaches(&field.ty, name))
        {
            candidates.push(min_encoded_len(&variant.fields));
        }
    }

    let encode = quote! {
        match self {
            #arms
        }
    };
    let decode = quote! {
        match decoder.read_u8()? {
            #branches
            other => {
                return ::core::result::Result::Err(
                    ::hyperscale_hbor::DecodeError::InvalidDiscriminant(other),
                );
            }
        }
    };
    // One byte of discriminant, plus the lightest variant: no encoding of
    // this type is shorter, and a container dividing by it must not
    // overestimate.
    let min = if candidates.is_empty() {
        quote!(1)
    } else {
        quote! {{
            let mut smallest = usize::MAX;
            #(
                let candidate = #candidates;
                if candidate < smallest {
                    smallest = candidate;
                }
            )*
            1 + smallest
        }}
    };
    Ok((encode, decode, min))
}

pub fn bounds(input: &DeriveInput, bound: &TokenStream) -> TokenStream {
    let parameters: Vec<_> = input.generics.type_params().map(|p| &p.ident).collect();
    if parameters.is_empty() {
        return TokenStream::new();
    }
    let clauses = parameters.iter().map(|p| quote!(#p: #bound));
    if input.generics.where_clause.is_some() {
        quote!(, #(#clauses),*)
    } else {
        quote!(where #(#clauses),*)
    }
}

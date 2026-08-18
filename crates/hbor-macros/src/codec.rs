//! Emission of `HborEncode` and `HborDecode` bodies.

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::spanned::Spanned;
use syn::{
    Data, DataEnum, DeriveInput, Error, Expr, Field, Fields, GenericArgument, Ident, Index,
    PathArguments, Result, Type,
};

use crate::attrs::{
    CapSite, FieldAttrs, Shape, TypeAttrs, VariantAttrs, cap_site, reject_unencodable, shape,
};
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

    let width_bounds = bounds(input, &quote!(__hbor::HborWidth));
    let encode_bounds = bounds(input, &quote!(__hbor::HborEncode));
    let decode_bounds = bounds(input, &quote!(__hbor::HborDecode));

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
            #path(&value).map_err(__hbor::DecodeError::FailedValidation)?;
        }
    });
    let signed = signing::derive(input, &attrs)?;

    // Every path the impls name is bound once, here, so a crate that
    // re-exports the codec can host a derive without the deriving crate
    // depending on it directly. A guest crate is exactly that: it names
    // the SDK and nothing else, and the SDK is where it finds HBOR.
    let krate = &attrs.crate_path;
    Ok(quote! {
        const _: () = {
        use #krate as __hbor;

        #[automatically_derived]
        impl #impl_generics __hbor::HborWidth for #name #type_generics
        #where_clause #width_bounds {
            const MIN_ENCODED_LEN: usize = #min_len;
        }

        #[automatically_derived]
        impl #impl_generics __hbor::HborEncode for #name #type_generics
        #where_clause #encode_bounds {
            fn encode(
                &self,
                encoder: &mut __hbor::Encoder<'_>,
            ) -> ::core::result::Result<(), __hbor::EncodeError> {
                #encode_body
                ::core::result::Result::Ok(())
            }
        }

        #[automatically_derived]
        impl #impl_generics __hbor::HborDecode for #name #type_generics
        #where_clause #decode_bounds {
            fn decode(
                decoder: &mut __hbor::Decoder<'_>,
            ) -> ::core::result::Result<Self, __hbor::DecodeError> {
                let value = #decode_body;
                #validate
                ::core::result::Result::Ok(value)
            }
        }

        #signed
        };
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
        let attrs = FieldAttrs::parse(&field.attrs)?;
        if attrs.skip {
            refuse_skip_combinations(field, &attrs)?;
            continue;
        }
        reject_unencodable(&field.ty)?;
        if include == Include::Signed && attrs.unsigned {
            continue;
        }
        let value = access.get(index, field.ident.as_ref());
        let label = field
            .ident
            .as_ref()
            .map_or_else(|| index.to_string(), ToString::to_string);

        if let Some(max) = &attrs.max {
            let Some(site) = cap_site(&field.ty) else {
                return Err(capped_opaque(&field.ty));
            };
            match site {
                // `Arc` and `Box` deref to the collection, so the length
                // check and the write both reach through unchanged.
                CapSite::Direct(inner) | CapSite::Shared(inner) | CapSite::Boxed(inner) => {
                    out.extend(quote! {
                        __hbor::bounded::check_encoded_len(
                            #label, (#value).len(), #max,
                        )?;
                    });
                    out.extend(write_expression(inner, &value));
                }
                // The cap applies to the payload when present; the write is
                // the plain `Option` encoding, so the two spellings of a
                // `Some` produce the same bytes at the same depth.
                CapSite::Optional(_) => {
                    out.extend(quote! {
                        if let ::core::option::Option::Some(inner) = #value {
                            __hbor::bounded::check_encoded_len(
                                #label, inner.len(), #max,
                            )?;
                        }
                        encoder.nested(#value)?;
                    });
                }
            }
            continue;
        }

        out.extend(write_expression(shape(&field.ty), &value));
    }
    Ok(out)
}

fn decode_fields(fields: &Fields, constructor: &TokenStream) -> Result<TokenStream> {
    let mut reads = TokenStream::new();
    let mut names = Vec::new();

    for (index, field) in fields.iter().enumerate() {
        let attrs = FieldAttrs::parse(&field.attrs)?;
        let name = binding(index, field.ident.as_ref());
        let ty = &field.ty;
        if attrs.skip {
            refuse_skip_combinations(field, &attrs)?;
            // Off the wire entirely: nothing is read, and the value is
            // whatever an absent field means to the type.
            reads.extend(quote! { let #name: #ty = ::core::default::Default::default(); });
            names.push(name);
            continue;
        }
        reject_unencodable(&field.ty)?;
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

/// The write for an uncapped or length-checked field body.
fn write_expression(shape: Shape, value: &TokenStream) -> TokenStream {
    if shape == Shape::Bytes {
        quote! {
            encoder.descend(|encoder| {
                __hbor::bounded::encode_bytes(encoder, #value)
            })?;
        }
    } else {
        quote!(encoder.nested(#value)?;)
    }
}

fn read_expression(ty: &Type, max: Option<&Expr>) -> Result<TokenStream> {
    let Some(max) = max else {
        return Ok(if shape(ty) == Shape::Bytes {
            quote!(decoder.descend(__hbor::bounded::decode_bytes)?)
        } else {
            quote!(decoder.nested()?)
        });
    };

    let Some(site) = cap_site(ty) else {
        return Err(capped_opaque(ty));
    };
    // Every arm charges exactly what the uncapped spelling of the same
    // type charges: one level for the field, with the bounded readers
    // supplying the element level internally, plus one for an `Option`'s
    // payload — the level `Option`'s own impl spends on `nested`.
    Ok(match site {
        CapSite::Direct(inner) => {
            let reader = bounded_reader(inner);
            quote! {
                decoder.descend(|decoder| __hbor::bounded::#reader(decoder, #max))?
            }
        }
        CapSite::Shared(inner) => {
            let reader = bounded_reader(inner);
            quote! {
                decoder.descend(|decoder| {
                    ::core::result::Result::Ok(::std::sync::Arc::new(
                        __hbor::bounded::#reader(decoder, #max)?,
                    ))
                })?
            }
        }
        CapSite::Boxed(inner) => {
            let reader = bounded_reader(inner);
            quote! {
                decoder.descend(|decoder| {
                    ::core::result::Result::Ok(::std::boxed::Box::new(
                        __hbor::bounded::#reader(decoder, #max)?,
                    ))
                })?
            }
        }
        CapSite::Optional(inner) => {
            let reader = bounded_reader(inner);
            quote! {
                decoder.descend(|decoder| match decoder.read_u8()? {
                    0 => ::core::result::Result::Ok(::core::option::Option::None),
                    1 => decoder
                        .descend(|decoder| __hbor::bounded::#reader(decoder, #max))
                        .map(::core::option::Option::Some),
                    other => ::core::result::Result::Err(
                        __hbor::DecodeError::InvalidDiscriminant(other),
                    ),
                })?
            }
        }
    })
}

fn bounded_reader(shape: Shape) -> TokenStream {
    match shape {
        Shape::Bytes => quote!(decode_bounded_bytes),
        Shape::Sequence => quote!(decode_bounded_vec),
        Shape::Text => quote!(decode_bounded_string),
        Shape::Set => quote!(decode_bounded_btree_set),
        Shape::Map => quote!(decode_bounded_btree_map),
        Shape::Opaque => unreachable!("cap_site never yields an opaque shape"),
    }
}

fn capped_opaque(ty: &Type) -> Error {
    Error::new(
        ty.span(),
        "`max` needs a field written as Vec, String, BTreeSet, or BTreeMap — bare, or one \
         level under Arc, Box, or Option; a type that hides one behind an alias carries \
         its own bound instead",
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
    let terms = fields.iter().filter_map(|field| {
        let attrs = FieldAttrs::parse(&field.attrs).ok()?;
        if attrs.skip {
            return None;
        }
        let ty = &field.ty;
        Some(quote!(<#ty as __hbor::HborWidth>::MIN_ENCODED_LEN))
    });
    quote!(0 #(+ #terms)*)
}

/// `skip` composes with nothing: a field that is not on the wire can carry
/// no wire bound and no preimage marking.
fn refuse_skip_combinations(field: &Field, attrs: &FieldAttrs) -> Result<()> {
    if attrs.max.is_some() || attrs.unsigned {
        return Err(Error::new(
            field.span(),
            "`skip` takes a field off the wire entirely; `max` and `unsigned` describe wire \
             behaviour it cannot have",
        ));
    }
    Ok(())
}

fn transparent(fields: &Fields) -> Result<(TokenStream, TokenStream, TokenStream)> {
    let mut iter = fields.iter();
    let (Some(field), None) = (iter.next(), iter.next()) else {
        return Err(Error::new(
            fields.span(),
            "`transparent` needs exactly one field",
        ));
    };
    reject_unencodable(&field.ty)?;

    let ty = &field.ty;
    let access = SelfAccess.get(0, field.ident.as_ref());
    // No `descend`: a transparent wrapper is not a level, it is a name. The
    // inner type still charges for whatever it nests. A capped field swaps
    // in the bounded reader and writer at the same depth — the newtype's
    // own bound, expressed where the collection is written.
    let (encode, inner) = match FieldAttrs::parse(&field.attrs)?.max {
        Some(max) => {
            let Some(CapSite::Direct(inner_shape)) = cap_site(ty) else {
                return Err(capped_opaque(ty));
            };
            let reader = bounded_reader(inner_shape);
            let write = if inner_shape == Shape::Bytes {
                quote! {
                    __hbor::bounded::encode_bytes(encoder, #access)?;
                }
            } else {
                quote! {
                    __hbor::HborEncode::encode(#access, encoder)?;
                }
            };
            let label = field
                .ident
                .as_ref()
                .map_or_else(|| "0".to_string(), ToString::to_string);
            let encode = quote! {
                __hbor::bounded::check_encoded_len(#label, (#access).len(), #max)?;
                #write
            };
            let inner = quote!(__hbor::bounded::#reader(decoder, #max)?);
            (encode, inner)
        }
        None => (
            quote! { __hbor::HborEncode::encode(#access, encoder)?; },
            quote!(<#ty as __hbor::HborDecode>::decode(decoder)?),
        ),
    };
    let decode = field.ident.as_ref().map_or_else(
        || quote!(Self(#inner)),
        |name| quote!(Self { #name: #inner }),
    );
    let min = quote!(<#ty as __hbor::HborWidth>::MIN_ENCODED_LEN);
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
                    __hbor::DecodeError::InvalidDiscriminant(other),
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

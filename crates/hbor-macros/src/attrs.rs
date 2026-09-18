//! Attribute parsing, and the field-shape classification the emitter needs.

use syn::spanned::Spanned;
use syn::{
    Attribute, Error, Expr, ExprLit, GenericArgument, Lit, LitStr, Path, PathArguments, Result,
    Type,
};

/// What `#[hbor(...)]` says about a type.
pub struct TypeAttrs {
    /// Encode as the single field, charging no nesting level for the
    /// wrapper.
    pub(crate) transparent: bool,
    /// A predicate run on the decoded value before it escapes the decoder.
    pub(crate) validate: Option<Path>,
    /// What this type's signatures are for. Its presence is what asks for a
    /// preimage at all.
    pub(crate) signing_domain: Option<LitStr>,
    /// Session state the preimage mixes in ahead of the signed fields —
    /// held by signer and verifier alike, and never on the wire.
    pub(crate) signing_context: Option<Type>,
    /// What this type's merkle roots are for. Required by `HborMerkle`;
    /// inert under `Hbor` alone, which cannot know its sibling derive.
    pub(crate) merkle_domain: Option<LitStr>,
    /// Claim that this type's encoding carries no length.
    ///
    /// Asked for rather than inferred, because the shape a field is
    /// written in is not always the shape it has — an alias hiding a
    /// `Vec` reads as opaque here. Asking makes the emitted impl bound
    /// every field, so a field that carries a length is a compile error
    /// naming it rather than a claim nothing checks.
    pub(crate) length_free: bool,
    /// Where the emitted impls find the codec.
    ///
    /// Defaults to `::hyperscale_hbor`, which is right for every crate
    /// that depends on it directly. A crate reaching the codec through a
    /// re-export names that path instead — which is how a contract guest,
    /// whose only dependency is the SDK, hosts a derive at all.
    pub(crate) crate_path: Path,
}

impl Default for TypeAttrs {
    fn default() -> Self {
        Self {
            transparent: false,
            validate: None,
            signing_domain: None,
            signing_context: None,
            merkle_domain: None,
            length_free: false,
            crate_path: syn::parse_quote!(::hyperscale_hbor),
        }
    }
}

/// What `#[hbor(...)]` says about a variant.
#[derive(Default)]
pub struct VariantAttrs {
    /// The wire discriminant, when it is not the declaration index.
    ///
    /// A literal, not a constant expression: the emitter compares
    /// discriminants across variants to reject a collision, and a named
    /// constant would make that check silently unavailable.
    pub(crate) discriminant: Option<u8>,
}

/// What `#[hbor(...)]` says about a field.
#[derive(Default)]
pub struct FieldAttrs {
    /// Held out of the signing preimage. The field still rides the wire —
    /// a signature and the key that verifies it are transmitted, they just
    /// cannot be part of what they cover.
    pub(crate) unsigned: bool,
    /// Not on the wire at all: encode writes nothing, decode fills
    /// `Default::default()`. For in-memory caches riding a wire type.
    pub(crate) skip: bool,
}

impl TypeAttrs {
    /// Parse the type-level attributes.
    ///
    /// # Errors
    ///
    /// On an unknown key or a malformed value.
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut out = Self::default();
        for attr in attrs.iter().filter(|a| a.path().is_ident("hbor")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("transparent") {
                    out.transparent = true;
                    return Ok(());
                }
                if meta.path.is_ident("validate") {
                    out.validate = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("signing_domain") {
                    out.signing_domain = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("signing_context") {
                    out.signing_context = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("merkle_domain") {
                    out.merkle_domain = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("length_free") {
                    out.length_free = true;
                    return Ok(());
                }
                if meta.path.is_ident("crate") {
                    out.crate_path = meta.value()?.parse()?;
                    return Ok(());
                }
                Err(meta.error(
                    "unknown hbor attribute; a type takes `transparent`, `validate = path`, \
                     `signing_domain = \"...\"`, `signing_context = Ty`, \
                     `merkle_domain = \"...\"`, `length_free`, or `crate = path`",
                ))
            })?;
        }
        Ok(out)
    }
}

impl VariantAttrs {
    /// Parse the variant-level attributes.
    ///
    /// # Errors
    ///
    /// On an unknown key, or a discriminant outside a byte.
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut out = Self::default();
        for attr in attrs.iter().filter(|a| a.path().is_ident("hbor")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("discriminant") {
                    out.discriminant = Some(byte_literal(&meta.value()?.parse()?)?);
                    return Ok(());
                }
                Err(meta.error("unknown hbor attribute; a variant takes `discriminant = N`"))
            })?;
        }
        Ok(out)
    }
}

impl FieldAttrs {
    /// Parse the field-level attributes.
    ///
    /// # Errors
    ///
    /// On an unknown key.
    pub(crate) fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut out = Self::default();
        for attr in attrs.iter().filter(|a| a.path().is_ident("hbor")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("unsigned") {
                    out.unsigned = true;
                    return Ok(());
                }
                if meta.path.is_ident("skip") {
                    out.skip = true;
                    return Ok(());
                }
                Err(meta.error("unknown hbor attribute; a field takes `unsigned` or `skip`"))
            })?;
        }
        Ok(out)
    }
}

/// Whether `ty` is written as one run of bytes.
///
/// The codec's one fast path: `Vec<u8>` reads and writes in a single
/// copy where a generic sequence walks per element. Resolution is
/// syntactic, so an alias hiding a `Vec<u8>` takes the generic path,
/// which is correct and slower.
#[must_use]
pub fn writes_bytes(ty: &Type) -> bool {
    let Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    segment.ident == "Vec" && first_type_argument(&segment.arguments).is_some_and(is_u8)
}

/// Reject the types that have no canonical encoding, with the reason.
///
/// Catching these here rather than letting the trait system do it turns a
/// missing-impl error on a generated line into a message on the field the
/// author wrote.
///
/// # Errors
///
/// On a float, a pointer-width integer, or a hash-ordered collection.
pub fn reject_unencodable(ty: &Type) -> Result<()> {
    let Type::Path(path) = ty else {
        return Ok(());
    };
    let Some(segment) = path.path.segments.last() else {
        return Ok(());
    };
    let reason = match segment.ident.to_string().as_str() {
        "f32" | "f64" => "a float has no encoding every node agrees on",
        "usize" | "isize" => {
            "a pointer-width integer would encode differently per host; name a width"
        }
        "HashMap" | "HashSet" => {
            "hash-ordered collections have no canonical order; use BTreeMap or BTreeSet"
        }
        _ => return Ok(()),
    };
    Err(Error::new(ty.span(), reason))
}

fn first_type_argument(arguments: &PathArguments) -> Option<&Type> {
    let PathArguments::AngleBracketed(bracketed) = arguments else {
        return None;
    };
    bracketed.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })
}

fn is_u8(ty: &Type) -> bool {
    matches!(ty, Type::Path(path) if path.path.is_ident("u8"))
}

fn byte_literal(expr: &Expr) -> Result<u8> {
    let value = usize_literal(expr)?;
    u8::try_from(value).map_err(|_| Error::new(expr.span(), "a discriminant must fit in a byte"))
}

fn usize_literal(expr: &Expr) -> Result<usize> {
    let Expr::Lit(ExprLit {
        lit: Lit::Int(int), ..
    }) = expr
    else {
        return Err(Error::new(
            expr.span(),
            "expected an integer literal; collisions are checked at expansion, which a named \
             constant would prevent",
        ));
    };
    int.base10_parse()
}

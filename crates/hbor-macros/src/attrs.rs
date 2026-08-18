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
    pub transparent: bool,
    /// A predicate run on the decoded value before it escapes the decoder.
    pub validate: Option<Path>,
    /// What this type's signatures are for. Its presence is what asks for a
    /// preimage at all.
    pub signing_domain: Option<LitStr>,
    /// Session state the preimage mixes in ahead of the signed fields —
    /// held by signer and verifier alike, and never on the wire.
    pub signing_context: Option<Type>,
    /// What this type's merkle roots are for. Required by `HborMerkle`;
    /// inert under `Hbor` alone, which cannot know its sibling derive.
    pub merkle_domain: Option<LitStr>,
    /// Where the emitted impls find the codec.
    ///
    /// Defaults to `::hyperscale_hbor`, which is right for every crate
    /// that depends on it directly. A crate reaching the codec through a
    /// re-export names that path instead — which is how a contract guest,
    /// whose only dependency is the SDK, hosts a derive at all.
    pub crate_path: Path,
}

impl Default for TypeAttrs {
    fn default() -> Self {
        Self {
            transparent: false,
            validate: None,
            signing_domain: None,
            signing_context: None,
            merkle_domain: None,
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
    pub discriminant: Option<u8>,
}

/// What `#[hbor(...)]` says about a field.
#[derive(Default)]
pub struct FieldAttrs {
    /// The largest length this field may carry, as any `usize` constant
    /// expression. Protocol caps are named constants, so a literal-only
    /// attribute would force the number to be written twice.
    pub max: Option<Expr>,
    /// Held out of the signing preimage. The field still rides the wire —
    /// a signature and the key that verifies it are transmitted, they just
    /// cannot be part of what they cover.
    pub unsigned: bool,
    /// Not on the wire at all: encode writes nothing, decode fills
    /// `Default::default()`. For in-memory caches riding a wire type.
    pub skip: bool,
}

/// The collection shape of a field's type, as written.
///
/// Resolution is syntactic: an alias hiding a `Vec` reads as [`Shape::Opaque`]
/// and takes the generic path, which is correct but declines the fast path
/// and cannot host a cap. Naming the type is the fix, and the diagnostic for
/// a cap on an opaque type says so.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// `Vec<u8>` — read and written in one copy.
    Bytes,
    /// `Vec<T>` for some other `T`.
    Sequence,
    /// `String`.
    Text,
    /// `BTreeSet<T>`.
    Set,
    /// `BTreeMap<K, V>`.
    Map,
    /// Anything else, including an alias.
    Opaque,
}

impl TypeAttrs {
    /// Parse the type-level attributes.
    ///
    /// # Errors
    ///
    /// On an unknown key or a malformed value.
    pub fn parse(attrs: &[Attribute]) -> Result<Self> {
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
                if meta.path.is_ident("crate") {
                    out.crate_path = meta.value()?.parse()?;
                    return Ok(());
                }
                Err(meta.error(
                    "unknown hbor attribute; a type takes `transparent`, `validate = path`, \
                     `signing_domain = \"...\"`, `signing_context = Ty`, \
                     `merkle_domain = \"...\"`, or `crate = path`",
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
    pub fn parse(attrs: &[Attribute]) -> Result<Self> {
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
    pub fn parse(attrs: &[Attribute]) -> Result<Self> {
        let mut out = Self::default();
        for attr in attrs.iter().filter(|a| a.path().is_ident("hbor")) {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("max") {
                    out.max = Some(meta.value()?.parse()?);
                    return Ok(());
                }
                if meta.path.is_ident("unsigned") {
                    out.unsigned = true;
                    return Ok(());
                }
                if meta.path.is_ident("skip") {
                    out.skip = true;
                    return Ok(());
                }
                Err(meta.error(
                    "unknown hbor attribute; a field takes `max = N`, `unsigned`, or `skip`",
                ))
            })?;
        }
        Ok(out)
    }
}

/// Classify a field's type by how it is written.
#[must_use]
pub fn shape(ty: &Type) -> Shape {
    let Type::Path(path) = ty else {
        return Shape::Opaque;
    };
    let Some(segment) = path.path.segments.last() else {
        return Shape::Opaque;
    };
    match segment.ident.to_string().as_str() {
        "String" => Shape::Text,
        "BTreeSet" => Shape::Set,
        "BTreeMap" => Shape::Map,
        "Vec" => {
            if first_type_argument(&segment.arguments).is_some_and(is_u8) {
                Shape::Bytes
            } else {
                Shape::Sequence
            }
        }
        _ => Shape::Opaque,
    }
}

/// Where a capped field's collection sits relative to the written type.
///
/// `max` reaches through the containers that add nothing of their own to
/// the wire: an `Arc` or `Box` is pure forwarding, and an `Option`'s
/// payload is the collection when present. Resolution stays syntactic —
/// exactly one named container layer, never a type-system walk — so an
/// alias still reads as opaque.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CapSite {
    /// The field is the collection itself.
    Direct(Shape),
    /// `Arc<C>` — rebuilt with `Arc::new` on decode.
    Shared(Shape),
    /// `Box<C>` — rebuilt with `Box::new` on decode.
    Boxed(Shape),
    /// `Option<C>` — the cap applies to the payload when present.
    Optional(Shape),
}

/// Resolve where a cap on `ty` lands, or `None` when no collection is
/// written where the emitter can see one.
#[must_use]
pub fn cap_site(ty: &Type) -> Option<CapSite> {
    let direct = shape(ty);
    if direct != Shape::Opaque {
        return Some(CapSite::Direct(direct));
    }
    let Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    let inner = first_type_argument(&segment.arguments).map(shape)?;
    if inner == Shape::Opaque {
        return None;
    }
    match segment.ident.to_string().as_str() {
        "Arc" => Some(CapSite::Shared(inner)),
        "Box" => Some(CapSite::Boxed(inner)),
        "Option" => Some(CapSite::Optional(inner)),
        _ => None,
    }
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

//! `#[derive(Hbor)]` — canonical codecs from a type's declaration.
//!
//! The derive writes what a hand-written impl would write, in declaration
//! order, and its bar is byte-identical agreement with one. It is not a
//! shorthand for a different encoding; the wire form of a derived type and a
//! hand-written type of the same shape are the same bytes.
//!
//! # Attributes
//!
//! On a type:
//!
//! - `#[hbor(transparent)]` — a single-field wrapper encodes as its inner
//!   type and charges no nesting level. The wrapper is a name, not a layer.
//! - `#[hbor(validate = path)]` — `path` is `fn(&Self) -> Result<(),
//!   &'static str>`, run once every field is decoded and before the value
//!   escapes the decoder. This is where a cross-field invariant lives: a
//!   length that must match a count, a hash that must match what it covers.
//!   It runs on decode only; construction is the encode-side gate.
//! - `#[hbor(signing_domain = "...")]` — this type's signatures cover a
//!   framed domain then its signed fields, canonically encoded. Structs
//!   only: an enum's variants would each cover different content under one
//!   domain. The domain must not be empty, and no two message types may
//!   share one.
//! - `#[hbor(signing_context = Ty)]` — the signing preimage mixes a value
//!   of `Ty` in ahead of the fields, and `signing_bytes` takes one: how a
//!   message binds to the session it is for — a network id — without
//!   carrying it as a field. Only beside `signing_domain`.
//! - `#[hbor(infallible)]` — also emit `HborInfallible`, with
//!   `MAX_ENCODED_LEN` summed from the fields' own bounds. The type must
//!   hold only infallible fields; the no-alloc encoding path is what it
//!   buys.
//! - `#[hbor(crate = path)]` — the path generated code names the hbor
//!   crate by, for a caller that reaches it through a re-export rather
//!   than as a direct dependency.
//!
//! On a variant:
//!
//! - `#[hbor(discriminant = N)]` — the wire byte, when it should not be the
//!   declaration index. Pinning it lets variants be reordered in source
//!   without moving the wire form. Duplicates are a compile error.
//!
//! On a field:
//!
//! - `#[hbor(max = N)]` — the largest length this field may carry, checked
//!   against the claimed length before the collection is built, and again on
//!   encode. The field must be written as a `Vec`, `String`, `BTreeSet`, or
//!   `BTreeMap` — bare, one level under an `Arc`, `Box`, or `Option` (the
//!   cap applies to the payload when present), or as the single field of a
//!   `transparent` wrapper, whose bound is then its own. Resolution is
//!   syntactic, so an alias cannot host a cap.
//! - `#[hbor(unsigned)]` — held out of the signing preimage. The field still
//!   rides the wire; a signature and the key that verifies it are
//!   transmitted, they just cannot be part of what they cover. A field added
//!   later is signed unless it says otherwise, so widening a message cannot
//!   quietly leave the new content unauthenticated.
//! - `#[hbor(skip)]` — not on the wire at all: encoded as nothing, rebuilt
//!   as `Default::default()` at decode. What a locally-derived cache rides
//!   a wire type as, so a peer can never supply it.
//!
//! A cap is a protocol bound, not a safety one — decoding already refuses a
//! length the remaining input cannot satisfy, whether or not a field declares
//! a maximum.
//!
//! # Refusals
//!
//! Floats, `usize`, `isize`, `HashMap`, and `HashSet` are rejected on the
//! field the author wrote rather than left to surface as a missing impl on a
//! generated line. Floats and hash-ordered collections have no canonical
//! form; a pointer-width integer would encode differently per host.

mod attrs;
mod codec;
mod merkle;
mod shape;
mod signing;

use proc_macro::TokenStream;
use syn::{DeriveInput, parse_macro_input};

/// Derive `HborEncode` and `HborDecode`.
///
/// A struct is its fields in declaration order. An enum is a one-byte
/// discriminant then the variant's fields. Nothing else is written — no
/// field names, no type tags, no padding.
#[proc_macro_derive(Hbor, attributes(hbor))]
pub fn hbor(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    codec::derive(&input).map_or_else(|error| error.to_compile_error().into(), Into::into)
}

/// Derive `Chunked`: one merkle leaf per field, in declaration order.
///
/// A type deriving this has its root as its identity. Hashing its encoding
/// separately alongside would be a second hash for one value, which is what
/// this encoding exists to avoid.
///
/// Requires `#[hbor(merkle_domain = "...")]`. The domain is mixed into the
/// root, so two types whose fields encode to identical bytes still root
/// differently — the same substitution a signing domain prevents, one seam
/// over. No two types may share a domain. The attribute lives in the shared
/// `hbor(...)` namespace, so a `merkle_domain` on a type that derives only
/// `Hbor` is accepted and inert: derives expand independently, and neither
/// can see whether the other is present.
///
/// An enum's discriminant is its own leaf, so which variant a value is can be
/// proven without revealing the variant's content.
#[proc_macro_derive(HborMerkle, attributes(hbor))]
pub fn hbor_merkle(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    merkle::derive(&input).map_or_else(|error| error.to_compile_error().into(), Into::into)
}

/// Derive `HborShape`: a type written down for a consumer that does not
/// have it.
///
/// Read off the same declaration the codec is, so the description and the
/// bytes cannot disagree. A struct or enum registers its definition under
/// its kebab name and is referenced by it; a `transparent` wrapper is a
/// name and not a layer, so it describes as the type it holds. A `skip`
/// field is absent from both the wire and the shape.
///
/// Opt-in, and read by nothing on the encode or decode path: a type that
/// nobody needs to describe carries no shape at all.
#[proc_macro_derive(HborShape, attributes(hbor))]
pub fn hbor_shape(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    shape::derive(&input).map_or_else(|error| error.to_compile_error().into(), Into::into)
}

//! The metadata section of a publishable artifact.
//!
//! Effect metadata rides the component as a wasm custom section, so the
//! code and the signatures it declares are one content-addressed artifact
//! and cannot drift apart. This module owns the section's name, its
//! payload codec — canonical HBOR of [`PackageMetadata`], decoded at the
//! vocabulary's own nesting bound and judged by [`check_metadata`], so
//! canonical means within bounds — and the framing walk that finds it.
//! Judging what an artifact may publish beyond that — a byte budget, a
//! profile — is the embedder's policy, layered on top of these.

use hyperscale_hbor::{from_slice_with_depth, to_vec_with_depth};

use crate::dsl::{MAX_CLAUSE_DEPTH, MAX_EXPR_DEPTH};
use crate::hash::Hasher;
use crate::metadata::{MAX_SHAPE_DEPTH, PackageHash, PackageMetadata};
use crate::publish::check_metadata;
use crate::types::MAX_VALUE_DEPTH;

/// The custom section effect metadata rides in.
pub const METADATA_SECTION: &str = "hyperscale:effect-metadata";

/// The domain a declaration addresses under, distinct from the one an
/// artifact does.
const DOMAIN_DECLARATION: &[u8] = b"hyperscale-vm/declaration";

/// The section id wasm reserves for custom sections.
const CUSTOM_SECTION_ID: u8 = 0;

/// The magic and version word every module and component opens with.
const WASM_MAGIC: [u8; 4] = *b"\0asm";
const PREAMBLE_LEN: usize = 8;

/// The nesting cap the section codec encodes and decodes at.
///
/// A vocabulary layer costs at most two decoder levels — a collection
/// field and its hoisted element body — so the clause, expression, and
/// value bounds translate at two apiece, over a fixed prefix for the
/// record, its method table, a method, and a clause's target and mode.
/// A shape layer costs three: the variant's own sequence field, that
/// sequence's elements, and the field or variant body one level down.
/// The cap admits everything [`check_metadata`] accepts; the checks are
/// what decide.
pub const METADATA_WIRE_DEPTH: usize =
    16 + 3 * MAX_SHAPE_DEPTH + 2 * (MAX_CLAUSE_DEPTH + MAX_EXPR_DEPTH + MAX_VALUE_DEPTH);

/// Why an artifact's metadata section could not be read or written.
///
/// Deterministic: every node reaches the identical verdict for the same
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    /// The artifact does not open with the wasm preamble.
    #[error("artifact does not open with the wasm preamble")]
    NotWasm,
    /// A section's declared length runs past the artifact.
    #[error("section runs past the artifact")]
    SectionOverrun,
    /// A custom section's name runs past its own section.
    #[error("custom section name runs past its section")]
    NameOverrun,
    /// A length field is malformed or oversized.
    #[error("malformed section length")]
    BadLength,
    /// The artifact declares the metadata section more than once — which
    /// one meant the package's effects would be a question the format
    /// does not answer.
    #[error("artifact declares the effect metadata section twice")]
    DuplicateSection,
    /// The artifact already declares a metadata section, so attaching
    /// another would create the duplicate above.
    #[error("artifact already declares an effect metadata section")]
    AlreadyAttached,
    /// The section's payload is not canonical metadata.
    #[error("metadata payload is not canonical: {0}")]
    Payload(String),
    /// The metadata is past a bound the vocabulary fixes.
    #[error("metadata is past a vocabulary bound: {0}")]
    Bounds(String),
}

/// Encode package metadata into its canonical section bytes.
///
/// # Errors
///
/// [`ArtifactError`] if the metadata is past a bound decode enforces, so
/// that whatever this returns decodes back to an equal value.
pub fn encode_metadata(metadata: &PackageMetadata) -> Result<Vec<u8>, ArtifactError> {
    check_metadata(metadata).map_err(|error| ArtifactError::Bounds(error.to_string()))?;
    to_vec_with_depth(metadata, METADATA_WIRE_DEPTH)
        .map_err(|error| ArtifactError::Payload(error.to_string()))
}

/// The content address of a declaration on its own, for a world that has
/// one and no artifact to put it in.
///
/// Takes the declaration rather than bytes, and hashes under a domain of
/// its own, because this and [`package_hash`](crate::package_hash) answer
/// different questions: a package's identity covers the code as well as
/// what the code says about itself, and this covers only the second half.
/// Two packages that declare alike and run differently are one address
/// here and two on a chain, which is why nothing a network publishes is
/// addressed this way.
///
/// # Errors
///
/// [`ArtifactError`] if the metadata is past a bound decode enforces.
pub fn declaration_hash(
    hasher: &dyn Hasher,
    metadata: &PackageMetadata,
) -> Result<PackageHash, ArtifactError> {
    let declaration = encode_metadata(metadata)?;
    Ok(PackageHash(
        hasher.hash(DOMAIN_DECLARATION, &[&declaration]),
    ))
}

/// Decode a metadata section's canonical bytes.
///
/// # Errors
///
/// [`ArtifactError`] on malformed or non-canonical bytes, or a structure
/// past a bound the vocabulary fixes.
pub fn decode_metadata(bytes: &[u8]) -> Result<PackageMetadata, ArtifactError> {
    let metadata: PackageMetadata = from_slice_with_depth(bytes, METADATA_WIRE_DEPTH)
        .map_err(|error| ArtifactError::Payload(error.to_string()))?;
    check_metadata(&metadata).map_err(|error| ArtifactError::Bounds(error.to_string()))?;
    Ok(metadata)
}

/// Attach `metadata` to a component artifact as its metadata section.
///
/// The result is the publishable artifact: same code, one section longer,
/// and a different content address.
///
/// # Errors
///
/// [`ArtifactError`] if the artifact's section framing is malformed, if it
/// already declares a metadata section, or if the metadata is past a bound
/// the codec enforces.
pub fn attach_metadata(
    artifact: &[u8],
    metadata: &PackageMetadata,
) -> Result<Vec<u8>, ArtifactError> {
    if metadata_section(artifact)?.is_some() {
        return Err(ArtifactError::AlreadyAttached);
    }
    let payload = encode_metadata(metadata)?;

    let mut content = Vec::with_capacity(METADATA_SECTION.len() + payload.len() + 8);
    write_uleb128(METADATA_SECTION.len(), &mut content);
    content.extend_from_slice(METADATA_SECTION.as_bytes());
    content.extend_from_slice(&payload);

    let mut out = Vec::with_capacity(artifact.len() + content.len() + 8);
    out.extend_from_slice(artifact);
    out.push(CUSTOM_SECTION_ID);
    write_uleb128(content.len(), &mut out);
    out.extend_from_slice(&content);
    Ok(out)
}

/// The effect metadata a component artifact declares, if it declares any.
///
/// # Errors
///
/// [`ArtifactError`] if the artifact's section framing is malformed, if it
/// declares the metadata section more than once, or if the section's
/// payload is not canonical metadata.
pub fn extract_metadata(artifact: &[u8]) -> Result<Option<PackageMetadata>, ArtifactError> {
    metadata_section(artifact)?.map(decode_metadata).transpose()
}

/// The metadata section's payload, walking the artifact's sections.
///
/// The framing walk alone, for an embedder whose policy judges the raw
/// payload — a byte budget, say — before it decodes. Every step is
/// checked against the bytes that remain, so a truncated length, a
/// section running past the artifact, or a name running past its own
/// section is a refusal rather than a panic.
///
/// # Errors
///
/// [`ArtifactError`] if the artifact's section framing is malformed or it
/// declares the metadata section more than once.
pub fn metadata_section(artifact: &[u8]) -> Result<Option<&[u8]>, ArtifactError> {
    if artifact.len() < PREAMBLE_LEN || artifact[..WASM_MAGIC.len()] != WASM_MAGIC {
        return Err(ArtifactError::NotWasm);
    }
    let mut found: Option<&[u8]> = None;
    let mut pos = PREAMBLE_LEN;
    while pos < artifact.len() {
        let id = artifact[pos];
        pos += 1;
        let size = read_uleb128(artifact, &mut pos)?;
        let end = pos
            .checked_add(size)
            .filter(|end| *end <= artifact.len())
            .ok_or(ArtifactError::SectionOverrun)?;

        if id == CUSTOM_SECTION_ID {
            // Bounded by the section's own end, so a name length cannot
            // read into whatever follows.
            let section = &artifact[..end];
            let mut inner = pos;
            let name_len = read_uleb128(section, &mut inner)?;
            let name_end = inner
                .checked_add(name_len)
                .filter(|name_end| *name_end <= end)
                .ok_or(ArtifactError::NameOverrun)?;
            if &artifact[inner..name_end] == METADATA_SECTION.as_bytes() {
                if found.is_some() {
                    return Err(ArtifactError::DuplicateSection);
                }
                found = Some(&artifact[name_end..end]);
            }
        }
        pos = end;
    }
    Ok(found)
}

fn write_uleb128(mut value: usize, out: &mut Vec<u8>) {
    loop {
        #[allow(clippy::cast_possible_truncation)] // masked to seven bits
        let seven = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(seven);
            return;
        }
        out.push(seven | 0x80);
    }
}

/// Read one wasm `u32` length, capped at the five bytes the encoding
/// admits so a padded run cannot spin.
fn read_uleb128(bytes: &[u8], pos: &mut usize) -> Result<usize, ArtifactError> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos).ok_or(ArtifactError::BadLength)?;
        *pos += 1;
        value |= u64::from(byte & 0x7F) << shift;
        if byte < 0x80 {
            break;
        }
        shift += 7;
        if shift >= 32 {
            return Err(ArtifactError::BadLength);
        }
    }
    if value > u64::from(u32::MAX) {
        return Err(ArtifactError::BadLength);
    }
    usize::try_from(value).map_err(|_| ArtifactError::BadLength)
}

#[cfg(test)]
mod tests {
    use hyperscale_hbor::{ShapeField, TypeShape, to_vec_with_depth};
    use hyperscale_vm_types::Moves;

    use super::{
        ArtifactError, CUSTOM_SECTION_ID, METADATA_SECTION, METADATA_WIRE_DEPTH, attach_metadata,
        check_metadata, declaration_hash, decode_metadata, encode_metadata, extract_metadata,
        write_uleb128,
    };
    use crate::dsl::{Clause, Expr, MAX_EXPR_DEPTH, ModeExpr, TargetExpr};
    use crate::hash::TestHasher;
    use crate::metadata::{MAX_SHAPE_DEPTH, PackageMetadata, package_hash};
    use crate::signature::{MethodSignature, Totality};

    /// The wire depth admits every shape the door admits, so a package
    /// cannot pass the checks and then fail to be written down.
    #[test]
    fn the_wire_depth_carries_the_deepest_admissible_shape() {
        use hyperscale_hbor::ShapeVariant;

        // The costliest form per level: a struct's field and an enum's
        // variant each put a sequence between one shape and the next.
        let nested = |levels| {
            let deepest = (0..levels).fold(TypeShape::U8, |inner, level| {
                let held = TypeShape::Struct(vec![ShapeField {
                    name: format!("field{level}"),
                    shape: inner,
                }]);
                TypeShape::Enum(vec![ShapeVariant {
                    name: format!("variant{level}"),
                    discriminant: 0,
                    content: held,
                }])
            });
            PackageMetadata {
                types: std::iter::once(("deepest".to_owned(), deepest)).collect(),
                ..PackageMetadata::default()
            }
        };
        // Whatever the door's last word is, the section codec carries it.
        // A level costs at least one of the walk's budget, so no
        // admissible shape has more of them than the cap.
        let deepest = (1..=MAX_SHAPE_DEPTH)
            .map(nested)
            .take_while(|metadata| check_metadata(metadata).is_ok())
            .last()
            .expect("some depth is admissible");
        let section = encode_metadata(&deepest).expect("the deepest shape encodes");
        assert_eq!(decode_metadata(&section).expect("and decodes"), deepest);
    }

    fn empty_component() -> Vec<u8> {
        let mut artifact = b"\0asm".to_vec();
        artifact.extend_from_slice(&[0x0D, 0x00, 0x01, 0x00]);
        artifact
    }

    /// A declaration and an artifact are addressed under domains of their
    /// own, so the same bytes read as one are never the other.
    ///
    /// The separation is the whole of what distinguishes the two: without
    /// it, a world holding only a declaration would be handing out
    /// addresses in the space a published package's identity occupies.
    #[test]
    fn a_declaration_addresses_apart_from_an_artifact() {
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert(
            "swap".to_owned(),
            MethodSignature {
                totality: Totality::Fallible,
                ..MethodSignature::default()
            },
        );
        let declaration = encode_metadata(&metadata).expect("the declaration encodes");

        let declared = declaration_hash(&TestHasher, &metadata).expect("the declaration addresses");
        assert_ne!(
            declared,
            package_hash(&TestHasher, &declaration),
            "a declaration must not address as the artifact carrying it"
        );
        assert_eq!(
            declared,
            declaration_hash(&TestHasher, &metadata).expect("the declaration addresses"),
            "and it addresses by content"
        );
    }

    #[test]
    fn metadata_rides_the_artifact_and_comes_back_canonical() {
        let mut metadata = PackageMetadata::default();
        metadata.events.push("transferred".to_owned());
        metadata.types.insert(
            "transferred".to_owned(),
            TypeShape::Struct(vec![ShapeField {
                name: "amount".to_owned(),
                shape: TypeShape::U128,
            }]),
        );

        let published = attach_metadata(&empty_component(), &metadata).unwrap();
        assert_eq!(extract_metadata(&published).unwrap(), Some(metadata));
        assert!(
            published
                .windows(METADATA_SECTION.len())
                .any(|window| window == METADATA_SECTION.as_bytes())
        );
    }

    #[test]
    fn a_bare_artifact_declares_nothing() {
        assert_eq!(extract_metadata(&empty_component()).unwrap(), None);
    }

    #[test]
    fn a_second_section_refuses_at_attach_and_at_extract() {
        let metadata = PackageMetadata::default();
        let once = attach_metadata(&empty_component(), &metadata).unwrap();
        assert_eq!(
            attach_metadata(&once, &metadata),
            Err(ArtifactError::AlreadyAttached)
        );

        // Two sections framed by hand.
        let mut twice = once.clone();
        twice.extend_from_slice(&once[empty_component().len()..]);
        assert_eq!(
            extract_metadata(&twice),
            Err(ArtifactError::DuplicateSection)
        );
    }

    /// The codec is where the vocabulary's bounds hold, so no path — not
    /// attach, not extract — carries a structure past them, and the two
    /// sides refuse the same structures.
    #[test]
    fn metadata_past_a_vocabulary_bound_refuses_on_both_sides() {
        let mut expr = Expr::Arg(0);
        for _ in 0..=MAX_EXPR_DEPTH {
            expr = Expr::Field(Box::new(expr), 0);
        }
        let mut metadata = PackageMetadata::default();
        metadata.methods.insert(
            "m".into(),
            MethodSignature {
                totality: Totality::Fallible,
                effects: vec![Clause::Effect {
                    reach: None,
                    guard: None,
                    target: TargetExpr::Point(expr),
                    mode: ModeExpr::Write { moves: Moves::Both },
                    denomination: None,
                }],
                ..MethodSignature::default()
            },
        );
        assert!(matches!(
            attach_metadata(&empty_component(), &metadata),
            Err(ArtifactError::Bounds(_))
        ));

        // The same structure framed by hand — what a hostile publisher
        // writes — refuses at extract rather than decoding unchecked.
        let payload = to_vec_with_depth(&metadata, METADATA_WIRE_DEPTH)
            .expect("the structure encodes within the wire depth");
        let mut content = Vec::new();
        write_uleb128(METADATA_SECTION.len(), &mut content);
        content.extend_from_slice(METADATA_SECTION.as_bytes());
        content.extend_from_slice(&payload);
        let mut artifact = empty_component();
        artifact.push(CUSTOM_SECTION_ID);
        write_uleb128(content.len(), &mut artifact);
        artifact.extend_from_slice(&content);
        assert!(matches!(
            extract_metadata(&artifact),
            Err(ArtifactError::Bounds(_))
        ));
    }

    #[test]
    fn the_section_is_found_past_other_custom_sections() {
        // A real component carries name and producers sections; the walk
        // has to skip custom sections it does not know, and must not
        // match on a prefix of the name either.
        let metadata = PackageMetadata::default();
        let mut plain = empty_component();
        for name in ["name", "producers", "hyperscale:effect-metadata-x"] {
            let mut content = Vec::new();
            write_uleb128(name.len(), &mut content);
            content.extend_from_slice(name.as_bytes());
            content.extend_from_slice(b"payload");
            plain.push(CUSTOM_SECTION_ID);
            write_uleb128(content.len(), &mut plain);
            plain.extend_from_slice(&content);
        }
        assert_eq!(extract_metadata(&plain).unwrap(), None);

        let artifact = attach_metadata(&plain, &metadata).unwrap();
        assert_eq!(extract_metadata(&artifact).unwrap(), Some(metadata));
    }

    #[test]
    fn malformed_framing_is_refused_rather_than_walked() {
        let artifact = attach_metadata(&empty_component(), &PackageMetadata::default()).unwrap();

        // No preamble at all, and a preamble that is not wasm's.
        assert_eq!(extract_metadata(b""), Err(ArtifactError::NotWasm));
        assert_eq!(
            extract_metadata(&artifact[..4]),
            Err(ArtifactError::NotWasm)
        );
        assert!(extract_metadata(&[0u8; 16]).is_err());

        // A section claiming more bytes than the artifact holds.
        let mut overrun = empty_component();
        overrun.push(1);
        write_uleb128(64, &mut overrun);
        overrun.extend_from_slice(b"short");
        assert_eq!(
            extract_metadata(&overrun),
            Err(ArtifactError::SectionOverrun)
        );

        // A length that never terminates, and one padded past 32 bits.
        let mut truncated = empty_component();
        truncated.extend_from_slice(&[1, 0x80]);
        assert_eq!(extract_metadata(&truncated), Err(ArtifactError::BadLength));
        let mut oversized = empty_component();
        oversized.extend_from_slice(&[1, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00]);
        assert_eq!(extract_metadata(&oversized), Err(ArtifactError::BadLength));

        // A custom section with no room for its own name.
        let mut nameless = empty_component();
        nameless.push(CUSTOM_SECTION_ID);
        write_uleb128(0, &mut nameless);
        assert!(extract_metadata(&nameless).is_err());

        // A name longer than the section that carries it.
        let mut overlong = empty_component();
        let mut content = Vec::new();
        write_uleb128(64, &mut content);
        content.extend_from_slice(b"name");
        overlong.push(CUSTOM_SECTION_ID);
        write_uleb128(content.len(), &mut overlong);
        overlong.extend_from_slice(&content);
        assert_eq!(extract_metadata(&overlong), Err(ArtifactError::NameOverrun));

        // Truncating the payload leaves the framing intact and the
        // metadata undecodable, which is a refusal and not a None.
        let truncated = &artifact[..artifact.len() - 1];
        assert!(extract_metadata(truncated).is_err());
    }
}

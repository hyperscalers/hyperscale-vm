//! The metadata section of a publishable artifact.
//!
//! Effect metadata rides the component as a wasm custom section, so the
//! code and the signatures it declares are one content-addressed artifact
//! and cannot drift apart. This module owns the section's name, its
//! payload codec — canonical HBOR of [`PackageMetadata`] — and the framing
//! walk that finds it. Judging what an artifact may publish is the
//! embedder's policy, layered on top of these.

use hyperscale_hbor::{from_slice, to_vec};

use crate::metadata::PackageMetadata;

/// The custom section effect metadata rides in.
pub const METADATA_SECTION: &str = "hyperscale:effect-metadata";

/// The section id wasm reserves for custom sections.
const CUSTOM_SECTION_ID: u8 = 0;

/// The magic and version word every module and component opens with.
const WASM_MAGIC: [u8; 4] = *b"\0asm";
const PREAMBLE_LEN: usize = 8;

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
    if find_section(artifact)?.is_some() {
        return Err(ArtifactError::AlreadyAttached);
    }
    let payload = to_vec(metadata).map_err(|error| ArtifactError::Payload(error.to_string()))?;

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
    find_section(artifact)?
        .map(|payload| {
            from_slice(payload).map_err(|error| ArtifactError::Payload(error.to_string()))
        })
        .transpose()
}

/// The metadata section's payload, walking the artifact's sections.
///
/// Every step is checked against the bytes that remain, so a truncated
/// length, a section running past the artifact, or a name running past
/// its own section is a refusal rather than a panic.
fn find_section(artifact: &[u8]) -> Result<Option<&[u8]>, ArtifactError> {
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

fn read_uleb128(bytes: &[u8], pos: &mut usize) -> Result<usize, ArtifactError> {
    let mut value = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = *bytes.get(*pos).ok_or(ArtifactError::BadLength)?;
        *pos += 1;
        value |= ((byte & 0x7F) as usize) << shift;
        if byte < 0x80 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 32 {
            return Err(ArtifactError::BadLength);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{attach_metadata, extract_metadata, ArtifactError, METADATA_SECTION};
    use crate::metadata::PackageMetadata;

    fn empty_component() -> Vec<u8> {
        let mut artifact = b"\0asm".to_vec();
        artifact.extend_from_slice(&[0x0D, 0x00, 0x01, 0x00]);
        artifact
    }

    #[test]
    fn metadata_rides_the_artifact_and_comes_back_canonical() {
        let mut metadata = PackageMetadata::default();
        metadata.events.push("transferred".to_owned());

        let published = attach_metadata(&empty_component(), &metadata).unwrap();
        assert_eq!(extract_metadata(&published).unwrap(), Some(metadata));
        assert!(published
            .windows(METADATA_SECTION.len())
            .any(|window| window == METADATA_SECTION.as_bytes()));
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

    #[test]
    fn a_truncated_artifact_refuses_rather_than_panics() {
        assert_eq!(extract_metadata(b"\0as"), Err(ArtifactError::NotWasm));
        let published = attach_metadata(&empty_component(), &PackageMetadata::default()).unwrap();
        let truncated = &published[..published.len() - 1];
        assert!(extract_metadata(truncated).is_err());
    }
}

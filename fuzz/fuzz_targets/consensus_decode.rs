//! The consensus-critical decode surfaces, fuzzed: the package metadata
//! every validator decodes off a published artifact, and the manifest
//! graph a transaction signs. The sibling `hbor_decode` lane proves the
//! canonicity theorem over a synthetic zoo of shapes; this proves it over
//! the two `Hbor`-derived types the network actually hands a validator as
//! bytes, whose recursive clause and expression shapes the zoo does not
//! represent.
//!
//! Two promises per input: every byte string either rejects or decodes to
//! a value that re-encodes to exactly itself, and a metadata that decodes
//! runs the publish check to a verdict rather than a panic. Same promotion
//! policy as the sibling targets: a finding is checked into a unit test
//! before the fix merges.

#![no_main]

use hyperscale_hbor::{from_slice, to_vec};
use hyperscale_vm_effects::{ManifestGraph, PackageMetadata, check_metadata};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(metadata) = from_slice::<PackageMetadata>(data) {
        let re_encoded = to_vec(&metadata).expect("decoded metadata re-encodes");
        assert_eq!(re_encoded, data, "two byte strings for one metadata");
        // The publish gate runs over hostile-reached metadata: it reaches
        // a verdict, never a panic — the decoder having admitted the bytes
        // is no promise the declaration is well formed.
        let _ = check_metadata(&metadata);
    }
    if let Ok(graph) = from_slice::<ManifestGraph>(data) {
        let re_encoded = to_vec(&graph).expect("decoded graph re-encodes");
        assert_eq!(re_encoded, data, "two byte strings for one graph");
    }
});

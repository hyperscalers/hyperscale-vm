//! A signed transaction, built with nothing but this workspace.
//!
//! The claim the client tier exists to make: composing, wrapping and
//! signing need the VM crates, a hash, and a key — and nothing from the
//! protocol workspace. This file is the downstream crate that claim is
//! about, so it supplies its own hasher, signer and verifier and never
//! names blake3 or a curve.
//!
//! The signer below is test-grade in the way [`TestHasher`] is: it fills
//! the widths ed25519 registers with values only this file can reproduce.
//! It is not a signature scheme and proves nothing about one. What it
//! proves is that the seams close — that a key which can answer three
//! questions can sign an envelope, and a verifier that agrees with it can
//! accept the result.

use hyperscale_vm_effects::{
    EnvelopeTree, Hasher, IntentDecl, IntentHeader, PackageHash, Records, TestHasher,
};
use hyperscale_vm_manifest_builder::TypedBuilder;
use hyperscale_vm_manifest_builder::signing::{Terms, sign, wrap, wrap_publish};
use hyperscale_vm_stdlib::account;
use hyperscale_vm_types::{
    AccountSigner, MAX_TX_BYTES_LEN, NetworkId, PrincipalAddr, ResourceAddr, SchemeId,
    SchemeVerifier, TransactionBody, TransactionEnvelope,
};

const ALICE: PrincipalAddr = PrincipalAddr::new([0x10; 31]);
const BOB: PrincipalAddr = PrincipalAddr::new([0x20; 31]);
const RES: ResourceAddr = ResourceAddr::new([0xE1; 31]);
const NETWORK: NetworkId = NetworkId(242);

/// Any window; these tests never validate one against a clock.
const HEADER: IntentHeader = IntentHeader {
    network: NETWORK,
    validity_start_ms: 0,
    validity_end_ms: 3_600_000,
};

/// A key whose signature is a digest anyone holding the same seed can
/// recompute. Test-grade: reproducible, and secret from nobody.
struct TestSigner(u8);

impl TestSigner {
    fn material(&self) -> Vec<u8> {
        TestHasher.hash(b"test-signer/key", &[&[self.0]]).0.to_vec()
    }
}

impl AccountSigner for TestSigner {
    fn scheme(&self) -> SchemeId {
        SchemeId::ED25519
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.material()
    }

    fn sign_digest(&self, digest: &[u8; 32]) -> Vec<u8> {
        expected_signature(&self.material(), digest)
    }
}

/// The verifier that agrees with it, on the same terms.
struct TestVerifier;

impl SchemeVerifier for TestVerifier {
    fn verify(&self, scheme: SchemeId, key: &[u8], signature: &[u8], message: &[u8]) -> bool {
        let Some(spec) = scheme.spec() else {
            return false;
        };
        if !spec.admits(key, signature) {
            return false;
        }
        let Ok(digest) = <&[u8; 32]>::try_from(message) else {
            return false;
        };
        signature == expected_signature(key, digest)
    }
}

/// Two hashed halves, which is how the fixture reaches a signature's
/// registered width without a curve.
fn expected_signature(key: &[u8], digest: &[u8; 32]) -> Vec<u8> {
    let mut signature = TestHasher
        .hash(b"test-signer/lo", &[key, digest])
        .0
        .to_vec();
    signature.extend_from_slice(&TestHasher.hash(b"test-signer/hi", &[key, digest]).0);
    signature
}

fn world() -> Records {
    let package = PackageHash(TestHasher.hash(b"package", &[b"account"]));
    let mut chain = Records::new();
    chain
        .packages
        .publish_unchecked(package, account::metadata());
    chain.instances.serve_principals(package);
    chain
}

const fn terms() -> Terms {
    Terms {
        max_fee: 1_000,
        gas_limit: 1_000_000,
        validity_start_ms: 0,
        validity_end_ms: 60_000,
        message: Vec::new(),
    }
}

/// Compose a transfer, wrap it, sign it, and have the signature accepted
/// — with no crate outside this workspace in the path.
#[test]
fn a_transaction_signs_and_verifies_inside_this_workspace() {
    let chain = world();
    let mut builder = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut builder, ALICE, RES, 100).expect("an account withdraws");
    account::deposit(&mut builder, BOB, funds).expect("an account is paid");
    let graph = builder.build().expect("every output is consumed");

    let tree = EnvelopeTree {
        root: IntentDecl {
            header: HEADER,
            graph,
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    };

    let key = TestSigner(7);
    let envelope = sign(
        wrap(&tree, Vec::new(), ALICE, NETWORK, terms()),
        &key,
        &TestHasher,
    )
    .expect("an envelope within its caps signs");

    assert_eq!(envelope.signer_scheme, SchemeId::ED25519);
    assert!(TestVerifier.verify(
        envelope.signer_scheme,
        &envelope.signer,
        &envelope.signature,
        &envelope.signing_digest(&TestHasher).expect("it encodes"),
    ));
}

/// The signature covers the content and not itself, so re-tagging the
/// scheme or moving a signed field loses it.
#[test]
fn the_signature_covers_what_the_envelope_says() {
    let chain = world();
    let mut builder = TypedBuilder::new(&chain, &TestHasher, ALICE);
    let funds = account::withdraw(&mut builder, ALICE, RES, 100).expect("an account withdraws");
    account::deposit(&mut builder, BOB, funds).expect("an account is paid");
    let tree = EnvelopeTree {
        root: IntentDecl {
            header: HEADER,
            graph: builder.build().expect("every output is consumed"),
            sockets: Vec::new(),
        },
        root_bindings: Vec::new(),
        subintents: Vec::new(),
        instances: Vec::new(),
        resources: Vec::new(),
    };

    let key = TestSigner(7);
    let signed = sign(
        wrap(&tree, Vec::new(), ALICE, NETWORK, terms()),
        &key,
        &TestHasher,
    )
    .expect("an envelope within its caps signs");
    let (material, signature) = (signed.signer.clone(), signed.signature.clone());
    let accepts = |envelope: &TransactionEnvelope| {
        TestVerifier.verify(
            SchemeId::ED25519,
            &material,
            &signature,
            &envelope.signing_digest(&TestHasher).expect("it encodes"),
        )
    };
    assert!(accepts(&signed));

    // The scheme is signed content.
    let mut retagged = signed.clone();
    retagged.signer_scheme = SchemeId::SECP256K1;
    assert!(!accepts(&retagged));

    // So is everything the composer chose.
    let mut repriced = signed.clone();
    repriced.max_fee += 1;
    assert!(!accepts(&repriced));

    let mut retargeted = signed;
    retargeted.network = NetworkId(1);
    assert!(!accepts(&retargeted));
}

/// A signed publish envelope verifies, and its body is signed content.
///
/// The `Publish` half of the signing seam: `wrap_publish` builds the
/// unsigned intent, `sign` fills the scheme, key and signature, and the
/// signature covers the artifact — so altering a byte of the body loses
/// it, exactly as re-tagging the scheme does for a call.
#[test]
fn a_publish_envelope_signs_and_verifies() {
    let key = TestSigner(7);
    let signed = sign(
        wrap_publish(vec![0xAB; 64], ALICE, NETWORK, terms()),
        &key,
        &TestHasher,
    )
    .expect("a publish envelope within its caps signs");

    assert_eq!(signed.signer_scheme, SchemeId::ED25519);
    let accepts = |envelope: &TransactionEnvelope| {
        TestVerifier.verify(
            envelope.signer_scheme,
            &envelope.signer,
            &envelope.signature,
            &envelope.signing_digest(&TestHasher).expect("it encodes"),
        )
    };
    assert!(
        accepts(&signed),
        "the signature covers the envelope it signed"
    );

    // The artifact is signed content: a body flipped after signing no
    // longer verifies.
    let mut tampered = signed;
    let TransactionBody::Publish(bytes) = &mut tampered.body else {
        panic!("wrap_publish builds a publish body");
    };
    bytes[0] ^= 1;
    assert!(
        !accepts(&tampered),
        "a tampered artifact loses the signature"
    );
}

/// A locally built publish body over the wire cap comes back as a refusal
/// from `sign`, not a panic.
///
/// A decoded envelope is bounded — the decoder holds the same cap — so this
/// reaches `sign` only for an envelope a host built in memory, where the
/// artifact outsizes what any envelope can carry. The signer is handed the
/// encode error rather than a signature over bytes it can never submit.
#[test]
fn an_over_cap_publish_body_refuses_to_sign() {
    let key = TestSigner(7);
    let envelope = wrap_publish(vec![0u8; MAX_TX_BYTES_LEN + 1], ALICE, NETWORK, terms());
    assert!(sign(envelope, &key, &TestHasher).is_err());
}

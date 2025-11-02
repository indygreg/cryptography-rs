// Test case for: https://github.com/indygreg/cryptography-rs/issues/XXX
//
// Demonstrates that CertificateChoices corrupts certificates by re-encoding
// them and adding NULL parameters to ECDSA signature algorithms.
//
// This test uses real certificates from the Sigstore ecosystem that triggered
// the bug in production.

use bcder::{decode::Constructed, Mode};
use cryptographic_message_syntax::asn1::{rfc3161::TimeStampResp, rfc5652::*};

/// Test that certificates extracted from CMS SignedData preserve their
/// original DER encoding byte-for-byte.
///
/// Prior to the fix, this test would fail because CertificateChoices::encode_ref()
/// re-encoded the certificate, adding NULL parameters to the ECDSA signature
/// algorithm where there were none in the original.
#[test]
fn test_sigstore_tsa_certificate_preserved() {
    // Load a real Sigstore timestamp response that contains an embedded TSA certificate
    let timestamp_der = include_bytes!("../test_data/sigstore_timestamp.der");

    // Parse the timestamp response
    let tsr = Constructed::decode(timestamp_der.as_ref(), Mode::Der, TimeStampResp::take_from)
        .expect("Failed to parse TimeStampResp");

    let tst_token = tsr.time_stamp_token.expect("No timestamp token");

    assert_eq!(tst_token.content_type, OID_ID_SIGNED_DATA);

    // Decode the SignedData
    let signed_data = tst_token
        .content
        .clone()
        .decode(SignedData::take_from)
        .expect("Failed to decode SignedData");

    // Extract the embedded certificate
    let certs = signed_data
        .certificates
        .as_ref()
        .expect("No certificates in SignedData");

    assert_eq!(certs.len(), 1, "Expected exactly 1 certificate");

    let cert_choice = &certs[0];

    // Re-encode the certificate
    use bcder::encode::Values;
    let mut re_encoded = Vec::new();
    cert_choice
        .encode_ref()
        .write_encoded(Mode::Der, &mut re_encoded)
        .expect("Failed to encode certificate");

    // Load the expected certificate (extracted with OpenSSL, known to be correct)
    let expected_cert = include_bytes!("../test_data/sigstore_tsa_cert.der");

    // The re-encoded certificate MUST be byte-for-byte identical to the original
    assert_eq!(
        re_encoded.len(),
        expected_cert.len(),
        "Certificate size changed during extraction! \
         Original: {} bytes, Re-encoded: {} bytes. \
         This indicates the certificate was re-encoded rather than preserved.",
        expected_cert.len(),
        re_encoded.len()
    );

    assert_eq!(
        &re_encoded[..],
        &expected_cert[..],
        "Certificate bytes differ! The certificate was corrupted during extraction. \
         Check offset 0x20-0x30 for NULL parameters added to signature algorithm."
    );
}

/// Test that the specific corruption (NULL parameter addition) doesn't occur.
///
/// The bug manifests as certificates being 535 bytes instead of 531 bytes
/// due to NULL parameters being added during re-encoding.
/// With the fix, certificates should be exactly 531 bytes.
#[test]
fn test_no_null_parameters_added() {
    let timestamp_der = include_bytes!("../test_data/sigstore_timestamp.der");
    let expected_cert = include_bytes!("../test_data/sigstore_tsa_cert.der");

    let tsr = Constructed::decode(timestamp_der.as_ref(), Mode::Der, TimeStampResp::take_from)
        .expect("Failed to parse TimeStampResp");

    let tst_token = tsr.time_stamp_token.expect("No timestamp token");
    let signed_data = tst_token
        .content
        .clone()
        .decode(SignedData::take_from)
        .expect("Failed to decode SignedData");

    let cert_choice = &signed_data.certificates.as_ref().unwrap()[0];

    use bcder::encode::Values;
    let mut re_encoded = Vec::new();
    cert_choice
        .encode_ref()
        .write_encoded(Mode::Der, &mut re_encoded)
        .expect("Failed to encode");

    // The certificate should be the correct size (no NULL parameters added)
    assert_eq!(
        re_encoded.len(),
        expected_cert.len(),
        "Certificate size should be {} bytes (no NULL parameters added), but got {} bytes",
        expected_cert.len(),
        re_encoded.len()
    );

    // Should be byte-for-byte identical
    assert_eq!(
        &re_encoded[..],
        &expected_cert[..],
        "Certificate bytes should be identical (no corruption during extraction)"
    );
}

/// Verify the certificate parses correctly in the first place
#[test]
fn test_certificate_parses() {
    let cert_der = include_bytes!("../test_data/sigstore_tsa_cert.der");

    // Should parse without error
    use x509_certificate::rfc5280::Certificate;
    Constructed::decode(cert_der.as_ref(), Mode::Der, |cons| {
        cons.take_constructed(|_, inner| Certificate::from_sequence(inner))
    })
    .expect("Certificate should parse correctly");
}

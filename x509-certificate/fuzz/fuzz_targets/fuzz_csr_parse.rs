#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::rfc2986::CertificationRequest;
use bcder::{decode::Constructed, Mode};

fuzz_target!(|data: &[u8]| {
    // Try to parse Certificate Signing Request (CSR)
    let _ = Constructed::decode(data, Mode::Der, |cons| {
        CertificationRequest::take_from(cons)
    });

    // Also try BER mode
    let _ = Constructed::decode(data, Mode::Ber, |cons| {
        CertificationRequest::take_from(cons)
    });
});

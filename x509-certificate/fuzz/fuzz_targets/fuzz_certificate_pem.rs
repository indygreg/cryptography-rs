#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::CapturedX509Certificate;

fuzz_target!(|data: &[u8]| {
    // Try to parse PEM-encoded certificate(s)
    let _ = CapturedX509Certificate::from_pem(data);
    let _ = CapturedX509Certificate::from_pem_multiple(data);
});

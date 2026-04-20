#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::CapturedX509Certificate;

fuzz_target!(|data: &[u8]| {
    // Try to parse the data as a DER-encoded X.509 certificate
    let _ = CapturedX509Certificate::from_der(data.to_vec());
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::rfc3280::Name;
use bcder::{decode::Constructed, Mode};

fuzz_target!(|data: &[u8]| {
    // Try to parse Distinguished Names (used in subject/issuer fields)
    let result = Constructed::decode(data, Mode::Der, |cons| {
        Name::take_from(cons)
    });

    // If parsing succeeded, try to iterate over its contents
    if let Ok(name) = result {
        let _ = name.iter_rdn().count();
        let _ = name.iter_attributes().count();
    }
});

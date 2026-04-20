#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::rfc5280::{Extension, Extensions};
use bcder::{decode::Constructed, Mode};

fuzz_target!(|data: &[u8]| {
    // Try to parse X.509 extensions
    let result = Constructed::decode(data, Mode::Der, |cons| {
        Extension::take_from(cons)
    });

    // Also try parsing as extension sequence
    let _ = Constructed::decode(data, Mode::Der, |cons| {
        Extensions::take_from(cons)
    });

    // If we got an extension, try to access its fields
    if let Ok(ext) = result {
        let _ = &ext.id;
        let _ = &ext.critical;
        let _ = &ext.value;
    }
});

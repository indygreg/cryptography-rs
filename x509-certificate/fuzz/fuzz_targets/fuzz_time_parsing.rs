#![no_main]

use libfuzzer_sys::fuzz_target;
use x509_certificate::asn1time::{GeneralizedTime, GeneralizedTimeAllowedTimezone};
use bcder::decode::SliceSource;

fuzz_target!(|data: &[u8]| {
    // Fuzz GeneralizedTime parsing with various timezone configurations
    let _ = GeneralizedTime::parse(
        SliceSource::new(data),
        false,
        GeneralizedTimeAllowedTimezone::Z,
    );

    let _ = GeneralizedTime::parse(
        SliceSource::new(data),
        true,
        GeneralizedTimeAllowedTimezone::Z,
    );

    let _ = GeneralizedTime::parse(
        SliceSource::new(data),
        false,
        GeneralizedTimeAllowedTimezone::Any,
    );

    let _ = GeneralizedTime::parse(
        SliceSource::new(data),
        true,
        GeneralizedTimeAllowedTimezone::Any,
    );
});

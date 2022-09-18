# x509-certificate

`x509-certificate` is a library crate for interfacing with X.509 certificates.
It supports the following:

* Parsing certificates from BER, DER, and PEM.
* Serializing certificates to BER, DER, and PEM.
* Defining common algorithm identifiers.
* Generating new certificates.
* Verifying signatures on certificates.
* And more.

**This crate has not undergone a security audit. It does not
employ many protections for malformed data when parsing certificates.
Use at your own risk. See additional notes in `src/lib.rs`.**

## Developing

The root of the repository is a Cargo workspace and has a lot of members.
The dependency tree for the entire repo is massive and `cargo build` likely
will fail due to Python dependency weirdness.

For best results, `cd x509-certificate` and run commands there. Or
`cargo build -p x509-certificate`, `cargo test -p x509-certificate`, etc.

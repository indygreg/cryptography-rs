# pgp-cleartext

`pgp-cleartext` is a library crate implementing support for the PGP cleartext
framework (RFC 4880 Section 7) using the `pgp` crate.

As of version 0.13, the `pgp` crate has built-in PGP cleartext framework
support. You should probably use the `pgp` crate directly instead of using
this crate. (This crate predated existence of this feature in the `pgp` crate.)

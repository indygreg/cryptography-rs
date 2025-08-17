# `cryptographic-message-syntax` History

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

* MSRV 1.75 -> 1.85.

## 0.27.0

Released on 2024-11-02.

* MSRV 1.65 -> 1.75.
* The crate now has an `http` feature to control availability of features making
  HTTP requests (notably time-stamp protocol support). Disabling the feature
  removes the dependency on `reqwest`, which slims down the dependency tree
  significantly. (#21)
* `bytes` 1.5 -> 1.8.
* `reqwest` 0.11 -> 0.12.
* `signature` 2.1 -> 2.2.

## 0.26.0

Released on 2023-11-07.

## 0.25.1

Released on 2023-11-05.

* `SignedDataBuilder` now stores a signing time and uses it for all signatures.
  Before, each signer would compute the current time and use that time, possibly
  resulting in signatures having slightly different times. The signing time
  is computed at `SignedDataBuilder` construction time. A `signing_time()`
  method can be used to pass a custom time to use for signing.

## 0.25.0

Released on 2023-11-03.

* `pem` 2.0 -> 3.0.
* `ring` 0.16 -> 0.17.

## 0.24.0

Released on 2023-07-24.

* `TimeStampResponse` is now exported in the public API.
* `TimeStampResponse` now implements `From<TimeStampResp>`.
* New method `SignedDataBuilder::build_signed_data()` has been extracted from
  `SignedDataBuilder::build_der()` and returns a `SignedData` instance,
  allowing access to a Rust struct representation before serialization.
* `SignedAttributes` are now sorted by taking the serialization of the
  entire `Attribute` (OID type + values). The previous implementation only
  encoded the `Attribute`'s `attrValues` field and would not yield correct
  sorting if the `attrType` OID was different. (#16)

## 0.23.0

Released on 2023-06-03.

* pem upgraded 1.1 -> 2.0.
* ``chrono`` compiled without default features (#12).

## 0.22.0

Released on 2023-03-19.

* `SignerBuilder` gained a `new_with_signer_identifier()` that allows constructing
  from a `SignerIdentifier` instead of a `CapturedX509Certificate`. This API allows
  usage in alternate signing scenarios, such as those found in RFC 5272. Contributed
  by Outurnate in #8.
* bytes upgraded 1.3 -> 1.4.
* Minimum Rust version 1.61 -> 1.65.

## 0.21.0

Released on 2023-01-21.

* signature upgraded 1.6 -> 2.0.

## 0.20.0

Released on 2022-12-30.

* bytes upgraded 1.0 -> 1.3.
* pem upgraded 1.0 -> 1.1.
* signature upgraded 1.3 -> 1.6.

## 0.19.0

Released on 2022-12-19.

* Canonical home of project moved to https://github.com/indygreg/cryptography-rs.
* Cargo.toml now defines patch versions of all dependencies.

## 0.18.0

(Released 2022-09-17)

## 0.17.0

(Released 2022-08-07)

* bcder crate upgraded from 0.6.1 to 0.7.0. This entailed a lot of
  changes, mainly to error handling.
* `SignedAttributes` should now be sorted properly. Previous versions
  had a sorting mechanism that was only partially correct and would
  result in incorrect sorting for some inputs. The old behavior could
  have resulted in incorrect signatures being produced or validations
  incorrectly failing. (#614)
* The crate now re-exports some symbols for 3rd party crates
  `bcder::Oid` and `bytes::Bytes`.
* Support for creating *external signatures*, which are signatures
  over external content not stored inline in produced signatures.
  (#614)
* (API change) `SignedDataBuilder::signed_content()` has effectively
  been renamed to `content_inline()`. (#614)

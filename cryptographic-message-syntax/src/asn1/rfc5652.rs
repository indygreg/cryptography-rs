// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! ASN.1 data structures defined by RFC 5652.

The types defined in this module are intended to be extremely low-level
and only to be used for (de)serialization. See types outside the
`asn1` module tree for higher-level functionality.

Some RFC 5652 types are defined in the `x509-certificate` crate, which
this crate relies on for certificate parsing functionality.
*/
use {
    bcder::{
        decode::{Constructed, DecodeError, Source}, encode, encode::{PrimitiveContent, Values}, BitString, Captured, ConstOid, Integer, Mode,
        OctetString,
        Oid,
        Tag,
    },
    std::{
        fmt::{Debug, Formatter},
        io::Write,
        ops::{Deref, DerefMut},
    },
    x509_certificate::{asn1time::*, rfc3280::*, rfc5280::*, rfc5652::*},
};
use crate::asn1::rfc3281::AttributeCertificate;

/// The data content type.
///
/// `id-data` in the specification.
///
/// 1.2.840.113549.1.7.1
pub const OID_ID_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 1]);

/// The signed-data content type.
///
/// 1.2.840.113549.1.7.2
pub const OID_ID_SIGNED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 2]);

/// Enveloped data content type.
///
/// 1.2.840.113549.1.7.3
pub const OID_ENVELOPE_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 3]);

/// Digested-data content type.
///
/// 1.2.840.113549.1.7.5
pub const OID_DIGESTED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 5]);

/// Encrypted-data content type.
///
/// 1.2.840.113549.1.7.6
pub const OID_ENCRYPTED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 7, 6]);

/// Authenticated-data content type.
///
/// 1.2.840.113549.1.9.16.1.2
pub const OID_AUTHENTICATED_DATA: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 16, 1, 2]);

/// Identifies the content-type attribute.
///
/// 1.2.840.113549.1.9.3
pub const OID_CONTENT_TYPE: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 3]);

/// Identifies the message-digest attribute.
///
/// 1.2.840.113549.1.9.4
pub const OID_MESSAGE_DIGEST: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 4]);

/// Identifies the signing-time attribute.
///
/// 1.2.840.113549.1.9.5
pub const OID_SIGNING_TIME: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 5]);

/// Identifies the countersignature attribute.
///
/// 1.2.840.113549.1.9.6
pub const OID_COUNTER_SIGNATURE: ConstOid = Oid(&[42, 134, 72, 134, 247, 13, 1, 9, 6]);

/// RFC 5940 - Revocation information types
/// 1.3.6.1.5.5.7.16
pub const OID_ID_RI: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 16]);

/// id-ri-crl
/// 1.3.6.1.5.5.7.16.1
/// This ID is not used because this format uses the RevocationInfoChoice crl CHOICE when included in CMS
pub const OID_ID_RI_CRL: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 16, 1]);

/// id-ri-ocsp-response
/// 1.3.6.1.5.5.7.16.2
pub const OID_ID_RI_OCSP_RESPONSE: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 16, 2]);

/// id-ri-delta-crl
/// 1.3.6.1.5.5.7.16.3
/// This ID is not used because this format uses the RevocationInfoChoice crl CHOICE when included in CMS
pub const OID_ID_RI_DELTA_CRL: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 16, 3]);

/// id-ri-scvp
/// 1.3.6.1.5.5.7.16.4
pub const OID_ID_RI_SCVP: ConstOid = Oid(&[43, 6, 1, 5, 5, 7, 16, 4]);

/// OCSP response.
///
/// ```ASN.1
///    OCSPResponse ::= SEQUENCE {
///       responseStatus         OCSPResponseStatus,
///       responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
///
///    OCSPResponseStatus ::= ENUMERATED {
///        successful            (0),  --Response has valid confirmations
///        malformedRequest      (1),  --Illegal confirmation request
///        internalError         (2),  --Internal error in issuer
///        tryLater              (3),  --Try again later
///                                    --(4) is not used
///        sigRequired           (5),  --Must sign the request
///        unauthorized          (6)   --Request unauthorized
///    }
///
///    ResponseBytes ::=       SEQUENCE {
///        responseType   OBJECT IDENTIFIER,
///        response       OCTET STRING }
/// ```
#[derive(Clone, Debug)]
pub struct OCSPResponse {
    pub response_status: Integer,
    pub response_bytes: Option<ResponseBytes>,
    pub raw: Captured,
}

impl PartialEq for OCSPResponse {
    fn eq(&self, other: &Self) -> bool {
        self.raw.as_slice() == other.raw.as_slice()
    }
}

impl Eq for OCSPResponse {}

impl OCSPResponse {
    pub fn decode_ber<S: Source>(source: &mut S) -> Result<Self, DecodeError<S::Error>> {
        Constructed::decode(source, Mode::Ber, Self::take_from)
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let mut inner = None;
        let raw = cons.capture(|cons| {
            cons.take_sequence(|cons| {
                let response_status = cons.take_primitive_if(Tag::ENUMERATED, |prim| Integer::from_primitive(prim))?;
                let response_bytes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| ResponseBytes::take_from(cons))?;
                let _ = cons.capture_all()?;
                inner = Some((response_status, response_bytes));
                Ok(())
            })
        })?;

        Ok(Self {
            response_status: inner.as_ref().unwrap().0.clone(),
            response_bytes: inner.unwrap().1,
            raw,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        &self.raw
    }
}

impl Values for OCSPResponse {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponseBytes {
    pub response_type: Oid,
    pub response: OctetString,
}

impl ResponseBytes {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            Ok(Self {
                response_type: Oid::take_from(cons)?,
                response: OctetString::take_from(cons)?,
            })
        })
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(tag, self.encode_values())
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence(self.encode_values())
    }

    fn encode_values(&self) -> impl Values + '_ {
        (self.response_type.encode_ref(), self.response.encode_ref())
    }
}

/// Content info.
///
/// ```ASN.1
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ```
#[derive(Clone, Debug)]
pub struct ContentInfo {
    pub content_type: ContentType,
    pub content: Captured,
}

impl PartialEq for ContentInfo {
    fn eq(&self, other: &Self) -> bool {
        self.content_type == other.content_type
            && self.content.as_slice() == other.content.as_slice()
    }
}

impl Eq for ContentInfo {}

impl ContentInfo {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let content_type = ContentType::take_from(cons)?;
        let content = cons.take_constructed_if(Tag::CTX_0, |cons| cons.capture_all())?;

        Ok(Self {
            content_type,
            content,
        })
    }
}

impl Values for ContentInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        encode::sequence((self.content_type.encode_ref(), &self.content)).encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        encode::sequence((self.content_type.encode_ref(), &self.content))
            .write_encoded(mode, target)
    }
}

/// Represents signed data.
///
/// ASN.1 type specification:
///
/// ```ASN.1
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedData {
    pub version: CmsVersion,
    pub digest_algorithms: DigestAlgorithmIdentifiers,
    pub content_info: EncapsulatedContentInfo,
    pub certificates: Option<CertificateSet>,
    pub crls: Option<RevocationInfoChoices>,
    pub signer_infos: SignerInfos,
}

impl SignedData {
    /// Calculate the version of the SignedData structure according to RFC 5652.
    pub fn calculate_version(&self) -> CmsVersion {
        let certificates_present = self.certificates.as_ref().map_or(false, |c| !c.is_empty());
        let crls_present = self.crls.as_ref().map_or(false, |c| !c.0.is_empty());

        let any_certs_other = self.certificates.as_ref().map_or(false, |certs| {
            certs.iter().any(|c| matches!(c, CertificateChoices::Other(_)))
        });
        let any_crls_other = self.crls.as_ref().map_or(false, |crls| {
            crls.0.iter().any(|c| matches!(c, RevocationInfoChoice::Other(_)))
        });

        if (certificates_present && any_certs_other) || (crls_present && any_crls_other) {
            return CmsVersion::V5;
        }

        let any_v2_attr_certs = self.certificates.as_ref().map_or(false, |certs| {
            certs.iter().any(|c| matches!(c, CertificateChoices::AttributeCertificateV2(_)))
        });

        if certificates_present && any_v2_attr_certs {
            return CmsVersion::V4;
        }

        let any_v1_attr_certs = false; // V1 attribute certificates are not supported/implemented
        let any_signer_info_v3 = self.signer_infos.iter().any(|si| si.version == CmsVersion::V3);
        let encap_content_other_than_id_data = self.content_info.content_type != OID_ID_DATA;

        if (certificates_present && any_v1_attr_certs)
            || any_signer_info_v3
            || encap_content_other_than_id_data
        {
            return CmsVersion::V3;
        }

        CmsVersion::V1
    }

    /// Attempt to decode BER encoded bytes to a parsed data structure.
    pub fn decode_ber(data: &[u8]) -> Result<Self, DecodeError<std::convert::Infallible>> {
        Constructed::decode(data, bcder::Mode::Ber, |cons| Self::decode(cons))
    }

    pub fn decode<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let oid = Oid::take_from(cons)?;

            if oid != OID_ID_SIGNED_DATA {
                return Err(cons.content_err("expected signed data OID"));
            }

            cons.take_constructed_if(Tag::CTX_0, Self::take_from)
        })
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let version = CmsVersion::take_from(cons)?;
            let digest_algorithms = DigestAlgorithmIdentifiers::take_from(cons)?;
            let content_info = EncapsulatedContentInfo::take_from(cons)?;
            let certificates =
                cons.take_opt_constructed_if(Tag::CTX_0, CertificateSet::take_from_implicit)?;
            let crls = cons.take_opt_constructed_if(Tag::CTX_1, RevocationInfoChoices::take_from_implicit)?;
            let signer_infos = SignerInfos::take_from(cons)?;

            Ok(Self {
                version,
                digest_algorithms,
                content_info,
                certificates,
                crls,
                signer_infos,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        let version = self.calculate_version();
        encode::sequence((
            OID_ID_SIGNED_DATA.encode_ref(),
            encode::sequence_as(
                Tag::CTX_0,
                encode::sequence((
                    version.encode(),
                    self.digest_algorithms.encode_ref(),
                    self.content_info.encode_ref(),
                    self.certificates
                        .as_ref()
                        .map(|certs| certs.encode_ref_as(Tag::CTX_0)),
                    self.crls
                        .as_ref()
                        .map(|crls| crls.encode_ref_as(Tag::CTX_1)),
                    self.signer_infos.encode_ref(),
                )),
            ),
        ))
    }
}

/// Digest algorithm identifiers.
///
/// ```ASN.1
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DigestAlgorithmIdentifiers(Vec<DigestAlgorithmIdentifier>);

impl Deref for DigestAlgorithmIdentifiers {
    type Target = Vec<DigestAlgorithmIdentifier>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for DigestAlgorithmIdentifiers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl DigestAlgorithmIdentifiers {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut identifiers = Vec::new();

            while let Some(identifier) = AlgorithmIdentifier::take_opt_from(cons)? {
                identifiers.push(identifier);
            }

            Ok(Self(identifiers))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

pub type DigestAlgorithmIdentifier = AlgorithmIdentifier;

/// Signer infos.
///
/// ```ASN.1
/// SignerInfos ::= SET OF SignerInfo
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignerInfos(Vec<SignerInfo>);

impl Deref for SignerInfos {
    type Target = Vec<SignerInfo>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignerInfos {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignerInfos {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| {
            let mut infos = Vec::new();

            while let Some(info) = SignerInfo::take_opt_from(cons)? {
                infos.push(info);
            }

            Ok(Self(infos))
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

/// Encapsulated content info.
///
/// ```ASN.1
/// EncapsulatedContentInfo ::= SEQUENCE {
///   eContentType ContentType,
///   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulatedContentInfo {
    pub content_type: ContentType,
    pub content: Option<OctetString>,
}

impl Debug for EncapsulatedContentInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("EncapsulatedContentInfo");
        s.field("content_type", &format_args!("{}", self.content_type));
        s.field(
            "content",
            &format_args!(
                "{:?}",
                self.content
                    .as_ref()
                    .map(|x| hex::encode(x.clone().to_bytes().as_ref()))
            ),
        );
        s.finish()
    }
}

impl EncapsulatedContentInfo {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let content_type = ContentType::take_from(cons)?;
            let content =
                cons.take_opt_constructed_if(Tag::CTX_0, |cons| OctetString::take_from(cons))?;

            Ok(Self {
                content_type,
                content,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            self.content_type.encode_ref(),
            self.content
                .as_ref()
                .map(|content| encode::sequence_as(Tag::CTX_0, content.encode_ref())),
        ))
    }
}

/// Per-signer information.
///
/// ```ASN.1
/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct SignerInfo {
    pub version: CmsVersion,
    pub sid: SignerIdentifier,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub signed_attributes: Option<SignedAttributes>,
    pub signature_algorithm: SignatureAlgorithmIdentifier,
    pub signature: SignatureValue,
    pub unsigned_attributes: Option<UnsignedAttributes>,

    /// Raw bytes backing signed attributes data.
    ///
    /// Does not include constructed tag or length bytes.
    pub signed_attributes_data: Option<Vec<u8>>,
}

impl SignerInfo {
    pub fn take_opt_from<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_sequence(|cons| Self::from_sequence(cons))
    }

    pub fn from_sequence<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let version = CmsVersion::take_from(cons)?;
        let sid = SignerIdentifier::take_from(cons)?;
        let digest_algorithm = DigestAlgorithmIdentifier::take_from(cons)?;
        let signed_attributes = cons.take_opt_constructed_if(Tag::CTX_0, |cons| {
            // RFC 5652 Section 5.3: SignedAttributes MUST be DER encoded, even if the
            // rest of the structure is BER encoded. So buffer all data so we can
            // feed into a new decoder.
            let der = cons.capture_all()?;

            // But wait there's more! The raw data constituting the signed
            // attributes is also digested and used for content/signature
            // verification. Because our DER serialization may not roundtrip
            // losslessly, we stash away a copy of these bytes so they may be
            // referenced as part of verification.
            let der_data = der.as_slice().to_vec();

            Ok((
                Constructed::decode(der.as_slice(), bcder::Mode::Der, |cons| {
                    SignedAttributes::take_from_set(cons)
                })
                .map_err(|e| e.convert())?,
                der_data,
            ))
        })?;

        let (signed_attributes, signed_attributes_data) = if let Some((x, y)) = signed_attributes {
            (Some(x), Some(y))
        } else {
            (None, None)
        };

        let signature_algorithm = SignatureAlgorithmIdentifier::take_from(cons)?;
        let signature = SignatureValue::take_from(cons)?;
        let unsigned_attributes = cons
            .take_opt_constructed_if(Tag::CTX_1, |cons| UnsignedAttributes::take_from_set(cons))?;

        Ok(Self {
            version,
            sid,
            digest_algorithm,
            signed_attributes,
            signature_algorithm,
            signature,
            unsigned_attributes,
            signed_attributes_data,
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((
            u8::from(self.version).encode(),
            &self.sid,
            &self.digest_algorithm,
            // Always write signed attributes with DER encoding per RFC 5652.
            self.signed_attributes
                .as_ref()
                .map(|attrs| SignedAttributesDer::new(attrs.clone(), Some(Tag::CTX_0))),
            &self.signature_algorithm,
            self.signature.encode_ref(),
            self.unsigned_attributes
                .as_ref()
                .map(|attrs| attrs.encode_ref_as(Tag::CTX_1)),
        ))
    }

    /// Obtain content representing the signed attributes data to be digested.
    ///
    /// Computing the content to go into the digest calculation is nuanced.
    /// From RFC 5652:
    ///
    ///    The result of the message digest calculation process depends on
    ///    whether the signedAttrs field is present.  When the field is absent,
    ///    the result is just the message digest of the content as described
    ///    above.  When the field is present, however, the result is the message
    ///    digest of the complete DER encoding of the SignedAttrs value
    ///    contained in the signedAttrs field.  Since the SignedAttrs value,
    ///    when present, must contain the content-type and the message-digest
    ///    attributes, those values are indirectly included in the result.  The
    ///    content-type attribute MUST NOT be included in a countersignature
    ///    unsigned attribute as defined in Section 11.4.  A separate encoding
    ///    of the signedAttrs field is performed for message digest calculation.
    ///    The `IMPLICIT [0]` tag in the signedAttrs is not used for the DER
    ///    encoding, rather an EXPLICIT SET OF tag is used.  That is, the DER
    ///    encoding of the EXPLICIT SET OF tag, rather than of the `IMPLICIT [0]`
    ///    tag, MUST be included in the message digest calculation along with
    ///    the length and content octets of the SignedAttributes value.
    ///
    /// A few things to note here:
    ///
    /// * We must ensure DER (not BER) encoding of the entire SignedAttrs values.
    /// * The SignedAttr tag must use `EXPLICIT SET OF` instead of `IMPLICIT [0]`,
    ///   so default encoding is not appropriate.
    /// * If this instance came into existence via a parse, we stashed away the
    ///   raw bytes constituting SignedAttributes to ensure we can do a lossless
    ///   copy.
    pub fn signed_attributes_digested_content(&self) -> Result<Option<Vec<u8>>, std::io::Error> {
        if let Some(signed_attributes) = &self.signed_attributes {
            if let Some(existing_data) = &self.signed_attributes_data {
                // +8 should be enough for tag + length.
                let mut buffer = Vec::with_capacity(existing_data.len() + 8);
                // EXPLICIT SET OF.
                buffer.write_all(&[0x31])?;

                // Length isn't exported by bcder :/ So do length encoding manually.
                if existing_data.len() < 0x80 {
                    buffer.write_all(&[existing_data.len() as u8])?;
                } else if existing_data.len() < 0x100 {
                    buffer.write_all(&[0x81, existing_data.len() as u8])?;
                } else if existing_data.len() < 0x10000 {
                    buffer.write_all(&[
                        0x82,
                        (existing_data.len() >> 8) as u8,
                        existing_data.len() as u8,
                    ])?;
                } else if existing_data.len() < 0x1000000 {
                    buffer.write_all(&[
                        0x83,
                        (existing_data.len() >> 16) as u8,
                        (existing_data.len() >> 8) as u8,
                        existing_data.len() as u8,
                    ])?;
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "signed attributes length too long",
                    ));
                }

                buffer.write_all(existing_data)?;

                Ok(Some(buffer))
            } else {
                // No existing copy present. Serialize from raw data structures.
                // But we obtain a sorted instance of those attributes first, because
                // bcder doesn't appear to follow DER encoding rules for sets.
                let signed_attributes = signed_attributes.as_sorted()?;
                let mut der = Vec::new();
                // The mode argument here is actually ignored.
                signed_attributes.write_encoded(Mode::Der, &mut der)?;

                Ok(Some(der))
            }
        } else {
            Ok(None)
        }
    }
}

impl Debug for SignerInfo {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("SignerInfo");

        s.field("version", &self.version);
        s.field("sid", &self.sid);
        s.field("digest_algorithm", &self.digest_algorithm);
        s.field("signed_attributes", &self.signed_attributes);
        s.field("signature_algorithm", &self.signature_algorithm);
        s.field("signature", &format_args!("{}", hex::encode(self.signature.clone().into_bytes().as_ref())));
        s.field("unsigned_attributes", &self.unsigned_attributes);
        s.field("signed_attributes_data", &format_args!("{:?}", self.signed_attributes_data.as_ref().map(hex::encode)));
        s.finish()
    }
}

impl Values for SignerInfo {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Identifies the signer.
///
/// ```ASN.1
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SignerIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

impl SignerIdentifier {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        if let Some(identifier) =
            cons.take_opt_constructed_if(Tag::CTX_0, |cons| SubjectKeyIdentifier::take_from(cons))?
        {
            Ok(Self::SubjectKeyIdentifier(identifier))
        } else {
            Ok(Self::IssuerAndSerialNumber(
                IssuerAndSerialNumber::take_from(cons)?,
            ))
        }
    }
}

impl Values for SignerIdentifier {
    fn encoded_len(&self, mode: Mode) -> usize {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().encoded_len(mode),
            Self::SubjectKeyIdentifier(v) => v.encode_ref_as(Tag::CTX_0).encoded_len(mode),
        }
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        match self {
            Self::IssuerAndSerialNumber(v) => v.encode_ref().write_encoded(mode, target),
            Self::SubjectKeyIdentifier(v) => {
                v.encode_ref_as(Tag::CTX_0).write_encoded(mode, target)
            }
        }
    }
}

/// Signed attributes.
///
/// ```ASN.1
/// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SignedAttributes(Vec<Attribute>);

impl Deref for SignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl SignedAttributes {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| Self::take_from_set(cons))
    }

    pub fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    /// Obtain an instance where the attributes are sorted according to DER
    /// rules. See the comment in [SignerInfo::signed_attributes_digested_content].
    pub fn as_sorted(&self) -> Result<Self, std::io::Error> {
        // Sorted is based on encoding of each Attribute, per DER encoding rules.
        // The encoding is supported to be padded with 0s. But Rust will sort a
        // shorter value with a prefix match against a longer value as less than,
        // so we can avoid the padding.

        let mut attributes = self
            .0
            .iter()
            .map(|x| {
                let mut encoded = vec![];
                // See (https://github.com/indygreg/cryptography-rs/issues/16)
                // The entire attribute must be encoded in order to be compared
                // to a sibling attribute
                x.encode_ref().write_encoded(Mode::Der, &mut encoded)?;

                Ok((encoded, x.clone()))
            })
            .collect::<Result<Vec<(_, _)>, std::io::Error>>()?;

        attributes.sort_by(|(a, _), (b, _)| a.cmp(b));

        Ok(Self(
            attributes.into_iter().map(|(_, x)| x).collect::<Vec<_>>(),
        ))
    }

    fn encode_ref(&self) -> impl Values + '_ {
        encode::set(encode::slice(&self.0, |x| x.clone().encode()))
    }

    fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

impl Values for SignedAttributes {
    // SignedAttributes are always written as DER encoded.
    fn encoded_len(&self, _: Mode) -> usize {
        self.encode_ref().encoded_len(Mode::Der)
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(Mode::Der, target)
    }
}

pub struct SignedAttributesDer(SignedAttributes, Option<Tag>);

impl SignedAttributesDer {
    pub fn new(sa: SignedAttributes, tag: Option<Tag>) -> Self {
        Self(sa, tag)
    }
}

impl Values for SignedAttributesDer {
    fn encoded_len(&self, _: Mode) -> usize {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).encoded_len(Mode::Der)
        } else {
            self.0.encode_ref().encoded_len(Mode::Der)
        }
    }

    fn write_encoded<W: Write>(&self, _: Mode, target: &mut W) -> Result<(), std::io::Error> {
        if let Some(tag) = &self.1 {
            self.0.encode_ref_as(*tag).write_encoded(Mode::Der, target)
        } else {
            self.0.encode_ref().write_encoded(Mode::Der, target)
        }
    }
}

/// Unsigned attributes.
///
/// ```ASN.1
/// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UnsignedAttributes(Vec<Attribute>);

impl Deref for UnsignedAttributes {
    type Target = Vec<Attribute>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for UnsignedAttributes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl UnsignedAttributes {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(|cons| Self::take_from_set(cons))
    }

    pub fn take_from_set<S: Source>(
        cons: &mut Constructed<S>,
    ) -> Result<Self, DecodeError<S::Error>> {
        let mut attributes = Vec::new();

        while let Some(attribute) = Attribute::take_opt_from(cons)? {
            attributes.push(attribute);
        }

        Ok(Self(attributes))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, encode::slice(&self.0, |x| x.clone().encode()))
    }
}

pub type SignatureValue = OctetString;

/// Enveloped-data content type.
///
/// ```ASN.1
/// EnvelopedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvelopedData {
    pub version: CmsVersion,
    pub originator_info: Option<OriginatorInfo>,
    pub recipient_infos: RecipientInfos,
    pub encrypted_content_info: EncryptedContentInfo,
    pub unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Originator info.
///
/// ```ASN.1
/// OriginatorInfo ::= SEQUENCE {
///   certs [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginatorInfo {
    pub certs: Option<CertificateSet>,
    pub crls: Option<RevocationInfoChoices>,
}

pub type RecipientInfos = Vec<RecipientInfo>;

/// Encrypted content info.
///
/// ```ASN.1
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
///   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedContentInfo {
    pub content_type: ContentType,
    pub content_encryption_algorithms: ContentEncryptionAlgorithmIdentifier,
    pub encrypted_content: Option<EncryptedContent>,
}

pub type EncryptedContent = OctetString;

pub type UnprotectedAttributes = Vec<Attribute>;

/// Recipient info.
///
/// ```ASN.1
/// RecipientInfo ::= CHOICE {
///   ktri KeyTransRecipientInfo,
///   kari [1] KeyAgreeRecipientInfo,
///   kekri [2] KEKRecipientInfo,
///   pwri [3] PasswordRecipientinfo,
///   ori [4] OtherRecipientInfo }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientInfo {
    KeyTransRecipientInfo(KeyTransRecipientInfo),
    KeyAgreeRecipientInfo(KeyAgreeRecipientInfo),
    KekRecipientInfo(KekRecipientInfo),
    PasswordRecipientInfo(PasswordRecipientInfo),
    OtherRecipientInfo(OtherRecipientInfo),
}

pub type EncryptedKey = OctetString;

/// Key trans recipient info.
///
/// ```ASN.1
/// KeyTransRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 0 or 2
///   rid RecipientIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyTransRecipientInfo {
    pub version: CmsVersion,
    pub rid: RecipientIdentifier,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

/// Recipient identifier.
///
/// ```ASN.1
/// RecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
}

/// Key agreement recipient info.
///
/// ```ASN.1
/// KeyAgreeRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 3
///   originator [0] EXPLICIT OriginatorIdentifierOrKey,
///   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   recipientEncryptedKeys RecipientEncryptedKeys }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyAgreeRecipientInfo {
    pub version: CmsVersion,
    pub originator: OriginatorIdentifierOrKey,
    pub ukm: Option<UserKeyingMaterial>,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub recipient_encrypted_keys: RecipientEncryptedKeys,
}

/// Originator identifier or key.
///
/// ```ASN.1
/// OriginatorIdentifierOrKey ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier,
///   originatorKey [1] OriginatorPublicKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OriginatorIdentifierOrKey {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    SubjectKeyIdentifier(SubjectKeyIdentifier),
    OriginatorKey(OriginatorPublicKey),
}

/// Originator public key.
///
/// ```ASN.1
/// OriginatorPublicKey ::= SEQUENCE {
///   algorithm AlgorithmIdentifier,
///   publicKey BIT STRING }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginatorPublicKey {
    pub algorithm: AlgorithmIdentifier,
    pub public_key: BitString,
}

/// SEQUENCE of RecipientEncryptedKey.
type RecipientEncryptedKeys = Vec<RecipientEncryptedKey>;

/// Recipient encrypted key.
///
/// ```ASN.1
/// RecipientEncryptedKey ::= SEQUENCE {
///   rid KeyAgreeRecipientIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientEncryptedKey {
    pub rid: KeyAgreeRecipientInfo,
    pub encrypted_key: EncryptedKey,
}

/// Key agreement recipient identifier.
///
/// ```ASN.1
/// KeyAgreeRecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   rKeyId [0] IMPLICIT RecipientKeyIdentifier }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyAgreeRecipientIdentifier {
    IssuerAndSerialNumber(IssuerAndSerialNumber),
    RKeyId(RecipientKeyIdentifier),
}

/// Recipient key identifier.
///
/// ```ASN.1
/// RecipientKeyIdentifier ::= SEQUENCE {
///   subjectKeyIdentifier SubjectKeyIdentifier,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecipientKeyIdentifier {
    pub subject_key_identifier: SubjectKeyIdentifier,
    pub date: Option<GeneralizedTime>,
    pub other: Option<OtherKeyAttribute>,
}

type SubjectKeyIdentifier = OctetString;

/// Key encryption key recipient info.
///
/// ```ASN.1
/// KEKRecipientInfo ::= SEQUENCE {
///   version CMSVersion,  -- always set to 4
///   kekid KEKIdentifier,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KekRecipientInfo {
    pub version: CmsVersion,
    pub kek_id: KekIdentifier,
    pub kek_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

/// Key encryption key identifier.
///
/// ```ASN.1
/// KEKIdentifier ::= SEQUENCE {
///   keyIdentifier OCTET STRING,
///   date GeneralizedTime OPTIONAL,
///   other OtherKeyAttribute OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KekIdentifier {
    pub key_identifier: OctetString,
    pub date: Option<GeneralizedTime>,
    pub other: Option<OtherKeyAttribute>,
}

/// Password recipient info.
///
/// ```ASN.1
/// PasswordRecipientInfo ::= SEQUENCE {
///   version CMSVersion,   -- Always set to 0
///   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
///                                OPTIONAL,
///   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
///   encryptedKey EncryptedKey }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordRecipientInfo {
    pub version: CmsVersion,
    pub key_derivation_algorithm: Option<KeyDerivationAlgorithmIdentifier>,
    pub key_encryption_algorithm: KeyEncryptionAlgorithmIdentifier,
    pub encrypted_key: EncryptedKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherRecipientInfo {
    pub ori_type: Oid,
    // TODO Any
    pub ori_value: Option<()>,
}

/// Digested data.
///
/// ```ASN.1
/// DigestedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   digest Digest }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestedData {
    pub version: CmsVersion,
    pub digest_algorithm: DigestAlgorithmIdentifier,
    pub content_type: EncapsulatedContentInfo,
    pub digest: Digest,
}

pub type Digest = OctetString;

/// Encrypted data.
///
/// ```ASN.1
/// EncryptedData ::= SEQUENCE {
///   version CMSVersion,
///   encryptedContentInfo EncryptedContentInfo,
///   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedData {
    pub version: CmsVersion,
    pub encrypted_content_info: EncryptedContentInfo,
    pub unprotected_attributes: Option<UnprotectedAttributes>,
}

/// Authenticated data.
///
/// ```ASN.1
/// AuthenticatedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   macAlgorithm MessageAuthenticationCodeAlgorithm,
///   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
///   encapContentInfo EncapsulatedContentInfo,
///   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
///   mac MessageAuthenticationCode,
///   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedData {
    pub version: CmsVersion,
    pub originator_info: Option<OriginatorInfo>,
    pub recipient_infos: RecipientInfos,
    pub mac_algorithm: MessageAuthenticationCodeAlgorithm,
    pub digest_algorithm: Option<DigestAlgorithmIdentifier>,
    pub content_info: EncapsulatedContentInfo,
    pub authenticated_attributes: Option<AuthAttributes>,
    pub mac: MessageAuthenticationCode,
    pub unauthenticated_attributes: Option<UnauthAttributes>,
}

pub type AuthAttributes = Vec<Attribute>;

pub type UnauthAttributes = Vec<Attribute>;

pub type MessageAuthenticationCode = OctetString;

pub type SignatureAlgorithmIdentifier = AlgorithmIdentifier;

pub type KeyEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub type ContentEncryptionAlgorithmIdentifier = AlgorithmIdentifier;

pub type MessageAuthenticationCodeAlgorithm = AlgorithmIdentifier;

pub type KeyDerivationAlgorithmIdentifier = AlgorithmIdentifier;

/// Revocation info choices.
///
/// ```ASN.1
///  RevocationInfoChoices ::= SET OF RevocationInfoChoice
/// ```
#[derive(Clone, Debug, Default)]
pub struct RevocationInfoChoices(pub Vec<RevocationInfoChoice>);

impl PartialEq for RevocationInfoChoices {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for RevocationInfoChoices {}

impl RevocationInfoChoices {
    pub fn push(&mut self, choice: RevocationInfoChoice) {
        self.0.push(choice);
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(Self::take_content_from)
    }

    pub fn take_from_implicit<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Self::take_content_from(cons)
    }

    fn take_content_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let mut choices = Vec::new();

        while let Some(choice) = RevocationInfoChoice::take_opt_from(cons)? {
            choices.push(choice);
        }

        Ok(Self(choices))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, &self.0)
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

impl Values for RevocationInfoChoices {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

#[derive(Clone, Debug)]
pub enum RevocationInfoChoice {
    Crl(Captured),
    Other(OtherRevocationInfoFormat),
}

impl PartialEq for RevocationInfoChoice {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Crl(s), Self::Crl(o)) => s.as_slice() == o.as_slice(),
            (Self::Other(s), Self::Other(o)) => s == o,
            _ => false,
        }
    }
}

impl Eq for RevocationInfoChoice {}

impl RevocationInfoChoice {
    pub fn crl(captured: Captured) -> Self {
        Self::Crl(captured)
    }

    pub fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>> {
        if let Some(other) = cons.take_opt_constructed_if(Tag::CTX_1, OtherRevocationInfoFormat::take_from_content)? {
            Ok(Some(Self::Other(other)))
        } else if let Some(crl) = cons.take_opt_sequence(|cons| cons.capture_all())? {
            Ok(Some(Self::Crl(crl)))
        } else {
            Ok(None)
        }
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Crl(crl) => Choice2::One(encode::sequence(crl.clone())),
            Self::Other(other) => Choice2::Two(other.encode_ref_as(Tag::CTX_1)),
        }
    }
}

enum Choice2<O, T> {
    One(O),
    Two(T),
}

impl<O: Values, T: Values> Values for Choice2<O, T> {
    fn encoded_len(&self, mode: Mode) -> usize {
        match self {
            Self::One(v) => v.encoded_len(mode),
            Self::Two(v) => v.encoded_len(mode),
        }
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        match self {
            Self::One(v) => v.write_encoded(mode, target),
            Self::Two(v) => v.write_encoded(mode, target),
        }
    }
}

impl Values for RevocationInfoChoice {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Other revocation info format.
///
/// ```ASN.1
/// OtherRevocationInfoFormat ::= SEQUENCE {
///   otherRevInfoFormat OBJECT IDENTIFIER,
///   otherRevInfo ANY DEFINED BY otherRevInfoFormat }
/// ```
#[derive(Clone, Debug)]
pub enum OtherRevocationInfoFormat {
    RiOcspResponse(OCSPResponse),
    Other(Oid, Captured),
}

impl PartialEq for OtherRevocationInfoFormat {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::RiOcspResponse(s), Self::RiOcspResponse(o)) => s == o,
            (Self::Other(s_oid, s_cap), Self::Other(o_oid, o_cap)) => s_oid == o_oid && s_cap.as_slice() == o_cap.as_slice(),
            _ => false,
        }
    }
}

impl Eq for OtherRevocationInfoFormat {}

impl OtherRevocationInfoFormat {
    pub fn from_sequence<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(Self::take_from_content)
    }

    pub fn take_from_content<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let other_rev_info_format = Oid::take_from(cons)?;

        match other_rev_info_format {
            v if v == OID_ID_RI_OCSP_RESPONSE => {
                let ocsp = OCSPResponse::take_from(cons)?;
                Ok(Self::RiOcspResponse(ocsp))
            }
            _ => {
                let other_rev_info = cons.capture_all()?;
                Ok(Self::Other(other_rev_info_format, other_rev_info))
            }
        }
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::sequence_as(tag, self.encode_values())
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence(self.encode_values())
    }

    fn encode_values(&self) -> impl Values + '_ {
        match self {
            Self::RiOcspResponse(ocsp) => Choice2::One((OID_ID_RI_OCSP_RESPONSE.encode_ref(), ocsp.encode_ref())),
            Self::Other(oid, captured) => Choice2::Two((oid.encode_ref(), captured)),
        }
    }
}

impl Values for OtherRevocationInfoFormat {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Certificate choices.
///
/// ```ASN.1
/// CertificateChoices ::= CHOICE {
///   certificate Certificate,
///   extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
///   v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
///   v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///   other [3] IMPLICIT OtherCertificateFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateChoices {
    Certificate(Box<Certificate>),
    // ExtendedCertificate(ExtendedCertificate),
    // AttributeCertificateV1(AttributeCertificateV1),
    AttributeCertificateV2(Box<AttributeCertificateV2>),
    Other(Box<OtherCertificateFormat>),
}

impl CertificateChoices {
    pub fn take_opt_from<S: Source>(cons: &mut Constructed<S>) -> Result<Option<Self>, DecodeError<S::Error>> {
        cons.take_opt_constructed_if(Tag::CTX_0, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("ExtendedCertificate parsing not implemented"))
        })?;
        cons.take_opt_constructed_if(Tag::CTX_1, |cons| -> Result<(), DecodeError<S::Error>> {
            Err(cons.content_err("AttributeCertificateV1 parsing not implemented"))
        })?;

        // TODO these first 2 need methods that parse an already entered SEQUENCE.
        if let Some(certificate) = cons.take_opt_constructed_if(Tag::CTX_2, |cons| AttributeCertificateV2::take_from(cons))? {
            Ok(Some(Self::AttributeCertificateV2(Box::new(certificate))))
        } else if let Some(certificate) = cons.take_opt_constructed_if(Tag::CTX_3, |cons| OtherCertificateFormat::take_from(cons))? {
            Ok(Some(Self::Other(Box::new(certificate))))
        } else if let Some(certificate) = cons.take_opt_constructed(|_, cons| Certificate::from_sequence(cons))? {
            Ok(Some(Self::Certificate(Box::new(certificate))))
        } else {
            Ok(None)
        }
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        match self {
            Self::Certificate(cert) => Choice2::One(cert.encode_ref()),
            Self::AttributeCertificateV2(_) => Choice2::Two(OID_ID_DATA.encode_ref()),
            Self::Other(_) => Choice2::Two(OID_ID_DATA.encode_ref()),
        }
    }
}

impl CertificateChoices {
    pub fn certificate(cert: Certificate) -> Self {
        Self::Certificate(Box::new(cert))
    }
}

impl Values for CertificateChoices {
    fn encoded_len(&self, mode: Mode) -> usize {
        self.encode_ref().encoded_len(mode)
    }

    fn write_encoded<W: Write>(&self, mode: Mode, target: &mut W) -> Result<(), std::io::Error> {
        self.encode_ref().write_encoded(mode, target)
    }
}

/// Other certificate format.
///
/// ```ASN.1
/// OtherCertificateFormat ::= SEQUENCE {
///   otherCertFormat OBJECT IDENTIFIER,
///   otherCert ANY DEFINED BY otherCertFormat }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherCertificateFormat {
    pub other_cert_format: Oid,
    // TODO Any
    pub other_cert: Option<()>,
}

impl OtherCertificateFormat {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Err(cons.content_err("OtherCertificateFormat parsing not implemented"))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CertificateSet(Vec<CertificateChoices>);

impl Deref for CertificateSet {
    type Target = Vec<CertificateChoices>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for CertificateSet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl CertificateSet {
    pub fn push(&mut self, choice: CertificateChoices) {
        self.0.push(choice);
    }

    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_set(Self::take_content_from)
    }

    pub fn take_from_implicit<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        Self::take_content_from(cons)
    }

    fn take_content_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        let mut certs = Vec::new();

        while let Some(cert) = CertificateChoices::take_opt_from(cons)? {
            certs.push(cert);
        }

        Ok(Self(certs))
    }

    pub fn encode_ref_as(&self, tag: Tag) -> impl Values + '_ {
        encode::set_as(tag, &self.0)
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::set(&self.0)
    }
}

/// Issuer and serial number.
///
/// ```ASN.1
/// IssuerAndSerialNumber ::= SEQUENCE {
///   issuer Name,
///   serialNumber CertificateSerialNumber }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAndSerialNumber {
    pub issuer: Name,
    pub serial_number: CertificateSerialNumber,
}

impl IssuerAndSerialNumber {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        cons.take_sequence(|cons| {
            let issuer = Name::take_from(cons)?;
            let serial_number = Integer::take_from(cons)?;

            Ok(Self {
                issuer,
                serial_number,
            })
        })
    }

    pub fn encode_ref(&self) -> impl Values + '_ {
        encode::sequence((self.issuer.encode_ref(), (&self.serial_number).encode()))
    }
}

pub type CertificateSerialNumber = Integer;

/// Version number.
///
/// ```ASN.1
/// CMSVersion ::= INTEGER
///                { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CmsVersion {
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    V4 = 4,
    V5 = 5,
}

impl CmsVersion {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        match cons.take_primitive_if(Tag::INTEGER, Integer::i8_from_primitive)? {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            3 => Ok(Self::V3),
            4 => Ok(Self::V4),
            5 => Ok(Self::V5),
            _ => Err(cons.content_err("unexpected CMSVersion")),
        }
    }

    pub fn encode(self) -> impl Values {
        u8::from(self).encode()
    }
}

impl From<CmsVersion> for u8 {
    fn from(v: CmsVersion) -> u8 {
        match v {
            CmsVersion::V0 => 0,
            CmsVersion::V1 => 1,
            CmsVersion::V2 => 2,
            CmsVersion::V3 => 3,
            CmsVersion::V4 => 4,
            CmsVersion::V5 => 5,
        }
    }
}

impl From<u8> for CmsVersion {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::V0,
            1 => Self::V1,
            2 => Self::V2,
            3 => Self::V3,
            4 => Self::V4,
            5 => Self::V5,
            _ => Self::V0,
        }
    }
}

pub type UserKeyingMaterial = OctetString;

/// Other key attribute.
///
/// ```ASN.1
/// OtherKeyAttribute ::= SEQUENCE {
///   keyAttrId OBJECT IDENTIFIER,
///   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OtherKeyAttribute {
    pub key_attribute_id: Oid,
    // TODO Any
    pub key_attribute: Option<()>,
}

pub type ContentType = Oid;

pub type MessageDigest = OctetString;

pub type SigningTime = Time;

/// Time variant.
///
/// ```ASN.1
/// Time ::= CHOICE {
///   utcTime UTCTime,
///   generalizedTime GeneralizedTime }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Time {
    UtcTime(UtcTime),
    GeneralizedTime(GeneralizedTime),
}

impl Time {
    pub fn take_from<S: Source>(cons: &mut Constructed<S>) -> Result<Self, DecodeError<S::Error>> {
        if let Some(utc) =
            cons.take_opt_primitive_if(Tag::UTC_TIME, |prim| UtcTime::from_primitive(prim))?
        {
            Ok(Self::UtcTime(utc))
        } else if let Some(generalized) = cons
            .take_opt_primitive_if(Tag::GENERALIZED_TIME, |prim| {
                GeneralizedTime::from_primitive_no_fractional_or_timezone_offsets(prim)
            })?
        {
            Ok(Self::GeneralizedTime(generalized))
        } else {
            Err(cons.content_err("invalid Time value"))
        }
    }
}

impl From<Time> for chrono::DateTime<chrono::Utc> {
    fn from(t: Time) -> Self {
        match t {
            Time::UtcTime(utc) => *utc,
            Time::GeneralizedTime(gt) => gt.into(),
        }
    }
}

pub type CounterSignature = SignerInfo;

pub type AttributeCertificateV2 = AttributeCertificate;

#[cfg(test)]
mod tests {
    use super::{OtherRevocationInfoFormat, RevocationInfoChoice, SignedData};
    use bcder::encode::Values;

    #[test]
    fn test_rfc5940() {
        // Test data from russhousley/pyasn1-alt-modules
        // Only suitable for syntax testing
        let pem_content = std::fs::read_to_string("src/testdata/rfc5940.p7s").unwrap();
        let p = pem::parse(pem_content).unwrap();
        let encoded = p.contents();

        let signed_data = SignedData::decode_ber(encoded).unwrap();
        //println!("{:#?}", signed_data);

        let revocation_info = signed_data.crls.unwrap();
        let mut found_crl = false;
        let mut found_ocsp = false;

        for choice in revocation_info.0.iter() {
            match choice {
                RevocationInfoChoice::Crl(crl_encoded) => {
                    found_crl = true;
                    assert!(!crl_encoded.as_slice().is_empty());
                }
                RevocationInfoChoice::Other(OtherRevocationInfoFormat::RiOcspResponse(ocsp_resp)) => {
                    found_ocsp = true;
                    let mut encoded_ocsp = Vec::new();
                    Values::write_encoded(&ocsp_resp.encode_ref(), bcder::Mode::Ber, &mut encoded_ocsp).unwrap();
                    assert!(!encoded_ocsp.is_empty());
                }
                _ => {}
            }
        }

        assert!(found_crl);
        assert!(found_ocsp);
    }
}

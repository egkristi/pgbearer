//! `tls-server-end-point` channel binding (RFC 5929 §4).
//!
//! The binding data is a hash of the server's leaf certificate. The hash
//! function is the one used in the certificate's `signatureAlgorithm`, except
//! that MD5 and SHA-1 are replaced by SHA-256 (RFC 5929 §4.1). This matches
//! PostgreSQL's `be_tls_get_certificate_hash`, which is what the server side
//! of `SCRAM-SHA-256-PLUS` computes.

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x509_parser::certificate::X509CertificateParser;
use x509_parser::nom::Parser;
use x509_parser::oid_registry::Oid;
use x509_parser::signature_algorithm::RsaSsaPssParams;
use x509_parser::x509::AlgorithmIdentifier;

/// Hash function selected for the channel binding data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EndPointHash {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl EndPointHash {
    /// Hash `data` with this function.
    pub(crate) fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            EndPointHash::Sha224 => Sha224::digest(data).to_vec(),
            EndPointHash::Sha256 => Sha256::digest(data).to_vec(),
            EndPointHash::Sha384 => Sha384::digest(data).to_vec(),
            EndPointHash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// Hash function for `cert_der`'s channel binding; SHA-256 when the
/// certificate cannot be parsed or its algorithm is unknown.
pub(crate) fn end_point_hash(cert_der: &[u8]) -> EndPointHash {
    // Extensions are not needed here; skipping their deep parse makes this
    // tolerant of certificates with unusual or malformed extension contents.
    let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
    match parser.parse(cert_der) {
        Ok((_, cert)) => hash_for_signature_algorithm(&cert.signature_algorithm),
        Err(_) => EndPointHash::Sha256,
    }
}

/// Map a certificate signature algorithm to the channel binding hash.
fn hash_for_signature_algorithm(alg: &AlgorithmIdentifier<'_>) -> EndPointHash {
    let Some(arcs) = oid_arcs(&alg.algorithm) else {
        return EndPointHash::Sha256;
    };
    match arcs.as_slice() {
        // PKCS#1 v1.5: md5WithRSAEncryption (4), sha1WithRSAEncryption (5),
        // sha256WithRSAEncryption (11).
        [1, 2, 840, 113549, 1, 1, 4 | 5 | 11] => EndPointHash::Sha256,
        [1, 2, 840, 113549, 1, 1, 12] => EndPointHash::Sha384,
        [1, 2, 840, 113549, 1, 1, 13] => EndPointHash::Sha512,
        [1, 2, 840, 113549, 1, 1, 14] => EndPointHash::Sha224,
        // RSASSA-PSS: the hash is in the parameters.
        [1, 2, 840, 113549, 1, 1, 10] => pss_hash(alg),
        // ECDSA: ecdsa-with-SHA1, ecdsa-with-SHA224/256/384/512.
        [1, 2, 840, 10045, 4, 1] => EndPointHash::Sha256,
        [1, 2, 840, 10045, 4, 3, 1] => EndPointHash::Sha224,
        [1, 2, 840, 10045, 4, 3, 2] => EndPointHash::Sha256,
        [1, 2, 840, 10045, 4, 3, 3] => EndPointHash::Sha384,
        [1, 2, 840, 10045, 4, 3, 4] => EndPointHash::Sha512,
        // DSA: dsa-with-sha1, dsa-with-sha224, dsa-with-sha256.
        [1, 2, 840, 10040, 4, 3] => EndPointHash::Sha256,
        [2, 16, 840, 1, 101, 3, 4, 3, 1] => EndPointHash::Sha224,
        [2, 16, 840, 1, 101, 3, 4, 3, 2] => EndPointHash::Sha256,
        // Ed25519, Ed448 and anything unknown.
        _ => EndPointHash::Sha256,
    }
}

/// Hash for RSASSA-PSS from its parameters (RFC 4055). An absent hash
/// algorithm means SHA-1, which is upgraded to SHA-256.
fn pss_hash(alg: &AlgorithmIdentifier<'_>) -> EndPointHash {
    let Some(params) = alg.parameters.as_ref() else {
        return EndPointHash::Sha256;
    };
    let Ok(params) = RsaSsaPssParams::try_from(params) else {
        return EndPointHash::Sha256;
    };
    let Some(arcs) = oid_arcs(params.hash_algorithm_oid()) else {
        return EndPointHash::Sha256;
    };
    match arcs.as_slice() {
        [2, 16, 840, 1, 101, 3, 4, 2, 4] => EndPointHash::Sha224,
        [2, 16, 840, 1, 101, 3, 4, 2, 2] => EndPointHash::Sha384,
        [2, 16, 840, 1, 101, 3, 4, 2, 3] => EndPointHash::Sha512,
        // SHA-256, SHA-1, MD5 and anything unknown.
        _ => EndPointHash::Sha256,
    }
}

/// The arcs of an OID; `None` if an arc does not fit in a `u64` (no OID we
/// care about has such an arc).
fn oid_arcs(oid: &Oid<'_>) -> Option<Vec<u64>> {
    oid.iter().map(Iterator::collect)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_lengths() {
        assert_eq!(EndPointHash::Sha224.digest(b"x").len(), 28);
        assert_eq!(EndPointHash::Sha256.digest(b"x").len(), 32);
        assert_eq!(EndPointHash::Sha384.digest(b"x").len(), 48);
        assert_eq!(EndPointHash::Sha512.digest(b"x").len(), 64);
    }

    #[test]
    fn garbage_falls_back_to_sha256() {
        assert_eq!(end_point_hash(b""), EndPointHash::Sha256);
        assert_eq!(end_point_hash(b"\x30"), EndPointHash::Sha256);
        assert_eq!(end_point_hash(b"\x30\x82\xff\xff"), EndPointHash::Sha256);
        assert_eq!(end_point_hash(&[0u8; 64]), EndPointHash::Sha256);
    }
}

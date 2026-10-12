//! Server certificate verifiers for the libpq `sslmode` semantics that rustls
//! does not provide out of the box (`verify-ca` and `require`).

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::{CertificateError, DigitallySignedStruct, Error, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

/// `verify-ca`: verify the chain (trust anchor, validity period, key usage)
/// with the webpki verifier, but accept a certificate whose only problem is
/// that it does not name the server.
///
/// [`WebPkiServerVerifier`] checks the host name only after the chain has
/// been verified, so a name error implies that the chain is valid.
#[derive(Debug)]
pub(crate) struct VerifyChainOnly {
    inner: Arc<WebPkiServerVerifier>,
}

impl VerifyChainOnly {
    pub(crate) fn new(inner: Arc<WebPkiServerVerifier>) -> VerifyChainOnly {
        VerifyChainOnly { inner }
    }
}

impl ServerCertVerifier for VerifyChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Err(Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// `require`: accept any server certificate. The handshake signatures are
/// still verified against the presented certificate's key, so the session is
/// encrypted to whoever holds that key, but nothing ties the key to the
/// intended server (no protection against an active man in the middle).
#[derive(Debug)]
pub(crate) struct AcceptAnyServerCert {
    algorithms: WebPkiSupportedAlgorithms,
}

impl AcceptAnyServerCert {
    pub(crate) fn new(algorithms: WebPkiSupportedAlgorithms) -> AcceptAnyServerCert {
        AcceptAnyServerCert { algorithms }
    }
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

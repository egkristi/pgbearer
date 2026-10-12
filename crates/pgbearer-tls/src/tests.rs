//! Tests for pgbearer-tls.
//!
//! Certificates are generated with rcgen (ECDSA P-256 keys unless stated
//! otherwise). rcgen's ring backend cannot generate RSA keys or emit PKCS#1 /
//! SEC1, so `src/testdata/` holds OpenSSL-generated TEST-ONLY keys (the same
//! RSA-2048 key as PKCS#8 and PKCS#1, the same P-256 key as PKCS#8, SEC1 and
//! encrypted PKCS#8). They are not used anywhere else.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use pgbearer_config::{BackendTlsConfig, BackendTlsMode, ListenerTlsConfig, TlsVersion};
use pgbearer_telemetry::{CertLabels, Metrics};
use proptest::prelude::*;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, SupportedProtocolVersion};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
use tokio_util::sync::CancellationToken;

use super::*;

const RSA_PKCS8: &str = include_str!("testdata/rsa2048-pkcs8.pem");
const RSA_PKCS1: &str = include_str!("testdata/rsa2048-pkcs1.pem");
const EC_PKCS8: &str = include_str!("testdata/ec-p256-pkcs8.pem");
const EC_SEC1: &str = include_str!("testdata/ec-p256-sec1.pem");
const EC_ENCRYPTED: &str = include_str!("testdata/ec-p256-encrypted.pem");

const SERVER_DNS: &str = "db.example.test";

// ---------------------------------------------------------------------------
// PKI helpers
// ---------------------------------------------------------------------------

struct TestCa {
    params: CertificateParams,
    key: KeyPair,
    cert: rcgen::Certificate,
}

/// A leaf certificate and its key.
struct Leaf {
    cert_pem: String,
    key_pem: String,
    der: CertificateDer<'static>,
}

impl TestCa {
    fn new(common_name: &str) -> TestCa {
        let key = KeyPair::generate().expect("CA key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let cert = params.self_signed(&key).expect("CA certificate");
        TestCa { params, key, cert }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    fn der(&self) -> CertificateDer<'static> {
        self.cert.der().clone()
    }

    fn sign(&self, params: &CertificateParams, key: &KeyPair) -> rcgen::Certificate {
        let issuer = Issuer::from_params(&self.params, &self.key);
        params.signed_by(key, &issuer).expect("sign leaf")
    }

    /// Server certificate for `db.example.test` and `127.0.0.1`.
    fn server_leaf(&self) -> Leaf {
        self.server_leaf_with(KeyPair::generate().expect("server key"), |_| {})
    }

    fn server_leaf_with(
        &self,
        key: KeyPair,
        customize: impl FnOnce(&mut CertificateParams),
    ) -> Leaf {
        let mut params =
            CertificateParams::new(vec![SERVER_DNS.to_string(), "127.0.0.1".to_string()])
                .expect("server params");
        params
            .distinguished_name
            .push(DnType::CommonName, SERVER_DNS);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        customize(&mut params);
        let cert = self.sign(&params, &key);
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    /// Client certificate with the given common name (a PostgreSQL role).
    fn client_leaf(&self, common_name: &str) -> Leaf {
        let key = KeyPair::generate().expect("client key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("client params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = self.sign(&params, &key);
        Leaf {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            der: cert.der().clone(),
        }
    }

    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.der()).expect("add CA root");
        roots
    }
}

fn write(dir: &TempDir, name: &str, contents: impl AsRef<[u8]>) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("write test file");
    path
}

/// Replace a file the way Kubernetes does: write a new file and rename it
/// over the old one (new inode, so the change is visible to stamps even
/// within the same mtime tick).
fn replace(path: &Path, contents: impl AsRef<[u8]>) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).expect("write replacement");
    std::fs::rename(&tmp, path).expect("rename replacement");
}

fn server_tls(leaf: &Leaf) -> ServerTls {
    ServerTls::from_pem(leaf.cert_pem.as_bytes(), leaf.key_pem.as_bytes(), false)
        .expect("server tls")
}

fn backend_cfg(mode: BackendTlsMode, ca_file: Option<&Path>) -> BackendTlsConfig {
    BackendTlsConfig {
        mode,
        ca_file: ca_file.map(Path::to_path_buf),
        server_name: None,
    }
}

fn backend(mode: BackendTlsMode, ca_file: Option<&Path>, server_name: &str) -> BackendTls {
    BackendTls::new(&backend_cfg(mode, ca_file), server_name).expect("backend tls")
}

/// A rustls client config trusting `ca`, offering `alpn` with `versions`.
fn plain_client(
    ca: &TestCa,
    alpn: &[&[u8]],
    versions: &[&'static SupportedProtocolVersion],
) -> TlsConnector {
    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(versions)
        .expect("versions")
        .with_root_certificates(ca.roots())
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
    TlsConnector::from(Arc::new(config))
}

fn dns(name: &str) -> ServerName<'static> {
    ServerName::try_from(name.to_string()).expect("server name")
}

// ---------------------------------------------------------------------------
// Handshake helpers
// ---------------------------------------------------------------------------

type Handshake = (
    io::Result<server::TlsStream<DuplexStream>>,
    io::Result<client::TlsStream<DuplexStream>>,
);

/// Run both sides of a handshake over an in-memory pipe.
async fn handshake(
    acceptor: TlsAcceptor,
    connector: TlsConnector,
    name: ServerName<'static>,
) -> Handshake {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let both = async move {
        tokio::join!(
            acceptor.accept(server_io),
            connector.connect(name, client_io)
        )
    };
    tokio::time::timeout(Duration::from_secs(10), both)
        .await
        .expect("handshake timed out")
}

/// Handshake with a [`BackendTls`] connector.
async fn backend_handshake(
    acceptor: TlsAcceptor,
    tls: &BackendTls,
    client_cert: Option<&ClientCertPaths>,
) -> Handshake {
    let (connector, name) = tls
        .connector(client_cert)
        .expect("connector")
        .expect("tls enabled");
    handshake(acceptor, connector, name).await
}

/// Both sides succeeded; exchange a few bytes each way.
async fn expect_connected(
    result: Handshake,
) -> (
    server::TlsStream<DuplexStream>,
    client::TlsStream<DuplexStream>,
) {
    let (server, client) = result;
    let mut server = server.expect("server handshake");
    let mut client = client.expect("client handshake");
    client.write_all(b"ping").await.expect("client write");
    client.flush().await.expect("client flush");
    let mut buf = [0u8; 4];
    server.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"ping");
    server.write_all(b"pong").await.expect("server write");
    server.flush().await.expect("server flush");
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(&buf, b"pong");
    (server, client)
}

/// The rustls error inside an I/O error from a failed handshake.
fn rustls_error(error: &io::Error) -> Option<&rustls::Error> {
    error.get_ref()?.downcast_ref::<rustls::Error>()
}

fn expect_client_cert_error(result: &Handshake) -> rustls::CertificateError {
    let error = result.1.as_ref().expect_err("client handshake must fail");
    match rustls_error(error) {
        Some(rustls::Error::InvalidCertificate(e)) => e.clone(),
        other => panic!("expected a certificate error, got {other:?} ({error})"),
    }
}

fn peer_leaf(client: &client::TlsStream<DuplexStream>) -> CertificateDer<'static> {
    client
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .expect("peer certificate")
        .clone()
        .into_owned()
}

// ---------------------------------------------------------------------------
// BackendTls modes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_full_succeeds_and_negotiates_alpn() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), SERVER_DNS);
    assert_eq!(tls.mode(), BackendTlsMode::VerifyFull);

    let server = server_tls(&leaf);
    let (server, client) =
        expect_connected(backend_handshake(server.acceptor(), &tls, None).await).await;
    assert_eq!(server.get_ref().1.alpn_protocol(), Some(ALPN_POSTGRESQL));
    assert_eq!(client.get_ref().1.alpn_protocol(), Some(ALPN_POSTGRESQL));
    assert_eq!(server.get_ref().1.server_name(), Some(SERVER_DNS));
    assert_eq!(peer_leaf(&client), leaf.der);
}

#[tokio::test]
async fn verify_full_accepts_ip_address_server_name() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), "127.0.0.1");
    let server = server_tls(&leaf);
    let (server, _client) =
        expect_connected(backend_handshake(server.acceptor(), &tls, None).await).await;
    // No SNI is sent for IP addresses.
    assert_eq!(server.get_ref().1.server_name(), None);
}

#[tokio::test]
async fn verify_full_rejects_wrong_server_name() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let server = server_tls(&ca.server_leaf());
    for name in ["other.example.test", "10.0.0.1"] {
        let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), name);
        let result = backend_handshake(server.acceptor(), &tls, None).await;
        assert!(result.0.is_err(), "server must see the failure too");
        let error = expect_client_cert_error(&result);
        assert!(
            matches!(
                error,
                rustls::CertificateError::NotValidForName
                    | rustls::CertificateError::NotValidForNameContext { .. }
            ),
            "{name}: {error:?}"
        );
    }
}

#[tokio::test]
async fn verify_full_rejects_untrusted_ca() {
    let ca = TestCa::new("test CA");
    let other_ca = TestCa::new("other CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", other_ca.pem());
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), SERVER_DNS);
    let server = server_tls(&ca.server_leaf());
    let result = backend_handshake(server.acceptor(), &tls, None).await;
    assert_eq!(
        expect_client_cert_error(&result),
        rustls::CertificateError::UnknownIssuer
    );
}

#[tokio::test]
async fn verify_full_without_ca_file_uses_public_roots() {
    let ca = TestCa::new("private CA");
    let tls = backend(BackendTlsMode::VerifyFull, None, SERVER_DNS);
    assert!(format!("{tls:?}").contains("webpki-roots"));
    let server = server_tls(&ca.server_leaf());
    let result = backend_handshake(server.acceptor(), &tls, None).await;
    assert_eq!(
        expect_client_cert_error(&result),
        rustls::CertificateError::UnknownIssuer
    );
}

#[tokio::test]
async fn verify_ca_accepts_wrong_name_but_rejects_untrusted_ca() {
    let ca = TestCa::new("test CA");
    let other_ca = TestCa::new("other CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let other_ca_file = write(&dir, "other.crt", other_ca.pem());
    let server = server_tls(&ca.server_leaf());

    let tls = backend(
        BackendTlsMode::VerifyCa,
        Some(&ca_file),
        "wrong.example.test",
    );
    assert_eq!(tls.mode(), BackendTlsMode::VerifyCa);
    let (server_stream, _) =
        expect_connected(backend_handshake(server.acceptor(), &tls, None).await).await;
    // SNI is still sent.
    assert_eq!(
        server_stream.get_ref().1.server_name(),
        Some("wrong.example.test")
    );

    let tls = backend(BackendTlsMode::VerifyCa, Some(&other_ca_file), SERVER_DNS);
    let result = backend_handshake(server.acceptor(), &tls, None).await;
    assert_eq!(
        expect_client_cert_error(&result),
        rustls::CertificateError::UnknownIssuer
    );
}

#[tokio::test]
async fn verify_ca_still_rejects_expired_certificates() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let expired = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.not_before = rcgen::date_time_ymd(2020, 1, 1);
        p.not_after = rcgen::date_time_ymd(2021, 1, 1);
    });
    let server = server_tls(&expired);
    for mode in [BackendTlsMode::VerifyCa, BackendTlsMode::VerifyFull] {
        let tls = backend(mode, Some(&ca_file), "wrong.example.test");
        let result = backend_handshake(server.acceptor(), &tls, None).await;
        let error = expect_client_cert_error(&result);
        assert!(
            matches!(
                error,
                rustls::CertificateError::Expired | rustls::CertificateError::ExpiredContext { .. }
            ),
            "{mode:?}: {error:?}"
        );
    }
}

#[tokio::test]
async fn verify_ca_rejects_server_certificate_without_server_auth_usage() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let client_only = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    });
    let server = server_tls(&client_only);
    let tls = backend(BackendTlsMode::VerifyCa, Some(&ca_file), SERVER_DNS);
    let result = backend_handshake(server.acceptor(), &tls, None).await;
    let error = expect_client_cert_error(&result);
    assert!(
        !matches!(
            error,
            rustls::CertificateError::NotValidForName
                | rustls::CertificateError::NotValidForNameContext { .. }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn require_accepts_untrusted_ca_and_wrong_name() {
    let untrusted = TestCa::new("untrusted CA");
    let other_ca = TestCa::new("other CA");
    let dir = TempDir::new().expect("tempdir");
    // ca_file is ignored for `require`.
    let ca_file = write(&dir, "ca.crt", other_ca.pem());
    let leaf = untrusted.server_leaf();
    let server = server_tls(&leaf);
    for ca in [None, Some(ca_file.as_path())] {
        let tls = backend(BackendTlsMode::Require, ca, "wrong.example.test");
        assert_eq!(tls.mode(), BackendTlsMode::Require);
        let (_, client) =
            expect_connected(backend_handshake(server.acceptor(), &tls, None).await).await;
        assert_eq!(peer_leaf(&client), leaf.der);
    }
}

#[tokio::test]
async fn require_works_over_tls12() {
    let untrusted = TestCa::new("untrusted CA");
    let leaf = untrusted.server_leaf();
    // A TLS 1.2-only server exercises the TLS 1.2 signature check.
    let mut config = ServerConfig::builder_with_provider(crypto_provider())
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der.clone()],
            PrivateKeyDer::from_pem_slice(leaf.key_pem.as_bytes()).expect("key"),
        )
        .expect("server config");
    config.alpn_protocols = vec![ALPN_POSTGRESQL.to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let tls = backend(BackendTlsMode::Require, None, SERVER_DNS);
    let (_, client) = expect_connected(backend_handshake(acceptor, &tls, None).await).await;
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
}

#[test]
fn disable_has_no_connector() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing.crt");
    // Neither the server name nor the CA file matter.
    let tls = BackendTls::new(
        &backend_cfg(BackendTlsMode::Disable, Some(&missing)),
        "/var/run/postgresql",
    )
    .expect("disable");
    assert_eq!(tls.mode(), BackendTlsMode::Disable);
    assert!(tls.connector(None).expect("connector").is_none());
    let paths = ClientCertPaths {
        cert_file: missing.clone(),
        key_file: missing,
    };
    assert!(tls.connector(Some(&paths)).expect("connector").is_none());
    assert!(format!("{tls:?}").contains("Disable"));
}

#[test]
fn backend_rejects_invalid_server_names() {
    for name in [
        "",
        "bad name",
        "a..b",
        "exa mple.com",
        "[::1",
        "*.example.com",
        "\u{0}",
    ] {
        for mode in [
            BackendTlsMode::Require,
            BackendTlsMode::VerifyCa,
            BackendTlsMode::VerifyFull,
        ] {
            match BackendTls::new(&backend_cfg(mode, None), name) {
                Err(TlsError::ServerName(n)) => assert_eq!(n, name),
                other => panic!("{name:?} {mode:?}: expected ServerName error, got {other:?}"),
            }
        }
    }
}

#[test]
fn backend_accepts_dns_names_and_ip_addresses() {
    for (name, expected) in [
        ("db.example.test", dns("db.example.test")),
        (
            "orders-db-rw.data.svc.cluster.local",
            dns("orders-db-rw.data.svc.cluster.local"),
        ),
        ("10.1.2.3", dns("10.1.2.3")),
        ("::1", dns("::1")),
        ("[::1]", dns("::1")),
    ] {
        let tls = backend(BackendTlsMode::Require, None, name);
        let (_, server_name) = tls.connector(None).expect("connector").expect("enabled");
        assert_eq!(server_name, expected, "{name}");
    }
}

#[test]
fn backend_ca_file_errors() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing.crt");
    assert!(matches!(
        BackendTls::new(&backend_cfg(BackendTlsMode::VerifyFull, Some(&missing)), SERVER_DNS),
        Err(TlsError::Io { path, .. }) if path == missing
    ));

    let empty = write(&dir, "empty.crt", "");
    assert!(matches!(
        BackendTls::new(&backend_cfg(BackendTlsMode::VerifyCa, Some(&empty)), SERVER_DNS),
        Err(TlsError::InvalidPem { path, .. }) if path == empty
    ));

    // Well-formed PEM whose content is not a certificate.
    let junk = write(
        &dir,
        "junk.crt",
        "-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\n",
    );
    match BackendTls::new(
        &backend_cfg(BackendTlsMode::VerifyFull, Some(&junk)),
        SERVER_DNS,
    ) {
        Err(TlsError::InvalidPem { reason, .. }) => {
            assert!(reason.contains("trust anchor"), "{reason}");
        }
        other => panic!("expected InvalidPem, got {other:?}"),
    }
}

#[test]
fn backend_ca_file_with_some_unparsable_certificates_is_accepted() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let bundle = format!(
        "# comment\n-----BEGIN CERTIFICATE-----\nAAECAwQF\n-----END CERTIFICATE-----\n{}",
        ca.pem()
    );
    let ca_file = write(&dir, "bundle.crt", bundle);
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), SERVER_DNS);
    assert!(format!("{tls:?}").contains("bundle.crt"));
}

// ---------------------------------------------------------------------------
// Client certificates
// ---------------------------------------------------------------------------

/// A server that requires client certificates issued by `client_ca`.
fn mtls_acceptor(server_leaf: &Leaf, client_ca: &TestCa) -> TlsAcceptor {
    let provider = crypto_provider();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(client_ca.roots()), provider.clone())
            .build()
            .expect("client verifier");
    let mut config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_leaf.der.clone()],
            PrivateKeyDer::from_pem_slice(server_leaf.key_pem.as_bytes()).expect("key"),
        )
        .expect("server config");
    config.alpn_protocols = vec![ALPN_POSTGRESQL.to_vec()];
    TlsAcceptor::from(Arc::new(config))
}

fn server_seen_client_cert(server: &server::TlsStream<DuplexStream>) -> CertificateDer<'static> {
    server
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|c| c.first())
        .expect("client certificate")
        .clone()
        .into_owned()
}

#[tokio::test]
async fn client_certificate_is_presented() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let client = ca.client_leaf("app_reader");
    let paths = ClientCertPaths {
        cert_file: write(&dir, "client.crt", &client.cert_pem),
        key_file: write(&dir, "client.key", &client.key_pem),
    };
    let acceptor = mtls_acceptor(&ca.server_leaf(), &ca);
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), SERVER_DNS);

    let (server, _) =
        expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), client.der);

    // Without a client certificate the server refuses the connection.
    let result = backend_handshake(acceptor, &tls, None).await;
    assert!(result.0.is_err());
}

#[test]
fn client_certificate_config_is_cached_until_files_change() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let client = ca.client_leaf("app_reader");
    let paths = ClientCertPaths {
        cert_file: write(&dir, "client.crt", &client.cert_pem),
        key_file: write(&dir, "client.key", &client.key_pem),
    };
    let tls = backend(BackendTlsMode::Require, None, SERVER_DNS);
    let config = |tls: &BackendTls| {
        let (connector, _) = tls
            .connector(Some(&paths))
            .expect("connector")
            .expect("enabled");
        Arc::clone(connector.config())
    };
    let first = config(&tls);
    let second = config(&tls);
    assert!(
        Arc::ptr_eq(&first, &second),
        "unchanged files must hit the cache"
    );

    let (base, _) = tls.connector(None).expect("connector").expect("enabled");
    assert!(!Arc::ptr_eq(base.config(), &first));
    assert_eq!(first.alpn_protocols, vec![ALPN_POSTGRESQL.to_vec()]);

    let rotated = ca.client_leaf("app_reader");
    replace(&paths.cert_file, &rotated.cert_pem);
    replace(&paths.key_file, &rotated.key_pem);
    let third = config(&tls);
    assert!(
        !Arc::ptr_eq(&first, &third),
        "rotated files must be reloaded"
    );
    assert!(format!("{tls:?}").contains("cached_client_certs: 1"));
}

#[tokio::test]
async fn rotated_client_certificate_is_used_and_bad_rotation_keeps_previous() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let ca_file = write(&dir, "ca.crt", ca.pem());
    let first = ca.client_leaf("app_writer");
    let paths = ClientCertPaths {
        cert_file: write(&dir, "client.crt", &first.cert_pem),
        key_file: write(&dir, "client.key", &first.key_pem),
    };
    let acceptor = mtls_acceptor(&ca.server_leaf(), &ca);
    let tls = backend(BackendTlsMode::VerifyFull, Some(&ca_file), SERVER_DNS);

    let (server, _) =
        expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), first.der);

    // Rotation picked up on the next connector() call.
    let second = ca.client_leaf("app_writer");
    replace(&paths.cert_file, &second.cert_pem);
    replace(&paths.key_file, &second.key_pem);
    let (server, _) =
        expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), second.der);

    // Half-done rotation (new certificate, old key): keep the previous pair.
    let third = ca.client_leaf("app_writer");
    replace(&paths.cert_file, &third.cert_pem);
    for _ in 0..2 {
        let (server, _) =
            expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
        assert_eq!(server_seen_client_cert(&server), second.der);
    }

    // Garbage key: still the previous pair.
    replace(&paths.key_file, "not a key");
    let (server, _) =
        expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), second.der);

    // Rotation completed.
    replace(&paths.key_file, &third.key_pem);
    let (server, _) =
        expect_connected(backend_handshake(acceptor.clone(), &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), third.der);

    // Files removed: the cached pair keeps working.
    std::fs::remove_file(&paths.key_file).expect("remove key");
    let (server, _) = expect_connected(backend_handshake(acceptor, &tls, Some(&paths)).await).await;
    assert_eq!(server_seen_client_cert(&server), third.der);
}

#[test]
fn client_certificate_errors_without_previous_certificate() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let client = ca.client_leaf("app");
    let other = ca.client_leaf("app");
    let tls = backend(BackendTlsMode::Require, None, SERVER_DNS);

    let missing = ClientCertPaths {
        cert_file: dir.path().join("missing.crt"),
        key_file: dir.path().join("missing.key"),
    };
    assert!(matches!(
        tls.connector(Some(&missing)),
        Err(TlsError::Io { path, .. }) if path == missing.cert_file
    ));

    let garbage = ClientCertPaths {
        cert_file: write(&dir, "garbage.crt", "garbage"),
        key_file: write(&dir, "garbage.key", &client.key_pem),
    };
    assert!(matches!(
        tls.connector(Some(&garbage)),
        Err(TlsError::InvalidPem { path, .. }) if path == garbage.cert_file
    ));

    let mismatched = ClientCertPaths {
        cert_file: write(&dir, "mismatch.crt", &client.cert_pem),
        key_file: write(&dir, "mismatch.key", &other.key_pem),
    };
    assert!(matches!(
        tls.connector(Some(&mismatched)),
        Err(TlsError::Config(_))
    ));
    // Errors are not cached: fixing the files fixes the next call.
    replace(&mismatched.key_file, &client.key_pem);
    assert!(
        tls.connector(Some(&mismatched))
            .expect("connector")
            .is_some()
    );
}

// ---------------------------------------------------------------------------
// ServerTls: ALPN, versions
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alpn_postgresql_is_negotiated() {
    let ca = TestCa::new("test CA");
    let server = server_tls(&ca.server_leaf());
    let client = plain_client(&ca, &[b"h2", ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (server_stream, client_stream) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    assert_eq!(
        server_stream.get_ref().1.alpn_protocol(),
        Some(ALPN_POSTGRESQL)
    );
    assert_eq!(
        client_stream.get_ref().1.alpn_protocol(),
        Some(ALPN_POSTGRESQL)
    );
}

#[tokio::test]
async fn alpn_without_postgresql_is_rejected() {
    let ca = TestCa::new("test CA");
    let server = server_tls(&ca.server_leaf());
    let client = plain_client(&ca, &[b"h2"], TLS12_AND_TLS13);
    let (server_result, client_result) =
        handshake(server.acceptor(), client, dns(SERVER_DNS)).await;
    let server_error = server_result.expect_err("server must refuse");
    assert!(
        matches!(
            rustls_error(&server_error),
            Some(rustls::Error::NoApplicationProtocol)
        ),
        "{server_error}"
    );
    assert!(client_result.is_err());
}

#[tokio::test]
async fn no_alpn_is_accepted() {
    let ca = TestCa::new("test CA");
    let server = server_tls(&ca.server_leaf());
    let client = plain_client(&ca, &[], TLS12_AND_TLS13);
    let (server_stream, client_stream) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    assert_eq!(server_stream.get_ref().1.alpn_protocol(), None);
    assert_eq!(client_stream.get_ref().1.alpn_protocol(), None);
}

#[tokio::test]
async fn tls13_only_server_rejects_tls12_client() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let server =
        ServerTls::from_pem(leaf.cert_pem.as_bytes(), leaf.key_pem.as_bytes(), true).expect("tls");
    let tls12_client = plain_client(&ca, &[ALPN_POSTGRESQL], &[&rustls::version::TLS12]);
    let (server_result, client_result) =
        handshake(server.acceptor(), tls12_client, dns(SERVER_DNS)).await;
    assert!(server_result.is_err());
    assert!(client_result.is_err());

    let tls13_client = plain_client(&ca, &[ALPN_POSTGRESQL], &[&rustls::version::TLS13]);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), tls13_client, dns(SERVER_DNS)).await).await;
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

#[tokio::test]
async fn default_server_accepts_tls12_and_prefers_tls13() {
    let ca = TestCa::new("test CA");
    let server = server_tls(&ca.server_leaf());
    let tls12_client = plain_client(&ca, &[ALPN_POSTGRESQL], &[&rustls::version::TLS12]);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), tls12_client, dns(SERVER_DNS)).await).await;
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_2)
    );
    let any_client = plain_client(&ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), any_client, dns(SERVER_DNS)).await).await;
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
}

#[tokio::test]
async fn load_honours_min_version_from_config() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let dir = TempDir::new().expect("tempdir");
    let cfg = ListenerTlsConfig {
        cert_file: write(&dir, "tls.crt", &leaf.cert_pem),
        key_file: write(&dir, "tls.key", &leaf.key_pem),
        min_version: TlsVersion::Tls13,
        direct_tls: true,
        reload_interval: Duration::from_secs(30),
    };
    let server = ServerTls::load(&cfg).expect("load");
    let tls12_client = plain_client(&ca, &[ALPN_POSTGRESQL], &[&rustls::version::TLS12]);
    let (server_result, _) = handshake(server.acceptor(), tls12_client, dns(SERVER_DNS)).await;
    assert!(server_result.is_err());
    let debug = format!("{server:?}");
    assert!(
        debug.contains("tls.crt") && debug.contains("min_tls13: true"),
        "{debug}"
    );
}

// ---------------------------------------------------------------------------
// ServerTls: loading and reloading
// ---------------------------------------------------------------------------

fn listener_cfg(dir: &TempDir, leaf: &Leaf) -> ListenerTlsConfig {
    ListenerTlsConfig {
        cert_file: write(dir, "tls.crt", &leaf.cert_pem),
        key_file: write(dir, "tls.key", &leaf.key_pem),
        min_version: TlsVersion::Tls12,
        direct_tls: true,
        reload_interval: Duration::from_secs(30),
    }
}

async fn served_leaf(server: &ServerTls, ca: &TestCa) -> CertificateDer<'static> {
    let client = plain_client(ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    peer_leaf(&client)
}

#[test]
fn not_after_matches_generated_certificate() {
    let ca = TestCa::new("test CA");
    let not_after = rcgen::date_time_ymd(2031, 3, 4);
    let leaf = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.not_after = not_after;
    });
    let expected = UNIX_EPOCH
        + Duration::from_secs(u64::try_from(not_after.unix_timestamp()).expect("after 1970"));
    let server = server_tls(&leaf);
    assert_eq!(server.not_after(), Some(expected));
    assert_eq!(certificate_not_after(leaf.der.as_ref()), Some(expected));

    let dir = TempDir::new().expect("tempdir");
    let loaded = ServerTls::load(&listener_cfg(&dir, &leaf)).expect("load");
    assert_eq!(loaded.not_after(), Some(expected));
}

#[test]
fn certificate_not_after_handles_garbage() {
    assert_eq!(certificate_not_after(b""), None);
    assert_eq!(certificate_not_after(b"\x30\x03\x02\x01\x00"), None);
    assert_eq!(certificate_not_after(&[0xff; 100]), None);
}

#[tokio::test]
async fn reload_swaps_certificate_and_rejects_corrupt_replacement() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let first = ca.server_leaf();
    let cfg = listener_cfg(&dir, &first);
    let server = ServerTls::load(&cfg).expect("load");
    assert_eq!(served_leaf(&server, &ca).await, first.der);

    // Unchanged files: nothing to do (also after touching them).
    assert!(!server.reload_if_changed().expect("reload"));
    replace(&cfg.cert_file, &first.cert_pem);
    assert!(!server.reload_if_changed().expect("reload"));

    // Valid replacement.
    let second = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.not_after = rcgen::date_time_ymd(2032, 5, 6);
    });
    replace(&cfg.cert_file, &second.cert_pem);
    replace(&cfg.key_file, &second.key_pem);
    assert!(server.reload_if_changed().expect("reload"));
    assert_eq!(served_leaf(&server, &ca).await, second.der);
    assert_eq!(
        server.not_after(),
        certificate_not_after(second.der.as_ref())
    );
    assert!(!server.reload_if_changed().expect("reload"));

    // Corrupt certificate: error, old config stays, and the error repeats.
    replace(&cfg.cert_file, "-----BEGIN CERTIFICATE-----\nnot base64!\n");
    for _ in 0..2 {
        assert!(matches!(
            server.reload_if_changed(),
            Err(TlsError::InvalidPem { path, .. }) if path == cfg.cert_file
        ));
        assert_eq!(served_leaf(&server, &ca).await, second.der);
    }

    // Certificate and key that do not match.
    let third = ca.server_leaf();
    replace(&cfg.cert_file, &third.cert_pem);
    assert!(matches!(
        server.reload_if_changed(),
        Err(TlsError::Config(_))
    ));
    assert_eq!(served_leaf(&server, &ca).await, second.der);

    // Missing key file.
    std::fs::remove_file(&cfg.key_file).expect("remove key");
    assert!(matches!(
        server.reload_if_changed(),
        Err(TlsError::Io { path, .. }) if path == cfg.key_file
    ));
    assert_eq!(served_leaf(&server, &ca).await, second.der);

    // Rotation completes.
    write(&dir, "tls.key", &third.key_pem);
    assert!(server.reload_if_changed().expect("reload"));
    assert_eq!(served_leaf(&server, &ca).await, third.der);
}

#[tokio::test]
async fn existing_connections_survive_reload() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let first = ca.server_leaf();
    let cfg = listener_cfg(&dir, &first);
    let server = ServerTls::load(&cfg).expect("load");
    let client = plain_client(&ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (mut server_stream, mut client_stream) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;

    let second = ca.server_leaf();
    replace(&cfg.cert_file, &second.cert_pem);
    replace(&cfg.key_file, &second.key_pem);
    assert!(server.reload_if_changed().expect("reload"));

    client_stream.write_all(b"after").await.expect("write");
    client_stream.flush().await.expect("flush");
    let mut buf = [0u8; 5];
    server_stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"after");
}

#[test]
fn from_pem_has_nothing_to_reload() {
    let ca = TestCa::new("test CA");
    let server = server_tls(&ca.server_leaf());
    assert!(!server.reload_if_changed().expect("reload"));
}

#[test]
fn load_reports_missing_and_invalid_files() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let dir = TempDir::new().expect("tempdir");
    let mut cfg = listener_cfg(&dir, &leaf);
    cfg.key_file = dir.path().join("missing.key");
    assert!(matches!(
        ServerTls::load(&cfg),
        Err(TlsError::Io { path, .. }) if path == cfg.key_file
    ));

    let mut cfg = listener_cfg(&dir, &leaf);
    cfg.cert_file = write(&dir, "key-as-cert.crt", &leaf.key_pem);
    assert!(matches!(
        ServerTls::load(&cfg),
        Err(TlsError::InvalidPem { path, .. }) if path == cfg.cert_file
    ));

    let mut cfg = listener_cfg(&dir, &leaf);
    cfg.key_file = write(&dir, "cert-as-key.key", &leaf.cert_pem);
    match ServerTls::load(&cfg) {
        Err(TlsError::InvalidPem { path, reason }) => {
            assert_eq!(path, cfg.key_file);
            assert!(reason.contains("no private key"), "{reason}");
        }
        other => panic!("expected InvalidPem, got {other:?}"),
    }
}

#[test]
fn from_pem_rejects_mismatched_and_malformed_input() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let other = ca.server_leaf();
    match ServerTls::from_pem(leaf.cert_pem.as_bytes(), other.key_pem.as_bytes(), false) {
        Err(TlsError::Config(message)) => assert!(message.contains("cannot use certificate")),
        other => panic!("expected Config error, got {other:?}"),
    }
    for (cert, key) in [
        (&b""[..], leaf.key_pem.as_bytes()),
        (leaf.cert_pem.as_bytes(), &b""[..]),
        (&b"\x00\xff\x30\x82"[..], leaf.key_pem.as_bytes()),
        (leaf.cert_pem.as_bytes(), EC_ENCRYPTED.as_bytes()),
    ] {
        assert!(matches!(
            ServerTls::from_pem(cert, key, false),
            Err(TlsError::InvalidPem { .. })
        ));
    }
    // A key that is valid PEM but not a valid key.
    let bogus_key = "-----BEGIN PRIVATE KEY-----\nAAECAwQF\n-----END PRIVATE KEY-----\n";
    assert!(matches!(
        ServerTls::from_pem(leaf.cert_pem.as_bytes(), bogus_key.as_bytes(), false),
        Err(TlsError::Config(_))
    ));
}

#[tokio::test]
async fn reloader_exports_expiry_and_picks_up_changes() {
    let ca = TestCa::new("test CA");
    let dir = TempDir::new().expect("tempdir");
    let first = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.not_after = rcgen::date_time_ymd(2030, 1, 1);
    });
    let cfg = listener_cfg(&dir, &first);
    let server = Arc::new(ServerTls::load(&cfg).expect("load"));
    let metrics = Metrics::new();
    let labels = CertLabels {
        cert: "listener:test".to_string(),
    };
    let expiry = |metrics: &Metrics| metrics.tls_cert_expiry.get_or_create(&labels).get();
    let shutdown = CancellationToken::new();
    let handle = server.spawn_reloader(
        Duration::from_millis(20),
        Arc::clone(&metrics),
        labels.cert.clone(),
        shutdown.clone(),
    );

    let first_expiry = rcgen::date_time_ymd(2030, 1, 1).unix_timestamp();
    wait_for(|| expiry(&metrics) == first_expiry).await;
    assert!(metrics.encode().contains("listener:test"));

    // A corrupt file is ignored.
    replace(&cfg.cert_file, "garbage");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(expiry(&metrics), first_expiry);
    assert_eq!(served_leaf(&server, &ca).await, first.der);

    let second = ca.server_leaf_with(KeyPair::generate().expect("key"), |p| {
        p.not_after = rcgen::date_time_ymd(2033, 7, 8);
    });
    replace(&cfg.key_file, &second.key_pem);
    replace(&cfg.cert_file, &second.cert_pem);
    let second_expiry = rcgen::date_time_ymd(2033, 7, 8).unix_timestamp();
    wait_for(|| expiry(&metrics) == second_expiry).await;
    assert_eq!(served_leaf(&server, &ca).await, second.der);

    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("reloader stops on shutdown")
        .expect("reloader task");
}

#[tokio::test]
async fn reloader_without_files_waits_for_shutdown() {
    let ca = TestCa::new("test CA");
    let server = Arc::new(server_tls(&ca.server_leaf()));
    let metrics = Metrics::new();
    let shutdown = CancellationToken::new();
    // A zero interval must not panic.
    let handle = server.spawn_reloader(
        Duration::ZERO,
        Arc::clone(&metrics),
        "listener:mem".to_string(),
        shutdown.clone(),
    );
    let labels = CertLabels {
        cert: "listener:mem".to_string(),
    };
    let expected = server.not_after().and_then(unix_seconds).expect("expiry");
    wait_for(|| metrics.tls_cert_expiry.get_or_create(&labels).get() == expected).await;
    assert!(!handle.is_finished());
    shutdown.cancel();
    tokio::time::timeout(Duration::from_secs(5), handle)
        .await
        .expect("stops")
        .expect("task");
}

/// Poll `condition` for up to 10 seconds.
async fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "condition not reached in time"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

// ---------------------------------------------------------------------------
// Key and certificate files
// ---------------------------------------------------------------------------

#[test]
fn load_private_key_accepts_pkcs8_pkcs1_and_sec1() {
    let dir = TempDir::new().expect("tempdir");
    let pkcs8 = load_private_key(&write(&dir, "ec.pk8", EC_PKCS8)).expect("pkcs8");
    assert!(matches!(pkcs8, PrivateKeyDer::Pkcs8(_)));
    let rsa_pkcs8 = load_private_key(&write(&dir, "rsa.pk8", RSA_PKCS8)).expect("rsa pkcs8");
    assert!(matches!(rsa_pkcs8, PrivateKeyDer::Pkcs8(_)));
    let pkcs1 = load_private_key(&write(&dir, "rsa.pk1", RSA_PKCS1)).expect("pkcs1");
    assert!(matches!(pkcs1, PrivateKeyDer::Pkcs1(_)));
    let sec1 = load_private_key(&write(&dir, "ec.sec1", EC_SEC1)).expect("sec1");
    assert!(matches!(sec1, PrivateKeyDer::Sec1(_)));

    // A combined file (certificate first, then key) works too.
    let ca = TestCa::new("test CA");
    let combined = format!("{}{}", ca.pem(), EC_SEC1);
    let key = load_private_key(&write(&dir, "combined.pem", combined)).expect("combined");
    assert!(matches!(key, PrivateKeyDer::Sec1(_)));
}

#[test]
fn load_private_key_errors() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing.key");
    assert!(matches!(
        load_private_key(&missing),
        Err(TlsError::Io { path, .. }) if path == missing
    ));
    for (name, contents, expected) in [
        ("empty.key", "", "no private key"),
        ("blank.key", "\n\n  \n", "no private key"),
        ("text.key", "hello world", "no private key"),
        (
            "encrypted.key",
            EC_ENCRYPTED,
            "encrypted private keys are not supported",
        ),
        (
            "truncated.key",
            "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49\n",
            "END",
        ),
        (
            "badbase64.key",
            "-----BEGIN PRIVATE KEY-----\n!!!!\n-----END PRIVATE KEY-----\n",
            "base64",
        ),
    ] {
        let path = write(&dir, name, contents);
        match load_private_key(&path) {
            Err(TlsError::InvalidPem { path: p, reason }) => {
                assert_eq!(p, path);
                assert!(reason.contains(expected), "{name}: {reason}");
                // Error messages never echo file contents.
                assert!(!reason.contains("MIGH"), "{name}: {reason}");
            }
            other => panic!("{name}: expected InvalidPem, got {other:?}"),
        }
    }
}

#[test]
fn load_certs_reads_chains_in_order() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let dir = TempDir::new().expect("tempdir");
    let chain = format!(
        "subject=leaf\n{}\nsubject=ca\n{}{}",
        leaf.cert_pem,
        ca.pem(),
        EC_PKCS8
    );
    let certs = load_certs(&write(&dir, "chain.pem", chain)).expect("chain");
    assert_eq!(certs, vec![leaf.der.clone(), ca.der()]);
}

#[test]
fn load_certs_errors() {
    let dir = TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing.crt");
    assert!(matches!(
        load_certs(&missing),
        Err(TlsError::Io { path, .. }) if path == missing
    ));
    // A directory is not a file.
    assert!(matches!(load_certs(dir.path()), Err(TlsError::Io { .. })));
    for (name, contents) in [
        ("empty.crt", ""),
        ("key-only.crt", EC_PKCS8),
        (
            "truncated.crt",
            "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n",
        ),
        (
            "badbase64.crt",
            "-----BEGIN CERTIFICATE-----\n*&^%\n-----END CERTIFICATE-----\n",
        ),
    ] {
        let path = write(&dir, name, contents);
        assert!(
            matches!(load_certs(&path), Err(TlsError::InvalidPem { .. })),
            "{name}"
        );
    }
}

#[test]
fn oversized_files_are_rejected() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("huge.crt");
    let file = std::fs::File::create(&path).expect("create");
    // Sparse file: cheap to create.
    file.set_len(MAX_PEM_FILE_BYTES + 1).expect("set_len");
    match load_certs(&path) {
        Err(TlsError::InvalidPem { reason, .. }) => assert!(reason.contains("larger than")),
        other => panic!("expected InvalidPem, got {other:?}"),
    }
    assert!(matches!(
        load_private_key(&path),
        Err(TlsError::InvalidPem { .. })
    ));
}

#[tokio::test]
async fn pkcs1_rsa_key_serves_tls() {
    let ca = TestCa::new("test CA");
    let rsa = KeyPair::from_pem_and_sign_algo(RSA_PKCS8, &rcgen::PKCS_RSA_SHA256).expect("rsa");
    let leaf = ca.server_leaf_with(rsa, |_| {});
    let server = ServerTls::from_pem(leaf.cert_pem.as_bytes(), RSA_PKCS1.as_bytes(), false)
        .expect("pkcs1 server");
    let client = plain_client(&ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    assert_eq!(peer_leaf(&client), leaf.der);
}

#[tokio::test]
async fn sec1_ec_key_serves_tls() {
    let ca = TestCa::new("test CA");
    let ec = KeyPair::from_pem(EC_PKCS8).expect("ec");
    let leaf = ca.server_leaf_with(ec, |_| {});
    let server =
        ServerTls::from_pem(leaf.cert_pem.as_bytes(), EC_SEC1.as_bytes(), false).expect("sec1");
    let client = plain_client(&ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (_, client) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    assert_eq!(peer_leaf(&client), leaf.der);
}

// ---------------------------------------------------------------------------
// Channel binding
// ---------------------------------------------------------------------------

fn self_signed_der(key: &KeyPair) -> Vec<u8> {
    let params = CertificateParams::new(vec![SERVER_DNS.to_string()]).expect("params");
    params.self_signed(key).expect("cert").der().to_vec()
}

#[test]
fn end_point_ecdsa_p256_sha256_is_sha256_of_der() {
    let der = self_signed_der(&KeyPair::generate().expect("key"));
    assert_eq!(tls_server_end_point(&der), Sha256::digest(&der).to_vec());
}

#[test]
fn end_point_ecdsa_p384_sha384_is_sha384_of_der() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).expect("p384");
    let der = self_signed_der(&key);
    assert_eq!(tls_server_end_point(&der), Sha384::digest(&der).to_vec());
}

#[test]
fn end_point_ed25519_is_sha256_of_der() {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    let der = self_signed_der(&key);
    assert_eq!(tls_server_end_point(&der), Sha256::digest(&der).to_vec());
}

#[test]
fn end_point_rsa_pkcs1_uses_signature_hash() {
    for (alg, expected_len) in [
        (&rcgen::PKCS_RSA_SHA256, 32),
        (&rcgen::PKCS_RSA_SHA384, 48),
        (&rcgen::PKCS_RSA_SHA512, 64),
    ] {
        let key = KeyPair::from_pem_and_sign_algo(RSA_PKCS8, alg).expect("rsa");
        let der = self_signed_der(&key);
        let expected = match expected_len {
            32 => Sha256::digest(&der).to_vec(),
            48 => Sha384::digest(&der).to_vec(),
            _ => Sha512::digest(&der).to_vec(),
        };
        assert_eq!(tls_server_end_point(&der), expected, "{alg:?}");
    }
}

/// Minimal DER TLV encoding (lengths up to 65535).
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend([0x81, len as u8]);
    } else {
        out.extend([0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// DER-encoded OBJECT IDENTIFIER.
fn oid(arcs: &[u64]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut push_base128 = |mut value: u64| {
        let mut bytes = vec![(value & 0x7f) as u8];
        value >>= 7;
        while value > 0 {
            bytes.push(0x80 | (value & 0x7f) as u8);
            value >>= 7;
        }
        bytes.reverse();
        body.extend(bytes);
    };
    push_base128(arcs[0] * 40 + arcs[1]);
    for &arc in &arcs[2..] {
        push_base128(arc);
    }
    tlv(0x06, &body)
}

/// Re-wrap a real certificate's TBS with a different outer signature
/// algorithm (the signature is not checked by the end-point code).
fn with_signature_algorithm(cert_der: &[u8], algorithm_identifier: &[u8]) -> Vec<u8> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).expect("parse");
    let mut body = cert.tbs_certificate.as_ref().to_vec();
    body.extend_from_slice(algorithm_identifier);
    body.extend(tlv(0x03, &[0x00, 0xAB, 0xCD]));
    tlv(0x30, &body)
}

fn alg_id(algorithm: &[u64], params: Option<Vec<u8>>) -> Vec<u8> {
    let mut body = oid(algorithm);
    body.extend(params.unwrap_or_else(|| vec![0x05, 0x00]));
    tlv(0x30, &body)
}

/// RSASSA-PSS parameters with the given hash (None = default SHA-1).
fn pss_params(hash: Option<&[u64]>) -> Vec<u8> {
    let content = match hash {
        Some(arcs) => {
            let mut hash_alg = oid(arcs);
            hash_alg.extend([0x05, 0x00]);
            tlv(0xA0, &tlv(0x30, &hash_alg))
        }
        None => Vec::new(),
    };
    tlv(0x30, &content)
}

#[test]
fn end_point_hash_follows_signature_algorithm_table() {
    use endpoint::EndPointHash::{Sha224, Sha256 as H256, Sha384 as H384, Sha512 as H512};
    let base = self_signed_der(&KeyPair::generate().expect("key"));
    const RSA: [u64; 6] = [1, 2, 840, 113549, 1, 1];
    let rsa = |n: u64| [RSA.as_slice(), &[n]].concat();
    const SHA2: [u64; 8] = [2, 16, 840, 1, 101, 3, 4, 2];
    let sha2 = |n: u64| [SHA2.as_slice(), &[n]].concat();
    let cases: Vec<(&str, Vec<u8>, endpoint::EndPointHash)> = vec![
        ("md5WithRSA", alg_id(&rsa(4), None), H256),
        ("sha1WithRSA", alg_id(&rsa(5), None), H256),
        ("sha256WithRSA", alg_id(&rsa(11), None), H256),
        ("sha384WithRSA", alg_id(&rsa(12), None), H384),
        ("sha512WithRSA", alg_id(&rsa(13), None), H512),
        ("sha224WithRSA", alg_id(&rsa(14), None), Sha224),
        (
            "ecdsa-with-SHA1",
            alg_id(&[1, 2, 840, 10045, 4, 1], Some(vec![])),
            H256,
        ),
        (
            "ecdsa-with-SHA224",
            alg_id(&[1, 2, 840, 10045, 4, 3, 1], Some(vec![])),
            Sha224,
        ),
        (
            "ecdsa-with-SHA256",
            alg_id(&[1, 2, 840, 10045, 4, 3, 2], Some(vec![])),
            H256,
        ),
        (
            "ecdsa-with-SHA384",
            alg_id(&[1, 2, 840, 10045, 4, 3, 3], Some(vec![])),
            H384,
        ),
        (
            "ecdsa-with-SHA512",
            alg_id(&[1, 2, 840, 10045, 4, 3, 4], Some(vec![])),
            H512,
        ),
        (
            "dsa-with-sha1",
            alg_id(&[1, 2, 840, 10040, 4, 3], Some(vec![])),
            H256,
        ),
        (
            "dsa-with-sha256",
            alg_id(&[2, 16, 840, 1, 101, 3, 4, 3, 2], Some(vec![])),
            H256,
        ),
        ("ed25519", alg_id(&[1, 3, 101, 112], Some(vec![])), H256),
        ("ed448", alg_id(&[1, 3, 101, 113], Some(vec![])), H256),
        ("unknown", alg_id(&[1, 2, 3, 4, 5], None), H256),
        ("huge arc", alg_id(&[1, 2, u64::MAX], None), H256),
        (
            "pss default (sha1)",
            alg_id(&rsa(10), Some(pss_params(None))),
            H256,
        ),
        (
            "pss sha256",
            alg_id(&rsa(10), Some(pss_params(Some(&sha2(1))))),
            H256,
        ),
        (
            "pss sha384",
            alg_id(&rsa(10), Some(pss_params(Some(&sha2(2))))),
            H384,
        ),
        (
            "pss sha512",
            alg_id(&rsa(10), Some(pss_params(Some(&sha2(3))))),
            H512,
        ),
        (
            "pss sha224",
            alg_id(&rsa(10), Some(pss_params(Some(&sha2(4))))),
            Sha224,
        ),
        (
            "pss md5",
            alg_id(&rsa(10), Some(pss_params(Some(&[1, 2, 840, 113549, 2, 5])))),
            H256,
        ),
        ("pss without params", alg_id(&rsa(10), Some(vec![])), H256),
        ("pss with NULL params", alg_id(&rsa(10), None), H256),
        (
            "pss with garbage params",
            alg_id(&rsa(10), Some(vec![0x04, 0x01, 0x00])),
            H256,
        ),
    ];
    for (name, algorithm_identifier, expected) in cases {
        let der = with_signature_algorithm(&base, &algorithm_identifier);
        assert_eq!(endpoint::end_point_hash(&der), expected, "{name}");
        assert_eq!(tls_server_end_point(&der), expected.digest(&der), "{name}");
    }
}

#[test]
fn end_point_of_garbage_is_sha256_of_input() {
    for input in [&b""[..], b"\x30\x00", b"not a certificate", &[0xff; 300]] {
        assert_eq!(tls_server_end_point(input), Sha256::digest(input).to_vec());
    }
}

#[tokio::test]
async fn peer_end_point_matches_server_certificate() {
    let ca = TestCa::new("test CA");
    let leaf = ca.server_leaf();
    let server = server_tls(&leaf);
    let client = plain_client(&ca, &[ALPN_POSTGRESQL], TLS12_AND_TLS13);
    let (server_stream, client_stream) =
        expect_connected(handshake(server.acceptor(), client, dns(SERVER_DNS)).await).await;
    assert_eq!(
        peer_tls_server_end_point(client_stream.get_ref().1),
        Some(Sha256::digest(leaf.der.as_ref()).to_vec())
    );
    // The server saw no client certificate.
    assert_eq!(peer_tls_server_end_point(server_stream.get_ref().1), None);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[test]
fn unix_time_conversions_round_trip() {
    for seconds in [
        0i64,
        1,
        -1,
        1_900_000_000,
        -86_400 * 365 * 50,
        253_402_300_799,
    ] {
        let time = system_time_from_unix(seconds).expect("representable");
        assert_eq!(unix_seconds(time), Some(seconds));
    }
}

#[test]
fn fingerprint_separates_cert_and_key() {
    assert_ne!(fingerprint(b"ab", b"c"), fingerprint(b"a", b"bc"));
    assert_eq!(fingerprint(b"ab", b"c"), fingerprint(b"ab", b"c"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn end_point_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let digest = tls_server_end_point(&bytes);
        prop_assert!([28, 32, 48, 64].contains(&digest.len()));
        let _ = certificate_not_after(&bytes);
    }

    #[test]
    fn end_point_survives_mutated_certificates(index in any::<prop::sample::Index>(), byte in any::<u8>()) {
        // Flip one byte of a real certificate: parsing may fail, but must not panic.
        static CERT: OnceLock<Vec<u8>> = OnceLock::new();
        let cert = CERT.get_or_init(|| self_signed_der(&KeyPair::generate().expect("key")));
        let mut mutated = cert.clone();
        let i = index.index(mutated.len());
        mutated[i] = byte;
        let digest = tls_server_end_point(&mutated);
        prop_assert!([28, 32, 48, 64].contains(&digest.len()));
    }

    #[test]
    fn pem_parsers_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let path = Path::new("<fuzz>");
        let _ = parse_certs(&bytes, path);
        let _ = parse_private_key(&bytes, path);
    }

    #[test]
    fn pem_parsers_never_panic_on_pem_like_input(
        label in "(CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY|X)",
        body in "[A-Za-z0-9+/=\n -]{0,200}",
        end in any::<bool>(),
    ) {
        let mut pem = format!("-----BEGIN {label}-----\n{body}\n");
        if end {
            pem.push_str(&format!("-----END {label}-----\n"));
        }
        let path = Path::new("<fuzz>");
        let _ = parse_certs(pem.as_bytes(), path);
        let _ = parse_private_key(pem.as_bytes(), path);
    }

    #[test]
    fn server_name_parsing_never_panics(name in "\\PC{0,64}") {
        let _ = parse_server_name(&name);
    }
}

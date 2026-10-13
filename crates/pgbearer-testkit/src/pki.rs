//! Generated TLS material: a CA, a server certificate for `localhost` and
//! `127.0.0.1`, and client certificates signed by the same CA.
//!
//! All keys are ECDSA P-256 (rcgen's default), which both PostgreSQL
//! (OpenSSL) and rustls accept.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use crate::TestkitError;

/// A client certificate minted by [`Pki::mint_client`].
pub(crate) struct ClientCert {
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) cert_der: CertificateDer<'static>,
    pub(crate) key_der: PrivateKeyDer<'static>,
}

/// The cluster's PKI. The CA key stays in memory so more client
/// certificates can be minted at any time.
pub(crate) struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
    ca_cert_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    clients_dir: PathBuf,
    next_client: AtomicU64,
}

impl Pki {
    /// Generate the CA and server certificate and write them to `dir`
    /// (`ca.crt`, `server.crt`, `server.key`). Client certificates go to
    /// `dir/clients`, which must exist.
    pub(crate) fn generate(dir: &Path) -> Result<Pki, TestkitError> {
        let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "pgbearer-testkit CA");
        ca_params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate()?)?;

        let server_key = KeyPair::generate()?;
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server_params.signed_by(&server_key, &*ca)?;

        let pki = Pki {
            ca_cert_path: dir.join("ca.crt"),
            server_cert_path: dir.join("server.crt"),
            server_key_path: dir.join("server.key"),
            clients_dir: dir.join("clients"),
            next_client: AtomicU64::new(0),
            ca,
        };
        write_file(&pki.ca_cert_path, pki.ca.pem().as_bytes(), 0o644)?;
        write_file(&pki.server_cert_path, server_cert.pem().as_bytes(), 0o644)?;
        // PostgreSQL refuses a server key readable by group or others.
        write_file(
            &pki.server_key_path,
            server_key.serialize_pem().as_bytes(),
            0o600,
        )?;
        Ok(pki)
    }

    pub(crate) fn ca_cert_path(&self) -> &Path {
        &self.ca_cert_path
    }

    pub(crate) fn server_cert_path(&self) -> &Path {
        &self.server_cert_path
    }

    pub(crate) fn server_key_path(&self) -> &Path {
        &self.server_key_path
    }

    pub(crate) fn ca_cert_der(&self) -> &CertificateDer<'static> {
        self.ca.der()
    }

    pub(crate) fn ca_cert_pem(&self) -> String {
        self.ca.pem()
    }

    /// Mint a client certificate (EKU clientAuth) with the given common
    /// name, write it and its key (mode 0600) to the clients directory, and
    /// return the paths and DER encodings.
    pub(crate) fn mint_client(&self, common_name: &str) -> Result<ClientCert, TestkitError> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::new(Vec::<String>::new())?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &*self.ca)?;

        let n = self.next_client.fetch_add(1, Ordering::Relaxed);
        let stem = format!("{n:03}-{}", file_stem(common_name));
        let cert_path = self.clients_dir.join(format!("{stem}.crt"));
        let key_path = self.clients_dir.join(format!("{stem}.key"));
        write_file(&cert_path, cert.pem().as_bytes(), 0o644)?;
        write_file(&key_path, key.serialize_pem().as_bytes(), 0o600)?;
        Ok(ClientCert {
            cert_path,
            key_path,
            cert_der: cert.der().clone(),
            key_der: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        })
    }
}

/// A file-name-safe rendering of a common name (at most 64 characters).
pub(crate) fn file_stem(common_name: &str) -> String {
    let stem: String = common_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if stem.is_empty() {
        "client".to_string()
    } else {
        stem
    }
}

/// Create `path` (which must not exist) with `mode` and write `contents`.
pub(crate) fn write_file(path: &Path, contents: &[u8], mode: u32) -> Result<(), TestkitError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| TestkitError::io(format!("create {}", path.display()), e))?;
    file.write_all(contents)
        .map_err(|e| TestkitError::io(format!("write {}", path.display()), e))
}

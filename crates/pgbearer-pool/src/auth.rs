//! Backend authentication: SCRAM-SHA-256(-PLUS), and MD5 / cleartext
//! passwords over TLS only.

use std::path::Path;

use bytes::BytesMut;
use pgbearer_config::ResolvedCredential;
use pgbearer_wire::messages::{Authentication, decode, encode};
use pgbearer_wire::tag;
use postgres_protocol::authentication::md5_hash;
use postgres_protocol::authentication::sasl::{
    ChannelBinding, SCRAM_SHA_256, SCRAM_SHA_256_PLUS, ScramSha256,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

use crate::BackendError;
use crate::connect::{
    BackendAuthMethod, BackendConnection, ConnectParams, describe_tag, read_startup_message,
};

/// Largest password file that is read.
const MAX_PASSWORD_FILE_BYTES: u64 = 64 * 1024;

/// Where a SCRAM exchange stands.
enum Sasl {
    /// `SASLInitialResponse` sent; waiting for `AuthenticationSASLContinue`.
    Started(Box<ScramSha256>, BackendAuthMethod),
    /// `SASLResponse` sent; waiting for `AuthenticationSASLFinal`.
    Continued(Box<ScramSha256>, BackendAuthMethod),
    /// The server's signature was verified.
    Verified(BackendAuthMethod),
}

/// Run the authentication exchange (step 4 of the crate documentation) and
/// return the method used. `channel_binding` is the `tls-server-end-point`
/// data of the TLS connection (`None` without TLS).
pub(crate) async fn authenticate(
    conn: &mut BackendConnection,
    params: &ConnectParams<'_>,
    mut channel_binding: Option<Vec<u8>>,
) -> Result<BackendAuthMethod, BackendError> {
    let mut sasl: Option<Sasl> = None;
    let mut password_method: Option<BackendAuthMethod> = None;
    loop {
        let msg = read_startup_message(conn).await?;
        match msg.tag {
            tag::AUTHENTICATION => {}
            tag::ERROR_RESPONSE => return Err(BackendError::from_error_response(&msg.body)),
            tag::NOTICE_RESPONSE => continue,
            other => {
                return Err(BackendError::Protocol(format!(
                    "unexpected message {} during authentication",
                    describe_tag(other)
                )));
            }
        }
        match decode::authentication(&msg.body)? {
            Authentication::Ok => {
                return match (sasl, password_method) {
                    (None, None) => Ok(BackendAuthMethod::CertificateOrTrust),
                    (None, Some(method)) | (Some(Sasl::Verified(method)), None) => Ok(method),
                    (Some(_), _) => Err(BackendError::Auth(
                        "server accepted the login before completing SCRAM authentication \
                         (its signature was not verified)"
                            .into(),
                    )),
                };
            }
            Authentication::Sasl { mechanisms } => {
                if sasl.is_some() || password_method.is_some() {
                    return Err(protocol("server restarted authentication"));
                }
                let (mechanism, binding, method) =
                    choose_mechanism(&mechanisms, conn.tls, channel_binding.take())?;
                let password = read_password(params.credential).await?;
                let scram = Box::new(ScramSha256::new(&password, binding));
                let mut buf = BytesMut::new();
                encode::sasl_initial_response(&mut buf, mechanism, scram.message());
                send(conn, &mut buf).await?;
                sasl = Some(Sasl::Started(scram, method));
            }
            Authentication::SaslContinue { data } => {
                let Some(Sasl::Started(mut scram, method)) = sasl.take() else {
                    return Err(protocol("unexpected AuthenticationSASLContinue"));
                };
                scram
                    .update(&data)
                    .map_err(|e| BackendError::Auth(format!("invalid SCRAM server message: {e}")))?;
                let mut buf = BytesMut::new();
                encode::sasl_response(&mut buf, scram.message());
                send(conn, &mut buf).await?;
                sasl = Some(Sasl::Continued(scram, method));
            }
            Authentication::SaslFinal { data } => {
                let Some(Sasl::Continued(mut scram, method)) = sasl.take() else {
                    return Err(protocol("unexpected AuthenticationSASLFinal"));
                };
                scram.finish(&data).map_err(|e| {
                    BackendError::Auth(format!("server SCRAM signature verification failed: {e}"))
                })?;
                sasl = Some(Sasl::Verified(method));
            }
            Authentication::Md5Password { salt } => {
                start_password_exchange(conn, &sasl, &mut password_method, BackendAuthMethod::Md5)?;
                let password = read_password(params.credential).await?;
                let hash = Zeroizing::new(md5_hash(params.role.as_bytes(), &password, salt));
                let mut buf = BytesMut::new();
                encode::password_message(&mut buf, hash.as_bytes());
                send(conn, &mut buf).await?;
            }
            Authentication::CleartextPassword => {
                start_password_exchange(
                    conn,
                    &sasl,
                    &mut password_method,
                    BackendAuthMethod::Cleartext,
                )?;
                let password = read_password(params.credential).await?;
                let mut buf = BytesMut::new();
                encode::password_message(&mut buf, &password);
                send(conn, &mut buf).await?;
            }
            Authentication::Other(code) => {
                return Err(BackendError::Auth(format!(
                    "unsupported authentication method (request code {code})"
                )));
            }
        }
    }
}

/// Check that a password may be sent for an MD5 or cleartext request.
fn start_password_exchange(
    conn: &BackendConnection,
    sasl: &Option<Sasl>,
    password_method: &mut Option<BackendAuthMethod>,
    method: BackendAuthMethod,
) -> Result<(), BackendError> {
    if sasl.is_some() || password_method.is_some() {
        return Err(protocol("server restarted authentication"));
    }
    if !conn.tls {
        let what = match method {
            BackendAuthMethod::Md5 => "MD5",
            _ => "cleartext",
        };
        return Err(BackendError::Auth(format!(
            "server requested {what} password authentication without TLS; refusing to send the password"
        )));
    }
    *password_method = Some(method);
    Ok(())
}

/// Pick the SASL mechanism: `SCRAM-SHA-256-PLUS` when offered and TLS is
/// used, else `SCRAM-SHA-256` (announcing whether the client could have
/// bound the channel, as libpq does).
fn choose_mechanism(
    mechanisms: &[String],
    tls: bool,
    channel_binding: Option<Vec<u8>>,
) -> Result<(&'static str, ChannelBinding, BackendAuthMethod), BackendError> {
    let offered = |name: &str| mechanisms.iter().any(|m| m == name);
    let channel_binding = channel_binding.filter(|_| tls);
    match channel_binding {
        Some(data) if offered(SCRAM_SHA_256_PLUS) => Ok((
            SCRAM_SHA_256_PLUS,
            ChannelBinding::tls_server_end_point(data),
            BackendAuthMethod::ScramSha256Plus,
        )),
        binding if offered(SCRAM_SHA_256) => Ok((
            SCRAM_SHA_256,
            if binding.is_some() {
                // "y": the client supports channel binding but the server
                // did not offer it.
                ChannelBinding::unrequested()
            } else {
                // "n": no channel binding possible (no TLS).
                ChannelBinding::unsupported()
            },
            BackendAuthMethod::ScramSha256,
        )),
        _ => Err(BackendError::Auth(format!(
            "server offered no supported SASL mechanism ({})",
            mechanisms.join(", ")
        ))),
    }
}

/// Read the role's password file (on every connect, so rotation needs no
/// restart). One trailing line break (`\n` or `\r\n`) is removed. The
/// returned bytes are zeroized on drop.
async fn read_password(credential: &ResolvedCredential) -> Result<Zeroizing<Vec<u8>>, BackendError> {
    let ResolvedCredential::Password { password_file } = credential else {
        return Err(BackendError::Auth(
            "server requested a password, but the role's credential is a client certificate".into(),
        ));
    };
    let mut password = read_password_file(password_file).await.map_err(|e| {
        BackendError::Auth(format!(
            "cannot read password file {}: {e}",
            password_file.display()
        ))
    })?;
    if password.last() == Some(&b'\n') {
        password.pop();
        if password.last() == Some(&b'\r') {
            password.pop();
        }
    }
    if password.is_empty() {
        return Err(BackendError::Auth(format!(
            "password file {} is empty",
            password_file.display()
        )));
    }
    if password.contains(&0) {
        return Err(BackendError::Auth(format!(
            "password file {} contains a NUL byte",
            password_file.display()
        )));
    }
    Ok(password)
}

async fn read_password_file(path: &Path) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let file = tokio::fs::File::open(path).await?;
    // Reserve up front so that reading does not leave reallocated copies
    // of the password behind.
    let mut password = Zeroizing::new(Vec::with_capacity(4096));
    file.take(MAX_PASSWORD_FILE_BYTES + 1)
        .read_to_end(&mut password)
        .await?;
    if password.len() as u64 > MAX_PASSWORD_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("larger than {MAX_PASSWORD_FILE_BYTES} bytes"),
        ));
    }
    Ok(password)
}

/// Write an authentication message straight to the stream (bypassing the
/// writer's buffer, which is empty during startup, so no copy of a password
/// stays there), flush, and zeroize `buf`.
async fn send(conn: &mut BackendConnection, buf: &mut BytesMut) -> Result<(), BackendError> {
    let result = async {
        conn.writer.flush().await?;
        let stream = conn.writer.get_mut();
        stream.write_all(buf).await?;
        stream.flush().await
    }
    .await;
    buf.as_mut().zeroize();
    result.map_err(BackendError::Io)
}

fn protocol(message: &str) -> BackendError {
    BackendError::Protocol(message.into())
}

//! Sending a backend `CancelRequest` ([`CancelTarget`]).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use pgbearer_tls::BackendTls;
use pgbearer_wire::startup::encode_cancel_request;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use zeroize::{Zeroize, Zeroizing};

use crate::BackendError;
use crate::connect::negotiate_tls;

/// Upper bound on [`CancelTarget::send`].
pub(crate) const CANCEL_TIMEOUT: Duration = Duration::from_secs(5);

/// Where and how to send a cancel request for one backend connection.
#[derive(Clone)]
pub struct CancelTarget {
    inner: Arc<Inner>,
}

struct Inner {
    endpoint: SocketAddr,
    process_id: u32,
    /// The real backend secret; zeroized on drop.
    secret_key: Zeroizing<Vec<u8>>,
    /// The backend's TLS configuration when the session's connection used
    /// TLS; `None` sends the cancel in clear, like the session.
    tls: Option<Arc<BackendTls>>,
}

impl CancelTarget {
    /// A target for the connection with `process_id` and `secret_key`,
    /// reached at `endpoint`, with TLS when `tls` is given.
    pub(crate) fn new(
        endpoint: SocketAddr,
        process_id: u32,
        secret_key: &[u8],
        tls: Option<Arc<BackendTls>>,
    ) -> CancelTarget {
        CancelTarget {
            inner: Arc::new(Inner {
                endpoint,
                process_id,
                secret_key: Zeroizing::new(secret_key.to_vec()),
                tls,
            }),
        }
    }

    /// Connect to the physical endpoint, use TLS when the session's
    /// connection did (`SSLRequest`; `'N'` is an error so the secret is never
    /// sent in clear; the certificate is verified against the backend's
    /// configured server name), write `CancelRequest` with the real key, then
    /// wait for the server to close the connection. Everything within 5 s.
    ///
    /// No client certificate is presented: PostgreSQL does not authenticate
    /// cancel requests beyond the key.
    pub async fn send(&self) -> Result<(), BackendError> {
        tokio::time::timeout(CANCEL_TIMEOUT, self.send_inner())
            .await
            .unwrap_or(Err(BackendError::Timeout))
    }

    async fn send_inner(&self) -> Result<(), BackendError> {
        let inner = &*self.inner;
        // Prepare the TLS connector first: a configuration error must not
        // lead to a cleartext cancel.
        let connector = match &inner.tls {
            None => None,
            Some(tls) => Some(
                tls.connector(None)
                    .map_err(|e| BackendError::Tls(e.to_string()))?
                    .ok_or_else(|| {
                        BackendError::Tls(
                            "the session used TLS but the backend's TLS mode is disable".into(),
                        )
                    })?,
            ),
        };
        let tcp = TcpStream::connect(inner.endpoint).await?;
        tcp.set_nodelay(true)?;
        match connector {
            None => write_and_wait(tcp, inner).await,
            Some((connector, server_name)) => {
                let stream = negotiate_tls(tcp, &connector, server_name).await?;
                write_and_wait(stream, inner).await
            }
        }
    }

    /// The physical endpoint the cancel goes to.
    pub fn endpoint(&self) -> SocketAddr {
        self.inner.endpoint
    }

    /// The backend pid (safe to log; the secret is never exposed).
    pub fn backend_pid(&self) -> u32 {
        self.inner.process_id
    }

    /// Whether the cancel connection uses TLS (as the session's did).
    pub fn uses_tls(&self) -> bool {
        self.inner.tls.is_some()
    }
}

/// Write the `CancelRequest` and wait until the server closes the
/// connection (any data it sends is discarded).
async fn write_and_wait<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    inner: &Inner,
) -> Result<(), BackendError> {
    let mut packet = BytesMut::new();
    encode_cancel_request(&mut packet, inner.process_id, &inner.secret_key);
    let written = async {
        stream.write_all(&packet).await?;
        stream.flush().await
    }
    .await;
    packet.as_mut().zeroize();
    written?;
    let mut sink = [0u8; 64];
    loop {
        match stream.read(&mut sink).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            // The server ends the cancel connection without a TLS
            // close_notify, or with a reset: either way it is closed.
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset
                ) =>
            {
                return Ok(());
            }
            Err(e) => return Err(BackendError::Io(e)),
        }
    }
}

impl std::fmt::Debug for CancelTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CancelTarget")
            .field("endpoint", &self.inner.endpoint)
            .field("backend_pid", &self.inner.process_id)
            .field("tls", &self.inner.tls.is_some())
            .finish_non_exhaustive()
    }
}

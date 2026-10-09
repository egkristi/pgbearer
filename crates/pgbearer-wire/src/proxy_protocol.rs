//! PROXY protocol version 2 (binary) header parsing.
//!
//! Spec: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.
//! Only v2 is supported (v1 is text and not used by modern cloud load
//! balancers in TCP mode).

use std::net::SocketAddr;

use tokio::io::AsyncRead;

use crate::WireError;

/// The 12-byte v2 signature.
pub const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Maximum accepted header length (16-byte prefix + address block + TLVs).
pub const MAX_HEADER_LEN: usize = 16 + 1024;

/// A parsed PROXY v2 header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHeader {
    /// `PROXY` command with TCP over IPv4/IPv6: the original addresses.
    Proxied {
        /// Original client address.
        source: SocketAddr,
        /// Original destination address.
        destination: SocketAddr,
    },
    /// `LOCAL` command (health checks from the load balancer itself), or an
    /// address family pgbearer does not use (UNIX, UNSPEC): keep the socket peer.
    Local,
}

/// Returns true if `prefix` (at least 12 bytes) starts with the v2 signature.
pub fn has_signature(prefix: &[u8]) -> bool {
    prefix.len() >= SIGNATURE.len() && prefix[..SIGNATURE.len()] == SIGNATURE
}

/// Read and parse one PROXY v2 header with exact reads (no over-read).
///
/// The caller has already established that the stream starts with the
/// signature (for example with `TcpStream::peek`). Errors:
/// * wrong signature or version nibble (must be 2) → [`WireError::Protocol`];
/// * command other than LOCAL (0) / PROXY (1) → [`WireError::Protocol`];
/// * length above [`MAX_HEADER_LEN`] or address block shorter than the family
///   requires → [`WireError::Protocol`];
/// * TLVs are skipped.
pub async fn read_v2_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ProxyHeader, WireError> {
    let _ = reader;
    todo!("pgbearer-wire: proxy_protocol::read_v2_header")
}

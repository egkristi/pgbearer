//! PROXY protocol version 2 (binary) header parsing.
//!
//! Spec: <https://www.haproxy.org/download/2.9/doc/proxy-protocol.txt>.
//! Only v2 is supported (v1 is text and not used by modern cloud load
//! balancers in TCP mode).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::AsyncRead;

use crate::WireError;
use crate::codec::{Cursor, read_exact};

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

/// Length of the fixed part of a v2 header (signature, version/command,
/// family/protocol, address length).
pub const FIXED_HEADER_LEN: usize = 16;

/// Command nibble: `LOCAL`.
const CMD_LOCAL: u8 = 0x0;
/// Command nibble: `PROXY`.
const CMD_PROXY: u8 = 0x1;
/// Family/protocol byte: TCP over IPv4.
const TCP_OVER_IPV4: u8 = 0x11;
/// Family/protocol byte: TCP over IPv6.
const TCP_OVER_IPV6: u8 = 0x21;
/// Address block length for TCP/UDP over IPv4.
const IPV4_BLOCK_LEN: usize = 12;
/// Address block length for TCP/UDP over IPv6.
const IPV6_BLOCK_LEN: usize = 36;
/// Address block length for UNIX sockets.
const UNIX_BLOCK_LEN: usize = 216;

/// Read and parse one PROXY v2 header with exact reads (no over-read).
///
/// The caller has already established that the stream starts with the
/// signature (for example with `TcpStream::peek`). Errors:
/// * wrong signature or version nibble (must be 2) → [`WireError::Protocol`];
/// * command other than LOCAL (0) / PROXY (1) → [`WireError::Protocol`];
/// * length above [`MAX_HEADER_LEN`] or address block shorter than the family
///   requires → [`WireError::Protocol`];
/// * TLVs are skipped.
///
/// A `PROXY` header for TCP over IPv4 or IPv6 yields
/// [`ProxyHeader::Proxied`]. A `LOCAL` header, and a `PROXY` header for the
/// UNSPEC or UNIX family or for UDP, yields [`ProxyHeader::Local`]; its bytes
/// are still consumed. Family or transport values the specification does not
/// define are rejected. EOF inside the header is [`WireError::UnexpectedEof`].
pub async fn read_v2_header<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ProxyHeader, WireError> {
    let mut fixed = [0u8; FIXED_HEADER_LEN];
    read_exact(reader, &mut fixed).await?;
    if !has_signature(&fixed) {
        return Err(WireError::protocol("PROXY v2: bad signature"));
    }
    let version = fixed[12] >> 4;
    let command = fixed[12] & 0x0f;
    if version != 2 {
        return Err(WireError::protocol(format!(
            "PROXY v2: unsupported version {version}"
        )));
    }
    if command != CMD_LOCAL && command != CMD_PROXY {
        return Err(WireError::protocol(format!(
            "PROXY v2: unknown command {command}"
        )));
    }
    let family_protocol = fixed[13];
    let family = family_protocol >> 4;
    let transport = family_protocol & 0x0f;
    if family > 3 || transport > 2 {
        return Err(WireError::protocol(format!(
            "PROXY v2: unknown address family/protocol 0x{family_protocol:02x}"
        )));
    }
    let len = usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    if len > MAX_HEADER_LEN - FIXED_HEADER_LEN {
        return Err(WireError::protocol(format!(
            "PROXY v2: header length {} exceeds the limit of {MAX_HEADER_LEN} bytes",
            FIXED_HEADER_LEN + len
        )));
    }
    let mut rest = [0u8; MAX_HEADER_LEN - FIXED_HEADER_LEN];
    let rest = &mut rest[..len];
    read_exact(reader, rest).await?;

    if command == CMD_LOCAL {
        // Health check from the proxy itself: the address block (if any) is
        // meaningless and must be ignored.
        return Ok(ProxyHeader::Local);
    }
    let mut cur = Cursor::new(rest, "PROXY v2");
    let required = match family {
        1 => IPV4_BLOCK_LEN,
        2 => IPV6_BLOCK_LEN,
        3 => UNIX_BLOCK_LEN,
        _ => 0,
    };
    if len < required {
        return Err(cur.error(format_args!(
            "address block of {len} bytes is shorter than the {required} bytes family 0x{family_protocol:02x} requires"
        )));
    }
    // The remaining bytes are TLVs, which are skipped.
    match family_protocol {
        TCP_OVER_IPV4 => {
            let src = Ipv4Addr::from(cur.array::<4>()?);
            let dst = Ipv4Addr::from(cur.array::<4>()?);
            let src_port = cur.u16()?;
            let dst_port = cur.u16()?;
            Ok(ProxyHeader::Proxied {
                source: SocketAddr::from((src, src_port)),
                destination: SocketAddr::from((dst, dst_port)),
            })
        }
        TCP_OVER_IPV6 => {
            let src = Ipv6Addr::from(cur.array::<16>()?);
            let dst = Ipv6Addr::from(cur.array::<16>()?);
            let src_port = cur.u16()?;
            let dst_port = cur.u16()?;
            Ok(ProxyHeader::Proxied {
                source: SocketAddr::from((src, src_port)),
                destination: SocketAddr::from((dst, dst_port)),
            })
        }
        // UNSPEC, UDP and UNIX: keep the socket peer.
        _ => Ok(ProxyHeader::Local),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use crate::test_util::{ChunkedReader, block_on};
    use proptest::prelude::*;

    /// Build a v2 header from its parts.
    fn header(ver_cmd: u8, fam: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = SIGNATURE.to_vec();
        v.push(ver_cmd);
        v.push(fam);
        v.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn ipv4_block() -> Vec<u8> {
        let mut b = vec![192, 0, 2, 10, 10, 0, 0, 5];
        b.extend_from_slice(&54321u16.to_be_bytes());
        b.extend_from_slice(&5432u16.to_be_bytes());
        b
    }

    fn ipv6_block() -> Vec<u8> {
        let src: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::5".parse().unwrap();
        let mut b = src.octets().to_vec();
        b.extend_from_slice(&dst.octets());
        b.extend_from_slice(&40000u16.to_be_bytes());
        b.extend_from_slice(&6432u16.to_be_bytes());
        b
    }

    async fn parse(bytes: &[u8]) -> Result<ProxyHeader, WireError> {
        let mut r = bytes;
        read_v2_header(&mut r).await
    }

    fn assert_protocol(r: Result<ProxyHeader, WireError>, needle: &str) {
        match r {
            Err(WireError::Protocol(msg)) => {
                assert!(msg.contains(needle), "{msg:?} does not mention {needle:?}")
            }
            other => panic!("expected protocol error mentioning {needle:?}, got {other:?}"),
        }
    }

    #[test]
    fn signature_detection() {
        assert!(has_signature(&SIGNATURE));
        assert!(has_signature(&header(0x21, 0x11, &ipv4_block())));
        assert!(!has_signature(&SIGNATURE[..11]));
        assert!(!has_signature(b"PROXY TCP4 192.0.2.1 10.0.0.1 1 2\r\n"));
        assert!(!has_signature(&[0, 0, 0, 8, 4, 210, 22, 47, 0, 0, 0, 0]));
    }

    #[tokio::test]
    async fn tcp_over_ipv4() {
        let bytes = header(0x21, 0x11, &ipv4_block());
        assert_eq!(
            parse(&bytes).await.unwrap(),
            ProxyHeader::Proxied {
                source: "192.0.2.10:54321".parse().unwrap(),
                destination: "10.0.0.5:5432".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn tcp_over_ipv6() {
        let bytes = header(0x21, 0x21, &ipv6_block());
        assert_eq!(
            parse(&bytes).await.unwrap(),
            ProxyHeader::Proxied {
                source: "[2001:db8::1]:40000".parse().unwrap(),
                destination: "[fd00::5]:6432".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn tlvs_are_skipped_and_nothing_is_over_read() {
        let mut block = ipv4_block();
        // PP2_TYPE_ALPN and a PP2_TYPE_AWS-style TLV.
        block.extend_from_slice(&[0x01, 0x00, 0x0a]);
        block.extend_from_slice(b"postgresql");
        block.extend_from_slice(&[0xea, 0x00, 0x03, 0x01, b'v', b'p']);
        let mut bytes = header(0x21, 0x11, &block);
        let header_len = bytes.len();
        bytes.extend_from_slice(&[0, 0, 0, 8, 4, 210, 22, 47]); // SSLRequest follows
        let mut r = ChunkedReader::bytewise(bytes).pending();
        let h = read_v2_header(&mut r).await.unwrap();
        assert!(matches!(h, ProxyHeader::Proxied { .. }));
        assert_eq!(r.consumed(), header_len);

        let mut bytes = header(0x21, 0x21, &ipv6_block());
        bytes.extend_from_slice(b"rest");
        let mut s = &bytes[..];
        read_v2_header(&mut s).await.unwrap();
        assert_eq!(s, b"rest");
    }

    #[tokio::test]
    async fn local_and_unused_families() {
        // LOCAL with no address block (health check).
        assert_eq!(
            parse(&header(0x20, 0x00, &[])).await.unwrap(),
            ProxyHeader::Local
        );
        // LOCAL with an address block: still consumed and ignored.
        let mut bytes = header(0x20, 0x11, &ipv4_block());
        bytes.push(b'X');
        let mut r = &bytes[..];
        assert_eq!(read_v2_header(&mut r).await.unwrap(), ProxyHeader::Local);
        assert_eq!(r, b"X");
        // LOCAL with a short block is fine: the block is ignored.
        assert_eq!(
            parse(&header(0x20, 0x11, &[1, 2])).await.unwrap(),
            ProxyHeader::Local
        );
        // PROXY with UNSPEC.
        assert_eq!(
            parse(&header(0x21, 0x00, &[])).await.unwrap(),
            ProxyHeader::Local
        );
        // UDP over IPv4 / IPv6.
        assert_eq!(
            parse(&header(0x21, 0x12, &ipv4_block())).await.unwrap(),
            ProxyHeader::Local
        );
        assert_eq!(
            parse(&header(0x21, 0x22, &ipv6_block())).await.unwrap(),
            ProxyHeader::Local
        );
        // UNIX stream with a 216-byte block.
        let mut bytes = header(0x21, 0x31, &[0u8; 216]);
        bytes.push(b'Y');
        let mut r = &bytes[..];
        assert_eq!(read_v2_header(&mut r).await.unwrap(), ProxyHeader::Local);
        assert_eq!(r, b"Y");
    }

    #[tokio::test]
    async fn bad_signature_version_and_command() {
        let mut bytes = header(0x21, 0x11, &ipv4_block());
        bytes[0] = 0x0e;
        assert_protocol(parse(&bytes).await, "signature");
        assert_protocol(parse(&header(0x11, 0x11, &ipv4_block())).await, "version");
        assert_protocol(parse(&header(0x31, 0x11, &ipv4_block())).await, "version");
        assert_protocol(parse(&header(0x01, 0x11, &ipv4_block())).await, "version");
        assert_protocol(parse(&header(0x22, 0x11, &ipv4_block())).await, "command");
        assert_protocol(parse(&header(0x2f, 0x11, &ipv4_block())).await, "command");
    }

    #[tokio::test]
    async fn unknown_family_or_transport() {
        assert_protocol(parse(&header(0x21, 0x41, &ipv4_block())).await, "family");
        assert_protocol(parse(&header(0x21, 0x13, &ipv4_block())).await, "family");
        assert_protocol(parse(&header(0x21, 0xff, &ipv4_block())).await, "family");
    }

    #[tokio::test]
    async fn length_limits() {
        // The largest accepted header.
        let mut block = ipv4_block();
        block.resize(MAX_HEADER_LEN - FIXED_HEADER_LEN, 0);
        let bytes = header(0x21, 0x11, &block);
        assert_eq!(bytes.len(), MAX_HEADER_LEN);
        assert!(matches!(
            parse(&bytes).await.unwrap(),
            ProxyHeader::Proxied { .. }
        ));
        // One byte more is rejected before the payload is read.
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x21, 0x11]);
        bytes.extend_from_slice(&((MAX_HEADER_LEN - FIXED_HEADER_LEN + 1) as u16).to_be_bytes());
        assert_protocol(parse(&bytes).await, "exceeds");
        let mut bytes = SIGNATURE.to_vec();
        bytes.extend_from_slice(&[0x21, 0x11, 0xff, 0xff]);
        assert_protocol(parse(&bytes).await, "exceeds");
    }

    #[tokio::test]
    async fn address_block_too_short() {
        assert_protocol(
            parse(&header(0x21, 0x11, &ipv4_block()[..11])).await,
            "shorter",
        );
        assert_protocol(parse(&header(0x21, 0x21, &ipv4_block())).await, "shorter");
        assert_protocol(parse(&header(0x21, 0x12, &[])).await, "shorter");
        assert_protocol(parse(&header(0x21, 0x31, &[0; 100])).await, "shorter");
    }

    #[tokio::test]
    async fn eof_inside_the_header() {
        let bytes = header(0x21, 0x11, &ipv4_block());
        for cut in 0..bytes.len() {
            assert!(
                matches!(parse(&bytes[..cut]).await, Err(WireError::UnexpectedEof)),
                "cut at {cut}"
            );
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn random_bytes_never_panic(
            ver_cmd in any::<u8>(),
            fam in any::<u8>(),
            len in any::<u16>(),
            payload in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut bytes = SIGNATURE.to_vec();
            bytes.extend_from_slice(&[ver_cmd, fam]);
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend_from_slice(&payload);
            let mut r = &bytes[..];
            if block_on(read_v2_header(&mut r)).is_ok() {
                prop_assert_eq!(r.len(), bytes.len() - FIXED_HEADER_LEN - usize::from(len));
            }
        }

        #[test]
        fn fully_random_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let _ = block_on(parse(&bytes));
        }

        #[test]
        fn ipv4_round_trip(src in any::<[u8; 4]>(), dst in any::<[u8; 4]>(), sp in any::<u16>(), dp in any::<u16>()) {
            let mut block = src.to_vec();
            block.extend_from_slice(&dst);
            block.extend_from_slice(&sp.to_be_bytes());
            block.extend_from_slice(&dp.to_be_bytes());
            let h = block_on(parse(&header(0x21, 0x11, &block))).unwrap();
            prop_assert_eq!(h, ProxyHeader::Proxied {
                source: SocketAddr::from((Ipv4Addr::from(src), sp)),
                destination: SocketAddr::from((Ipv4Addr::from(dst), dp)),
            });
        }
    }
}

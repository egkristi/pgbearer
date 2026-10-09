//! SASL `OAUTHBEARER` (RFC 7628) server-side message handling, as used by
//! libpq 18 (see the PostgreSQL protocol docs, "OAUTHBEARER Authentication").
//!
//! Exchange handled by the session crate:
//!
//! 1. Server: `AuthenticationSASL ["OAUTHBEARER"]`.
//! 2. Client: `SASLInitialResponse("OAUTHBEARER", gs2-header kvpairs)`.
//!    * If `auth` is empty/absent → *discovery*: server sends
//!      `AuthenticationSASLContinue(discovery_error_json(..))`, client replies
//!      with `SASLResponse` containing a single `0x01` byte, server sends a
//!      FATAL `ErrorResponse` (28000) and closes. The client then runs its
//!      OAuth flow and reconnects.
//!    * If `auth` is `Bearer <token>` → validate the token. On success the
//!      server sends `AuthenticationOk` (no `AuthenticationSASLFinal`). On
//!      failure it sends the error JSON in `AuthenticationSASLContinue`, waits
//!      for the `0x01` response, then sends FATAL 28P01.

/// A parsed client initial response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInitialResponse {
    /// The bearer token, or `None` for a discovery request.
    pub token: Option<String>,
}

/// Parse a client initial response.
///
/// Format (RFC 7628 §3.1): `gs2-header %x01 *(kvpair %x01) %x01`, where the
/// gs2 header is `n,,` or `y,,` (an authzid `a=...` is tolerated and
/// ignored; `p=` channel binding is rejected because OAUTHBEARER has no
/// channel binding). `auth=Bearer <token>` (scheme case-insensitive) yields the
/// token; an empty `auth` value or no `auth` key means discovery. Other keys
/// (`host`, `port`) are ignored. Malformed input is an error.
pub fn parse_client_initial_response(data: &[u8]) -> Result<ClientInitialResponse, String> {
    let _ = data;
    todo!("pgbearer-auth: oauthbearer::parse_client_initial_response")
}

/// The JSON error/discovery document sent in `AuthenticationSASLContinue`:
/// `{"status":"invalid_token","scope":"<scope>","openid-configuration":"<url>"}`.
pub fn discovery_error_json(openid_configuration_url: &str, scope: &str) -> Vec<u8> {
    let _ = (openid_configuration_url, scope);
    todo!("pgbearer-auth: oauthbearer::discovery_error_json")
}

/// Returns true if `data` is the client's error-acknowledgement (a single `0x01`).
pub fn is_error_ack(data: &[u8]) -> bool {
    data == [0x01]
}

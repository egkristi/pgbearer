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
//!
//! All input here comes from unauthenticated clients: parsing is strict,
//! never panics, and error messages do not echo client data.

/// The key/value separator (`kvsep`, `%x01`).
const KVSEP: u8 = 0x01;

/// A parsed client initial response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientInitialResponse {
    /// The bearer token, or `None` for a discovery request.
    pub token: Option<String>,
}

fn split_once(data: &[u8], sep: u8) -> Option<(&[u8], &[u8])> {
    let i = data.iter().position(|b| *b == sep)?;
    Some((&data[..i], &data[i + 1..]))
}

/// `value = *(VCHAR / SP / HTAB / CR / LF)`.
fn is_value_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x7e | b' ' | b'\t' | b'\r' | b'\n')
}

/// RFC 6750 `b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="`.
fn is_b64token(token: &str) -> bool {
    let body = token.trim_end_matches('=');
    !body.is_empty()
        && body.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
}

/// Parse the `auth` value: empty → discovery; `Bearer <token>` → token.
fn parse_auth_value(value: &[u8]) -> Result<Option<String>, String> {
    if value.is_empty() {
        return Ok(None);
    }
    // `value` was checked to be ASCII, so this cannot fail.
    let value = std::str::from_utf8(value).map_err(|_| "auth value is not ASCII".to_string())?;
    let (scheme, rest) = value
        .split_once(' ')
        .ok_or_else(|| "auth value must be \"Bearer <token>\"".to_string())?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err("auth scheme must be Bearer".into());
    }
    let token = rest.trim_start_matches(' ');
    if token.is_empty() {
        return Err("auth value has no bearer token".into());
    }
    if !is_b64token(token) {
        return Err("bearer token contains invalid characters".into());
    }
    Ok(Some(token.to_string()))
}

/// Parse a client initial response.
///
/// Format (RFC 7628 §3.1): `gs2-header %x01 *(kvpair %x01) %x01`, where the
/// gs2 header is `n,,` or `y,,` (an authzid `a=...` is tolerated and
/// ignored; `p=` channel binding is rejected because OAUTHBEARER has no
/// channel binding). `auth=Bearer <token>` (scheme case-insensitive) yields the
/// token; an empty `auth` value or no `auth` key means discovery. Other keys
/// (`host`, `port`) are ignored. Malformed input is an error.
///
/// Keys must be alphabetic, values limited to visible ASCII, space, tab, CR
/// and LF; a duplicate `auth` key, data after the final separator and a token
/// with characters outside RFC 6750 `b64token` are errors.
pub fn parse_client_initial_response(data: &[u8]) -> Result<ClientInitialResponse, String> {
    let (cb_flag, rest) = split_once(data, b',').ok_or_else(|| "missing GS2 header".to_string())?;
    match cb_flag {
        b"n" | b"y" => {}
        _ if cb_flag.starts_with(b"p=") => {
            return Err("channel binding is not supported with OAUTHBEARER".into());
        }
        _ => return Err("invalid GS2 channel-binding flag".into()),
    }
    let (authzid, rest) =
        split_once(rest, b',').ok_or_else(|| "GS2 header is not terminated".to_string())?;
    if !authzid.is_empty() && !authzid.starts_with(b"a=") {
        return Err("invalid GS2 authorization identity".into());
    }
    if authzid.contains(&KVSEP) {
        return Err("invalid GS2 authorization identity".into());
    }
    let rest = rest
        .strip_prefix(&[KVSEP])
        .ok_or_else(|| "missing separator after GS2 header".to_string())?;
    let mut remaining = rest
        .strip_suffix(&[KVSEP])
        .ok_or_else(|| "message is not terminated by a separator".to_string())?;

    let mut auth: Option<&[u8]> = None;
    while !remaining.is_empty() {
        let (pair, tail) = split_once(remaining, KVSEP)
            .ok_or_else(|| "key/value pair is not terminated".to_string())?;
        remaining = tail;
        let (key, value) =
            split_once(pair, b'=').ok_or_else(|| "key/value pair has no '='".to_string())?;
        if key.is_empty() || !key.iter().all(u8::is_ascii_alphabetic) {
            return Err("invalid key in key/value pair".into());
        }
        if !value.iter().copied().all(is_value_byte) {
            return Err("invalid characters in a key/value pair value".into());
        }
        if key == b"auth" {
            if auth.is_some() {
                return Err("duplicate auth key".into());
            }
            auth = Some(value);
        }
    }
    let token = match auth {
        None => None,
        Some(value) => parse_auth_value(value)?,
    };
    Ok(ClientInitialResponse { token })
}

/// Escape a string as a JSON string literal (with quotes).
fn json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => {
                out.push_str(&format!("\\u{:04x}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The JSON error/discovery document sent in `AuthenticationSASLContinue`:
/// `{"status":"invalid_token","scope":"<scope>","openid-configuration":"<url>"}`.
pub fn discovery_error_json(openid_configuration_url: &str, scope: &str) -> Vec<u8> {
    let mut out = String::with_capacity(64 + openid_configuration_url.len() + scope.len());
    out.push_str("{\"status\":\"invalid_token\",\"scope\":");
    json_string(scope, &mut out);
    out.push_str(",\"openid-configuration\":");
    json_string(openid_configuration_url, &mut out);
    out.push('}');
    out.into_bytes()
}

/// Returns true if `data` is the client's error-acknowledgement (a single `0x01`).
pub fn is_error_ack(data: &[u8]) -> bool {
    data == [0x01]
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn parse(s: &[u8]) -> Result<Option<String>, String> {
        parse_client_initial_response(s).map(|r| r.token)
    }

    #[test]
    fn libpq_discovery_request() {
        assert_eq!(parse(b"n,,\x01auth=\x01\x01"), Ok(None));
        assert_eq!(parse(b"y,,\x01auth=\x01\x01"), Ok(None));
        assert_eq!(parse(b"n,,\x01\x01"), Ok(None));
        assert_eq!(
            parse(b"n,,\x01host=db.example.com\x01port=5432\x01\x01"),
            Ok(None)
        );
    }

    #[test]
    fn bearer_token() {
        assert_eq!(
            parse(b"n,,\x01auth=Bearer abc.def-ghi_j\x01\x01"),
            Ok(Some("abc.def-ghi_j".into()))
        );
        assert_eq!(
            parse(b"n,,\x01auth=bearer tok\x01\x01"),
            Ok(Some("tok".into()))
        );
        assert_eq!(
            parse(b"n,,\x01auth=BEARER  tok==\x01\x01"),
            Ok(Some("tok==".into()))
        );
        assert_eq!(
            parse(b"y,a=user,\x01host=h\x01auth=Bearer t~+/\x01port=1\x01\x01"),
            Ok(Some("t~+/".into()))
        );
        // authzid is tolerated and ignored.
        assert_eq!(
            parse(b"n,a=alice,\x01auth=Bearer t\x01\x01"),
            Ok(Some("t".into()))
        );
    }

    #[test]
    fn rejects_channel_binding_and_bad_gs2_headers() {
        let e = parse(b"p=tls-server-end-point,,\x01auth=Bearer t\x01\x01").unwrap_err();
        assert!(e.contains("channel binding"), "{e}");
        assert!(parse(b"").is_err());
        assert!(parse(b"\x01").is_err());
        assert!(parse(b"n").is_err());
        assert!(parse(b"n,").is_err());
        assert!(parse(b"x,,\x01\x01").is_err());
        assert!(parse(b"N,,\x01\x01").is_err());
        assert!(parse(b"F,n,,\x01\x01").is_err());
        assert!(parse(b"n,b=x,\x01\x01").is_err());
        assert!(parse(b"n,a=x\x01y,\x01\x01").is_err());
    }

    #[test]
    fn rejects_bad_framing() {
        assert!(parse(b"n,,").is_err());
        assert!(parse(b"n,,auth=Bearer t\x01\x01").is_err());
        assert!(parse(b"n,,\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer t\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer t").is_err());
        assert!(parse(b"n,,\x01auth=Bearer t\x01\x01junk").is_err());
        assert!(parse(b"n,,\x01auth=Bearer t\x01\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth\x01\x01").is_err());
        assert!(parse(b"n,,\x01=x\x01\x01").is_err());
        assert!(parse(b"n,,\x01au th=x\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth1=x\x01\x01").is_err());
    }

    #[test]
    fn rejects_bad_auth_values() {
        assert!(parse(b"n,,\x01auth=Bearer\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer \x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Basic dXNlcjpwYXNz\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer a b\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer a=b\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer ===\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer\ttok\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=Bearer t\x00\x01\x01").is_err());
        assert!(parse("n,,\x01auth=Bearer tøk\x01\x01".as_bytes()).is_err());
        assert!(parse(b"n,,\x01auth=Bearer t\x01auth=Bearer u\x01\x01").is_err());
        assert!(parse(b"n,,\x01auth=\x01auth=\x01\x01").is_err());
    }

    #[test]
    fn discovery_json_is_exact() {
        let json = discovery_error_json(
            "https://login.example.com/t/v2.0/.well-known/openid-configuration",
            "api://pgbearer/Database.Connect",
        );
        assert_eq!(
            String::from_utf8(json).unwrap(),
            r#"{"status":"invalid_token","scope":"api://pgbearer/Database.Connect","openid-configuration":"https://login.example.com/t/v2.0/.well-known/openid-configuration"}"#
        );
    }

    #[test]
    fn discovery_json_escapes() {
        let json = discovery_error_json("https://x/\"\\\n\u{1}\u{7f}é", "a b\t");
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains(r#"\"\\\n\u0001\u007fé"#), "{text}");
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["openid-configuration"], "https://x/\"\\\n\u{1}\u{7f}é");
        assert_eq!(v["scope"], "a b\t");
        assert_eq!(v["status"], "invalid_token");
    }

    #[test]
    fn error_ack() {
        assert!(is_error_ack(&[0x01]));
        assert!(!is_error_ack(&[]));
        assert!(!is_error_ack(&[0x01, 0x01]));
        assert!(!is_error_ack(b"n,,\x01\x01"));
    }

    proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse_client_initial_response(&data);
        }

        #[test]
        fn structured_inputs_never_panic(
            flag in prop_oneof![
                Just("n".to_string()),
                Just("y".to_string()),
                Just("p=x".to_string()),
                ".{0,3}",
            ],
            authzid in ".{0,8}",
            pairs in proptest::collection::vec(("[a-z]{0,5}", ".{0,12}"), 0..4),
        ) {
            let mut msg = format!("{flag},{authzid},\x01").into_bytes();
            for (k, v) in pairs {
                msg.extend_from_slice(format!("{k}={v}\x01").as_bytes());
            }
            msg.push(0x01);
            let _ = parse_client_initial_response(&msg);
        }

        #[test]
        fn valid_tokens_round_trip(token in "[A-Za-z0-9._~+/-]{1,200}={0,2}", host in "[a-z.]{0,20}") {
            let msg = format!("n,,\x01host={host}\x01auth=Bearer {token}\x01\x01");
            let parsed = parse_client_initial_response(msg.as_bytes()).unwrap();
            prop_assert_eq!(parsed.token, Some(token));
        }

        #[test]
        fn discovery_json_always_parses(url in ".{0,80}", scope in ".{0,40}") {
            let json = discovery_error_json(&url, &scope);
            let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
            prop_assert_eq!(v["openid-configuration"].as_str(), Some(url.as_str()));
            prop_assert_eq!(v["scope"].as_str(), Some(scope.as_str()));
            prop_assert_eq!(v.as_object().map(|o| o.len()), Some(3));
        }
    }
}

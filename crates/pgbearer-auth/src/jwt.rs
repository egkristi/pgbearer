//! Parsing of compact JWS tokens *before* verification, and mapping of
//! `jsonwebtoken` errors to [`AuthError`].
//!
//! Everything here handles untrusted input: it must never panic, and any
//! attacker-controlled text that ends up in an error message is passed
//! through [`sanitize`] first.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::Algorithm;
use serde_json::{Map, Value};

use crate::AuthError;

/// Maximum number of characters of attacker-controlled text echoed in errors.
const MAX_ECHO_CHARS: usize = 64;

/// Make attacker-controlled text safe for error messages and logs: control
/// characters are replaced with `?` and the text is truncated.
pub(crate) fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(MAX_ECHO_CHARS + 3));
    for (i, c) in s.chars().enumerate() {
        if i >= MAX_ECHO_CHARS {
            out.push('…');
            break;
        }
        out.push(if c.is_control() { '?' } else { c });
    }
    out
}

/// A token split and decoded but **not verified**.
#[derive(Debug, Clone)]
pub(crate) struct UnverifiedToken {
    /// Header `alg`, already checked to be a supported asymmetric algorithm.
    pub(crate) alg: Algorithm,
    /// Header `kid`.
    pub(crate) kid: Option<String>,
    /// Header `typ`.
    pub(crate) typ: Option<String>,
    /// Unverified payload.
    pub(crate) claims: Map<String, Value>,
}

/// Split a compact JWS and decode its header and payload without verifying
/// anything. Checks the structure, the `alg` (asymmetric only; `none` and
/// HMAC are rejected) and rejects `crit` (no extensions are understood).
pub(crate) fn parse_unverified(token: &str) -> Result<UnverifiedToken, AuthError> {
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        let segments = token.split('.').count();
        return Err(AuthError::Malformed(format!(
            "expected a signed JWT with three dot-separated segments, found {segments} segment(s)"
        )));
    };

    let header = decode_json_object(header, "header")?;
    let alg = header_alg(&header)?;
    if header.contains_key("crit") {
        return Err(AuthError::Malformed(
            "critical header parameters (crit) are not supported".into(),
        ));
    }
    let kid = optional_header_string(&header, "kid")?;
    let typ = optional_header_string(&header, "typ")?;
    let claims = decode_json_object(payload, "payload")?;
    if signature.is_empty() {
        return Err(AuthError::Malformed("the token has no signature".into()));
    }
    if !is_base64url(signature) {
        return Err(AuthError::Malformed(
            "signature is not base64url-encoded".into(),
        ));
    }
    Ok(UnverifiedToken {
        alg,
        kid,
        typ,
        claims,
    })
}

fn is_base64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn decode_json_object(segment: &str, what: &str) -> Result<Map<String, Value>, AuthError> {
    if segment.is_empty() {
        return Err(AuthError::Malformed(format!("empty JWT {what}")));
    }
    if !is_base64url(segment) {
        return Err(AuthError::Malformed(format!(
            "JWT {what} is not base64url-encoded"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| AuthError::Malformed(format!("JWT {what} is not valid base64url")))?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(AuthError::Malformed(format!(
            "JWT {what} is not a JSON object"
        ))),
        Err(_) => Err(AuthError::Malformed(format!(
            "JWT {what} is not valid JSON"
        ))),
    }
}

fn optional_header_string(
    header: &Map<String, Value>,
    name: &str,
) -> Result<Option<String>, AuthError> {
    match header.get(name) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(AuthError::Malformed(format!(
            "JWT header {name} is not a string"
        ))),
    }
}

fn header_alg(header: &Map<String, Value>) -> Result<Algorithm, AuthError> {
    match header.get("alg") {
        None => Err(AuthError::Malformed("JWT header has no alg".into())),
        Some(Value::String(s)) => {
            parse_asymmetric_alg(s).ok_or_else(|| AuthError::DisallowedAlgorithm(sanitize(s)))
        }
        Some(_) => Err(AuthError::Malformed(
            "JWT header alg is not a string".into(),
        )),
    }
}

/// Parse a JWA algorithm name, accepting only the asymmetric signature
/// algorithms pgbearer supports. `none`, `HS*` and unknown names yield `None`.
/// Names are case-sensitive (RFC 7518).
pub(crate) fn parse_asymmetric_alg(name: &str) -> Option<Algorithm> {
    Some(match name {
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EdDSA" => Algorithm::EdDSA,
        _ => return None,
    })
}

/// The JWA name of an algorithm.
pub(crate) fn alg_name(alg: Algorithm) -> &'static str {
    match alg {
        Algorithm::HS256 => "HS256",
        Algorithm::HS384 => "HS384",
        Algorithm::HS512 => "HS512",
        Algorithm::ES256 => "ES256",
        Algorithm::ES384 => "ES384",
        Algorithm::RS256 => "RS256",
        Algorithm::RS384 => "RS384",
        Algorithm::RS512 => "RS512",
        Algorithm::PS256 => "PS256",
        Algorithm::PS384 => "PS384",
        Algorithm::PS512 => "PS512",
        Algorithm::EdDSA => "EdDSA",
        // `Algorithm` is non-exhaustive; any future variant is not allowed.
        _ => "unknown",
    }
}

/// Map a `jsonwebtoken` verification error to an [`AuthError`].
pub(crate) fn map_jwt_error(
    err: &jsonwebtoken::errors::Error,
    alg: Algorithm,
    issuer: &str,
) -> AuthError {
    use jsonwebtoken::errors::ErrorKind as K;
    match err.kind() {
        K::ExpiredSignature => AuthError::Expired,
        K::ImmatureSignature => AuthError::NotYetValid,
        K::InvalidAudience => AuthError::BadAudience,
        K::InvalidSignature | K::InvalidEcdsaKey | K::InvalidEddsaKey | K::InvalidRsaKey(_) => {
            AuthError::BadSignature
        }
        K::InvalidIssuer => AuthError::UnknownIssuer(sanitize(issuer)),
        K::MissingRequiredClaim(c) | K::InvalidClaimFormat(c) => {
            AuthError::MissingClaim(sanitize(c))
        }
        K::InvalidSubject => AuthError::MissingClaim("sub".into()),
        K::InvalidAlgorithm
        | K::MissingAlgorithm
        | K::InvalidKeyFormat
        | K::UnsupportedAlgorithm
        | K::InvalidAlgorithmName => AuthError::DisallowedAlgorithm(alg_name(alg).into()),
        K::Base64(_) | K::Json(_) | K::Utf8(_) | K::InvalidToken => {
            AuthError::Malformed(format!("cannot decode token: {err}"))
        }
        _ => AuthError::Malformed(format!("token rejected: {err}")),
    }
}

/// Read a JSON number as whole seconds (`u64`), the way `jsonwebtoken` does:
/// non-negative integers, or finite non-negative floats rounded.
pub(crate) fn numeric_date(value: &Value) -> Option<u64> {
    if let Some(n) = value.as_u64() {
        return Some(n);
    }
    let f = value.as_f64()?;
    // `u64::MAX as f64` rounds up to 2^64, so `<` keeps the cast in range.
    if f.is_finite() && f >= 0.0 && f < u64::MAX as f64 {
        Some(f.round() as u64)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn b64(v: &Value) -> String {
        URL_SAFE_NO_PAD.encode(v.to_string())
    }

    fn token(header: &Value, payload: &Value) -> String {
        format!("{}.{}.c2ln", b64(header), b64(payload))
    }

    fn malformed(t: &str) -> String {
        match parse_unverified(t) {
            Err(AuthError::Malformed(m)) => m,
            other => panic!("expected Malformed for {t:?}, got {other:?}"),
        }
    }

    #[test]
    fn parses_a_well_formed_token() {
        let t = token(
            &json!({"alg": "ES256", "kid": "k1", "typ": "at+jwt"}),
            &json!({"iss": "https://idp", "n": 1}),
        );
        let p = parse_unverified(&t).unwrap();
        assert_eq!(p.alg, Algorithm::ES256);
        assert_eq!(p.kid.as_deref(), Some("k1"));
        assert_eq!(p.typ.as_deref(), Some("at+jwt"));
        assert_eq!(p.claims["iss"], "https://idp");
    }

    #[test]
    fn rejects_wrong_segment_counts() {
        assert!(malformed("").contains("1 segment"));
        assert!(malformed("abc").contains("1 segment"));
        assert!(malformed("a.b").contains("2 segment"));
        assert!(malformed("a.b.c.d").contains("4 segment"));
        assert!(malformed("a.b.c.d.e").contains("5 segment"));
    }

    #[test]
    fn rejects_bad_encodings() {
        let payload = b64(&json!({"iss": "x"}));
        assert!(malformed(&format!(".{payload}.c2ln")).contains("empty JWT header"));
        assert!(malformed(&format!("a+b.{payload}.c2ln")).contains("base64url"));
        assert!(malformed(&format!("eyJ=.{payload}.c2ln")).contains("base64url"));
        // Not valid base64 length (1 char)
        assert!(malformed(&format!("e.{payload}.c2ln")).contains("valid base64url"));
        // Valid base64 but not JSON
        let not_json = URL_SAFE_NO_PAD.encode("not json");
        assert!(malformed(&format!("{not_json}.{payload}.c2ln")).contains("valid JSON"));
        // JSON but not an object
        let arr = URL_SAFE_NO_PAD.encode("[1,2]");
        assert!(malformed(&format!("{arr}.{payload}.c2ln")).contains("JSON object"));
        // Payload problems
        let header = b64(&json!({"alg": "ES256"}));
        assert!(malformed(&format!("{header}..c2ln")).contains("empty JWT payload"));
        assert!(malformed(&format!("{header}.{not_json}.c2ln")).contains("payload"));
        assert!(malformed(&format!("{header}.{payload}.")).contains("no signature"));
        assert!(malformed(&format!("{header}.{payload}.a/b")).contains("signature"));
    }

    #[test]
    fn rejects_none_and_symmetric_algorithms() {
        for alg in [
            "none", "None", "NONE", "HS256", "HS384", "HS512", "es256", "XX",
        ] {
            let t = token(&json!({"alg": alg}), &json!({}));
            assert_eq!(
                parse_unverified(&t).unwrap_err(),
                AuthError::DisallowedAlgorithm(alg.into()),
                "{alg}"
            );
        }
        // alg none with an empty signature is reported as a disallowed algorithm.
        let t = format!("{}.{}.", b64(&json!({"alg": "none"})), b64(&json!({})));
        assert_eq!(
            parse_unverified(&t).unwrap_err(),
            AuthError::DisallowedAlgorithm("none".into())
        );
    }

    #[test]
    fn rejects_bad_header_fields() {
        assert!(malformed(&token(&json!({}), &json!({}))).contains("no alg"));
        assert!(malformed(&token(&json!({"alg": 5}), &json!({}))).contains("alg"));
        assert!(malformed(&token(&json!({"alg": "ES256", "kid": 1}), &json!({}))).contains("kid"));
        assert!(malformed(&token(&json!({"alg": "ES256", "typ": []}), &json!({}))).contains("typ"));
        assert!(
            malformed(&token(
                &json!({"alg": "ES256", "crit": ["exp"]}),
                &json!({})
            ))
            .contains("crit")
        );
    }

    #[test]
    fn sanitize_truncates_and_strips_control_characters() {
        assert_eq!(sanitize("a\nb\u{0}c"), "a?b?c");
        let long = "x".repeat(500);
        let s = sanitize(&long);
        assert_eq!(s.chars().count(), MAX_ECHO_CHARS + 1);
        assert!(s.ends_with('…'));
        assert_eq!(sanitize(""), "");
    }

    #[test]
    fn numeric_dates() {
        assert_eq!(numeric_date(&json!(5)), Some(5));
        assert_eq!(numeric_date(&json!(5.4)), Some(5));
        assert_eq!(numeric_date(&json!(-1)), None);
        assert_eq!(numeric_date(&json!(-1.5)), None);
        assert_eq!(numeric_date(&json!("5")), None);
        assert_eq!(numeric_date(&json!(1e300)), None);
        assert_eq!(numeric_date(&json!(null)), None);
    }

    #[test]
    fn alg_names_round_trip() {
        for name in [
            "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
        ] {
            let alg = parse_asymmetric_alg(name).unwrap();
            assert_eq!(alg_name(alg), name);
        }
    }

    #[test]
    fn maps_jsonwebtoken_errors() {
        use jsonwebtoken::errors::{ErrorKind as K, new_error};
        let m = |k| map_jwt_error(&new_error(k), Algorithm::ES256, "https://i");
        assert_eq!(m(K::ExpiredSignature), AuthError::Expired);
        assert_eq!(m(K::ImmatureSignature), AuthError::NotYetValid);
        assert_eq!(m(K::InvalidAudience), AuthError::BadAudience);
        assert_eq!(m(K::InvalidSignature), AuthError::BadSignature);
        assert_eq!(m(K::InvalidEcdsaKey), AuthError::BadSignature);
        assert_eq!(
            m(K::InvalidIssuer),
            AuthError::UnknownIssuer("https://i".into())
        );
        assert_eq!(
            m(K::MissingRequiredClaim("aud".into())),
            AuthError::MissingClaim("aud".into())
        );
        assert_eq!(
            m(K::InvalidClaimFormat("exp".into())),
            AuthError::MissingClaim("exp".into())
        );
        assert_eq!(
            m(K::InvalidAlgorithm),
            AuthError::DisallowedAlgorithm("ES256".into())
        );
        assert_eq!(
            m(K::InvalidKeyFormat),
            AuthError::DisallowedAlgorithm("ES256".into())
        );
        assert!(matches!(m(K::InvalidToken), AuthError::Malformed(_)));
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_strings(s in ".{0,300}") {
            let _ = parse_unverified(&s);
        }

        #[test]
        fn never_panics_on_arbitrary_segments(
            h in proptest::collection::vec(any::<u8>(), 0..64),
            p in proptest::collection::vec(any::<u8>(), 0..64),
            s in "[A-Za-z0-9_-]{0,20}",
        ) {
            let t = format!("{}.{}.{}", URL_SAFE_NO_PAD.encode(&h), URL_SAFE_NO_PAD.encode(&p), s);
            let _ = parse_unverified(&t);
        }

        #[test]
        fn arbitrary_json_headers_never_panic(alg in ".{0,12}", kid in proptest::option::of(".{0,12}")) {
            let mut header = json!({"alg": alg});
            if let Some(k) = kid {
                header["kid"] = json!(k);
            }
            let t = token(&header, &json!({"iss": "x"}));
            match parse_unverified(&t) {
                Ok(p) => prop_assert!(parse_asymmetric_alg(alg_name(p.alg)).is_some()),
                Err(e) => prop_assert!(matches!(e, AuthError::DisallowedAlgorithm(_) | AuthError::Malformed(_))),
            }
        }
    }
}

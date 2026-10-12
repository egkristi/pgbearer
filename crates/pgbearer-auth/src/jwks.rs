//! JSON Web Key Set parsing and the in-memory key set (ARCHITECTURE.md §8.3).
//!
//! JWKS documents come from the network and are untrusted: every key is
//! checked individually, unusable keys are skipped (never fatal for the whole
//! set), and nothing here panics.

use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde_json::Value;

use crate::jwt::parse_asymmetric_alg;

/// Maximum number of usable keys kept from one JWKS document.
pub(crate) const MAX_KEYS: usize = 64;

/// RSA modulus sizes accepted for verification (the aws-lc verifiers accept
/// 2048–8192 bits; smaller keys could never verify anything).
const RSA_MIN_BITS: usize = 2048;
const RSA_MAX_BITS: usize = 8192;

/// The key material type of a verification key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyKind {
    /// RSA (RS*/PS*).
    Rsa,
    /// ECDSA P-256 (ES256).
    EcP256,
    /// ECDSA P-384 (ES384).
    EcP384,
    /// Ed25519 (EdDSA).
    Ed25519,
}

impl KeyKind {
    fn supports(self, alg: Algorithm) -> bool {
        match self {
            KeyKind::Rsa => matches!(
                alg,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::PS256
                    | Algorithm::PS384
                    | Algorithm::PS512
            ),
            KeyKind::EcP256 => alg == Algorithm::ES256,
            KeyKind::EcP384 => alg == Algorithm::ES384,
            KeyKind::Ed25519 => alg == Algorithm::EdDSA,
        }
    }
}

/// A usable signature verification key from a JWKS.
#[derive(Clone)]
pub(crate) struct VerifyKey {
    /// `kid`, if the key has one.
    pub(crate) kid: Option<String>,
    /// `alg`, if the key pins one; the token header must then match it.
    pub(crate) alg: Option<Algorithm>,
    /// Key type.
    pub(crate) kind: KeyKind,
    /// The key itself.
    pub(crate) key: DecodingKey,
}

impl std::fmt::Debug for VerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyKey")
            .field("kid", &self.kid)
            .field("alg", &self.alg)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl VerifyKey {
    /// Whether this key may verify a token signed with `alg`.
    pub(crate) fn supports(&self, alg: Algorithm) -> bool {
        self.kind.supports(alg) && self.alg.is_none_or(|a| a == alg)
    }
}

/// Result of parsing a JWKS document.
#[derive(Debug)]
pub(crate) struct ParsedJwks {
    /// Usable keys (at most [`MAX_KEYS`]).
    pub(crate) keys: Vec<VerifyKey>,
    /// Number of keys that were skipped, with the first few reasons.
    pub(crate) skipped: Vec<String>,
}

/// Parse a JWKS document. Fails only if the document itself is unusable
/// (not JSON, no `keys` array); individual bad keys are skipped.
pub(crate) fn parse_jwks(body: &[u8]) -> Result<ParsedJwks, String> {
    let doc: Value =
        serde_json::from_slice(body).map_err(|e| format!("JWKS is not valid JSON: {e}"))?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "JWKS has no \"keys\" array".to_string())?;
    let mut parsed = ParsedJwks {
        keys: Vec::new(),
        skipped: Vec::new(),
    };
    for (index, key) in keys.iter().enumerate() {
        match parse_key(key) {
            Ok(k) if parsed.keys.len() < MAX_KEYS => parsed.keys.push(k),
            Ok(_) => parsed
                .skipped
                .push(format!("key #{index}: more than {MAX_KEYS} usable keys")),
            Err(reason) => parsed.skipped.push(format!("key #{index}: {reason}")),
        }
    }
    Ok(parsed)
}

fn parse_key(value: &Value) -> Result<VerifyKey, String> {
    let obj = value
        .as_object()
        .ok_or_else(|| "not a JSON object".to_string())?;
    match obj.get("use") {
        None => {}
        Some(Value::String(u)) if u == "sig" => {}
        Some(other) => return Err(format!("use {other} is not \"sig\"")),
    }
    if let Some(ops) = obj.get("key_ops") {
        let verify = ops
            .as_array()
            .is_some_and(|ops| ops.iter().any(|o| o == "verify"));
        if !verify {
            return Err("key_ops does not include \"verify\"".into());
        }
    }
    let kid = match obj.get("kid") {
        None => None,
        Some(Value::String(k)) => Some(k.clone()),
        Some(_) => return Err("kid is not a string".into()),
    };
    let alg = match obj.get("alg") {
        None => None,
        Some(Value::String(a)) => Some(
            parse_asymmetric_alg(a)
                .ok_or_else(|| format!("alg {a:?} is not an allowed signature algorithm"))?,
        ),
        Some(_) => return Err("alg is not a string".into()),
    };
    let jwk: Jwk =
        serde_json::from_value(value.clone()).map_err(|e| format!("invalid JWK: {e}"))?;
    let kind = match &jwk.algorithm {
        AlgorithmParameters::RSA(p) => {
            let n = decode_component(&p.n, "n")?;
            let bits = bit_length(&n);
            if !(RSA_MIN_BITS..=RSA_MAX_BITS).contains(&bits) {
                return Err(format!(
                    "RSA modulus has {bits} bits (accepted: {RSA_MIN_BITS}–{RSA_MAX_BITS})"
                ));
            }
            if decode_component(&p.e, "e")?.iter().all(|b| *b == 0) {
                return Err("RSA exponent is zero".into());
            }
            KeyKind::Rsa
        }
        AlgorithmParameters::EllipticCurve(p) => {
            let (kind, len) = match p.curve {
                EllipticCurve::P256 => (KeyKind::EcP256, 32),
                EllipticCurve::P384 => (KeyKind::EcP384, 48),
                _ => return Err("unsupported elliptic curve".into()),
            };
            if decode_component(&p.x, "x")?.len() != len
                || decode_component(&p.y, "y")?.len() != len
            {
                return Err("EC coordinates have the wrong length for the curve".into());
            }
            kind
        }
        AlgorithmParameters::OctetKeyPair(p) => {
            if p.curve != EllipticCurve::Ed25519 {
                return Err("unsupported OKP curve".into());
            }
            if decode_component(&p.x, "x")?.len() != 32 {
                return Err("Ed25519 public key has the wrong length".into());
            }
            KeyKind::Ed25519
        }
        AlgorithmParameters::OctetKey(_) => {
            return Err("symmetric (oct) keys are never accepted".into());
        }
        _ => return Err("unsupported key type".into()),
    };
    if let Some(a) = alg
        && !kind.supports(a)
    {
        return Err(format!("alg {a:?} does not match the key type"));
    }
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| format!("unusable key: {e}"))?;
    Ok(VerifyKey {
        kid,
        alg,
        kind,
        key,
    })
}

fn decode_component(value: &str, name: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| format!("JWK parameter {name} is not valid base64url"))
}

fn bit_length(bytes: &[u8]) -> usize {
    match bytes.iter().position(|b| *b != 0) {
        None => 0,
        Some(i) => {
            let rest = bytes.len() - i - 1;
            rest * 8 + (8 - bytes[i].leading_zeros() as usize)
        }
    }
}

/// A key set in use for one provider.
#[derive(Debug, Clone, Default)]
pub(crate) struct KeySet {
    /// Usable keys.
    pub(crate) keys: Vec<VerifyKey>,
    /// When the keys were fetched (`None`: never).
    pub(crate) fetched_at: Option<Instant>,
    /// `Cache-Control: max-age` of the response, if any.
    pub(crate) cache_max_age: Option<Duration>,
}

/// Outcome of a key lookup.
#[derive(Debug)]
pub(crate) enum KeyLookup<'a> {
    /// A key that may verify the token.
    Found(&'a VerifyKey),
    /// The set is empty.
    Empty,
    /// No key has this `kid`.
    UnknownKid,
    /// The token has no `kid` and the set does not have exactly one key.
    Ambiguous,
    /// A key matched, but not for this algorithm.
    AlgMismatch,
}

impl KeySet {
    /// Find the key for a token header. A token without `kid` is accepted
    /// only when the set has exactly one key.
    pub(crate) fn find(&self, kid: Option<&str>, alg: Algorithm) -> KeyLookup<'_> {
        if self.keys.is_empty() {
            return KeyLookup::Empty;
        }
        match kid {
            Some(kid) => {
                let mut matched = false;
                for key in self.keys.iter().filter(|k| k.kid.as_deref() == Some(kid)) {
                    if key.supports(alg) {
                        return KeyLookup::Found(key);
                    }
                    matched = true;
                }
                if matched {
                    KeyLookup::AlgMismatch
                } else {
                    KeyLookup::UnknownKid
                }
            }
            None => match self.keys.as_slice() {
                [only] if only.supports(alg) => KeyLookup::Found(only),
                [_] => KeyLookup::AlgMismatch,
                _ => KeyLookup::Ambiguous,
            },
        }
    }
}

/// The smallest `max-age` in `Cache-Control` header values; `no-cache` and
/// `no-store` count as zero. Unparseable directives are ignored.
pub(crate) fn parse_cache_control<'a>(
    values: impl IntoIterator<Item = &'a str>,
) -> Option<Duration> {
    let mut result: Option<u64> = None;
    let mut take = |secs: u64| result = Some(result.map_or(secs, |r| r.min(secs)));
    for value in values {
        for directive in value.split(',') {
            let directive = directive.trim();
            if directive.eq_ignore_ascii_case("no-cache")
                || directive.eq_ignore_ascii_case("no-store")
            {
                take(0);
            } else if let Some((name, arg)) = directive.split_once('=')
                && name.trim().eq_ignore_ascii_case("max-age")
                && let Ok(secs) = arg.trim().trim_matches('"').parse::<u64>()
            {
                take(secs);
            }
        }
    }
    result.map(Duration::from_secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // A panic in a test is a test failure.
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn ec_p256(kid: &str) -> Value {
        // Any 32-byte coordinates parse; verification would fail, which is fine here.
        json!({"kty": "EC", "crv": "P-256", "kid": kid, "use": "sig", "alg": "ES256",
               "x": b64(&[1; 32]), "y": b64(&[2; 32])})
    }

    fn rsa(kid: &str, bits: usize) -> Value {
        let mut n = vec![0xffu8; bits / 8];
        n[0] = 0x80;
        json!({"kty": "RSA", "kid": kid, "n": b64(&n), "e": "AQAB"})
    }

    fn parse(keys: Vec<Value>) -> ParsedJwks {
        parse_jwks(json!({"keys": keys}).to_string().as_bytes()).unwrap()
    }

    #[test]
    fn accepts_supported_keys() {
        let p = parse(vec![
            ec_p256("ec"),
            rsa("rsa", 2048),
            json!({"kty": "EC", "crv": "P-384", "kid": "p384", "x": b64(&[1; 48]), "y": b64(&[2; 48])}),
            json!({"kty": "OKP", "crv": "Ed25519", "kid": "ed", "x": b64(&[3; 32])}),
        ]);
        assert_eq!(p.keys.len(), 4, "{:?}", p.skipped);
        assert!(p.skipped.is_empty());
        assert_eq!(p.keys[0].kind, KeyKind::EcP256);
        assert_eq!(p.keys[0].alg, Some(Algorithm::ES256));
        assert_eq!(p.keys[1].kind, KeyKind::Rsa);
        assert_eq!(p.keys[1].alg, None);
        assert_eq!(p.keys[2].kind, KeyKind::EcP384);
        assert_eq!(p.keys[3].kind, KeyKind::Ed25519);
    }

    #[test]
    fn skips_unusable_keys() {
        let mut enc = rsa("enc", 2048);
        enc["use"] = json!("enc");
        let mut ops = rsa("ops", 2048);
        ops["key_ops"] = json!(["encrypt"]);
        let mut hs = ec_p256("hs");
        hs["alg"] = json!("HS256");
        let mut wrong_alg = ec_p256("wrong");
        wrong_alg["alg"] = json!("RS256");
        let mut oaep = rsa("oaep", 2048);
        oaep["alg"] = json!("RSA-OAEP");
        let p = parse(vec![
            enc,
            ops,
            hs,
            wrong_alg,
            oaep,
            json!({"kty": "oct", "k": "c2VjcmV0", "kid": "sym"}),
            json!({"kty": "EC", "crv": "P-521", "x": b64(&[1; 66]), "y": b64(&[1; 66])}),
            json!({"kty": "EC", "crv": "P-256", "x": b64(&[1; 31]), "y": b64(&[2; 32])}),
            json!({"kty": "EC", "crv": "P-256", "x": "!!", "y": b64(&[2; 32])}),
            json!({"kty": "OKP", "crv": "Ed25519", "x": b64(&[3; 31])}),
            rsa("small", 1024),
            rsa("huge", 16384),
            json!({"kty": "RSA", "n": "AQAB"}),
            json!({"kty": "XYZ"}),
            json!({"kid": 5, "kty": "RSA", "n": b64(&[1; 256]), "e": "AQAB"}),
            json!("not an object"),
            json!(null),
        ]);
        assert!(p.keys.is_empty(), "{:?}", p.keys);
        assert_eq!(p.skipped.len(), 17);
    }

    #[test]
    fn rejects_documents_without_keys() {
        assert!(parse_jwks(b"not json").is_err());
        assert!(parse_jwks(b"{}").is_err());
        assert!(parse_jwks(b"{\"keys\": {}}").is_err());
        assert!(parse_jwks(b"[]").is_err());
        assert!(parse_jwks(b"{\"keys\": []}").unwrap().keys.is_empty());
    }

    #[test]
    fn caps_the_number_of_keys() {
        let keys = (0..MAX_KEYS + 5)
            .map(|i| ec_p256(&format!("k{i}")))
            .collect();
        let p = parse(keys);
        assert_eq!(p.keys.len(), MAX_KEYS);
        assert_eq!(p.skipped.len(), 5);
    }

    #[test]
    fn lookup_by_kid_and_alg() {
        let p = parse(vec![ec_p256("a"), rsa("b", 2048)]);
        let set = KeySet {
            keys: p.keys,
            fetched_at: Some(Instant::now()),
            cache_max_age: None,
        };
        assert!(matches!(
            set.find(Some("a"), Algorithm::ES256),
            KeyLookup::Found(_)
        ));
        assert!(matches!(
            set.find(Some("b"), Algorithm::PS256),
            KeyLookup::Found(_)
        ));
        assert!(matches!(
            set.find(Some("a"), Algorithm::RS256),
            KeyLookup::AlgMismatch
        ));
        assert!(matches!(
            set.find(Some("b"), Algorithm::ES256),
            KeyLookup::AlgMismatch
        ));
        assert!(matches!(
            set.find(Some("zz"), Algorithm::ES256),
            KeyLookup::UnknownKid
        ));
        assert!(matches!(
            set.find(None, Algorithm::ES256),
            KeyLookup::Ambiguous
        ));
        assert!(matches!(
            KeySet::default().find(Some("a"), Algorithm::ES256),
            KeyLookup::Empty
        ));
    }

    #[test]
    fn lookup_without_kid_needs_exactly_one_key() {
        let p = parse(vec![ec_p256("a")]);
        let set = KeySet {
            keys: p.keys,
            ..KeySet::default()
        };
        assert!(matches!(
            set.find(None, Algorithm::ES256),
            KeyLookup::Found(_)
        ));
        assert!(matches!(
            set.find(None, Algorithm::ES384),
            KeyLookup::AlgMismatch
        ));
    }

    #[test]
    fn duplicate_kids_pick_the_compatible_key() {
        let p = parse(vec![ec_p256("same"), rsa("same", 2048)]);
        let set = KeySet {
            keys: p.keys,
            ..KeySet::default()
        };
        match set.find(Some("same"), Algorithm::RS256) {
            KeyLookup::Found(k) => assert_eq!(k.kind, KeyKind::Rsa),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bit_lengths() {
        assert_eq!(bit_length(&[]), 0);
        assert_eq!(bit_length(&[0, 0]), 0);
        assert_eq!(bit_length(&[1]), 1);
        assert_eq!(bit_length(&[0, 0x80, 0]), 16);
        assert_eq!(bit_length(&[0xff; 256]), 2048);
    }

    #[test]
    fn cache_control() {
        let d = |v: &[&str]| parse_cache_control(v.iter().copied());
        assert_eq!(d(&[]), None);
        assert_eq!(d(&["public, max-age=300"]), Some(Duration::from_secs(300)));
        assert_eq!(d(&["MAX-AGE = \"60\""]), Some(Duration::from_secs(60)));
        assert_eq!(
            d(&["max-age=300", "max-age=100"]),
            Some(Duration::from_secs(100))
        );
        assert_eq!(d(&["no-cache"]), Some(Duration::ZERO));
        assert_eq!(d(&["max-age=abc, private"]), None);
        assert_eq!(d(&["s-maxage=10"]), None);
        assert_eq!(d(&["max-age=-5"]), None);
    }

    proptest! {
        #[test]
        fn arbitrary_documents_never_panic(body in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse_jwks(&body);
        }

        #[test]
        fn arbitrary_keys_never_panic(
            kty in prop_oneof![
                Just("RSA".to_string()),
                Just("EC".to_string()),
                Just("OKP".to_string()),
                Just("oct".to_string()),
                ".{0,4}",
            ],
            crv in prop_oneof![
                Just("P-256".to_string()),
                Just("P-384".to_string()),
                Just("Ed25519".to_string()),
                ".{0,6}",
            ],
            x in proptest::collection::vec(any::<u8>(), 0..70),
            n in proptest::collection::vec(any::<u8>(), 0..300),
            alg in proptest::option::of(".{0,6}"),
        ) {
            let mut key = json!({"kty": kty, "crv": crv, "x": b64(&x), "y": b64(&x), "n": b64(&n), "e": "AQAB"});
            if let Some(a) = alg {
                key["alg"] = json!(a);
            }
            let _ = parse(vec![key]);
        }

        #[test]
        fn arbitrary_cache_control_never_panics(v in ".{0,80}") {
            let _ = parse_cache_control([v.as_str()]);
        }
    }
}

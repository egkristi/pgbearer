//! Serde helpers for human-readable durations such as `"30s"`, `"5m"`, `"1h"`.
//!
//! Integers are accepted as seconds.

use std::time::Duration;

use serde::de::{self, Deserializer, Visitor};
use serde::{Deserialize, Serializer};

/// Deserialize a [`Duration`] from `"5m"`-style strings or integer seconds.
pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_any(DurationVisitor)
}

/// Serialize a [`Duration`] as a humantime string.
pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&humantime::format_duration(*value).to_string())
}

struct DurationVisitor;

impl<'de> Visitor<'de> for DurationVisitor {
    type Value = Duration;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a duration such as \"30s\", \"5m\", \"1h\", or an integer number of seconds")
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Duration, E> {
        Ok(Duration::from_secs(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Duration, E> {
        u64::try_from(v)
            .map(Duration::from_secs)
            .map_err(|_| E::custom("duration must not be negative"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Duration, E> {
        parse(v).map_err(E::custom)
    }
}

/// Parse a human-readable duration.
pub fn parse(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    if let Ok(secs) = s.parse::<u64>() {
        return Ok(Duration::from_secs(secs));
    }
    humantime::parse_duration(s).map_err(|e| format!("invalid duration {s:?}: {e}"))
}

/// Serde helpers for `Option<Duration>`.
pub mod option {
    use super::*;

    /// Deserialize an optional duration.
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wrapper(#[serde(deserialize_with = "super::deserialize")] Duration);
        Option::<Wrapper>::deserialize(deserializer).map(|o| o.map(|w| w.0))
    }

    /// Serialize an optional duration.
    pub fn serialize<S>(value: &Option<Duration>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(d) => super::serialize(d, serializer),
            None => serializer.serialize_none(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_common_forms() {
        assert_eq!(parse("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse("1h 30m"), Ok(Duration::from_secs(5400)));
        assert_eq!(parse("200ms"), Ok(Duration::from_millis(200)));
        assert_eq!(parse("42"), Ok(Duration::from_secs(42)));
        assert!(parse("soon").is_err());
    }
}

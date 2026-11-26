//! Provider configuration and response rules for the Windows and Linux
//! transport (desktop-approval-spec D-2), ported from the macOS/Android
//! adapters (`ProviderRules.kt`, `ProviderSettings.swift`). Pure: no I/O.
use serde_json::{Map, Value};

pub const MAX_REQUEST: usize = 16_384;
pub const MAX_RESPONSE: usize = 1_048_576;
pub const ALLOWED_STATUS: [u16; 7] = [200, 400, 403, 409, 422, 429, 503];

/// A provider endpoint: https, a host, an optional port, no userinfo, query
/// or fragment, path "", "/" or "/v1/companion"; always used as /v1/companion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub host: String,
    pub port: u16,
}
impl Endpoint {
    pub fn parse(text: &str) -> Option<Self> {
        if text.len() > 2048 || text.chars().any(|c| c.is_whitespace() || c == '\\') {
            return None;
        }
        let rest = text.strip_prefix("https://")?;
        let (authority, path) = match rest.find('/') {
            Some(index) => rest.split_at(index),
            None => (rest, ""),
        };
        if !["", "/", "/v1/companion"].contains(&path)
            || authority.contains(['@', '?', '#'])
            || authority.is_empty()
        {
            return None;
        }
        let bracketed = authority.starts_with('[');
        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (host, after) = inner.split_once(']')?;
            (host, after)
        } else {
            match authority.rsplit_once(':') {
                Some((host, _)) => (host, &authority[host.len()..]),
                None => (authority, ""),
            }
        };
        let port = match port {
            "" => 443,
            port => {
                let digits = port.strip_prefix(':')?;
                if digits.is_empty()
                    || digits.len() > 5
                    || !digits.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                digits.parse::<u16>().ok().filter(|p| *p > 0)?
            }
        };
        // Only a bracketed IPv6 literal may contain ':'.
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && (bracketed || !host.contains(':'))
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
        valid_host.then(|| Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
    pub fn url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 443 {
            format!("https://{host}/v1/companion")
        } else {
            format!("https://{host}:{}/v1/companion", self.port)
        }
    }
}

/// A JSON object whose members (at any depth) are unique, as the other
/// platforms' parsers require; `None` for anything else.
pub fn parse(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice::<Strict>(body).ok()?.0 {
        Value::Object(map) => Some(map),
        _ => None,
    }
}
struct Strict(Value);
impl<'de> serde::Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate members")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E>(self, v: f64) -> Result<Strict, E> {
                Ok(Strict(
                    serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
                ))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.into())))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Strict, A::Error> {
                let mut items = Vec::new();
                while let Some(Strict(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(Strict(Value::Array(items)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if out.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate member"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        de.deserialize_any(Visitor)
    }
}
fn int(value: Option<&Value>) -> Option<u64> {
    value?.as_u64()
}
pub fn valid_hex(value: &str, count: usize) -> bool {
    value.len() == count
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
pub fn valid_request_id(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Only an exact v1 unlock (no other members) gets the longer wait.
pub fn timeout_seconds(body: &[u8]) -> u64 {
    let Some(json) = parse(body) else { return 5 };
    let password = json.get("password").and_then(Value::as_str);
    match password {
        Some(p)
            if json.len() == 3
                && json.get("command").and_then(Value::as_str) == Some("unlock")
                && int(json.get("version")) == Some(1)
                && !p.is_empty()
                && p.len() <= 4096 =>
        {
            60
        }
        _ => 5,
    }
}

/// A 200 never carries `error`; any other status is the exact v1 error
/// envelope whose error maps to that status.
pub fn accepts_response(
    status: u16,
    content_type: Option<&str>,
    content_encoding: Option<&str>,
    body: &[u8],
) -> bool {
    if !ALLOWED_STATUS.contains(&status) || body.len() > MAX_RESPONSE || content_encoding.is_some()
    {
        return false;
    }
    let media = content_type
        .and_then(|t| t.split(';').next())
        .map(|t| t.trim().to_ascii_lowercase());
    if media.as_deref() != Some("application/json") {
        return false;
    }
    let Some(json) = parse(body) else {
        return false;
    };
    if status == 200 {
        return !json.contains_key("error");
    }
    let expected = match json.get("error").and_then(Value::as_str) {
        Some("invalid_request") => 400,
        Some("unauthorized") => 403,
        Some("stale") => 409,
        Some("authentication_failed") => 422,
        Some("rate_limited") => 429,
        Some("unavailable") => 503,
        _ => return false,
    };
    json.len() == 2 && int(json.get("version")) == Some(1) && expected == status
}

#[cfg(test)]
#[path = "rules_tests.rs"]
mod tests;

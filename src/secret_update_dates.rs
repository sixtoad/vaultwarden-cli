//! Date members compared as instants: Vaultwarden 1.36 re-serializes the dates
//! it parses (`2026-11-22T01:02:55.659Z` is stored as `…55.659000Z`), so the
//! stored string is not the sent one. Everything else is compared byte-exact.
use serde_json::Value;

/// Members whose value is an RFC 3339 date the server may re-serialize:
/// password history `lastUsedDate`, `login.passwordRevisionDate` and a
/// passkey's `creationDate`.
const DATE_MEMBERS: [&str; 3] = ["lastUsedDate", "passwordRevisionDate", "creationDate"];

/// Seconds and nanoseconds since 1970-01-01T00:00:00Z of an RFC 3339
/// date-time (`T`, 0 to 9 fractional digits, `Z` or `±HH:MM`). Anything else,
/// including a leap second or an impossible date, is `None`.
fn instant(text: &str) -> Option<(i64, u32)> {
    let digits = |s: &str| -> Option<i64> {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse().ok())
            .flatten()
    };
    let b = text.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' {
        return None;
    }
    if b[16] != b':' {
        return None;
    }
    let (year, month, day) = (
        digits(&text[..4])?,
        digits(&text[5..7])?,
        digits(&text[8..10])?,
    );
    let (hour, minute) = (digits(&text[11..13])?, digits(&text[14..16])?);
    let second = digits(&text[17..19])?;
    let mut rest = &text[19..];
    let mut nanos = 0_u32;
    if let Some(fraction) = rest.strip_prefix('.') {
        let end = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        if end == 0 || end > 9 {
            return None;
        }
        let scaled = format!("{:0<9}", &fraction[..end]);
        nanos = u32::try_from(digits(&scaled)?).ok()?;
        rest = &fraction[end..];
    }
    let offset = match rest.as_bytes() {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let (h, m) = (digits(&rest[1..3])?, digits(&rest[4..6])?);
            if h > 23 || m > 59 {
                return None;
            }
            let minutes = h * 60 + m;
            if *sign == b'+' { minutes } else { -minutes }
        }
        _ => return None,
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let valid_day = usize::try_from(month - 1)
        .ok()
        .and_then(|index| month_days.get(index))
        .is_some_and(|&last| (1..=last).contains(&day));
    if !valid_day || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    // Days since 1970-01-01 from a civil date (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + day_of_year;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset * 60;
    Some((seconds, nanos))
}

/// A date member is preserved when the stored value is the sent one, or both
/// are RFC 3339 dates of the same instant (any fractional precision or offset).
#[must_use]
pub fn same_instant(sent: &Value, stored: &Value) -> bool {
    if sent == stored {
        return true;
    }
    match (
        sent.as_str().and_then(instant),
        stored.as_str().and_then(instant),
    ) {
        (Some(sent), Some(stored)) => sent == stored,
        _ => false,
    }
}

/// Byte-exact JSON equality, except that [`DATE_MEMBERS`] compare by instant.
#[must_use]
pub fn same_json(sent: &Value, stored: &Value) -> bool {
    match (sent, stored) {
        (Value::Object(sent), Value::Object(stored)) => {
            sent.len() == stored.len()
                && sent.iter().all(|(key, value)| {
                    stored.get(key).is_some_and(|other| {
                        if DATE_MEMBERS.contains(&key.as_str()) {
                            same_instant(value, other)
                        } else {
                            same_json(value, other)
                        }
                    })
                })
        }
        (Value::Array(sent), Value::Array(stored)) => {
            sent.len() == stored.len() && sent.iter().zip(stored).all(|(a, b)| same_json(a, b))
        }
        _ => sent == stored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dates_compare_as_instants_at_any_precision_or_offset() {
        let sent = json!("2026-11-22T01:02:55.659Z");
        for stored in [
            "2026-11-22T01:02:55.659000Z",
            "2026-11-22T01:02:55.659000000Z",
            "2026-11-22T02:02:55.659+01:00",
            "2026-11-21T23:32:55.659-01:30",
        ] {
            assert!(same_instant(&sent, &json!(stored)), "{stored}");
        }
        assert!(same_instant(
            &json!("2026-01-01T00:00:00Z"),
            &json!("2026-01-01T00:00:00.000000Z")
        ));
        assert!(same_instant(&Value::Null, &Value::Null));
        for stored in [
            json!("2026-11-22T01:02:55.660000Z"),
            json!("2026-11-22T01:02:55.659001Z"),
            json!("2026-11-22T01:02:56.659Z"),
            json!("2026-11-23T01:02:55.659Z"),
            json!("2026-11-22T01:02:55.659+01:00"),
            json!("2026-11-22 01:02:55.659Z"),
            json!("2026-11-22T01:02:55.Z"),
            json!("2026-11-22T01:02:55.6590000000Z"),
            json!("2026-11-22T01:02:55.659"),
            json!("2026-02-30T01:02:55.659Z"),
            json!("2026-11-22T24:02:55.659Z"),
            json!("2026-11-22T01:02:60.659Z"),
            json!("garbage"),
            Value::Null,
            json!(1),
        ] {
            assert!(!same_instant(&sent, &stored), "{stored}");
        }
        // An unparsable sent date never equals a different stored string.
        assert!(!same_instant(
            &json!("soon"),
            &json!("2026-11-22T01:02:55.659Z")
        ));
        assert_eq!(instant("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(
            instant("2000-02-29T00:00:00.5Z"),
            Some((951_782_400, 500_000_000))
        );
        assert_eq!(instant("1900-02-29T00:00:00Z"), None);
    }

    #[test]
    fn only_date_members_are_compared_by_instant() {
        let sent = json!({"password": "2.a|b|c", "lastUsedDate": "2026-11-22T01:02:55.659Z",
            "nested": [{"creationDate": "2026-11-01T00:00:00.000Z"}]});
        let stored = json!({"password": "2.a|b|c", "lastUsedDate": "2026-11-22T01:02:55.659000Z",
            "nested": [{"creationDate": "2026-11-01T00:00:00Z"}]});
        assert!(same_json(&sent, &stored));
        let mut other = stored.clone();
        other["password"] = json!("2.a|b|d");
        assert!(!same_json(&sent, &other));
        let mut other = stored.clone();
        other["note"] = json!("2026-11-22T01:02:55.659Z");
        assert!(!same_json(&sent, &other), "an added member");
        let mut dropped = stored.clone();
        dropped.as_object_mut().unwrap().remove("lastUsedDate");
        assert!(!same_json(&sent, &dropped), "a dropped date");
        let undated_sent = json!({"name": "2026-11-22T01:02:55.659Z"});
        let undated_stored = json!({"name": "2026-11-22T01:02:55.659000Z"});
        assert!(
            !same_json(&undated_sent, &undated_stored),
            "a non-date member stays byte-exact"
        );
        assert!(!same_json(&json!([sent.clone()]), &json!([])));
    }
}

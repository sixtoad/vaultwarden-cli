use super::*;

#[test]
fn endpoints_are_https_to_the_companion_path_only() {
    let url = |text: &str| Endpoint::parse(text).map(|e| e.url());
    assert_eq!(
        url("https://p.example:8443").unwrap(),
        "https://p.example:8443/v1/companion"
    );
    assert_eq!(
        url("https://P.Example/").unwrap(),
        "https://p.example/v1/companion"
    );
    assert_eq!(
        url("https://127.0.0.1/v1/companion").unwrap(),
        "https://127.0.0.1/v1/companion"
    );
    assert_eq!(
        url("https://[::1]:9/").unwrap(),
        "https://[::1]:9/v1/companion"
    );
    assert_eq!(
        url("https://p.example:443").unwrap(),
        "https://p.example/v1/companion"
    );
    let long = format!("https://{}", "a".repeat(2050));
    for bad in [
        "http://p.example",
        "https://",
        "https://u:p@p.example",
        "https://p.example/?a=1",
        "https://p.example/#x",
        "https://p.example/other",
        "https://p.example /",
        "https://p.example\\x",
        "https://p.example:0",
        "ftp://p.example",
        "https://p.example/v1/companion/",
        "https://p.example:65536",
        "https://p.example:",
        "https://p.example:+1",
        "https://::1",
        "https://[::1",
        "https://p_example",
        long.as_str(),
    ] {
        assert!(Endpoint::parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn only_an_exact_unlock_waits_longer() {
    assert_eq!(
        timeout_seconds(br#"{"command":"unlock","password":"pw","version":1}"#),
        60
    );
    for body in [
        r#"{"command":"unlock","password":"","version":1}"#,
        r#"{"command":"unlock","password":"pw","version":1,"x":1}"#,
        r#"{"command":"unlock","password":"pw","version":1.0}"#,
        r#"{"command":"status","password":"pw","version":1}"#,
        r#"{"command":"unlock","password":"pw","password":"x","version":1}"#,
        "not json",
    ] {
        assert_eq!(timeout_seconds(body.as_bytes()), 5, "{body}");
    }
}

#[test]
fn status_and_body_form_one_response() {
    let json = Some("application/json");
    assert!(accepts_response(200, json, None, br#"{"version":1}"#));
    assert!(accepts_response(
        200,
        Some("application/json; charset=utf-8"),
        None,
        b"{}"
    ));
    assert!(!accepts_response(200, json, None, br#"{"error":"stale"}"#));
    assert!(accepts_response(
        409,
        json,
        None,
        br#"{"version":1,"error":"stale"}"#
    ));
    assert!(!accepts_response(
        400,
        json,
        None,
        br#"{"version":1,"error":"stale"}"#
    ));
    assert!(!accepts_response(
        503,
        json,
        None,
        br#"{"version":1,"error":"unavailable","x":1}"#
    ));
    assert!(!accepts_response(500, json, None, b"{}"));
    assert!(!accepts_response(302, json, None, b"{}"));
    assert!(!accepts_response(200, Some("text/html"), None, b"{}"));
    assert!(!accepts_response(200, None, None, b"{}"));
    assert!(!accepts_response(200, json, Some("gzip"), b"{}"));
    assert!(!accepts_response(200, json, None, b"[]"));
    assert!(!accepts_response(200, json, None, br#"{"a":1,"a":2}"#));
    assert!(!accepts_response(
        200,
        json,
        None,
        &vec![b' '; MAX_RESPONSE + 1]
    ));
}

#[test]
fn duplicate_members_are_refused_at_any_depth() {
    assert!(parse(br#"{"a":{"b":1,"b":2}}"#).is_none());
    assert!(parse(br#"{"a":[{"b":1,"b":2}]}"#).is_none());
    assert!(parse(br#"{"a":[1,{"b":null}],"c":-1.5}"#).is_some());
}

use super::*;
use crate::desktop::transport::tests::{http, pin, serve};

const P12: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/client-3des.p12"
);
const ID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

struct Setup {
    _dir: tempfile::TempDir,
    service: Service,
    ca: String,
}
fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("ca.der");
    std::fs::write(&ca, crate::desktop::transport::tests::server_ca()).unwrap();
    Setup {
        service: Service::new(Store::new(dir.path().join("provider"))),
        ca: ca.to_str().unwrap().into(),
        _dir: dir,
    }
}
impl Setup {
    fn configure(&self, port: u16) -> Result<Configuration, &'static str> {
        self.service.setup(
            &format!("https://127.0.0.1:{port}"),
            &pin(),
            &self.ca,
            P12,
            "synthetic-p12-passphrase",
        )
    }
}

#[test]
fn setup_validates_everything_before_writing() {
    let s = setup();
    assert_eq!(s.service.configuration().unwrap(), Configuration::default());
    let bad = [
        (
            "http://127.0.0.1",
            pin(),
            s.ca.clone(),
            P12.to_owned(),
            "synthetic-p12-passphrase",
        ),
        (
            "https://127.0.0.1",
            "A".repeat(64),
            s.ca.clone(),
            P12.to_owned(),
            "synthetic-p12-passphrase",
        ),
        (
            "https://127.0.0.1",
            pin(),
            "ca.der".into(),
            P12.to_owned(),
            "synthetic-p12-passphrase",
        ),
        (
            "https://127.0.0.1",
            pin(),
            P12.to_owned(),
            P12.to_owned(),
            "synthetic-p12-passphrase",
        ),
        (
            "https://127.0.0.1",
            pin(),
            s.ca.clone(),
            s.ca.clone(),
            "synthetic-p12-passphrase",
        ),
        (
            "https://127.0.0.1",
            pin(),
            s.ca.clone(),
            P12.to_owned(),
            "wrong",
        ),
    ];
    for (endpoint, pin, ca, identity, passphrase) in bad {
        assert!(
            s.service
                .setup(endpoint, &pin, &ca, &identity, passphrase)
                .is_err(),
            "{endpoint} {ca} {passphrase}"
        );
        assert_eq!(s.service.configuration().unwrap(), Configuration::default());
    }
    let configured = s.configure(8443).unwrap();
    assert!(configured.configured);
    assert_eq!(configured.endpoint, "https://127.0.0.1:8443/v1/companion");
    assert_eq!(
        configured.fingerprint,
        crate::desktop::transport::tests::identity().fingerprint()
    );
    assert_eq!(s.service.configuration().unwrap(), configured);
}

#[test]
fn a_sent_decision_stays_uncertain_and_blocks_setup_until_settled() {
    let s = setup();
    let (port, server) = serve(Some(http(
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"version":1,"status":{"status":"denied"}}"#,
    )));
    s.configure(port).unwrap();
    let decision = format!(
        r#"{{"version":1,"command":"decision","request_id":"{ID}","ticket":"{}","decision":"deny"}}"#,
        "d".repeat(64)
    );
    assert!(s.service.send(decision.as_bytes(), true).is_ok());
    server.join().unwrap().unwrap();
    assert_eq!(s.service.configuration().unwrap().uncertain_id, ID);
    // Only that request's status may be sent, and setup is refused.
    assert!(s
        .service
        .send(br#"{"version":1,"command":"list"}"#, true)
        .is_err());
    assert!(s.configure(port).is_err());
    assert!(s
        .service
        .settle("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
        .is_err());
    s.service.settle(ID).unwrap();
    assert_eq!(s.service.configuration().unwrap().uncertain_id, "");
    assert!(s.configure(port).is_ok());
}

/// Issue 48 phase 2: the Windows/Linux transport carries a version 2 approve
/// decision, its `update-review.v1` capability and Windows Hello proof, byte
/// for byte (the Rust session builds it; the transport never rewrites it).
#[test]
fn an_update_approval_reaches_the_provider_with_its_capability() {
    let s = setup();
    let (port, server) = serve(Some(http(
        "200 OK",
        "Content-Type: application/json\r\n",
        r#"{"version":2,"status":{"status":"approved"}}"#,
    )));
    s.configure(port).unwrap();
    let decision = serde_json::json!({
        "version": 2, "command": "decision", "request_id": ID,
        "ticket": "d".repeat(64), "decision": "approve",
        "proof": {"key_id": "e".repeat(64), "signature": "c2ln", "authenticator_data": "ZGF0YQ"},
        "capabilities": ["update-review.v1"],
    })
    .to_string();
    assert!(s.service.send(decision.as_bytes(), true).is_ok());
    let (request, _) = server.join().unwrap().unwrap();
    assert!(request.ends_with(decision.as_bytes()));
    assert_eq!(s.service.configuration().unwrap().uncertain_id, ID);
}

#[test]
fn a_failed_exchange_keeps_the_marker_and_frees_the_slot() {
    let s = setup();
    s.configure(1).unwrap();
    let decision =
        format!(r#"{{"version":1,"command":"decision","request_id":"{ID}","decision":"deny"}}"#);
    assert!(s.service.send(decision.as_bytes(), true).is_err());
    assert_eq!(s.service.configuration().unwrap().uncertain_id, ID);
    // The slot is free again: the next status attempt reaches the transport.
    let status = format!(r#"{{"version":1,"command":"status","request_id":"{ID}"}}"#);
    assert_eq!(s.service.send(status.as_bytes(), true), Err("transport"));
}

#[test]
fn an_administrative_ticket_dies_with_the_foreground() {
    let s = setup();
    let client = "c".repeat(64);
    let reply = format!(
        r#"{{"version":2,"identity":{{"kind":"approval_client","id":"{client}"}},"action_id":"{ID}","ticket":"{}","generation":1,"valid_for_seconds":55}}"#,
        "d".repeat(64)
    );
    let (port, server) = serve(Some(http(
        "200 OK",
        "Content-Type: application/json\r\n",
        &reply,
    )));
    s.configure(port).unwrap();
    let prepare = format!(
        r#"{{"version":2,"command":"identity_prepare","target":{{"kind":"approval_client","id":"{client}"}}}}"#
    );
    assert!(s.service.send(prepare.as_bytes(), true).is_ok());
    server.join().unwrap();
    s.service.invalidate();
    let revoke = format!(
        r#"{{"version":2,"command":"identity_revoke","target":{{"kind":"approval_client","id":"{client}"}},"action_id":"{ID}","ticket":"{}","password":"pw"}}"#,
        "d".repeat(64)
    );
    assert_eq!(
        s.service.send(revoke.as_bytes(), true),
        Err("provider_configuration_invalid")
    );
    // Refused before anything was persisted.
    assert_eq!(s.service.configuration().unwrap().management_recovery, "");
}

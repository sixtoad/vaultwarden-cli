//! Loopback mutual TLS with the repository's synthetic fixtures: the
//! provider leaf (IP SAN 127.0.0.1) signed by its CA, and the companion
//! client identity from a PKCS#12.
use super::*;
use rustls::pki_types::pem::PemObject;
use std::net::TcpListener;
use std::thread::JoinHandle;

const SERVER: &[u8] = include_bytes!("../../../../tests/fixtures/provider-tls/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../../../tests/fixtures/provider-tls/server-key.pem");
const SERVER_CA: &[u8] = include_bytes!("../../../../tests/fixtures/provider-tls/ca.pem");
const CLIENT_CA: &[u8] = include_bytes!("../../../../tests/companion-tls/ca.pem");
const P12: &[u8] = include_bytes!("../../tests/fixtures/client-3des.p12");

pub(crate) fn der(pem: &[u8]) -> Vec<u8> {
    CertificateDer::from_pem_slice(pem).unwrap().to_vec()
}
pub(crate) fn pin() -> String {
    super::super::identity::hex(&Sha256::digest(der(SERVER)))
}
pub(crate) fn identity() -> ClientIdentity {
    ClientIdentity::from_pkcs12(P12, "synthetic-p12-passphrase").unwrap()
}
pub(crate) fn server_ca() -> Vec<u8> {
    der(SERVER_CA)
}

/// Serves one connection: records the request and the client leaf
/// fingerprint, then answers `response` verbatim (`None`: never answers).
/// The request bytes and the client leaf fingerprint the server saw.
pub(crate) type Seen = Option<(Vec<u8>, String)>;
pub(crate) fn serve(response: Option<Vec<u8>>) -> (u16, JoinHandle<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // A client that never connects (refused earlier) ends the server.
        listener.set_nonblocking(true).ok()?;
        let started = Instant::now();
        let socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && started.elapsed() < Duration::from_secs(10) =>
                {
                    std::thread::sleep(Duration::from_millis(20))
                }
                Err(_) => return None,
            }
        };
        socket.set_nonblocking(false).ok()?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(CertificateDer::from(der(CLIENT_CA))).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider.clone(),
        )
        .build()
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![CertificateDer::from(der(SERVER))],
                PrivateKeyDer::from_pem_slice(SERVER_KEY).unwrap(),
            )
            .unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .ok()?;
        let mut tls = rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            socket,
        );
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            tls.read_exact(&mut byte).ok()?;
            request.push(byte[0]);
        }
        let head = String::from_utf8(request.clone()).ok()?;
        let length: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))?
            .trim()
            .parse()
            .ok()?;
        let mut body = vec![0; length];
        tls.read_exact(&mut body).ok()?;
        request.extend_from_slice(&body);
        let client =
            super::super::identity::hex(&Sha256::digest(tls.conn.peer_certificates()?.first()?));
        match response {
            Some(response) => {
                tls.write_all(&response).ok()?;
                tls.conn.send_close_notify();
                tls.flush().ok()?;
            }
            None => std::thread::sleep(Duration::from_secs(7)),
        }
        Some((request, client))
    });
    (port, handle)
}
pub(crate) fn http(status: &str, headers: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}
fn exchange(
    host: &str,
    port: u16,
    ca: &[u8],
    pin: &str,
    body: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let identity = identity();
    let endpoint = Endpoint {
        host: host.into(),
        port,
    };
    send(
        &Exchange {
            endpoint: &endpoint,
            ca,
            pin,
            identity: &identity,
        },
        body,
    )
}
const JSON: &str = "Content-Type: application/json\r\n";
const LIST: &[u8] = br#"{"version":1,"command":"list"}"#;

#[test]
fn a_pinned_exchange_presents_the_client_identity_and_returns_the_body() {
    let (port, server) = serve(Some(http("200 OK", JSON, r#"{"version":1,"requests":[]}"#)));
    let reply = exchange("127.0.0.1", port, &server_ca(), &pin(), LIST).unwrap();
    assert_eq!(reply, br#"{"version":1,"requests":[]}"#);
    let (request, client) = server.join().unwrap().unwrap();
    assert_eq!(client, identity().fingerprint());
    let text = String::from_utf8(request).unwrap();
    assert!(
        text.starts_with("POST /v1/companion HTTP/1.1\r\n"),
        "{text}"
    );
    assert!(text.contains(&format!("\r\nHost: 127.0.0.1:{port}\r\n")));
    assert!(text.contains("\r\nContent-Type: application/json\r\n"));
    assert!(text.ends_with(std::str::from_utf8(LIST).unwrap()));
}

#[test]
fn an_error_envelope_with_its_status_is_a_response() {
    let (port, _server) = serve(Some(http(
        "409 Conflict",
        JSON,
        r#"{"version":1,"error":"stale"}"#,
    )));
    assert_eq!(
        exchange("127.0.0.1", port, &server_ca(), &pin(), LIST).unwrap(),
        br#"{"version":1,"error":"stale"}"#
    );
}

#[test]
fn trust_needs_the_configured_ca_the_host_and_the_exact_leaf() {
    let wrong_pin = "0".repeat(64);
    let cases: [(&str, Vec<u8>, &str); 3] = [
        ("127.0.0.1", server_ca(), wrong_pin.as_str()),
        ("127.0.0.1", der(CLIENT_CA), &pin()),
        ("localhost", server_ca(), &pin()),
    ];
    for (host, ca, pin) in cases {
        let (port, server) = serve(Some(http("200 OK", JSON, "{}")));
        assert_eq!(
            exchange(host, port, &ca, pin, LIST),
            Err(TransportError::Transport),
            "{host}"
        );
        // The server never received a request.
        assert!(server.join().unwrap().is_none(), "{host}");
    }
}

#[test]
fn malformed_or_oversized_responses_are_refused() {
    let cases = [
        http("200 OK", "", "{}"),
        http("200 OK", "Content-Type: text/html\r\n", "{}"),
        http("200 OK", "Content-Type: application/json\r\nContent-Encoding: gzip\r\n", "{}"),
        http("500 Internal", JSON, "{}"),
        http("302 Found", "Content-Type: application/json\r\nLocation: https://x/\r\n", "{}"),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{}".to_vec(),
        b"HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
        http("200 OK", "Content-Type: application/json\r\nContent-Length: 2\r\n", "{}"),
    ];
    for response in cases {
        let (port, _server) = serve(Some(response.clone()));
        assert_eq!(
            exchange("127.0.0.1", port, &server_ca(), &pin(), LIST),
            Err(TransportError::InvalidResponse),
            "{}",
            String::from_utf8_lossy(&response)
        );
    }
    let (port, _server) = serve(Some(
        format!(
            "HTTP/1.1 200 OK\r\n{JSON}Content-Length: {}\r\n\r\n",
            MAX_RESPONSE + 1
        )
        .into_bytes(),
    ));
    assert_eq!(
        exchange("127.0.0.1", port, &server_ca(), &pin(), LIST),
        Err(TransportError::Oversized)
    );
    assert_eq!(
        exchange(
            "127.0.0.1",
            1,
            &server_ca(),
            &pin(),
            &vec![b' '; MAX_REQUEST + 1]
        ),
        Err(TransportError::Oversized)
    );
}

#[test]
fn a_silent_provider_times_out_after_five_seconds() {
    let (port, _server) = serve(None);
    let started = Instant::now();
    assert_eq!(
        exchange("127.0.0.1", port, &server_ca(), &pin(), LIST),
        Err(TransportError::Timeout)
    );
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_secs(4) && elapsed < Duration::from_secs(7),
        "{elapsed:?}"
    );
}

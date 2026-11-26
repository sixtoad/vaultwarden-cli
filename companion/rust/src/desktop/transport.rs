//! One pinned mutual-TLS POST of one body (desktop-approval-spec D-2): the
//! provider chain must validate against the configured CA alone, for the
//! endpoint host, within its validity, and its leaf DER must hash to the pin.
//! No system trust store, proxy, redirect, retry, cookie or compression.
use super::identity::ClientIdentity;
use super::rules::{self, Endpoint, MAX_REQUEST, MAX_RESPONSE};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Closed failure codes; never OS text, hosts, paths or certificate detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportError {
    Oversized,
    InvalidResponse,
    Timeout,
    Transport,
}
impl TransportError {
    pub fn code(self) -> &'static str {
        match self {
            Self::Oversized => "oversized",
            Self::InvalidResponse => "invalid_response",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
        }
    }
}

#[derive(Debug)]
struct Pinned {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    pin: String,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp, now)?;
        if super::identity::hex(&Sha256::digest(end_entity)) != self.pin {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub struct Exchange<'a> {
    pub endpoint: &'a Endpoint,
    pub ca: &'a [u8],
    pub pin: &'a str,
    pub identity: &'a ClientIdentity,
}

fn config(exchange: &Exchange<'_>) -> Option<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(exchange.ca.to_vec())).ok()?;
    let inner = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .build()
    .ok()?;
    let chain = exchange
        .identity
        .chain
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(exchange.identity.key.to_vec()));
    rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .ok()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            inner,
            pin: exchange.pin.into(),
        }))
        .with_client_auth_cert(chain, key)
        .ok()
}

struct Deadline {
    stream: TcpStream,
    deadline: Instant,
}
impl Deadline {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}
impl Read for Deadline {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(buf)
    }
}
impl Write for Deadline {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
fn io(error: std::io::Error) -> TransportError {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TransportError::Timeout,
        _ => TransportError::Transport,
    }
}

pub fn send(exchange: &Exchange<'_>, body: &[u8]) -> Result<Vec<u8>, TransportError> {
    if body.len() > MAX_REQUEST {
        return Err(TransportError::Oversized);
    }
    let timeout = Duration::from_secs(rules::timeout_seconds(body));
    let deadline = Instant::now() + timeout;
    let config = config(exchange).ok_or(TransportError::Transport)?;
    let name = ServerName::try_from(exchange.endpoint.host.clone())
        .map_err(|_| TransportError::Transport)?;
    let address = (exchange.endpoint.host.as_str(), exchange.endpoint.port)
        .to_socket_addrs()
        .map_err(|_| TransportError::Transport)?
        .next()
        .ok_or(TransportError::Transport)?;
    let stream = TcpStream::connect_timeout(&address, timeout).map_err(io)?;
    let connection = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|_| TransportError::Transport)?;
    let mut tls = rustls::StreamOwned::new(connection, Deadline { stream, deadline });
    let host = exchange
        .endpoint
        .url()
        .trim_start_matches("https://")
        .trim_end_matches("/v1/companion")
        .to_owned();
    let head = format!(
        "POST /v1/companion HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    let mut request = zeroize::Zeroizing::new(head.into_bytes());
    request.extend_from_slice(body);
    tls.write_all(&request).map_err(io)?;
    tls.flush().map_err(io)?;
    read_response(&mut tls)
}

/// HTTP/1.1 with a Content-Length; no transfer or content encoding.
fn read_response(stream: &mut impl Read) -> Result<Vec<u8>, TransportError> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 8192 {
            return Err(TransportError::InvalidResponse);
        }
        let mut byte = [0];
        stream.read_exact(&mut byte).map_err(io)?;
        head.push(byte[0]);
    }
    let head = std::str::from_utf8(&head).map_err(|_| TransportError::InvalidResponse)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.strip_prefix("HTTP/1.1 "))
        .and_then(|rest| rest.get(..3))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or(TransportError::InvalidResponse)?;
    let (mut length, mut content_type, mut encoding) = (None, None, None);
    for line in lines.filter(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(TransportError::InvalidResponse)?;
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" if length.is_none() => {
                length = Some(
                    value
                        .parse::<usize>()
                        .map_err(|_| TransportError::InvalidResponse)?,
                )
            }
            "content-length" | "transfer-encoding" => return Err(TransportError::InvalidResponse),
            "content-type" => content_type = Some(value.to_owned()),
            "content-encoding" => encoding = Some(value.to_owned()),
            _ => {}
        }
    }
    let length = length.ok_or(TransportError::InvalidResponse)?;
    if length > MAX_RESPONSE {
        return Err(TransportError::Oversized);
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).map_err(io)?;
    if !rules::accepts_response(status, content_type.as_deref(), encoding.as_deref(), &body) {
        return Err(TransportError::InvalidResponse);
    }
    Ok(body)
}

#[cfg(test)]
#[path = "transport_tests.rs"]
pub(crate) mod tests;

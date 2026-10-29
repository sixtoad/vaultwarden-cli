//! Request-local SSH agent. No key export, forwarding, or shared identities.
use crate::access::ports::{ExecutionControl, ExecutionError, SensitiveString};
use signature::{Signer, Verifier};
use ssh_key::{
    Algorithm, HashAlg, PrivateKey, PublicKey, Signature,
    encoding::{Decode, Encode},
};
#[cfg(target_os = "linux")]
use std::os::fd::OwnedFd;
use std::{
    fs::File,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
#[cfg(target_os = "linux")]
type Recipient = (u32, OwnedFd);
#[cfg(target_os = "macos")]
use super::native::Recipient;

const MAX_FRAME: usize = 32 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_MESSAGES: usize = 32;
#[cfg(test)]
thread_local! {
    static FAIL_SETUP: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    pub(super) static FAIL_UNLINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
fn rsa_bits(bytes: &[u8]) -> usize {
    let bytes = bytes.strip_prefix(&[0]).unwrap_or(bytes);
    bytes
        .first()
        .map_or(0, |first| bytes.len() * 8 - first.leading_zeros() as usize)
}

#[cfg(all(test, target_os = "macos"))]
thread_local! {static TEST_AFTER_PEER_VALIDATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const {std::cell::RefCell::new(None)};}
pub(crate) struct Agent {
    listener: Option<UnixListener>,
    directory: File,
    socket_identity: (u64, u64),
    socket_name: std::ffi::CString,
    key: Option<PrivateKey>,
    public: Vec<u8>,
    host: PublicKey,
    host_blob: Vec<u8>,
    user: String,
    recipient: Option<Recipient>,
    connection: Option<Connection>,
    consumed: bool,
    messages: usize,
}
struct Connection {
    stream: UnixStream,
    input: Zeroizing<Vec<u8>>,
    session: Option<Vec<u8>>,
    deadline: Instant,
}
fn invalid<T>(_: T) -> ExecutionError {
    ExecutionError::InvalidArguments
}
fn string(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}
fn framed(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len() + 4));
    string(&mut out, value);
    out
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, ExecutionError> {
        let (&byte, rest) = self
            .0
            .split_first()
            .ok_or(ExecutionError::InvalidArguments)?;
        self.0 = rest;
        Ok(byte)
    }
    fn uint(&mut self) -> Result<u32, ExecutionError> {
        let bytes = self.0.get(..4).ok_or(ExecutionError::InvalidArguments)?;
        let result = u32::from_be_bytes(bytes.try_into().map_err(invalid)?);
        self.0 = &self.0[4..];
        Ok(result)
    }
    fn string(&mut self) -> Result<&'a [u8], ExecutionError> {
        let size = self.uint()? as usize;
        let value = self.0.get(..size).ok_or(ExecutionError::InvalidArguments)?;
        self.0 = &self.0[size..];
        Ok(value)
    }
    fn end(&self) -> Result<(), ExecutionError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ExecutionError::InvalidArguments)
        }
    }
}
fn socket_path(
    directory: &File,
    name: &std::ffi::CStr,
) -> Result<std::path::PathBuf, ExecutionError> {
    #[cfg(target_os = "linux")]
    {
        Ok(
            std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .join(name.to_str().map_err(invalid)?),
        )
    }
    #[cfg(target_os = "macos")]
    {
        Ok(super::native::platform::descriptor_path(directory)?
            .join(name.to_str().map_err(invalid)?))
    }
}
impl Agent {
    pub(crate) fn bind(
        directory: File,
        path: &Path,
        host: PublicKey,
        user: String,
    ) -> Result<Self, ExecutionError> {
        let host_blob = host.to_bytes().map_err(invalid)?;
        if host_blob.len() > 16 * 1024
            || host
                .key_data()
                .rsa()
                .is_some_and(|rsa| rsa_bits(rsa.n().as_bytes()) > 8192)
        {
            return Err(ExecutionError::InvalidArguments);
        }
        // Validate the actual consumer-visible sockaddr length before descriptor-anchored bind.
        if path.as_os_str().as_encoded_bytes().len()
            >= if cfg!(target_os = "macos") { 104 } else { 108 }
        {
            return Err(ExecutionError::UnsafePath);
        }
        let socket_name = std::ffi::CString::new(
            path.file_name()
                .ok_or(ExecutionError::UnsafePath)?
                .as_encoded_bytes(),
        )
        .map_err(invalid)?;
        let anchored = socket_path(&directory, &socket_name)?;
        let listener = UnixListener::bind(&anchored).map_err(invalid)?;
        let metadata = std::fs::symlink_metadata(&anchored).map_err(invalid)?;
        let socket_identity = (metadata.dev(), metadata.ino());
        let agent = Self {
            listener: Some(listener),
            directory,
            socket_identity,
            socket_name,
            key: None,
            public: Vec::new(),
            host,
            host_blob,
            user,
            recipient: None,
            connection: None,
            consumed: false,
            messages: 0,
        };
        // From here Drop owns inode-checked cleanup on every setup error.
        #[cfg(test)]
        if FAIL_SETUP.with(|fail| fail.get()) {
            return Err(ExecutionError::UnsafePath);
        }
        std::fs::set_permissions(&anchored, std::fs::Permissions::from_mode(0o600))
            .map_err(invalid)?;
        agent
            .listener
            .as_ref()
            .ok_or(ExecutionError::Unavailable)?
            .set_nonblocking(true)
            .map_err(invalid)?;
        Ok(agent)
    }
    pub(crate) fn install(&mut self, key: SensitiveString) -> Result<(), ExecutionError> {
        if self.key.is_some()
            || self.consumed
            || key.expose().is_empty()
            || key.expose().len() > 64 * 1024
            || key.expose().contains('\0')
        {
            return Err(ExecutionError::InvalidArguments);
        }
        let key = PrivateKey::from_openssh(key.expose()).map_err(invalid)?;
        if key.is_encrypted()
            || !matches!(
                key.algorithm(),
                Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
            )
        {
            return Err(ExecutionError::InvalidArguments);
        }
        // Bound RSA work as well as encoded size; reject pathological moduli before signing.
        if let Some(rsa) = key.key_data().rsa() {
            let size = rsa_bits(rsa.public().n().as_bytes());
            if !(2048..=8192).contains(&size) {
                return Err(ExecutionError::InvalidArguments);
            }
        }
        self.public = key.public_key().to_bytes().map_err(invalid)?;
        self.key = Some(key);
        Ok(())
    }
    pub(crate) fn recipient(&mut self, recipient: Recipient) -> Result<(), ExecutionError> {
        if self.recipient.is_some() || self.consumed {
            return Err(ExecutionError::ExecutionFailed);
        }
        self.recipient = Some(recipient);
        Ok(())
    }
    #[cfg(target_os = "linux")]
    fn recipient_alive(&self) -> bool {
        self.recipient.as_ref().is_some_and(|(_, fd)| {
            let mut poll = libc::pollfd {
                fd: fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            unsafe { libc::poll(&mut poll, 1, 0) == 0 }
        })
    }
    #[cfg(target_os = "macos")]
    fn recipient_alive(&self) -> bool {
        // The native observer owns the unreaped direct-child lease until close().
        self.recipient.is_some()
    }
    fn recipient_peer(&self, stream: &UnixStream) -> bool {
        #[cfg(target_os = "macos")]
        {
            let valid = self
                .recipient
                .as_ref()
                .is_some_and(|recipient| recipient.peer(stream));
            #[cfg(test)]
            if valid {
                TEST_AFTER_PEER_VALIDATION.with(|hook| {
                    if let Some(after) = hook.borrow_mut().take() {
                        after();
                    }
                });
            }
            valid
        }
        #[cfg(target_os = "linux")]
        {
            let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&peer) as libc::socklen_t;
            (unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_PEERCRED,
                    (&mut peer as *mut libc::ucred).cast(),
                    &mut length,
                )
            }) == 0
                && length as usize == std::mem::size_of_val(&peer)
                && peer.uid == unsafe { libc::geteuid() }
                && self
                    .recipient
                    .as_ref()
                    .is_some_and(|(pid, _)| peer.pid > 0 && peer.pid as u32 == *pid)
        }
    }
    pub(crate) fn close(&mut self) {
        self.key.take();
        self.connection.take();
        self.listener.take();
        self.recipient.take();
        self.consumed = true;
        {
            let Ok(anchored) = socket_path(&self.directory, &self.socket_name) else {
                return;
            };
            if std::fs::symlink_metadata(anchored)
                .is_ok_and(|m| (m.dev(), m.ino()) == self.socket_identity)
            {
                #[cfg(test)]
                if FAIL_UNLINK.with(|fail| fail.get()) {
                    return;
                }
                unsafe {
                    libc::unlinkat(self.directory.as_raw_fd(), self.socket_name.as_ptr(), 0);
                }
            }
        }
    }
    /// One bounded nonblocking step, on the provider observation thread.
    pub(crate) fn poll(&mut self, control: &dyn ExecutionControl) -> Result<(), ExecutionError> {
        if self.consumed {
            return Ok(());
        }
        if !control.live() || !self.recipient_alive() {
            self.close();
            return Ok(());
        }
        if self.connection.is_none() {
            let Some(listener) = &self.listener else {
                return Ok(());
            };
            match listener.accept() {
                Ok((stream, _)) => {
                    let valid = self.recipient_peer(&stream);
                    if !valid {
                        return Ok(());
                    }
                    stream.set_nonblocking(true).map_err(invalid)?;
                    self.connection = Some(Connection {
                        stream,
                        input: Zeroizing::new(Vec::new()),
                        session: None,
                        deadline: Instant::now() + IO_TIMEOUT,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => {
                    self.close();
                    return Err(ExecutionError::ExecutionFailed);
                }
            }
        }
        let mut connection = self
            .connection
            .take()
            .ok_or(ExecutionError::ExecutionFailed)?;
        if Instant::now() >= connection.deadline {
            self.close();
            return Ok(());
        }
        // Drain a complete buffered frame before reading again: EOF on the
        // peer's write half must not discard already received pipelined work.
        let complete = connection.input.get(..4).is_some_and(|header| {
            let size = u32::from_be_bytes(header.try_into().expect("four-byte header")) as usize;
            size == 0 || size > MAX_FRAME || connection.input.len() >= size + 4
        });
        if !complete {
            let mut bytes = [0u8; 4096];
            match connection.stream.read(&mut bytes) {
                Ok(0) => {
                    self.close();
                    return Ok(());
                }
                Ok(n) => connection.input.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    self.close();
                    return Ok(());
                }
            }
        }
        if connection.input.len() < 4 {
            self.connection = Some(connection);
            return Ok(());
        }
        let size = u32::from_be_bytes(connection.input[..4].try_into().map_err(invalid)?) as usize;
        if size == 0 || size > MAX_FRAME || connection.input.len() > MAX_FRAME + 4 {
            self.close();
            return Ok(());
        }
        if connection.input.len() < size + 4 {
            self.connection = Some(connection);
            return Ok(());
        }
        self.messages += 1;
        if self.messages > MAX_MESSAGES {
            self.close();
            return Ok(());
        }
        let message = Zeroizing::new(connection.input[4..size + 4].to_vec());
        connection.input.drain(..size + 4);
        let result = self.answer(&message, &mut connection.session);
        let (response, signing) = result.unwrap_or_else(|_| (vec![5], false));
        let response = framed(&response);
        if signing {
            // The full durable authority/epoch/cancel/deadline check and bounded send
            // share the same release lock. Partial delivery also consumes authority;
            // no signature bytes are queued for a later, ungated flush.
            let result = control.release(&mut || {
                if !self.recipient_alive()
                    || !self.recipient_peer(&connection.stream)
                    || control.remaining().is_zero()
                {
                    return Err(ExecutionError::Cancelled);
                }
                self.consumed = true;
                self.key.take();
                match connection.stream.write(&response) {
                    Ok(n) if n == response.len() => Ok(()),
                    _ => Err(ExecutionError::ExecutionFailed),
                }
            });
            self.close();
            return result;
        }
        match connection.stream.write(&response) {
            Ok(n) if n == response.len() => {}
            _ => {
                self.close();
                return Ok(());
            }
        }
        connection.deadline = Instant::now() + IO_TIMEOUT;
        self.connection = Some(connection);
        Ok(())
    }
    fn answer(
        &self,
        message: &[u8],
        session: &mut Option<Vec<u8>>,
    ) -> Result<(Vec<u8>, bool), ExecutionError> {
        let mut reader = Reader(message);
        match reader.byte()? {
            11 => {
                reader.end()?;
                let mut response = vec![12];
                response.extend_from_slice(&1u32.to_be_bytes());
                string(&mut response, &self.public);
                string(&mut response, b"");
                Ok((response, false))
            }
            27 => {
                if reader.string()? != b"session-bind@openssh.com"
                    || session.is_some()
                    || reader.string()? != self.host_blob
                {
                    return Err(ExecutionError::InvalidArguments);
                }
                let identifier = reader.string()?;
                if !(16..=64).contains(&identifier.len()) {
                    return Err(ExecutionError::InvalidArguments);
                }
                let mut encoded_signature = reader.string()?;
                let signature = Signature::decode(&mut encoded_signature).map_err(invalid)?;
                if !encoded_signature.is_empty() {
                    return Err(ExecutionError::InvalidArguments);
                }
                if reader.byte()? != 0 {
                    return Err(ExecutionError::InvalidArguments);
                }
                reader.end()?;
                Verifier::verify(&self.host, identifier, &signature).map_err(invalid)?;
                *session = Some(identifier.to_vec());
                Ok((vec![6], false))
            }
            13 => {
                if self.consumed || reader.string()? != self.public {
                    return Err(ExecutionError::InvalidArguments);
                }
                let data = reader.string()?;
                let flags = reader.uint()?;
                reader.end()?;
                let mut auth = Reader(data);
                if Some(auth.string()?) != session.as_deref()
                    || auth.byte()? != 50
                    || auth.string()? != self.user.as_bytes()
                    || auth.string()? != b"ssh-connection"
                {
                    return Err(ExecutionError::InvalidArguments);
                }
                let method = auth.string()?;
                let hostbound = method == b"publickey-hostbound-v00@openssh.com";
                if (!hostbound && method != b"publickey") || auth.byte()? != 1 {
                    return Err(ExecutionError::InvalidArguments);
                }
                let algorithm = auth.string()?;
                if auth.string()? != self.public {
                    return Err(ExecutionError::InvalidArguments);
                }
                if hostbound && auth.string()? != self.host_blob {
                    return Err(ExecutionError::InvalidArguments);
                }
                auth.end()?;
                let key = self.key.as_ref().ok_or(ExecutionError::InvalidArguments)?;
                let signature: Signature = if let Some(rsa) = key.key_data().rsa() {
                    let hash = match (flags, algorithm) {
                        (2, b"rsa-sha2-256") => HashAlg::Sha256,
                        (4, b"rsa-sha2-512") => HashAlg::Sha512,
                        _ => return Err(ExecutionError::InvalidArguments),
                    };
                    (rsa, Some(hash)).try_sign(data).map_err(invalid)?
                } else {
                    if flags != 0 || algorithm != key.algorithm().as_str().as_bytes() {
                        return Err(ExecutionError::InvalidArguments);
                    }
                    key.try_sign(data).map_err(invalid)?
                };
                let mut encoded = Vec::new();
                signature.encode(&mut encoded).map_err(invalid)?;
                let mut response = vec![14];
                string(&mut response, &encoded);
                Ok((response, true))
            }
            _ => Err(ExecutionError::InvalidArguments),
        }
    }
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[cfg(target_os = "linux")]
    use std::os::fd::FromRawFd;
    struct Control {
        allowed: Cell<bool>,
        deny_release: bool,
        releases: Cell<usize>,
        deadline: Cell<Option<Instant>>,
    }
    impl Control {
        fn new() -> Self {
            Self {
                allowed: Cell::new(true),
                deny_release: false,
                releases: Cell::new(0),
                deadline: Cell::new(None),
            }
        }
    }
    impl ExecutionControl for Control {
        fn live(&self) -> bool {
            self.allowed.get()
        }
        fn remaining(&self) -> Duration {
            self.deadline
                .get()
                .map_or(Duration::from_secs(60), |deadline| {
                    deadline.saturating_duration_since(Instant::now())
                })
        }
        fn release(
            &self,
            action: &mut dyn FnMut() -> Result<(), ExecutionError>,
        ) -> Result<(), ExecutionError> {
            self.releases.set(self.releases.get() + 1);
            if self.deny_release {
                self.allowed.set(false);
            }
            if !self.allowed.get() || self.remaining().is_zero() {
                return Err(ExecutionError::Cancelled);
            }
            action()
        }
        fn started(&self) -> Result<(), ExecutionError> {
            Ok(())
        }
    }
    fn setup() -> (tempfile::TempDir, Agent, PrivateKey, UnixStream) {
        let root = tempfile::tempdir().unwrap();
        let (_, encoded) = super::super::ssh_material::fixture(root.path());
        let key = PrivateKey::from_openssh(&encoded).unwrap();
        let mut agent = Agent::bind(
            File::open(root.path()).unwrap(),
            &root.path().join("agent.sock"),
            key.public_key().clone(),
            "backup".into(),
        )
        .unwrap();
        agent.install(SensitiveString::new(encoded)).unwrap();
        let pid = unsafe { libc::getpid() };
        #[cfg(target_os = "linux")]
        {
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
            assert!(raw >= 0);
            agent
                .recipient((pid as u32, unsafe { OwnedFd::from_raw_fd(raw) }))
                .unwrap();
        }
        #[cfg(target_os = "macos")]
        agent
            .recipient(Recipient {
                pid: pid as u32,
                requirement: super::super::native::test_requirement(
                    &std::env::current_exe().unwrap(),
                )
                .unwrap(),
            })
            .unwrap();
        let stream = UnixStream::connect(root.path().join("agent.sock")).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        (root, agent, key, stream)
    }
    fn binding(key: &PrivateKey) -> Vec<u8> {
        binding_session(key, &[7; 32])
    }
    fn binding_session(key: &PrivateKey, session: &[u8]) -> Vec<u8> {
        let mut request = vec![27];
        string(&mut request, b"session-bind@openssh.com");
        string(&mut request, &key.public_key().to_bytes().unwrap());
        string(&mut request, session);
        let signature: Signature = key.try_sign(session).unwrap();
        let mut encoded = Vec::new();
        signature.encode(&mut encoded).unwrap();
        string(&mut request, &encoded);
        request.push(0);
        request
    }
    fn authentication(
        public: &[u8],
        user: &[u8],
        algorithm: &[u8],
        host: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        string(&mut data, &[7; 32]);
        data.push(50);
        string(&mut data, user);
        string(&mut data, b"ssh-connection");
        string(
            &mut data,
            if host.is_some() {
                b"publickey-hostbound-v00@openssh.com"
            } else {
                b"publickey"
            },
        );
        data.push(1);
        string(&mut data, algorithm);
        string(&mut data, public);
        if let Some(host) = host {
            string(&mut data, host);
        }
        data
    }
    fn signing(public: &[u8], data: &[u8], flags: u32) -> Vec<u8> {
        let mut request = vec![13];
        string(&mut request, public);
        string(&mut request, data);
        request.extend_from_slice(&flags.to_be_bytes());
        request
    }
    fn exchange(
        agent: &mut Agent,
        stream: &mut UnixStream,
        control: &Control,
        request: &[u8],
    ) -> Vec<u8> {
        stream.write_all(&framed(request)).unwrap();
        agent.poll(control).unwrap();
        let mut length = [0u8; 4];
        stream.read_exact(&mut length).unwrap();
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        stream.read_exact(&mut response).unwrap();
        response
    }
    #[test]
    fn socket_authentication_verifies_once_without_private_files() {
        for hostbound in [false, true] {
            let (root, mut agent, key, mut stream) = setup();
            let control = Control::new();
            let ids = exchange(&mut agent, &mut stream, &control, &[11]);
            let mut reader = Reader(&ids);
            assert_eq!(reader.byte().unwrap(), 12);
            assert_eq!(reader.uint().unwrap(), 1);
            assert_eq!(reader.string().unwrap(), agent.public);
            assert!(reader.string().unwrap().is_empty());
            reader.end().unwrap();
            assert_eq!(
                exchange(&mut agent, &mut stream, &control, &binding(&key)),
                [6]
            );
            let data = authentication(
                &agent.public,
                b"backup",
                b"ssh-ed25519",
                hostbound.then_some(agent.host_blob.as_slice()),
            );
            let request = signing(&agent.public, &data, 0);
            let response = exchange(&mut agent, &mut stream, &control, &request);
            let mut reader = Reader(&response);
            assert_eq!(reader.byte().unwrap(), 14);
            let signature = Signature::decode(&mut reader.string().unwrap()).unwrap();
            Verifier::verify(key.public_key(), &data, &signature).unwrap();
            assert_eq!(control.releases.get(), 1);
            assert!(agent.key.is_none());
            assert!(agent.consumed);
            assert!(!root.path().join("agent.sock").exists());
            assert!(!root.path().join("identity").exists());
            assert!(agent.answer(&request, &mut Some(vec![7; 32])).is_err());
            assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
        }
    }
    #[test]
    fn final_authority_check_can_deny_after_signature_computation() {
        let (_root, mut agent, key, mut stream) = setup();
        let mut control = Control::new();
        assert_eq!(
            exchange(&mut agent, &mut stream, &control, &binding(&key)),
            [6]
        );
        control.deny_release = true;
        let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
        stream
            .write_all(&framed(&signing(&agent.public, &data, 0)))
            .unwrap();
        assert_eq!(agent.poll(&control), Err(ExecutionError::Cancelled));
        assert_eq!(control.releases.get(), 1);
        assert!(agent.key.is_none());
        assert_eq!(stream.read(&mut [0u8; 1]).unwrap(), 0);
    }
    #[test]
    fn signing_scope_and_session_binding_fail_closed() {
        let (_root, agent, key, _stream) = setup();
        for mutation in ["host", "session", "signature", "forwarding", "trailing"] {
            let mut request = binding(&key);
            match mutation {
                "host" => request[55] ^= 1,
                "session" => request[100] ^= 1,
                "signature" => {
                    let n = request.len();
                    request[n - 3] ^= 1;
                }
                "forwarding" => *request.last_mut().unwrap() = 1,
                _ => request.push(0),
            }
            assert!(agent.answer(&request, &mut None).is_err(), "{mutation}");
        }
        let mut session = None;
        agent.answer(&binding(&key), &mut session).unwrap();
        assert!(agent.answer(&binding(&key), &mut session).is_err());
        for mutation in [
            "unbound",
            "user",
            "key",
            "session",
            "algorithm",
            "flags",
            "arbitrary",
            "trailing",
            "hostbound",
        ] {
            let mut public = agent.public.clone();
            if mutation == "key" {
                *public.last_mut().unwrap() ^= 1;
            }
            let mut data = authentication(
                &public,
                if mutation == "user" {
                    b"other"
                } else {
                    b"backup"
                },
                if mutation == "algorithm" {
                    b"ssh-rsa"
                } else {
                    b"ssh-ed25519"
                },
                if mutation == "hostbound" {
                    Some(b"wrong-host")
                } else {
                    None
                },
            );
            if mutation == "session" {
                data[10] ^= 1;
            }
            if mutation == "arbitrary" {
                data = b"sign this arbitrary content".to_vec();
            }
            if mutation == "trailing" {
                data.push(0);
            }
            let request = signing(&agent.public, &data, u32::from(mutation == "flags"));
            let mut session = if mutation == "unbound" {
                None
            } else {
                Some(vec![7; 32])
            };
            assert!(agent.answer(&request, &mut session).is_err(), "{mutation}");
        }
        for code in [7, 8, 9, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 255] {
            assert!(agent.answer(&[code], &mut None).is_err());
        }
    }
    #[test]
    fn malformed_partial_oversized_disconnect_and_withdrawal_end_authority() {
        for scenario in [
            "oversized",
            "zero",
            "partial",
            "disconnect",
            "withdrawal",
            "message-budget",
        ] {
            let (_root, mut agent, _key, mut stream) = setup();
            let control = Control::new();
            match scenario {
                "oversized" => stream
                    .write_all(&((MAX_FRAME + 1) as u32).to_be_bytes())
                    .unwrap(),
                "zero" => stream.write_all(&[0; 4]).unwrap(),
                "partial" => {
                    stream.write_all(&[0, 0]).unwrap();
                    agent.poll(&control).unwrap();
                    agent.connection.as_mut().unwrap().deadline =
                        Instant::now() - Duration::from_secs(1);
                }
                "disconnect" => {
                    stream.shutdown(std::net::Shutdown::Both).unwrap();
                }
                "withdrawal" => control.allowed.set(false),
                _ => {
                    for _ in 0..MAX_MESSAGES {
                        assert_eq!(exchange(&mut agent, &mut stream, &control, &[255]), [5]);
                    }
                    stream.write_all(&framed(&[11])).unwrap();
                }
            }
            agent.poll(&control).unwrap();
            assert!(agent.key.is_none(), "{scenario}");
            assert!(agent.consumed, "{scenario}");
        }
    }
    #[test]
    fn same_uid_wrong_process_is_rejected_without_poisoning_next_peer() {
        let (root, mut agent, key, mut stream) = setup();
        let control = Control::new();
        #[cfg(target_os = "linux")]
        {
            agent.recipient.as_mut().unwrap().0 += 1;
        }
        #[cfg(target_os = "macos")]
        {
            agent.recipient.as_mut().unwrap().pid += 1;
        }
        stream.write_all(&framed(&[11])).unwrap();
        agent.poll(&control).unwrap();
        assert!(agent.connection.is_none());
        assert!(agent.key.is_some());
        assert!(stream.read(&mut [0u8; 1]).is_err() || stream.read(&mut [0u8; 1]).unwrap() == 0);
        #[cfg(target_os = "linux")]
        {
            agent.recipient.as_mut().unwrap().0 -= 1;
        }
        #[cfg(target_os = "macos")]
        {
            agent.recipient.as_mut().unwrap().pid -= 1;
        }
        let mut valid = UnixStream::connect(root.path().join("agent.sock")).unwrap();
        valid
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(
            exchange(&mut agent, &mut valid, &control, &binding(&key)),
            [6]
        );
        let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
        let request = signing(&agent.public, &data, 0);
        let response = exchange(&mut agent, &mut valid, &control, &request);
        let mut response = Reader(&response);
        assert_eq!(response.byte().unwrap(), 14);
        Verifier::verify(
            key.public_key(),
            &data,
            &Signature::decode(&mut response.string().unwrap()).unwrap(),
        )
        .unwrap();
    }
    #[test]
    #[cfg(target_os = "macos")]
    fn native_expiry_during_recipient_validation_cannot_release_signature() {
        let (_root, mut agent, key, mut stream) = setup();
        let control = Control::new();
        assert_eq!(
            exchange(&mut agent, &mut stream, &control, &binding(&key)),
            [6]
        );
        control
            .deadline
            .set(Some(Instant::now() + Duration::from_millis(100)));
        TEST_AFTER_PEER_VALIDATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| std::thread::sleep(Duration::from_millis(150))))
        });
        let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
        stream
            .write_all(&framed(&signing(&agent.public, &data, 0)))
            .unwrap();
        assert_eq!(agent.poll(&control), Err(ExecutionError::Cancelled));
        assert!(control.remaining().is_zero());
        assert!(agent.consumed);
        assert!(agent.key.is_none());
        assert_eq!(stream.read(&mut [0; 1]).unwrap(), 0);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn native_same_pid_exec_keeps_socket_but_cannot_release_signature() {
        use std::os::fd::OwnedFd;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("exec-recipient.c");
        let first = root.path().join("recipient-first");
        let second = root.path().join("recipient-second");
        std::fs::write(&source, br#"
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static int transfer(int fd, void *bytes, size_t size, int writing) {
    unsigned char *p=bytes;
    while(size) { ssize_t n=writing?write(fd,p,size):read(fd,p,size); if(n<=0) return -1; p+=n; size-=n; }
    return 0;
}
static int forward(int from, int to) {
    unsigned int length;
    unsigned char payload[32768];
    if(transfer(from,&length,4,0)) return -1;
    unsigned int size=ntohl(length);
    if(size>sizeof(payload) || transfer(from,payload,size,0)) return -1;
    return transfer(to,&length,4,1) || transfer(to,payload,size,1);
}
int main(int argc, char **argv) {
    struct timeval timeout={3,0};
    setsockopt(0,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
#ifdef SECOND_IMAGE
    if(argc!=2) return 1;
    int fd=atoi(argv[1]);
    unsigned int pid=htonl(getpid());
    unsigned char marker='B';
    if(transfer(0,&marker,1,1) || transfer(0,&pid,4,1) || forward(0,fd)) return 1;
    unsigned char response;
    ssize_t n=read(fd,&response,1);
    unsigned char denied=(n==0);
    if(transfer(0,&denied,1,1)) return 1;
    close(fd);
    return denied?0:1;
#else
    if(argc!=3) return 1;
    int fd=socket(AF_UNIX,SOCK_STREAM,0);
    if(fd<0) return 1;
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    struct sockaddr_un address={0}; address.sun_family=AF_UNIX;
    if(strlen(argv[1])>=sizeof(address.sun_path)) return 1;
    strcpy(address.sun_path,argv[1]);
    if(connect(fd,(struct sockaddr*)&address,sizeof(address)) || forward(0,fd) || forward(fd,0)) return 1;
    unsigned char proceed;
    if(transfer(0,&proceed,1,0) || proceed!='E') return 1;
    char number[32]; snprintf(number,sizeof(number),"%d",fd);
    execl(argv[2],argv[2],number,(char*)0);
    return 1;
#endif
}
"#).unwrap();
        for (path, second_image) in [(&first, false), (&second, true)] {
            let mut compile = Command::new("/usr/bin/clang");
            compile.arg(&source).arg("-o").arg(path);
            if second_image {
                compile.arg("-DSECOND_IMAGE");
            }
            assert!(compile.status().unwrap().success());
            assert!(
                Command::new("/usr/bin/codesign")
                    .args(["--force", "--sign", "-", "--options", "runtime"])
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
        }
        let expected = super::super::native::test_requirement(&first).unwrap();
        assert_ne!(
            expected,
            super::super::native::test_requirement(&second).unwrap()
        );
        let (_, encoded) = super::super::ssh_material::fixture(root.path());
        let key = PrivateKey::from_openssh(&encoded).unwrap();
        let path = root.path().join("agent.sock");
        let mut agent = Agent::bind(
            File::open(root.path()).unwrap(),
            &path,
            key.public_key().clone(),
            "backup".into(),
        )
        .unwrap();
        agent.install(SensitiveString::new(encoded)).unwrap();
        let (mut channel, child_channel) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let owned: OwnedFd = child_channel.into();
        let mut child = Command::new(&first)
            .arg(&path)
            .arg(&second)
            .env_clear()
            .stdin(Stdio::from(owned))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let pid = child.id();
        agent
            .recipient(Recipient {
                pid,
                requirement: expected.clone(),
            })
            .unwrap();
        let control = Control::new();
        // Any assertion failure still closes the owned control channel before waiting;
        // bounded child reads exit naturally. No test sends a consumer signal.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            channel.write_all(&framed(&binding(&key))).unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            while agent
                .connection
                .as_ref()
                .is_none_or(|connection| connection.session.is_none())
            {
                agent.poll(&control).unwrap();
                assert!(Instant::now() < deadline, "first executable did not bind");
                std::thread::sleep(Duration::from_millis(1));
            }
            let mut accepted = [0u8; 5];
            channel.read_exact(&mut accepted).unwrap();
            assert_eq!(accepted, [0, 0, 0, 1, 6]);
            channel.write_all(b"E").unwrap();
            let mut ready = [0u8; 5];
            channel.read_exact(&mut ready).unwrap();
            assert_eq!(ready[0], b'B');
            assert_eq!(u32::from_be_bytes(ready[1..].try_into().unwrap()), pid);
            assert_eq!(agent.recipient.as_ref().unwrap().requirement, expected);
            let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
            channel
                .write_all(&framed(&signing(&agent.public, &data, 0)))
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(3);
            let result = loop {
                let result = agent.poll(&control);
                if result.is_err() || agent.consumed {
                    break result;
                }
                assert!(
                    Instant::now() < deadline,
                    "second executable did not request signature"
                );
                std::thread::sleep(Duration::from_millis(1));
            };
            assert_eq!(result, Err(ExecutionError::Cancelled));
            assert!(agent.consumed && agent.key.is_none());
            let mut denied = [0];
            channel.read_exact(&mut denied).unwrap();
            assert_eq!(denied, [1], "exec recipient received signature bytes");
        }));
        drop(channel);
        agent.close();
        let status = child.wait().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
        assert!(status.success());
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn native_correct_peer_pid_with_wrong_cdhash_denies_acceptance_and_final_release() {
        for after_acceptance in [false, true] {
            let (_root, mut agent, key, mut stream) = setup();
            let control = Control::new();
            assert_eq!(
                agent.recipient.as_ref().unwrap().pid,
                unsafe { libc::getpid() } as u32
            );
            if after_acceptance {
                assert_eq!(
                    exchange(&mut agent, &mut stream, &control, &binding(&key)),
                    [6]
                );
            }
            // The UID and PID remain correct. Only the exact code identity differs:
            // this peer is the test executable, not any reviewed native SSH slice.
            agent.recipient.as_mut().unwrap().requirement =
                super::super::native::native_ssh_requirement().unwrap();
            let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
            stream
                .write_all(&framed(&signing(&agent.public, &data, 0)))
                .unwrap();
            let result = agent.poll(&control);
            if after_acceptance {
                assert_eq!(result, Err(ExecutionError::Cancelled));
                assert_eq!(control.releases.get(), 1);
                assert!(agent.consumed);
                assert!(agent.key.is_none());
            } else {
                result.unwrap();
                assert_eq!(control.releases.get(), 0);
                assert!(agent.key.is_some());
            }
            assert!(agent.connection.is_none());
            match stream.read(&mut [0u8; 1]) {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                other => panic!("wrong code identity received signature data: {other:?}"),
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn dead_recipient_and_socket_replacement_do_not_retain_authority_or_delete_unrelated_files() {
        let (root, mut agent, _key, _stream) = setup();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) } as i32;
        assert!(raw >= 0);
        agent.recipient = Some((child.id(), unsafe { OwnedFd::from_raw_fd(raw) }));
        child.wait().unwrap();
        let socket = root.path().join("agent.sock");
        std::fs::rename(&socket, root.path().join("old.sock")).unwrap();
        std::fs::write(&socket, b"unrelated replacement").unwrap();
        agent.poll(&Control::new()).unwrap();
        assert!(agent.key.is_none());
        assert!(agent.consumed);
        agent.close();
        drop(agent);
        assert_eq!(std::fs::read(&socket).unwrap(), b"unrelated replacement");
    }

    #[test]
    fn partial_setup_and_failed_unlink_retry_never_restore_authority() {
        let (root, mut agent, key, _stream) = setup();
        FAIL_UNLINK.with(|fail| fail.set(true));
        agent.close();
        assert!(root.path().join("agent.sock").exists());
        assert!(agent.key.is_none());
        assert!(agent.listener.is_none());
        assert!(agent.consumed);
        FAIL_UNLINK.with(|fail| fail.set(false));
        agent.close();
        assert!(!root.path().join("agent.sock").exists());
        assert!(
            agent
                .install(SensitiveString::new(
                    key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string()
                ))
                .is_err()
        );
        FAIL_SETUP.with(|fail| fail.set(true));
        assert!(
            Agent::bind(
                File::open(root.path()).unwrap(),
                &root.path().join("partial.sock"),
                key.public_key().clone(),
                "backup".into()
            )
            .is_err()
        );
        FAIL_SETUP.with(|fail| fail.set(false));
        assert!(!root.path().join("partial.sock").exists());
    }
    #[test]
    fn fragmented_and_coalesced_requests_survive_write_half_close() {
        for session_size in [32, 64] {
            let (_root, mut agent, key, mut stream) = setup();
            let control = Control::new();
            let session = vec![7; session_size];
            let frame = framed(&binding_session(&key, &session));
            for piece in [
                &frame[..2],
                &frame[2..5],
                &frame[5..frame.len() - 1],
                &frame[frame.len() - 1..],
            ] {
                stream.write_all(piece).unwrap();
                agent.poll(&control).unwrap();
            }
            let mut response = [0; 5];
            stream.read_exact(&mut response).unwrap();
            assert_eq!(response, [0, 0, 0, 1, 6]);
            let mut data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
            data.splice(0..36, framed(&session).iter().copied());
            let mut requests = framed(&[11]).to_vec();
            requests.extend_from_slice(&framed(&signing(&agent.public, &data, 0)));
            stream.write_all(&requests).unwrap();
            stream.shutdown(std::net::Shutdown::Write).unwrap();
            agent.poll(&control).unwrap();
            agent.poll(&control).unwrap();
            let mut bytes = Vec::new();
            stream.read_to_end(&mut bytes).unwrap();
            let mut responses = Reader(&bytes);
            let identities = responses.string().unwrap();
            assert_eq!(identities[0], 12);
            let mut signed = Reader(responses.string().unwrap());
            assert_eq!(signed.byte().unwrap(), 14);
            Verifier::verify(
                key.public_key(),
                &data,
                &Signature::decode(&mut signed.string().unwrap()).unwrap(),
            )
            .unwrap();
            responses.end().unwrap();
            assert!(agent.consumed);
            assert_eq!(control.releases.get(), 1);
        }
    }
    #[test]
    fn unsupported_encrypted_legacy_and_rsa_size_inputs_install_nothing() {
        use base64::Engine;
        use ssh_key::{
            Mpint,
            private::{DsaKeypair, DsaPrivateKey, RsaKeypair, RsaPrivateKey},
            public::{DsaPublicKey, RsaPublicKey},
        };
        let (_root, mut agent, _key, _stream) = setup();
        agent.key.take();
        agent.public.clear();
        let one = || Mpint::from_bytes(&[3]).unwrap();
        let mut inputs = vec![
            "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----".to_owned(),
            String::new(),
            "x".repeat(65537),
        ];
        for bits in [2047usize, 8193] {
            let mut n = vec![0xff; bits.div_ceil(8)];
            n[0] = ((1u16 << (bits % 8)) - 1) as u8;
            let public = RsaPublicKey::new(
                Mpint::from_bytes(&[1, 0, 1]).unwrap(),
                Mpint::from_positive_bytes(&n),
            )
            .unwrap();
            let private = RsaPrivateKey::new(one(), one(), one(), one()).unwrap();
            let key =
                PrivateKey::new(RsaKeypair::new(public, private).unwrap().into(), "").unwrap();
            inputs.push(key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string());
        }
        let dsa = DsaKeypair::new(
            DsaPublicKey::new(one(), one(), one(), one()).unwrap(),
            DsaPrivateKey::new(one()).unwrap(),
        )
        .unwrap();
        inputs.push(
            PrivateKey::new(dsa.into(), "")
                .unwrap()
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        );
        let mut encrypted = b"openssh-key-v1\0".to_vec();
        string(&mut encrypted, b"aes256-ctr");
        string(&mut encrypted, b"bcrypt");
        let mut options = Vec::new();
        string(&mut options, &[1; 16]);
        options.extend_from_slice(&16u32.to_be_bytes());
        string(&mut encrypted, &options);
        encrypted.extend_from_slice(&1u32.to_be_bytes());
        string(&mut encrypted, &agent.host_blob);
        string(&mut encrypted, &[0; 64]);
        assert!(PrivateKey::from_bytes(&encrypted).unwrap().is_encrypted());
        inputs.push(format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(encrypted)
        ));
        for input in inputs {
            assert!(agent.install(SensitiveString::new(input)).is_err());
            assert!(agent.key.is_none());
            assert!(agent.public.is_empty());
        }
        assert_eq!(rsa_bits(&[0, 0x80]), 8);
        assert_eq!(rsa_bits(&[0x7f]), 7);
    }

    #[test]
    fn supported_algorithms_produce_verified_ssh_signatures() {
        use ssh_key::EcdsaCurve;
        for algorithm in [
            Algorithm::Ed25519,
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Rsa { hash: None },
        ] {
            let key = if matches!(algorithm, Algorithm::Rsa { .. }) {
                PrivateKey::new(
                    ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)
                        .unwrap()
                        .into(),
                    "synthetic RSA",
                )
                .unwrap()
            } else {
                PrivateKey::random(&mut rand::rng(), algorithm.clone()).unwrap()
            };
            for flags in if matches!(algorithm, Algorithm::Rsa { .. }) {
                vec![2, 4]
            } else {
                vec![0]
            } {
                let (_root, mut agent, host, _stream) = setup();
                agent.key.take();
                agent
                    .install(SensitiveString::new(
                        key.to_openssh(ssh_key::LineEnding::LF).unwrap().to_string(),
                    ))
                    .unwrap();
                let algorithm_name = match flags {
                    2 => "rsa-sha2-256",
                    4 => "rsa-sha2-512",
                    _ => algorithm.as_str(),
                };
                let data =
                    authentication(&agent.public, b"backup", algorithm_name.as_bytes(), None);
                let mut session = None;
                agent.answer(&binding(&host), &mut session).unwrap();
                let (response, signing_response) = agent
                    .answer(&signing(&agent.public, &data, flags), &mut session)
                    .unwrap();
                assert!(signing_response);
                let mut reader = Reader(&response);
                assert_eq!(reader.byte().unwrap(), 14);
                let signature = Signature::decode(&mut reader.string().unwrap()).unwrap();
                Verifier::verify(key.public_key(), &data, &signature).unwrap();
            }
        }
    }

    #[test]
    fn blocked_signature_output_consumes_without_delayed_flush() {
        let (_root, mut agent, key, mut stream) = setup();
        let control = Control::new();
        assert_eq!(
            exchange(&mut agent, &mut stream, &control, &binding(&key)),
            [6]
        );
        let server = &mut agent.connection.as_mut().unwrap().stream;
        while server.write(&[0x55; 4096]).is_ok() {}
        let data = authentication(&agent.public, b"backup", b"ssh-ed25519", None);
        stream
            .write_all(&framed(&signing(&agent.public, &data, 0)))
            .unwrap();
        assert_eq!(agent.poll(&control), Err(ExecutionError::ExecutionFailed));
        assert!(agent.key.is_none());
        assert!(agent.consumed);
        let mut received = Vec::new();
        stream.read_to_end(&mut received).unwrap();
        assert!(received.iter().all(|byte| *byte == 0x55));
    }
}

#[cfg(test)]
mod openssh_tests;

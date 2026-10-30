//! Native producer output: an anonymous pipe whose write end becomes the child's fd 3.
//!
//! macOS has no memfd or file sealing and POSIX shared memory is mmap-only, so the
//! provider drains a pipe instead. No plaintext reaches disk. The pipe is not seekable:
//! producers write the frame sequentially (four-byte little-endian length, then JSON).
//! A provider-owned reader holds at most `MAX_IMPORT_BYTES + 4` bytes in zeroizing
//! memory; any further byte invalidates the output instead of truncating it.
use crate::access::ports::{CleanupEvidence, ExecutionError, ProducerOutput};
use crate::secret_storage::{MAX_IMPORT_BYTES, SecretImport};
use std::{
    fmt,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};
use zeroize::Zeroizing;

const CAPACITY: usize = MAX_IMPORT_BYTES + 4;
/// Upper bound on how long the reader waits before re-checking its stop request.
const POLL_MILLISECONDS: libc::c_int = 20;

/// Fixed lowest descriptor for both pipe ends: keeps them clear of 0..=3, which the
/// spawn file actions overwrite, so `dup2(write, 3)` is never a same-descriptor no-op.
const MIN_DESCRIPTOR: libc::c_int = 4;

/// Provider-side capability returned to the application.
pub(super) struct NativeProducerOutput {
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<Received>>,
}
impl fmt::Debug for NativeProducerOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeProducerOutput([REDACTED])")
    }
}

struct Received {
    bytes: Zeroizing<Vec<u8>>,
    filled: usize,
    invalid: bool,
}

/// Creates the channel. The returned write end must be handed only to the child's
/// spawn file actions and closed by the provider immediately after spawning.
pub(super) fn open() -> Result<(OwnedFd, NativeProducerOutput), ExecutionError> {
    let mut ends = [-1; 2];
    if unsafe { libc::pipe(ends.as_mut_ptr()) } != 0 {
        return Err(ExecutionError::Unavailable);
    }
    // macOS lacks pipe2; F_DUPFD_CLOEXEC yields close-on-exec copies at or above
    // MIN_DESCRIPTOR. The originals are closed (and owned) on every path.
    let originals = unsafe { [OwnedFd::from_raw_fd(ends[0]), OwnedFd::from_raw_fd(ends[1])] };
    let duplicate = |fd: &OwnedFd| -> Result<OwnedFd, ExecutionError> {
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, MIN_DESCRIPTOR) };
        if raw < 0 {
            return Err(ExecutionError::Unavailable);
        }
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    };
    let read = duplicate(&originals[0])?;
    let write = duplicate(&originals[1])?;
    drop(originals);
    let flags = unsafe { libc::fcntl(read.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(ExecutionError::Unavailable);
    }
    let stop = Arc::new(AtomicBool::new(false));
    let requested = stop.clone();
    let reader = std::thread::Builder::new()
        .name("native-producer-output".into())
        .spawn(move || drain(&read, &requested))
        .map_err(|_error| ExecutionError::Unavailable)?;
    Ok((
        write,
        NativeProducerOutput {
            stop,
            reader: Some(reader),
        },
    ))
}

/// Reads until end of file, overflow, an error, or a stop request. After a stop is
/// observed it performs one final nonblocking drain, then closes the read end.
fn drain(fd: &OwnedFd, stop: &AtomicBool) -> Received {
    let mut received = Received {
        bytes: Zeroizing::new(vec![0u8; CAPACITY + 1]),
        filled: 0,
        invalid: false,
    };
    loop {
        let stopping = stop.load(Ordering::Acquire);
        loop {
            if received.filled > CAPACITY {
                received.invalid = true;
                return received;
            }
            let spare = &mut received.bytes[received.filled..];
            let count =
                unsafe { libc::read(fd.as_raw_fd(), spare.as_mut_ptr().cast(), spare.len()) };
            if count > 0 {
                received.filled += count as usize;
                continue;
            }
            if count == 0 {
                return received;
            }
            match std::io::Error::last_os_error().raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::EAGAIN) => break,
                _ => {
                    received.invalid = true;
                    return received;
                }
            }
        }
        if stopping {
            return received;
        }
        let mut wait = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // Readiness, timeout and EINTR all lead back to the nonblocking drain.
        let _ready = unsafe { libc::poll(&mut wait, 1, POLL_MILLISECONDS) };
    }
}

impl NativeProducerOutput {
    fn finish(&mut self) -> Option<Received> {
        self.stop.store(true, Ordering::Release);
        self.reader.take().and_then(|reader| reader.join().ok())
    }
}
impl Drop for NativeProducerOutput {
    fn drop(&mut self) {
        drop(self.finish());
    }
}
impl ProducerOutput for NativeProducerOutput {
    /// One-shot: the reader stops on the first call whatever the evidence.
    fn read(&mut self, evidence: CleanupEvidence) -> Result<SecretImport, ExecutionError> {
        let received = self.finish();
        if evidence != CleanupEvidence::Reaped {
            return Err(ExecutionError::CleanupUncertain);
        }
        let received = received.ok_or(ExecutionError::ExecutionFailed)?;
        frame(
            &received.bytes[..received.filled.min(CAPACITY)],
            received.invalid,
        )
    }
}

/// Accepts exactly a four-byte little-endian length `n` (1..=MAX) followed by `n` bytes.
fn frame(bytes: &[u8], invalid: bool) -> Result<SecretImport, ExecutionError> {
    if invalid || bytes.len() < 4 {
        return Err(ExecutionError::ExecutionFailed);
    }
    let len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if len == 0 || len > MAX_IMPORT_BYTES || bytes.len() != 4 + len {
        return Err(ExecutionError::ExecutionFailed);
    }
    SecretImport::parse(&bytes[4..]).map_err(|_error| ExecutionError::ExecutionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn framed(json: &[u8]) -> Vec<u8> {
        let mut bytes = (json.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(json);
        bytes
    }

    #[test]
    fn frame_accepts_only_exact_length_prefixed_json() {
        let json = br#"{"password":"frame-sentinel"}"#;
        let valid = framed(json);
        assert_eq!(
            frame(&valid, false).unwrap().password.as_deref(),
            Some("frame-sentinel")
        );
        assert!(frame(&valid, true).is_err());
        assert!(frame(&valid[..3], false).is_err());
        assert!(frame(&valid[..valid.len() - 1], false).is_err());
        let mut trailing = valid.clone();
        trailing.push(b' ');
        assert!(frame(&trailing, false).is_err());
        assert!(frame(&[0, 0, 0, 0], false).is_err());
        let mut oversized = ((MAX_IMPORT_BYTES + 1) as u32).to_le_bytes().to_vec();
        oversized.extend(std::iter::repeat_n(b' ', MAX_IMPORT_BYTES + 1));
        assert!(frame(&oversized, false).is_err());
        assert!(frame(&framed(b"not json"), false).is_err());
    }

    #[test]
    fn debug_is_redacted() {
        let (write, output) = open().unwrap();
        drop(write);
        assert_eq!(format!("{output:?}"), "NativeProducerOutput([REDACTED])");
    }
}

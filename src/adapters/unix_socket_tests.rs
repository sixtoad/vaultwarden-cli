use super::*;
use std::{io::Write, os::unix::fs::PermissionsExt};

fn socket_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o750)).unwrap();
    directory
}

#[test]
fn raw_seed_checks_size_permissions_kind_and_links_without_waiting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("seed");
    for size in [0, 31, 32, 33, 4096] {
        fs::write(&path, vec![7; size]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(load_signing_key(&path).is_ok(), size == 32);
    }
    fs::write(&path, [7; 32]).unwrap();
    for mode in [0o400, 0o640, 0o644, 0o700, 0o4600] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(load_signing_key(&path).is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let linked = directory.path().join("link");
    std::os::unix::fs::symlink(&path, &linked).unwrap();
    assert!(load_signing_key(&linked).is_err());
    let linked_dir = directory.path().join("linked-dir");
    std::os::unix::fs::symlink(directory.path(), &linked_dir).unwrap();
    assert!(load_signing_key(&linked_dir.join("seed")).is_err());
    assert!(load_signing_key(directory.path()).is_err());
    let fifo = directory.path().join("fifo");
    let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let start = std::time::Instant::now();
    assert!(load_signing_key(&fifo).is_err());
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(load_signing_key(&path).unwrap().to_bytes(), [7; 32]);
}

#[test]
fn group_lengths_fail_closed_for_errors_misalignment_and_overflow() {
    for count in [0, 1, MAX_GROUPS] {
        assert_eq!(group_count(0, count * 4), Ok(count));
    }
    for bytes in [1, 3, 5, MAX_GROUPS * 4 + 4] {
        assert!(group_count(0, bytes).is_err());
    }
    for result in [-1, 1] {
        assert!(group_count(result, 4).is_err());
    }
}

#[test]
fn kernel_peer_credentials_include_primary_group() {
    let (left, right) = std::os::unix::net::UnixStream::pair().unwrap();
    for stream in [left, right] {
        let peer = peer_credentials(&stream).unwrap();
        assert_eq!(peer.uid, unsafe { libc::geteuid() });
        assert!(peer.groups.contains(&unsafe { libc::getegid() }));
    }
}

#[test]
fn socket_lifecycle_refuses_active_and_unsafe_paths_and_preserves_replacement() {
    let directory = socket_directory();
    let gid = unsafe { libc::getegid() };
    let path = directory.path().join(SOCKET_NAME);
    let socket = AgentSocket::bind(directory.path(), gid).unwrap();
    let metadata = fs::symlink_metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o7777, 0o660);
    assert_eq!(metadata.gid(), gid);
    assert!(AgentSocket::bind(directory.path(), gid).is_err());
    fs::remove_file(&path).unwrap();
    let replacement = StdListener::bind(&path).unwrap();
    drop(socket);
    assert!(path.exists());
    drop(replacement);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    let socket = AgentSocket::bind(directory.path(), gid).unwrap();
    drop(socket);
    assert!(!path.exists());
    fs::write(&path, b"not a socket").unwrap();
    assert!(AgentSocket::bind(directory.path(), gid).is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("absent", &path).unwrap();
    assert!(AgentSocket::bind(directory.path(), gid).is_err());
    fs::remove_file(&path).unwrap();
    for mode in [0o700, 0o755, 0o770, 0o1750] {
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(AgentSocket::bind(directory.path(), gid).is_err());
    }
}

#[test]
fn cleanup_remains_bound_to_original_directory_inode() {
    let parent = tempfile::tempdir().unwrap();
    let original = parent.path().join("socket-dir");
    fs::create_dir(&original).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o750)).unwrap();
    let socket = AgentSocket::bind(&original, unsafe { libc::getegid() }).unwrap();
    let moved = parent.path().join("moved");
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join(SOCKET_NAME), b"replacement").unwrap();
    drop(socket);
    assert!(!moved.join(SOCKET_NAME).exists());
    assert_eq!(
        fs::read(original.join(SOCKET_NAME)).unwrap(),
        b"replacement"
    );
}

#[tokio::test]
async fn frames_require_single_lf_and_eof_and_bound_total_size() {
    for (data, valid) in [
        (b"{}\n".as_slice(), true),
        (b"{}", false),
        (b"{}\r\n", false),
        (b"{}\n{}\n", false),
        (b"{}\n ", false),
        (b"\n", false),
        (b"", false),
    ] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(data).await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            read_frame(&mut server, 65536, Instant::now() + IO_TIMEOUT)
                .await
                .is_ok(),
            valid
        );
    }
    for size in [65536, 65537] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut data = vec![b'x'; size];
        data[size - 1] = b'\n';
        let writer = tokio::spawn(async move {
            let _ignored = client.write_all(&data).await;
        });
        assert_eq!(
            read_frame(&mut server, 65536, Instant::now() + IO_TIMEOUT)
                .await
                .is_ok(),
            size == 65536
        );
        writer.await.unwrap();
    }
}

#[tokio::test]
async fn partial_frames_work_but_slow_input_cannot_reset_deadline() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    let writer = tokio::spawn(async move {
        for part in [b"{".as_slice(), b"}\n"] {
            client.write_all(part).await.unwrap();
            tokio::task::yield_now().await;
        }
        client.shutdown().await.unwrap();
    });
    assert_eq!(
        read_frame(&mut server, 65536, Instant::now() + IO_TIMEOUT)
            .await
            .unwrap(),
        b"{}"
    );
    writer.await.unwrap();
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client.write_all(b"{}\n").await.unwrap();
    let start = Instant::now();
    assert!(
        read_frame(&mut server, 65536, start + Duration::from_millis(25))
            .await
            .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(1));
}

#[tokio::test]
async fn client_limits_request_before_connect() {
    use base64::Engine;
    let input = SignedSubmission::sign(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2u8; 32]),
        [3; 32],
        "deploy".into(),
        "a".repeat(64),
        vec!["x".repeat(4096); 64],
        &SigningKey::from_bytes(&[7; 32]),
    )
    .unwrap();
    let directory = socket_directory();
    let path = directory.path().join(SOCKET_NAME);
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    assert!(exchange(&path, &input).await.is_err());
    assert!(
        timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err()
    );
    // The same endpoint must independently work for a bounded request.
    let control = SignedSubmission::sign(
        input.binding_id,
        [4; 32],
        "deploy".into(),
        "a".repeat(64),
        vec!["staging".into()],
        &SigningKey::from_bytes(&[7; 32]),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert!(
            read_frame(
                &mut stream,
                MAX_REQUEST_FRAME_BYTES,
                Instant::now() + IO_TIMEOUT
            )
            .await
            .is_ok()
        );
        write_response(
            &mut stream,
            &AgentResponse::pending(
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([9; 32]),
            ),
        )
        .await
        .unwrap();
    });
    assert!(matches!(
        exchange(&path, &control).await.unwrap(),
        AgentResponse::Pending { .. }
    ));
    server.await.unwrap();
}

#[test]
fn seed_permission_and_socket_directory_group_are_independent() {
    let directory = socket_directory();
    assert!(
        AgentSocket::bind(directory.path(), unsafe { libc::getegid() }.wrapping_add(1)).is_err()
    );
    let path = directory.path().join("seed");
    let mut file = File::create(&path).unwrap();
    file.write_all(&[7; 32]).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(load_signing_key(&path).is_ok());
}

#[test]
fn peercred_requires_independent_success_and_exact_structure_size() {
    let size = std::mem::size_of::<libc::ucred>();
    assert!(validate_peer_length(0, size).is_ok());
    for invalid in [0, size - 1, size + 1] {
        assert!(validate_peer_length(0, invalid).is_err());
    }
    for result in [-1, 1] {
        assert!(validate_peer_length(result, size).is_err());
    }
}

#[tokio::test]
async fn already_expired_deadline_rejects_even_ready_complete_input() {
    let (mut client, mut server) = UnixStream::pair().unwrap();
    client.write_all(b"{}\n").await.unwrap();
    client.shutdown().await.unwrap();
    assert!(
        read_frame(
            &mut server,
            65536,
            Instant::now() - Duration::from_millis(1)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn blocked_response_writer_has_a_five_second_deadline() {
    let (mut server, _client) = UnixStream::pair().unwrap();
    let size: libc::c_int = 4096;
    assert_eq!(
        unsafe {
            libc::setsockopt(
                server.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        },
        0
    );
    server.writable().await.unwrap();
    loop {
        match server.try_write(&[0u8; 4096]) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("{error}"),
        }
    }
    let start = Instant::now();
    assert!(
        write_response(&mut server, &AgentResponse::rejected(AgentRejection::Busy))
            .await
            .is_err()
    );
    assert!(start.elapsed() >= Duration::from_secs(5));
    assert!(start.elapsed() < Duration::from_secs(7));
}

#[tokio::test]
async fn client_inode_replacement_rejects_before_any_signed_payload() {
    use base64::Engine;
    let directory = socket_directory();
    let path = directory.path().join(SOCKET_NAME);
    let listener = StdListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o660)).unwrap();
    let replacement = Arc::new(std::sync::Mutex::new(None));
    let hold = replacement.clone();
    CLIENT_CONNECTED_HOOK.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |path| {
            fs::remove_file(path).unwrap();
            let listener = StdListener::bind(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o660)).unwrap();
            *hold.lock().unwrap() = Some(listener);
        }))
    });
    let input = SignedSubmission::sign(
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([2; 32]),
        [3; 32],
        "deploy".into(),
        "a".repeat(64),
        vec!["staging".into()],
        &SigningKey::from_bytes(&[7; 32]),
    )
    .unwrap();
    assert!(exchange(&path, &input).await.is_err());
    let (mut connected, _) = listener.accept().unwrap();
    connected
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut payload = Vec::new();
    std::io::Read::read_to_end(&mut connected, &mut payload).unwrap();
    assert!(payload.is_empty());
    let replacement = replacement.lock().unwrap().take().unwrap();
    replacement.set_nonblocking(true).unwrap();
    assert_eq!(
        replacement.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn framing_remembers_a_terminal_lf_across_partial_reads() {
    for extra in [b"x".as_slice(), b"\n", b" "] {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let extra = extra.to_vec();
        let (consumed_tx, consumed_rx) = tokio::sync::oneshot::channel();
        let mut consumed_tx = Some(consumed_tx);
        FRAME_CHUNK_HOOK.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |chunk| {
                if chunk.last() == Some(&b'\n')
                    && let Some(sender) = consumed_tx.take()
                {
                    sender.send(()).unwrap();
                }
            }))
        });
        let writer = tokio::spawn(async move {
            client.write_all(b"{}\n").await.unwrap();
            consumed_rx.await.unwrap();
            client.write_all(&extra).await.unwrap();
            client.shutdown().await.unwrap();
        });
        assert!(
            read_frame(&mut server, 65536, Instant::now() + IO_TIMEOUT)
                .await
                .is_err()
        );
        FRAME_CHUNK_HOOK.with(|hook| *hook.borrow_mut() = None);
        writer.await.unwrap();
    }
}

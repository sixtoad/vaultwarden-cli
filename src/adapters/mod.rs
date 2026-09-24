pub mod desktop_launch;
pub mod human_socket;
pub mod loopback_ui;
pub mod session;
pub mod vaultwarden;

#[cfg(test)]
fn buffered_fifo(path: &std::path::Path, contents: &[u8]) -> std::fs::File {
    use std::{
        io::Write,
        os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    // Keep a reader open while filling the FIFO, then close the writer so a
    // second reader receives valid contents followed by EOF without blocking.
    let keeper = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .unwrap();
    let mut writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    writer.write_all(contents).unwrap();
    drop(writer);
    keeper
}

#[cfg(test)]
fn within_test_deadline<T: Send + 'static>(operation: impl FnOnce() -> T + Send + 'static) -> T {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ignored = sender.send(operation());
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("unsafe file must be rejected without waiting for a FIFO writer")
}

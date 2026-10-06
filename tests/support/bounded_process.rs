//! Failure bounds for subprocess fixtures; Drop always kills/reaps owned children.
use std::{
    io::Read,
    process::{Child, ChildStdout, Command, Output},
    time::{Duration, Instant},
};

const LIMIT: Duration = Duration::from_secs(10);

pub struct BoundedChild(Option<Child>);
impl BoundedChild {
    pub fn spawn(command: &mut Command) -> Self {
        Self(Some(command.spawn().unwrap()))
    }
    pub fn id(&self) -> u32 {
        self.0.as_ref().unwrap().id()
    }
    #[allow(dead_code)] // Used by the namespace fixture, not the human CLI fixture.
    pub fn stdin(&mut self) -> std::process::ChildStdin {
        self.0.as_mut().unwrap().stdin.take().unwrap()
    }
    pub fn stdout(&mut self) -> ChildStdout {
        self.0.as_mut().unwrap().stdout.take().unwrap()
    }
    pub fn wait_with_output(mut self) -> Output {
        let stdout = self.0.as_mut().unwrap().stdout.take();
        let stderr = self.0.as_mut().unwrap().stderr.take();
        let out = std::thread::spawn(move || read_all(stdout));
        let err = std::thread::spawn(move || read_all(stderr));
        let deadline = Instant::now() + LIMIT;
        let status = loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "child did not exit within fixture budget"
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        self.0.take();
        Output {
            status,
            stdout: join(out),
            stderr: join(err),
        }
    }
}
impl Drop for BoundedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ignored = child.kill();
            let _ignored = child.wait();
        }
    }
}
fn read_all(reader: Option<impl Read>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(mut reader) = reader {
        reader.read_to_end(&mut bytes).unwrap();
    }
    bytes
}
pub fn output(command: &mut Command) -> Output {
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    BoundedChild::spawn(command).wait_with_output()
}

pub fn join<T>(worker: std::thread::JoinHandle<T>) -> T {
    let deadline = Instant::now() + LIMIT;
    while !worker.is_finished() {
        assert!(Instant::now() < deadline, "fixture worker did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    worker
        .join()
        .unwrap_or_else(|error| std::panic::resume_unwind(error))
}

pub fn io<T: Send + 'static>(read: impl FnOnce() -> T + Send + 'static) -> T {
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let _ignored = sent.send(read());
    });
    let value = received
        .recv_timeout(LIMIT)
        .expect("fixture pipe read exceeded budget");
    join(worker);
    value
}

/// One absolute fixture deadline bounds all accepts, including missing reconnects.
pub struct Listener {
    inner: std::os::unix::net::UnixListener,
    deadline: Instant,
}
impl Listener {
    pub fn new(inner: std::os::unix::net::UnixListener) -> Self {
        inner.set_nonblocking(true).unwrap();
        Self {
            inner,
            deadline: Instant::now() + LIMIT,
        }
    }
    pub fn accept(&self) -> std::os::unix::net::UnixStream {
        loop {
            match self.inner.accept() {
                Ok((stream, _)) => {
                    stream.set_read_timeout(Some(LIMIT)).unwrap();
                    stream.set_write_timeout(Some(LIMIT)).unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < self.deadline, "fixture connection missing");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture accept: {error}"),
            }
        }
    }
}

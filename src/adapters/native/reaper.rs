//! Fixed-capacity ownership for naturally exiting detached consumers. Never signals.
use crate::access::ports::ExecutionError;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

const CAPACITY: usize = 64;
#[derive(Clone, Copy)]
enum Slot {
    Empty,
    Reserved,
    Detached(libc::pid_t),
}
struct Reaper {
    slots: Arc<Mutex<Vec<Slot>>>,
}
impl Reaper {
    fn create(
        capacity: usize,
        start: impl FnOnce(Weak<Mutex<Vec<Slot>>>) -> std::io::Result<()>,
    ) -> Result<Self, ExecutionError> {
        let slots = Arc::new(Mutex::new(vec![Slot::Empty; capacity]));
        start(Arc::downgrade(&slots)).map_err(|_error| ExecutionError::Unavailable)?;
        Ok(Self { slots })
    }
    fn reserve(&self) -> Result<Reservation, ExecutionError> {
        let mut slots = self
            .slots
            .lock()
            .map_err(|_error| ExecutionError::Unavailable)?;
        let index = slots
            .iter()
            .position(|slot| matches!(slot, Slot::Empty))
            .ok_or(ExecutionError::Unavailable)?;
        slots[index] = Slot::Reserved;
        Ok(Reservation {
            slots: self.slots.clone(),
            index,
            transferred: false,
        })
    }
}
fn start(slots: Weak<Mutex<Vec<Slot>>>) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("native-consumer-reaper".into())
        .spawn(move || {
            while let Some(shared) = slots.upgrade() {
                {
                    let mut slots = shared
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for slot in slots.iter_mut() {
                        if let Slot::Detached(pid) = *slot {
                            let result =
                                unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
                            // ECHILD means no owned child remains. Other errors retain ownership
                            // and capacity; never convert an uncertain PID into a signal target.
                            if result == pid
                                || (result < 0
                                    && std::io::Error::last_os_error().raw_os_error()
                                        == Some(libc::ECHILD))
                            {
                                *slot = Slot::Empty;
                            }
                        }
                    }
                }
                drop(shared);
                std::thread::sleep(Duration::from_millis(10));
            }
        })
        .map(drop)
}

/// Initialized and reserved in image preparation, before the application resolves secrets.
/// Reservation drop handles unlaunched/normally reaped children; detach transfers only PID ownership.
pub(super) struct Reservation {
    slots: Arc<Mutex<Vec<Slot>>>,
    index: usize,
    transferred: bool,
}
impl Reservation {
    pub(super) fn detach(mut self, pid: libc::pid_t) {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        slots[self.index] = Slot::Detached(pid);
        self.transferred = true;
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.transferred {
            self.slots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())[self.index] = Slot::Empty;
        }
    }
}
pub(super) fn reserve() -> Result<Reservation, ExecutionError> {
    static REAPER: OnceLock<Result<Reaper, ExecutionError>> = OnceLock::new();
    REAPER
        .get_or_init(|| Reaper::create(CAPACITY, start))
        .as_ref()
        .map_err(|_error| ExecutionError::Unavailable)?
        .reserve()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initialization_and_capacity_failure_deny_reservation_without_launch() {
        assert!(
            Reaper::create(1, |_| Err(std::io::Error::other(
                "synthetic thread failure"
            )))
            .is_err()
        );
        let reaper = Reaper::create(1, start).unwrap();
        let reservation = reaper.reserve().unwrap();
        assert!(reaper.reserve().is_err());
        drop(reservation);
        assert!(reaper.reserve().is_ok());
    }
    #[test]
    fn detached_child_is_naturally_reaped_and_capacity_reused() {
        let reaper = Reaper::create(1, start).unwrap();
        let reservation = reaper.reserve().unwrap();
        let child = std::process::Command::new("/usr/bin/true")
            .env_clear()
            .spawn()
            .unwrap();
        let pid = child.id() as libc::pid_t;
        drop(child); // ownership transfers below; std::process::Child drop does not reap.
        reservation.detach(pid);
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            if let Ok(reservation) = reaper.reserve() {
                drop(reservation);
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "natural exit was not reaped"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
}

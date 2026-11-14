//! An overlapped operation on Windows, waited for once, the crate's one
//! way: begun with an event of its own, waited for as long as it takes or
//! within a time and cancelled once that has passed, and its end read as
//! the handle's kind reads it — a pipe's by `GetOverlappedResult`, a
//! socket's by `WSAGetOverlappedResult`, which says Winsock's error, so a
//! refused connect keeps its kind. The named pipe's reads, writes and
//! accepts (`super::pipe`) and the TCP connect (`super::connect`) wait
//! here. Until 2026-11-14 this was the pipe's alone, in its `io`.
#![allow(unsafe_code)]

use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinSock::{SOCKET, WSAGetOverlappedResult};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::core::BOOL;

/// The event one connection's operations are waited for on, one at a time.
pub(crate) struct Event(HANDLE);

// SAFETY: an event handle may be waited on and closed from any thread.
unsafe impl Send for Event {}
// SAFETY: as above; its connection waits on it from one thread at a time.
unsafe impl Sync for Event {}

impl Event {
    /// A manual-reset event, which each operation resets as it starts.
    ///
    /// # Errors
    ///
    /// Where Windows makes none.
    pub(crate) fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed, with no attributes; closed on drop.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(event))
        }
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: made by `new`, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// What an operation is on: a file or a pipe's handle, or a socket.
#[derive(Clone, Copy)]
pub(crate) enum On {
    File(HANDLE),
    Socket(SOCKET),
}

impl On {
    /// The handle the operation is cancelled through: a socket is one.
    fn handle(self) -> HANDLE {
        match self {
            Self::File(handle) => handle,
            Self::Socket(socket) => std::ptr::without_provenance_mut(socket),
        }
    }

    /// The operation's end, waited for (`bWait`), and how many bytes it
    /// moved; its failure in the last error, Winsock's for a socket.
    ///
    /// # Safety
    ///
    /// The operation started on this handle with `overlapped`, which lives
    /// until the call returns.
    unsafe fn ended(self, overlapped: &OVERLAPPED, moved: &mut u32) -> BOOL {
        match self {
            // SAFETY: as the caller promises.
            Self::File(handle) => unsafe { GetOverlappedResult(handle, overlapped, moved, 1) },
            Self::Socket(socket) => {
                let mut flags = 0u32;
                // SAFETY: as the caller promises; `flags` is writable.
                unsafe { WSAGetOverlappedResult(socket, overlapped, moved, 1, &raw mut flags) }
            }
        }
    }
}

/// One overlapped operation `start` begins on `on` with `event`, waited for
/// to its end — within `within`, where it names a time, and cancelled once
/// that has passed: how many bytes it moved. An operation that ended as it
/// was cancelled is ended, not timed out. A failure to start is the
/// caller's to read.
///
/// # Errors
///
/// The operation's failure, `TimedOut` where it was cancelled at `within`.
pub(crate) fn waited(
    on: On,
    event: &Event,
    within: Option<Duration>,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> std::io::Result<usize> {
    // SAFETY: all zero is an OVERLAPPED's initial state.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    let mut timed_out = false;
    if start(&raw mut overlapped) == 0 {
        let error = std::io::Error::last_os_error();
        if code_of(&error) != Some(ERROR_IO_PENDING) {
            return Err(error);
        }
        if let Some(within) = within
            && !signaled(event, within)
        {
            timed_out = true;
            // SAFETY: the operation started on `on` with `overlapped`,
            // which lives until it has ended, waited for below.
            unsafe { CancelIoEx(on.handle(), &raw const overlapped) };
        }
    }
    let mut moved = 0u32;
    // SAFETY: the operation started on `on` with `overlapped`, which lives
    // until it has ended: this waits for that.
    let ended = unsafe { on.ended(&overlapped, &mut moved) };
    if ended == 0 {
        let error = std::io::Error::last_os_error();
        if timed_out && code_of(&error) == Some(ERROR_OPERATION_ABORTED) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "nothing came within {} ms",
                    within.unwrap_or_default().as_millis()
                ),
            ));
        }
        return Err(error);
    }
    Ok(moved as usize)
}

/// The Windows error code `error` carries.
pub(crate) fn code_of(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

/// Whether `event` was signaled within `within`.
fn signaled(event: &Event, within: Duration) -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    let milliseconds = u32::try_from(within.as_micros().div_ceil(1000))
        .unwrap_or(u32::MAX)
        .min(u32::MAX - 1);
    // SAFETY: the event is open while `event` lives.
    unsafe { WaitForSingleObject(event.0, milliseconds) == WAIT_OBJECT_0 }
}

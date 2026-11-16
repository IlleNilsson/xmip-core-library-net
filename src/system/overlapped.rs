//! An overlapped operation on Windows, waited for once, the crate's one
//! way: begun with an event of its own, waited for as long as it takes or
//! within a time and cancelled once that has passed, and its end read as
//! the handle's kind reads it — a pipe's by `GetOverlappedResult`, a
//! socket's by `WSAGetOverlappedResult`, which says Winsock's error, so a
//! refused connect keeps its kind. The named pipe's reads, writes and
//! accepts (`super::pipe`) and the TCP connect (`super::connect`) wait
//! here, and so do a serial port's reads, writes and its wait for a first
//! byte, ended early by the port's close (`serial`'s `system.rs`; ADR-0064,
//! amendment 2026-11-15). Until 2026-11-14 this was the pipe's alone, in
//! its `io`; public since 2026-11-15, as the serial technology's port
//! waited its own way until then.
#![allow(unsafe_code)]

use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinSock::{SOCKET, WSAGetOverlappedResult};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::BOOL;

/// The event an operation is waited for on, one operation at a time, or
/// the one that stops a wait ([`waited`]'s `stop`).
pub struct Event(HANDLE);

// SAFETY: an event handle may be waited on, set and closed from any thread.
unsafe impl Send for Event {}
// SAFETY: as above; an operation waits on it from one thread at a time, and
// a stop is set from any.
unsafe impl Sync for Event {}

impl Event {
    /// A manual-reset event, not set, which each operation resets as it
    /// starts.
    ///
    /// # Errors
    ///
    /// Where Windows makes none.
    pub fn new() -> std::io::Result<Self> {
        use windows_sys::Win32::System::Threading::CreateEventW;
        // SAFETY: unnamed, with no attributes; closed on drop.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self(event))
        }
    }

    /// Set, and kept set: every wait it stops, the one under way and each
    /// after it, ends at once.
    pub fn set(&self) {
        use windows_sys::Win32::System::Threading::SetEvent;
        // SAFETY: the event is open while `self` lives.
        unsafe { SetEvent(self.0) };
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        // SAFETY: made by `new`, closed once.
        unsafe { CloseHandle(self.0) };
    }
}

/// What an operation is on: a file, a pipe's or a serial port's handle, or
/// a socket.
#[derive(Clone, Copy)]
pub enum On {
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

/// One overlapped operation `start` begins on `on` with the OVERLAPPED it
/// is handed, its event `event`, waited for to its end — within `within`,
/// where it names a time, and until `stop` is set, where one is given,
/// cancelled once either came: how many bytes it moved. An operation that
/// ended as it was cancelled is ended, neither timed out nor stopped. A
/// failure to start is the caller's to read. `start` begins one operation,
/// on `on`, with that OVERLAPPED, or none: the `unsafe` call it makes rests
/// on this waiting for its end before the OVERLAPPED goes.
///
/// # Errors
///
/// The operation's failure, `TimedOut` where it was cancelled at `within`,
/// `Interrupted` where it was cancelled as `stop` was set.
pub fn waited(
    on: On,
    event: &Event,
    within: Option<Duration>,
    stop: Option<&Event>,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> std::io::Result<usize> {
    // SAFETY: all zero is an OVERLAPPED's initial state.
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    overlapped.hEvent = event.0;
    let mut cut = None;
    if start(&raw mut overlapped) == 0 {
        let error = std::io::Error::last_os_error();
        if code_of(&error) != Some(ERROR_IO_PENDING) {
            return Err(error);
        }
        if within.is_some() || stop.is_some() {
            cut = cut_by(event, stop, within);
        }
        if cut.is_some() {
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
        return Err(match cut {
            Some(kind) if code_of(&error) == Some(ERROR_OPERATION_ABORTED) => {
                std::io::Error::new(kind, cut_short(kind, within))
            }
            _ => error,
        });
    }
    Ok(moved as usize)
}

/// What an operation cut short by `kind` is said to be.
fn cut_short(kind: std::io::ErrorKind, within: Option<Duration>) -> String {
    match kind {
        std::io::ErrorKind::TimedOut => format!(
            "nothing came within {} ms",
            within.unwrap_or_default().as_millis()
        ),
        _ => "stopped before anything came".to_string(),
    }
}

/// `wait` in the milliseconds Windows counts a wait or a timeout in,
/// rounded up, so a wait of less than one is one; finite, never `INFINITE`.
#[must_use]
pub fn milliseconds(wait: Duration) -> u32 {
    u32::try_from(wait.as_micros().div_ceil(1000))
        .unwrap_or(u32::MAX)
        .min(INFINITE - 1)
}

/// The Windows error code `error` carries.
pub(crate) fn code_of(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

/// What cut a wait for `event` short: `TimedOut` where `within` passed,
/// `Interrupted` where `stop` was set first; `None` where `event` was.
fn cut_by(
    event: &Event,
    stop: Option<&Event>,
    within: Option<Duration>,
) -> Option<std::io::ErrorKind> {
    use windows_sys::Win32::System::Threading::WaitForMultipleObjects;
    let milliseconds = within.map_or(INFINITE, milliseconds);
    let ends = [event.0, stop.map_or(event.0, |stop| stop.0)];
    let count = if stop.is_some() { 2 } else { 1 };
    // SAFETY: the first `count` of `ends` are events open while their
    // `Event`s live, no handle twice.
    let woke = unsafe { WaitForMultipleObjects(count, ends.as_ptr(), 0, milliseconds) };
    match woke {
        WAIT_OBJECT_0 => None,
        stopped if stop.is_some() && stopped == WAIT_OBJECT_0 + 1 => {
            Some(std::io::ErrorKind::Interrupted)
        }
        _ => Some(std::io::ErrorKind::TimedOut),
    }
}

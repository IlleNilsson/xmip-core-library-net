//! A pipe's overlapped operations, either end, on the handle it was made,
//! opened or connected with: each waited for on an event of the
//! connection's own, for as long as it takes or within a time, and
//! cancellable from another thread ([`cancel`]). A read finding its peer
//! gone is the end, `Ok(0)`.
#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_NOT_CONNECTED, HANDLE, WAIT_OBJECT_0,
};
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

/// Read into `buffer` from `pipe`, waiting until something comes: how much
/// was read, `0` where the peer is gone.
///
/// # Errors
///
/// The read's failure, or its cancel.
pub(crate) fn read(pipe: &OwnedHandle, event: &Event, buffer: &mut [u8]) -> std::io::Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let length = u32::try_from(buffer.len()).unwrap_or(u32::MAX);
    let handle = handle_of(pipe);
    let read = waited(pipe, event, None, |overlapped| {
        // SAFETY: `buffer` holds `length` bytes and outlives the operation,
        // which `waited` ends before it returns.
        unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                length,
                std::ptr::null_mut(),
                overlapped,
            )
        }
    });
    match read {
        Err(error) if gone(&error) => Ok(0),
        read => read,
    }
}

/// Write `bytes` to `pipe`: how many were written.
///
/// # Errors
///
/// The write's failure, its cancel, or a peer gone.
pub(crate) fn write(pipe: &OwnedHandle, event: &Event, bytes: &[u8]) -> std::io::Result<usize> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let handle = handle_of(pipe);
    waited(pipe, event, None, |overlapped| {
        // SAFETY: `bytes` holds `length` bytes and outlives the operation,
        // which `waited` ends before it returns.
        unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                length,
                std::ptr::null_mut(),
                overlapped,
            )
        }
    })
}

/// Cancel every read and write in flight on the pipe whose handle `open`
/// holds, from any thread; nothing where it holds none. A connection
/// clears `open` under its lock before its handle closes, so the handle
/// cancelled is never one reused for something else.
pub(crate) fn cancel(open: &std::sync::Mutex<Option<usize>>) {
    let open = open
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(handle) = *open {
        // SAFETY: the handle is open — the lock it was read under is held,
        // and its connection clears it under that lock before it closes.
        unsafe { CancelIoEx(handle as HANDLE, std::ptr::null()) };
    }
}

/// Whether `error` says the peer is gone.
pub(crate) fn gone(error: &std::io::Error) -> bool {
    code_of(error).is_some_and(|code| code == ERROR_BROKEN_PIPE || code == ERROR_PIPE_NOT_CONNECTED)
}

/// The Windows error code `error` carries.
pub(crate) fn code_of(error: &std::io::Error) -> Option<u32> {
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
}

/// The raw handle of `pipe`, as the system's calls take it.
pub(crate) fn handle_of(pipe: &OwnedHandle) -> HANDLE {
    pipe.as_raw_handle() as HANDLE
}

/// One overlapped operation `start` begins on `pipe` with `event`, waited
/// for to its end — within `within`, where it names a time, and cancelled
/// once that has passed: how many bytes it moved. An operation that ended
/// as it was cancelled is ended, not timed out. A failure to start is the
/// caller's to read.
///
/// # Errors
///
/// The operation's failure, `TimedOut` where it was cancelled at `within`.
pub(crate) fn waited(
    pipe: &OwnedHandle,
    event: &Event,
    within: Option<Duration>,
    start: impl FnOnce(*mut OVERLAPPED) -> BOOL,
) -> std::io::Result<usize> {
    let handle = handle_of(pipe);
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
            // SAFETY: the operation started on `handle` with `overlapped`,
            // which lives until it has ended, waited for below.
            unsafe { CancelIoEx(handle, &raw const overlapped) };
        }
    }
    let mut moved = 0u32;
    // SAFETY: the operation started on `handle` with `overlapped`, which
    // lives until it has ended: this waits for that (`bWait`).
    let ended = unsafe { GetOverlappedResult(handle, &raw const overlapped, &raw mut moved, 1) };
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

/// Whether `event` was signaled within `within`.
fn signaled(event: &Event, within: Duration) -> bool {
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    let milliseconds = u32::try_from(within.as_micros().div_ceil(1000))
        .unwrap_or(u32::MAX)
        .min(u32::MAX - 1);
    // SAFETY: the event is open while `event` lives.
    unsafe { WaitForSingleObject(event.0, milliseconds) == WAIT_OBJECT_0 }
}

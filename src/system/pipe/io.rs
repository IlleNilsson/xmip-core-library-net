//! A pipe's overlapped operations, either end, on the handle it was made,
//! opened or connected with: each waited for on an event of the
//! connection's own, for as long as it takes or within a time
//! (`super::super::overlapped`), and cancellable from another thread
//! ([`cancel`]). A read finding its peer gone is the end, `Ok(0)`.
#![allow(unsafe_code)]

use std::os::windows::io::{AsRawHandle, OwnedHandle};

use windows_sys::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED, HANDLE};
use windows_sys::Win32::System::IO::CancelIoEx;

use crate::system::overlapped::{Event, On, code_of, waited};

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
    let read = waited(On::File(handle), event, None, |overlapped| {
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
    waited(On::File(handle), event, None, |overlapped| {
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

/// The raw handle of `pipe`, as the system's calls take it.
pub(crate) fn handle_of(pipe: &OwnedHandle) -> HANDLE {
    pipe.as_raw_handle() as HANDLE
}

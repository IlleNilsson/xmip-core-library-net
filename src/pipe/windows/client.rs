//! The client end of a named pipe: opened so the server may identify the
//! caller and never act as it, and the wait for an instance to be free.
#![allow(unsafe_code)]

use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::time::Duration;

use widestring::U16CStr;

/// Open the named pipe at `path` as a client the server may identify and
/// never act as: `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`, so the
/// server — or whatever made a pipe of that name first — learns the
/// caller's account and cannot impersonate it beyond reading who it is.
/// Read and write the data only: a client asks for no right to make an
/// instance of the pipe. `None` where every instance is busy.
pub(crate) fn open_identifying(path: &U16CStr) -> Option<std::io::Result<OwnedHandle>> {
    use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
        OPEN_EXISTING, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    };
    // SAFETY: `path` ends in NUL, as a `U16CStr` does; every other
    // argument is a constant or null.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | FILE_WRITE_DATA,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        let busy = error.raw_os_error() == i32::try_from(ERROR_PIPE_BUSY).ok();
        return (!busy).then_some(Err(error));
    }
    // SAFETY: just opened, and owned by nothing else.
    Some(Ok(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Wait for an instance of the pipe at `path` to be free, at most
/// `within`, or for as long as it takes; whether one is.
pub(crate) fn wait_free(path: &U16CStr, within: Option<Duration>) -> bool {
    use windows_sys::Win32::System::Pipes::{NMPWAIT_WAIT_FOREVER, WaitNamedPipeW};
    let milliseconds = within.map_or(NMPWAIT_WAIT_FOREVER, |within| {
        u32::try_from(within.as_millis())
            .unwrap_or(u32::MAX)
            .clamp(1, NMPWAIT_WAIT_FOREVER - 1)
    });
    // SAFETY: `path` ends in NUL, as a `U16CStr` does.
    unsafe { WaitNamedPipeW(path.as_ptr(), milliseconds) != 0 }
}

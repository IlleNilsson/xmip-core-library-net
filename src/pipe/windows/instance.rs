//! The server end of a named pipe: its security descriptor, each instance
//! made, a client waited for on one with an `OVERLAPPED` of its own, and
//! what Windows says of the client that connected.
//!
//! An instance is never waited on without an `OVERLAPPED` — Windows
//! documents a wait without one on an instance opened overlapped as
//! unsound (*may incorrectly report that the connect operation is
//! complete*) — and never disconnected to be used again: the handle a
//! client reached is the one read and written, and the next instance is
//! made before a connected one is handed out, so a client always finds one
//! listening and one client is one connection (`pipe::windows::Listener`).
#![allow(unsafe_code)]

use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::time::Duration;

use widestring::U16CStr;

use super::io::{Event, code_of, handle_of, waited};

/// Who may open a pipe, as Windows holds a security descriptor: read once
/// from SDDL and kept for every instance the pipe makes.
pub(crate) struct Descriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is read-only once made, and freed once, on drop.
unsafe impl Send for Descriptor {}
// SAFETY: as above.
unsafe impl Sync for Descriptor {}

impl Descriptor {
    /// The descriptor `sddl` writes.
    ///
    /// # Errors
    ///
    /// Where Windows does not read it.
    pub(crate) fn from_sddl(sddl: &U16CStr) -> std::io::Result<Self> {
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: `sddl` ends in NUL; `descriptor` receives what Windows
        // allocates, freed on drop.
        let read = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if read == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion, freed once.
        unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
    }
}

/// A new instance of the pipe at `path`, overlapped, byte mode, refusing
/// clients from another machine, each direction holding `buffer` bytes,
/// opened only by whom `descriptor` admits — the first of its name where
/// `first`, so a pipe another process made already is refused.
///
/// # Errors
///
/// Where Windows refuses the instance.
pub(crate) fn instance(
    path: &U16CStr,
    descriptor: &Descriptor,
    first: bool,
    buffer: u32,
) -> std::io::Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
        PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(0),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let first = if first {
        FILE_FLAG_FIRST_PIPE_INSTANCE
    } else {
        0
    };
    let open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first;
    let mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `path` ends in NUL; `attributes` and its descriptor live
    // across the call.
    let handle = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            open,
            mode,
            PIPE_UNLIMITED_INSTANCES,
            buffer,
            buffer,
            0,
            &raw const attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: just made, and owned by nothing else.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Wait until a client has connected to the listening instance `pipe`, on
/// `event`, for as long as it takes or within `within`. A client connected
/// already, or one connected and gone — whose first read then says it is
/// gone — returns at once; nothing else does.
///
/// # Errors
///
/// `TimedOut` where no client came within `within`; where Windows refuses
/// the wait.
pub(crate) fn connected(
    pipe: &OwnedHandle,
    event: &Event,
    within: Option<Duration>,
) -> std::io::Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_NO_DATA, ERROR_PIPE_CONNECTED};
    use windows_sys::Win32::System::Pipes::ConnectNamedPipe;
    let handle = handle_of(pipe);
    let waited = waited(pipe, event, within, |overlapped| {
        // SAFETY: `handle` is open for the call, and `overlapped` outlives
        // the operation, which `waited` ends before it returns.
        unsafe { ConnectNamedPipe(handle, overlapped) }
    });
    match waited {
        Ok(_) => Ok(()),
        Err(error) if matches!(code_of(&error), Some(ERROR_PIPE_CONNECTED | ERROR_NO_DATA)) => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// `act` run while this thread stands in for the client of the connected
/// instance `pipe` — at the level the client lent — and back to itself
/// after, acted or not.
///
/// # Errors
///
/// Where Windows lends nothing: a client that sent nothing yet.
pub(crate) fn impersonating<T>(pipe: &OwnedHandle, act: impl FnOnce() -> T) -> std::io::Result<T> {
    use windows_sys::Win32::Security::RevertToSelf;
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    // SAFETY: `pipe` is an open server instance.
    if unsafe { ImpersonateNamedPipeClient(handle_of(pipe)) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let acted = act();
    // SAFETY: the thread impersonates the client since the call above.
    unsafe { RevertToSelf() };
    Ok(acted)
}

/// The process id of the client connected to the instance `pipe`.
///
/// # Errors
///
/// Where Windows does not say.
pub(crate) fn client_process(pipe: &OwnedHandle) -> std::io::Result<u32> {
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
    let mut process = 0u32;
    // SAFETY: `pipe` is an open instance; `process` receives the id.
    if unsafe { GetNamedPipeClientProcessId(handle_of(pipe), &raw mut process) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(process)
}

//! A named pipe on Windows: the kernel object under `\\.\pipe\`, made by
//! one process and opened by another, one instance one connection.
//!
//! **Who may open it** is its security descriptor's to say: the account
//! that made it, the system and the machine's administrators, fully; each
//! account or group the maker admits, to read and write it and no more;
//! nobody else, and no caller from another machine. **Who connected** is
//! the account the client's token names, lent for identification alone:
//! [`connect`] opens the pipe so, and the server reads the account and can
//! never act as it.
//!
//! **One client is one connection.** An instance is waited on with an
//! `OVERLAPPED` of its own and never disconnected; the handle a client
//! reached is the one read and written; the next instance is made before
//! a connected one is handed out, so a client always finds one listening;
//! and an accept returns only once a client has connected (`instance`).
//! Until 2026-10-21 the named pipe transport and the runtime's local
//! endpoint made their pipes through the `interprocess` crate, whose
//! defects in exactly these were reported upstream (#100, #101).
//!
//! A pipe has no read timeout: a read waiting on its peer is ended by
//! [`Cancel`], the pipe's I/O cancelled from another thread.

mod account;
mod client;
mod instance;
mod io;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use widestring::U16CString;

pub use account::IDENTIFICATION;

/// Who may open a pipe always, as Windows writes a security descriptor:
/// the account that made it, the system and the machine's administrators,
/// each fully. No ACE for anyone else is a refusal of everyone else.
const OPENERS: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;GA;;;BA)"; // spellchecker:disable-line

/// What an admitted account or group may do to a pipe: read it, its
/// attributes and its descriptor, write its data and wait on it
/// (`FILE_GENERIC_READ | FILE_WRITE_DATA`) — never make an instance of it,
/// which a generic write would grant, so no admitted caller can stand in
/// for the maker.
const ADMITTED: &str = "0x12008b";

/// What each direction of a pipe holds before a write waits on the reader.
const BUFFER: u32 = 64 * 1024;

/// How much one read of a pipe asks for where its reader asks for less:
/// HTTP/2 reads a frame's header and then its payload, each a read the
/// pipe answers through an overlapped call, so a call's few frames are
/// read in one (measured 2026-10-21, open problem 35).
const READ: usize = 16 * 1024;

/// How many names [`NAMES`] keeps before it starts again: far more
/// accounts than one machine's callers run as.
const KEPT_NAMES: usize = 1024;

/// The names of the accounts that connected, by the identifier each token
/// proved ([`Stream::caller`]).
static NAMES: OnceLock<Mutex<HashMap<Vec<u32>, String>>> = OnceLock::new();

/// The security descriptor of a pipe `admit` names the accounts and groups
/// of beside [`OPENERS`], in SDDL.
///
/// # Errors
///
/// A name Windows knows no account or group by.
pub fn openers(admit: &[String]) -> Result<String, String> {
    let mut sddl = OPENERS.to_string();
    for name in admit {
        let sid = account::account_sid(name)?;
        sddl.push_str("(A;;");
        sddl.push_str(ADMITTED);
        sddl.push_str(";;;");
        sddl.push_str(&sid);
        sddl.push(')');
    }
    Ok(sddl)
}

/// The made end, waiting for a connection: the instance a client reaches
/// next, and how to make the one after.
pub struct Listener {
    path: PathBuf,
    wide: U16CString,
    descriptor: instance::Descriptor,
    next: Mutex<(OwnedHandle, io::Event)>,
}

impl Listener {
    /// Make the pipe at `path`, opened only by whom [`openers`] and
    /// `admit` name and never from another machine.
    ///
    /// # Errors
    ///
    /// A name Windows does not permit, a pipe of that name another process
    /// already made, or an admitted name Windows does not know.
    pub fn bind(path: &Path, admit: &[String]) -> std::io::Result<Self> {
        let refused = |why: String| std::io::Error::new(std::io::ErrorKind::NotFound, why);
        let sddl = U16CString::from_str(openers(admit).map_err(refused)?)
            .map_err(std::io::Error::other)?;
        let wide = U16CString::from_os_str(path.as_os_str()).map_err(std::io::Error::other)?;
        let descriptor = instance::Descriptor::from_sddl(&sddl)?;
        let first = instance::instance(&wide, &descriptor, true, BUFFER)?;
        Ok(Self {
            path: path.to_path_buf(),
            wide,
            descriptor,
            next: Mutex::new((first, io::Event::new()?)),
        })
    }

    /// Where the pipe is.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The next connection, once a client has connected: for as long as it
    /// takes, or within `within`. The instance a client reached is handed
    /// out and the next is made first, so a client always finds one.
    ///
    /// # Errors
    ///
    /// `TimedOut` where no client came within `within`; the pipe's own
    /// failure.
    pub fn accept(&self, within: Option<Duration>) -> std::io::Result<Stream> {
        let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
        // bounded: by `within`, or as long as the maker waits; a stop wakes it
        instance::connected(&next.0, &next.1, within)?;
        let after = instance::instance(&self.wide, &self.descriptor, false, BUFFER)?;
        let (reached, event) = std::mem::replace(&mut *next, (after, io::Event::new()?));
        Ok(Stream::new(reached, event, true))
    }
}

/// One connection, either end.
pub struct Stream {
    pipe: OwnedHandle,
    /// What its reads and writes wait on.
    event: io::Event,
    open: Arc<Mutex<Option<usize>>>,
    /// Whether this is the made end, which may ask who connected.
    made: bool,
    /// What was read to learn who connected, and is read again first.
    read_ahead: Vec<u8>,
}

impl Stream {
    fn new(pipe: OwnedHandle, event: io::Event, made: bool) -> Self {
        let handle = pipe.as_raw_handle() as usize;
        Self {
            pipe,
            event,
            open: Arc::new(Mutex::new(Some(handle))),
            made,
            read_ahead: Vec::new(),
        }
    }

    /// The account the connecting process runs as, `DOMAIN\user`, by its
    /// token's word: the identifier the token proves, named as Windows
    /// names it. Windows takes about 0.35 ms to name an identifier — it
    /// asks the local security authority, which for a directory's account
    /// may ask the directory — so a name is kept for the process's life,
    /// by its identifier: the identifier is what the token proved, and an
    /// account renamed meanwhile keeps its old name until the process
    /// restarts (measured 2026-10-21, open problem 35).
    ///
    /// # Errors
    ///
    /// Where Windows does not say, the client sent nothing, or this is the
    /// client's end.
    pub fn caller(&mut self) -> Result<String, String> {
        let (sid, _) = self.lent()?;
        let mut names = NAMES
            .get_or_init(Mutex::default)
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(name) = names.get(&sid) {
            return Ok(name.clone());
        }
        let name = account::account_name(&sid)?;
        if names.len() >= KEPT_NAMES {
            names.clear();
        }
        names.insert(sid, name.clone());
        Ok(name)
    }

    /// The client's token as it lent it: its user's identifier and the
    /// level it was lent at. Windows lets a pipe's client be impersonated
    /// only once something was read from it, so its first bytes are read
    /// here and handed on first.
    ///
    /// # Errors
    ///
    /// Where Windows does not say, the client sent nothing, or this is the
    /// client's end.
    pub fn lent(&mut self) -> Result<(Vec<u32>, i32), String> {
        if !self.made {
            return Err("the client's end has no client".to_string());
        }
        if self.read_ahead.is_empty() {
            let mut first = [0u8; 64];
            let read = io::read(&self.pipe, &self.event, &mut first)
                .map_err(|error| format!("the caller sent nothing: {error}"))?;
            if read == 0 {
                return Err("the caller sent nothing".to_string());
            }
            self.read_ahead.extend_from_slice(&first[..read]);
        }
        instance::impersonating(&self.pipe, account::impersonated)
            .map_err(|error| format!("the caller is not known: {error}"))?
            .map_err(|why| format!("the caller is not known: {why}"))
    }

    /// The process id of the client, where this is the made end and
    /// Windows says it.
    #[must_use]
    pub fn peer_process(&self) -> Option<u32> {
        self.made
            .then(|| instance::client_process(&self.pipe).ok())
            .flatten()
    }

    /// What ends a read waiting on this connection, from another thread.
    #[must_use]
    pub fn cancel(&self) -> Cancel {
        Cancel(Arc::clone(&self.open))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Before the handle closes, so a cancel never reaches a handle
        // reused for something else.
        *self.open.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.read_ahead.is_empty() {
            if buffer.len() >= READ {
                return io::read(&self.pipe, &self.event, buffer);
            }
            let mut read = [0u8; READ];
            let count = io::read(&self.pipe, &self.event, &mut read)?;
            if count == 0 {
                return Ok(0);
            }
            self.read_ahead.extend_from_slice(&read[..count]);
        }
        let count = self.read_ahead.len().min(buffer.len());
        buffer[..count].copy_from_slice(&self.read_ahead[..count]);
        self.read_ahead.drain(..count);
        Ok(count)
    }
}

impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        io::write(&self.pipe, &self.event, bytes)
    }

    /// A write is in the pipe once it returns, and what a client wrote
    /// before it closed is read whole after. Windows' flush of a pipe waits
    /// until the peer has read everything, which two peers flushing at once
    /// would wait on each other for.
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Ends a read waiting on a connection, while the connection lives.
#[derive(Clone)]
pub struct Cancel(Arc<Mutex<Option<usize>>>);

impl Cancel {
    /// Cancel every read and write in flight on the connection; nothing
    /// where it has closed.
    pub fn cancel(&self) {
        io::cancel(&self.0);
    }
}

/// Connect to the pipe at `path`, lending its maker this process's account
/// for identification alone, waiting for an instance to be free at most
/// `patience`, or for as long as it takes.
///
/// # Errors
///
/// No pipe there, or none free within `patience`.
pub fn connect(path: &Path, patience: Option<Duration>) -> std::io::Result<Stream> {
    let wide = U16CString::from_os_str(path.as_os_str()).map_err(std::io::Error::other)?;
    let until = patience.map(|patience| Instant::now() + patience);
    loop {
        if let Some(opened) = client::open_identifying(&wide) {
            return Ok(Stream::new(opened?, io::Event::new()?, false));
        }
        let left = until.map(|until| until.saturating_duration_since(Instant::now()));
        if left.is_some_and(|left| left.is_zero()) || !client::wait_free(&wide, left) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "every instance of the pipe is busy",
            ));
        }
    }
}

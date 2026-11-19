//! A named pipe on Unix: a FIFO, a special file a reader opens and a
//! writer opens, which the kernel joins. A writer's close is the end of
//! what the reader reads. A FIFO has no peer the kernel names, and admits
//! by its file's mode: its owner's alone, `0600`. Its path is claimed
//! before it is made, as a socket's is (`crate::socket_file`), and only
//! its own FIFO goes with it.
//!
//! An open of a FIFO blocks until the other end opens, so an open within
//! a time happens on a thread of its own, waited on with a deadline. An
//! open with `O_NONBLOCK` instead would return at once, and a reader's
//! would then read an end for a writer that has not arrived yet, which is
//! indistinguishable from one that has come and gone. When the deadline
//! passes, the waiting open is released by opening the other end — the one
//! thing a blocked open waits for — and closing it, so no thread is left
//! behind and nothing is handed out without its peer.

use std::fs::{File, OpenOptions};
use std::path::Path;
use std::sync::mpsc::{RecvTimeoutError, channel};
use std::time::Duration;

use crate::socket_file::{Claim, Kind, at, claimed};

/// The made end, a FIFO waiting for a writer; its FIFO, its own and
/// nothing that took its place, goes with it.
pub struct Listener {
    claim: Claim,
}

impl Listener {
    /// Make the FIFO at `path`, its owner's alone, on the path claimed
    /// first: a FIFO a stopped one left there is made anew.
    ///
    /// # Errors
    ///
    /// `admit` naming anyone, which a FIFO's mode cannot say; `AddrInUse`
    /// where another holds the path; `AlreadyExists` where a file of
    /// another kind is there, which is kept; where the directory is
    /// missing or the name not permitted. Each but the first names the
    /// path.
    pub fn bind(path: &Path, admit: &[String]) -> std::io::Result<Self> {
        use nix::sys::stat::Mode;
        if !admit.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "a FIFO admits its owner alone",
            ));
        }
        let mut claim = claimed(path, Kind::Fifo)?;
        nix::unistd::mkfifo(path, Mode::S_IRUSR | Mode::S_IWUSR)
            .map_err(|error| at(path, &error.into()))?;
        claim.made()?;
        Ok(Self { claim })
    }

    /// Where the pipe is.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.claim.path()
    }

    /// The next writer's connection, once one has opened the FIFO: for as
    /// long as it takes, or within `within`.
    ///
    /// # Errors
    ///
    /// `TimedOut` where no writer came within `within`; where the FIFO
    /// could not be opened.
    pub fn accept(&self, within: Option<Duration>) -> std::io::Result<Stream> {
        opened(self.claim.path(), false, within).map(Stream)
    }
}

/// One connection, either end: the FIFO opened for reading or writing.
pub struct Stream(File);

impl Stream {
    /// A FIFO has no peer the kernel names.
    #[must_use]
    #[allow(clippy::unused_self)]
    pub const fn peer_process(&self) -> Option<u32> {
        None
    }
}

impl std::io::Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buffer)
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// Open the FIFO at `path` for writing, once its reader has opened it:
/// for as long as it takes, or within `patience`.
///
/// # Errors
///
/// No FIFO there; `TimedOut` where no reader came within `patience`.
pub fn connect(path: &Path, patience: Option<Duration>) -> std::io::Result<Stream> {
    opened(path, true, patience).map(Stream)
}

/// The FIFO at `path` opened to `write` or to read, for as long as it
/// takes or within `within`, released at the deadline by its other end.
fn opened(path: &Path, write: bool, within: Option<Duration>) -> std::io::Result<File> {
    let open = move |path: &Path| OpenOptions::new().read(!write).write(write).open(path);
    let Some(within) = within else {
        return open(path);
    };
    let (handing, arrival) = channel();
    let opener = std::thread::spawn({
        let path = path.to_path_buf();
        move || drop(handing.send(open(&path)))
    });
    match arrival.recv_timeout(within) {
        Ok(file) => {
            drop(opener.join());
            file
        }
        Err(RecvTimeoutError::Timeout) => {
            // Blocks only until the opener's own open meets it, which it
            // does whether that open has begun yet or not.
            drop(OpenOptions::new().read(write).write(!write).open(path));
            drop(opener.join());
            let peer = if write { "reader" } else { "writer" };
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("no {peer} came within {} ms", within.as_millis()),
            ))
        }
        Err(RecvTimeoutError::Disconnected) => {
            drop(opener.join());
            Err(std::io::Error::other("the pipe's opener stopped"))
        }
    }
}

//! A path a listener binds on Unix, claimed before it is bound: a Unix
//! domain socket's ([`SocketFile`]), and the named pipe's FIFO
//! (`crate::pipe`), through the one claim (ADR-0018, amendment 2026-11-19).
//!
//! **The lock.** `<path>.lock` beside the path, opened without following a
//! link and held with `flock` for as long as the listener lives. Where
//! another holds it the start is refused (`AddrInUse`) and the holder is
//! never asked, so its listener takes no connection of a start's. Once
//! locked, the file is asked whether it still is the one at `<path>.lock`
//! (device and inode, `fstat` against `lstat`); where it is not, or the
//! path is gone, it was released and removed between the start's open and
//! its lock, and the start opens it anew, `ATTEMPTS` times at most. So a
//! start that locks a removed file never holds the path while another
//! holds the file now there.
//!
//! **The lock file goes with its listener**, removed while it is still
//! held, and only where it still is the listener's own; then it is let go.
//! A start that opened it before the removal finds, once it has the lock,
//! that the file is no longer the path's, and starts over.
//!
//! **What is at the path**, read without following a link: nothing, and
//! the listener is made; a file of another kind — an ordinary file, a
//! directory, a link, a FIFO where a socket goes — is refused
//! (`AlreadyExists`) naming its kind, and left where it is; a socket is
//! asked by a connect, and refuses (`AddrInUse`) where something answers,
//! which goes on answering. One that refuses the connect
//! (`ConnectionRefused`) is a stopped listener's, stale, and removed; any
//! other answer refuses. A FIFO has no listener to ask, so a FIFO whose
//! lock is free is a stopped one's and is made anew.
//!
//! **Only its own file goes with it.** A listener knows its file by device
//! and inode from the moment it made it, and as it goes removes the path
//! only where it still is that file; then its lock file, and the lock.
//!
//! What it costs is a start's, at phase 9: an open, a lock, two looks at
//! the lock file and one at the path and, where a socket was left there, a
//! connect. Nothing on the message path.

use std::fs::{File, FileType, OpenOptions, TryLockError};
use std::io::{Error, ErrorKind};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// A Unix domain socket bound at a path claimed for it: a Unix domain
/// socket Receive Location's, and a node's local operate endpoint's. Its
/// file goes with it, and only its own.
#[derive(Debug)]
pub struct SocketFile {
    listener: UnixListener,
    /// Dropped after the listener: the file goes, then the lock.
    claim: Claim,
}

impl SocketFile {
    /// Claim `path` and bind a socket there.
    ///
    /// # Errors
    ///
    /// `AddrInUse` where another listener holds the path or something
    /// answers on a socket there; `AlreadyExists` where a file of another
    /// kind is there, which is kept; where the folder is missing or not
    /// permitted. Each names the path.
    pub fn bind(path: &Path) -> std::io::Result<Self> {
        let mut claim = claimed(path, Kind::Socket)?;
        let listener = UnixListener::bind(path).map_err(|error| at(path, &error))?;
        claim.made()?;
        Ok(Self { listener, claim })
    }

    /// The listener, to accept from.
    #[must_use]
    pub const fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Where it is bound.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.claim.path
    }
}

/// What a listener makes at its path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Kind {
    /// A Unix domain socket, [`SocketFile`]'s.
    Socket,
    /// A FIFO, the named pipe's (`crate::pipe`).
    Fifo,
}

/// How many times a start opens the lock file anew where the file it locked
/// was no longer the path's: each time, another start released the path
/// and another claimed it between its open and its lock.
const ATTEMPTS: usize = 8;

/// A path claimed for a listener: its lock held, nothing in its way, and
/// once the listener has made its file, that file, which alone goes with
/// the claim.
#[derive(Debug)]
pub(crate) struct Claim {
    path: PathBuf,
    /// Held until the claim goes, after its file.
    _lock: Lock,
    /// The device and inode of the file the listener made.
    own: Option<(u64, u64)>,
}

/// The lock beside a path, held, and which file it is.
#[derive(Debug)]
struct Lock {
    /// Closed as the lock goes, after its file is removed: the lock is let
    /// go only then.
    _file: File,
    path: PathBuf,
    /// The device and inode of the file locked.
    id: (u64, u64),
}

impl Drop for Lock {
    fn drop(&mut self) {
        if identity(&self.path).ok().flatten() == Some(self.id) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Claim {
    /// The file now at the path is the one the listener made.
    ///
    /// # Errors
    ///
    /// Where the path cannot be looked at.
    pub(crate) fn made(&mut self) -> std::io::Result<()> {
        let made = std::fs::symlink_metadata(&self.path).map_err(|error| at(&self.path, &error))?;
        self.own = Some((made.dev(), made.ino()));
        Ok(())
    }

    /// Where the listener is.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        let found = identity(&self.path).ok().flatten();
        if found.is_some() && found == self.own {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// The device and inode of the file at `path`, its link where it is one;
/// `None` where nothing is there.
fn identity(path: &Path) -> std::io::Result<Option<(u64, u64)>> {
    match std::fs::symlink_metadata(path) {
        Ok(found) => Ok(Some((found.dev(), found.ino()))),
        Err(absent) if absent.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Claim `path` for a listener that makes a `kind` there: its lock taken,
/// and a stale one of its kind removed.
///
/// # Errors
///
/// `AddrInUse` where another holds the lock or something answers on a
/// socket there; `AlreadyExists` naming what is there where it is not a
/// `kind`, left as it is; where the lock or the path cannot be opened,
/// looked at or removed. Each names the path.
pub(crate) fn claimed(path: &Path, kind: Kind) -> std::io::Result<Claim> {
    let lock = locked(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(found) => cleared(path, kind, found.file_type())?,
        Err(absent) if absent.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(at(path, &error)),
    }
    Ok(Claim {
        path: path.to_path_buf(),
        _lock: lock,
        own: None,
    })
}

/// The lock beside `path`, taken on the file that is there.
fn locked(path: &Path) -> std::io::Result<Lock> {
    let beside = beside(path);
    for _ in 0..ATTEMPTS {
        if let Some(lock) = taken(opened(&beside)?, path, &beside)? {
            return Ok(lock);
        }
    }
    Err(Error::new(
        ErrorKind::AddrInUse,
        format!(
            "{} could not be claimed: its lock, {}, was released and made anew \
             by other starts each of the {ATTEMPTS} times it was taken",
            path.display(),
            beside.display()
        ),
    ))
}

/// `<path>.lock`, where the lock beside `path` is.
fn beside(path: &Path) -> PathBuf {
    let mut beside = path.as_os_str().to_owned();
    beside.push(".lock");
    PathBuf::from(beside)
}

/// The lock file at `beside`, opened without following a link, and made,
/// its owner's alone, where it is not there.
fn opened(beside: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(beside)
        .map_err(|error| at(beside, &error))
}

/// The lock of `file`, opened at `beside`, taken: held where `file` still
/// is the one at `beside`; `None` where it was removed or replaced since it
/// was opened, and the start opens it anew.
fn taken(file: File, path: &Path, beside: &Path) -> std::io::Result<Option<Lock>> {
    match file.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            return Err(Error::new(
                ErrorKind::AddrInUse,
                format!(
                    "another listener holds {}: its lock, {}, is taken",
                    path.display(),
                    beside.display()
                ),
            ));
        }
        Err(TryLockError::Error(error)) => return Err(at(beside, &error)),
    }
    let held = file.metadata().map_err(|error| at(beside, &error))?;
    let id = (held.dev(), held.ino());
    let there = identity(beside).map_err(|error| at(beside, &error))?;
    Ok((there == Some(id)).then(|| Lock {
        _file: file,
        path: beside.to_path_buf(),
        id,
    }))
}

/// `error`, met at `path`, saying so: the system's own words name no path.
pub(crate) fn at(path: &Path, error: &Error) -> Error {
    Error::new(error.kind(), format!("{}: {error}", path.display()))
}

/// Make way at `path` for a `kind`, where `found` is there: a stale one of
/// its kind removed, anything else refused and left.
fn cleared(path: &Path, kind: Kind, found: FileType) -> std::io::Result<()> {
    let fits = match kind {
        Kind::Socket => found.is_socket(),
        Kind::Fifo => found.is_fifo(),
    };
    if !fits {
        let wanted = match kind {
            Kind::Socket => "a socket",
            Kind::Fifo => "a FIFO",
        };
        return Err(Error::new(
            ErrorKind::AlreadyExists,
            format!(
                "{} is {}, not {wanted}: it is left as it is",
                path.display(),
                what(found)
            ),
        ));
    }
    if kind == Kind::Socket {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(Error::new(
                    ErrorKind::AddrInUse,
                    format!("something answers on the socket at {}", path.display()),
                ));
            }
            Err(stale) if stale.kind() == ErrorKind::ConnectionRefused => {}
            Err(error) => {
                return Err(Error::new(
                    error.kind(),
                    format!(
                        "the socket at {} could not be asked whether anything answers on it: \
                         {error}",
                        path.display()
                    ),
                ));
            }
        }
    }
    std::fs::remove_file(path).map_err(|error| at(path, &error))
}

/// What a file of type `found` is, in words.
fn what(found: FileType) -> &'static str {
    if found.is_file() {
        "an ordinary file"
    } else if found.is_dir() {
        "a directory"
    } else if found.is_symlink() {
        "a symbolic link"
    } else if found.is_socket() {
        "a socket"
    } else if found.is_fifo() {
        "a FIFO"
    } else if found.is_char_device() {
        "a character device"
    } else if found.is_block_device() {
        "a block device"
    } else {
        "a file of another kind"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use file::temporary::Folder;
    use std::io::{Read, Write};
    use std::sync::{Arc, Barrier};

    #[test]
    fn an_ordinary_file_at_the_path_is_refused_and_kept() {
        let folder = Folder::new("net-ordinary");
        let path = folder.join("in.sock");
        std::fs::write(&path, b"kept").expect("an ordinary file");
        let refused = SocketFile::bind(&path).expect_err("refused");
        assert_eq!(refused.kind(), ErrorKind::AlreadyExists, "{refused}");
        assert!(
            refused.to_string().contains("an ordinary file"),
            "{refused}"
        );
        assert_eq!(std::fs::read(&path).expect("still there"), b"kept");

        // A listener whose socket was replaced by another's file leaves
        // that file where it is as it goes.
        let other = folder.join("other.sock");
        let bound = SocketFile::bind(&other).expect("bound");
        std::fs::remove_file(&other).expect("its socket taken away");
        std::fs::write(&other, b"someone else's").expect("a file in its place");
        drop(bound);
        assert_eq!(std::fs::read(&other).expect("kept"), b"someone else's");
    }

    #[test]
    fn a_socket_something_answers_on_is_refused_and_still_answers() {
        let folder = Folder::new("net-answers");
        let path = folder.join("in.sock");
        let answering = UnixListener::bind(&path).expect("something listens");
        let refused = SocketFile::bind(&path).expect_err("refused");
        assert_eq!(refused.kind(), ErrorKind::AddrInUse, "{refused}");
        // Its probe is one connection the listener takes; the next is ours.
        drop(answering.accept().expect("the probe"));
        let mut client = UnixStream::connect(&path).expect("it still answers");
        client.write_all(b"x").expect("written");
        let (mut served, _) = answering.accept().expect("accepted");
        let mut byte = [0u8; 1];
        served.read_exact(&mut byte).expect("read");
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn a_stale_socket_nobody_answers_is_replaced() {
        let folder = Folder::new("net-stale");
        let path = folder.join("in.sock");
        drop(UnixListener::bind(&path).expect("a socket nobody listens on now"));
        assert!(path.exists(), "the socket file stays behind");
        let bound = SocketFile::bind(&path).expect("the stale one replaced");
        let mut client = UnixStream::connect(&path).expect("it answers");
        client.write_all(b"y").expect("written");
        let (mut served, _) = bound.listener().accept().expect("accepted");
        let mut byte = [0u8; 1];
        served.read_exact(&mut byte).expect("read");
        assert_eq!(byte, *b"y");
        drop(bound);
        assert!(!path.exists(), "its own socket goes with it");
        assert!(!folder.join("in.sock.lock").exists(), "and its lock file");
    }

    #[test]
    fn a_bind_and_its_release_leave_no_lock_file() {
        let folder = Folder::new("net-released");
        let bound = SocketFile::bind(&folder.join("in.sock")).expect("bound");
        assert!(
            folder.join("in.sock.lock").exists(),
            "held while it listens"
        );
        drop(bound);
        let made = crate::pipe::Listener::bind(&folder.join("in.pipe"), &[]).expect("made");
        assert!(folder.join("in.pipe.lock").exists(), "held while it waits");
        drop(made);
        for left in ["in.sock", "in.sock.lock", "in.pipe", "in.pipe.lock"] {
            assert!(!folder.join(left).exists(), "{left} is left behind");
        }
    }

    /// One round of a start racing a release: the start opens the lock file
    /// while the first listener holds it, the first lets go, removing that
    /// file, and a second start claims the path anew; only then does the
    /// early start take the lock it opened.
    fn raced<L>(path: &Path, kind: Kind, bind: impl Fn(&Path) -> std::io::Result<L>) {
        let first = bind(path).expect("the first binds");
        let lock = beside(path);
        let early = opened(&lock).expect("the early start opens the lock");
        drop(first);
        let second = bind(path).expect("the second binds");
        let unlinked = taken(early, path, &lock).expect("its lock taken");
        assert!(
            unlinked.is_none(),
            "a lock on a removed file was held for {}",
            path.display()
        );
        let again = claimed(path, kind).expect_err("the second holds the path");
        assert_eq!(again.kind(), ErrorKind::AddrInUse, "{again}");
        assert!(
            again.to_string().contains("another listener holds"),
            "{again}"
        );
        drop(second);
    }

    #[test]
    fn a_start_racing_a_release_never_holds_a_removed_lock() {
        let folder = Folder::new("net-racing");
        let socket = folder.join("in.sock");
        let pipe = folder.join("in.pipe");
        for _ in 0..4 {
            raced(&socket, Kind::Socket, SocketFile::bind);
            raced(&pipe, Kind::Fifo, |path| {
                crate::pipe::Listener::bind(path, &[])
            });
        }
        for left in ["in.sock", "in.sock.lock", "in.pipe", "in.pipe.lock"] {
            assert!(!folder.join(left).exists(), "{left} is left behind");
        }
    }

    #[test]
    fn of_eight_simultaneous_starts_exactly_one_binds() {
        let folder = Folder::new("net-eight");
        let path = Arc::new(folder.join("in.sock"));
        let starting = Arc::new(Barrier::new(8));
        let bound: Vec<std::io::Result<SocketFile>> = (0..8)
            .map(|_| {
                let path = Arc::clone(&path);
                let starting = Arc::clone(&starting);
                std::thread::spawn(move || {
                    starting.wait();
                    SocketFile::bind(&path)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|start| start.join().expect("a start ends"))
            .collect();
        let (one, refused): (Vec<_>, Vec<_>) = bound.into_iter().partition(Result::is_ok);
        assert_eq!(one.len(), 1, "{refused:?}");
        for refusal in refused {
            let refusal = refusal.expect_err("refused");
            assert_eq!(refusal.kind(), ErrorKind::AddrInUse, "{refusal}");
        }
        // None of the seven asked the one that bound: nothing waits on it.
        let one = one.into_iter().next().expect("one").expect("bound");
        one.listener().set_nonblocking(true).expect("not blocking");
        let queued = one.listener().accept().expect_err("nothing queued");
        assert_eq!(queued.kind(), ErrorKind::WouldBlock, "{queued}");
    }

    #[test]
    fn a_refusal_in_the_system_s_own_words_names_the_path() {
        let folder = Folder::new("net-words");
        let path = folder.join("missing").join("in.sock");
        let refused = SocketFile::bind(&path).expect_err("no folder");
        assert_eq!(refused.kind(), ErrorKind::NotFound, "{refused}");
        assert!(
            refused.to_string().contains(&path.display().to_string()),
            "{refused}"
        );
    }

    #[test]
    fn an_ordinary_file_where_a_fifo_goes_is_refused_and_kept() {
        let folder = Folder::new("net-fifo");
        let path = folder.join("in.pipe");
        std::fs::write(&path, b"kept").expect("an ordinary file");
        let refused = crate::pipe::Listener::bind(&path, &[])
            .err()
            .expect("refused");
        assert_eq!(refused.kind(), ErrorKind::AlreadyExists, "{refused}");
        assert!(
            refused.to_string().contains("an ordinary file"),
            "{refused}"
        );
        assert_eq!(std::fs::read(&path).expect("still there"), b"kept");
    }
}

//! A named local endpoint: where one is on this system ([`path_of`]), the
//! one rule for every part of Xmip that names one — the named pipe
//! transport and a node's local operate listener (ADR-0014, amendment
//! 2026-10-13) — and the named pipe itself, made, accepted, connected to,
//! read and written (ADR-0014, amendment 2026-10-21).
//!
//! On Windows a named pipe is a kernel object under `\\.\pipe\`, made
//! through the system's own calls in `pipe/windows/`, the one folder of
//! this crate that crosses a C interface (`test/Unsafe.Test.ps1`). On Unix
//! the transport's pipe is a FIFO, a file, and a bare name is a file in the
//! temporary directory; a node's local endpoint there is a Unix domain
//! socket, which the standard library makes. A name that already is a path
//! is taken as one. [`Listener`], [`Stream`] and [`connect`] are the same
//! on both, so a caller names no system.

use std::path::PathBuf;

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use unix::{Listener, Stream, connect};
#[cfg(windows)]
pub use windows::{Cancel, IDENTIFICATION, Listener, Stream, connect, openers};

/// The operating system's path for an endpoint called `name`: as given
/// where it already is a path, `\\.\pipe\<name>` on Windows otherwise, and
/// a file in the temporary directory on Unix otherwise.
#[must_use]
pub fn path_of(name: &str) -> PathBuf {
    if name.contains('/') || name.contains(char::from(92)) {
        return PathBuf::from(name);
    }
    if cfg!(windows) {
        PathBuf::from(format!("\\\\.\\pipe\\{name}"))
    } else {
        std::env::temp_dir().join(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn fresh(name: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(1);
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        path_of(&format!("xmip-net-{name}-{}-{count}", std::process::id()))
    }

    #[test]
    fn a_bare_name_becomes_the_systems_path_and_a_path_stays() {
        let bare = path_of("orders");
        if cfg!(windows) {
            assert_eq!(bare, PathBuf::from("\\\\.\\pipe\\orders"));
        } else {
            assert_eq!(bare, std::env::temp_dir().join("orders"));
        }
        assert_eq!(
            path_of("/run/xmip/orders"),
            PathBuf::from("/run/xmip/orders")
        );
        assert_eq!(
            path_of("\\\\server\\pipe\\orders"),
            PathBuf::from("\\\\server\\pipe\\orders")
        );
    }

    #[test]
    fn an_accept_never_returns_without_a_client() {
        let listener = Listener::bind(&fresh("nobody"), &[]).expect("made");
        for _ in 0..3 {
            let began = Instant::now();
            let Err(error) = listener.accept(Some(Duration::from_millis(50))) else {
                panic!("an accept returned with nobody there");
            };
            let waited = began.elapsed();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
            assert!(
                waited >= Duration::from_millis(45),
                "gave up after {waited:?}"
            );
            assert!(waited < Duration::from_millis(500), "waited {waited:?}");
        }
        // The pipe still listens after its waits ran out.
        let path = listener.path().to_path_buf();
        let writer = std::thread::spawn(move || {
            connect(&path, Some(Duration::from_secs(5)))
                .and_then(|mut stream| stream.write_all(b"late"))
        });
        let mut stream = listener
            .accept(Some(Duration::from_secs(5)))
            .expect("accepted");
        let mut read = Vec::new();
        stream.read_to_end(&mut read).expect("read");
        writer.join().expect("the writer ends").expect("written");
        assert_eq!(read, b"late");
    }

    #[test]
    fn one_client_is_exactly_one_connection() {
        let listener = Listener::bind(&fresh("one"), &[]).expect("made");
        for round in 0..20u8 {
            let path = listener.path().to_path_buf();
            let writer = std::thread::spawn(move || {
                connect(&path, Some(Duration::from_secs(5)))
                    .and_then(|mut stream| stream.write_all(&[round; 3]))
            });
            let mut stream = listener
                .accept(Some(Duration::from_secs(5)))
                .expect("accepted");
            let mut read = Vec::new();
            stream.read_to_end(&mut read).expect("read to its end");
            writer.join().expect("the writer ends").expect("written");
            assert_eq!(read, [round; 3], "the client's own connection, whole");
            let second = listener.accept(Some(Duration::from_millis(30)));
            assert!(
                second.is_err(),
                "round {round}: one client gave a second connection"
            );
        }
    }

    /// On Windows a client may connect before the accept begins; a FIFO's
    /// writer waits for its reader.
    #[cfg(windows)]
    #[test]
    fn a_client_that_closes_before_the_accept_is_one_empty_connection() {
        let listener = Listener::bind(&fresh("gone"), &[]).expect("made");
        drop(connect(listener.path(), Some(Duration::from_secs(5))).expect("connected"));
        let mut stream = listener
            .accept(Some(Duration::from_secs(5)))
            .expect("accepted");
        let mut read = Vec::new();
        stream.read_to_end(&mut read).expect("read");
        assert_eq!(read, [] as [u8; 0]);
        assert!(listener.accept(Some(Duration::from_millis(30))).is_err());
    }

    #[test]
    fn nothing_made_there_cannot_be_connected_to() {
        let error = connect(&fresh("unmade"), Some(Duration::from_millis(50)))
            .err()
            .expect("nothing there");
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
    }

    #[cfg(windows)]
    #[test]
    fn a_caller_lends_its_account_for_identification_alone() {
        let listener = Listener::bind(&fresh("lent"), &[]).expect("made");
        let path = listener.path().to_path_buf();
        let client = std::thread::spawn(move || {
            let mut stream = connect(&path, Some(Duration::from_secs(5))).expect("connected");
            assert!(stream.lent().is_err(), "the client's end has no client");
            stream.write_all(b"x").expect("written");
            let mut back = [0u8; 1];
            stream.read_exact(&mut back).map(|()| back)
        });
        let mut served = listener.accept(None).expect("accepted");
        let (_, level) = served.lent().expect("lent");
        assert_eq!(level, IDENTIFICATION, "identification alone");
        let caller = served.caller().expect("named");
        assert!(caller.contains('\\'), "DOMAIN\\user: {caller}");
        assert_eq!(served.peer_process(), Some(std::process::id()));
        let mut first = [0u8; 1];
        served.read_exact(&mut first).expect("what was read ahead");
        assert_eq!(first, *b"x");
        served.write_all(b"y").expect("answered");
        // The answer reaches the connection the caller made: one, not a
        // second opened behind it.
        let heard = client.join().expect("the client ends");
        assert_eq!(heard.expect("answered on its own connection"), *b"y");
    }

    #[cfg(windows)]
    #[test]
    fn an_admitted_account_may_read_and_write_and_a_name_nobody_has_is_refused() {
        let domain = std::env::var("USERDOMAIN").expect("a domain");
        let user = std::env::var("USERNAME").expect("a user");
        let sddl = openers(&[format!("{domain}\\{user}")]).expect("this test's account");
        let always = openers(&[]).expect("none");
        let admitted = sddl.strip_prefix(&always).expect("the openers first");
        assert!(admitted.starts_with("(A;;0x12008b;;;S-1-"), "{sddl}");
        assert!(admitted.ends_with(')') && admitted.matches('(').count() == 1);
        let nobody = openers(&["XMIP-NO-SUCH\\nobody-at-all".to_string()])
            .expect_err("nobody has that name");
        assert!(nobody.contains("knows no account or group"), "{nobody}");
    }

    #[cfg(windows)]
    #[test]
    fn a_read_waiting_on_its_peer_is_ended_by_its_cancel() {
        let listener = Listener::bind(&fresh("cancel"), &[]).expect("made");
        let client = connect(listener.path(), Some(Duration::from_secs(5))).expect("connected");
        let mut served = listener.accept(None).expect("accepted");
        let cancel = served.cancel();
        let ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let canceler = std::thread::spawn({
            let ended = std::sync::Arc::clone(&ended);
            move || {
                // Again until the read has ended: a cancel before the read
                // began cancels nothing.
                while !ended.load(std::sync::atomic::Ordering::Acquire) {
                    cancel.cancel();
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });
        let mut buffer = [0u8; 1];
        let read = served.read(&mut buffer);
        ended.store(true, std::sync::atomic::Ordering::Release);
        canceler.join().expect("the canceler ends");
        assert!(read.is_err(), "the cancel ends the read");
        drop(client);
    }
}

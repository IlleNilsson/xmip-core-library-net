//! A peer speaking HTTP/2 by prior knowledge that sends two runs of
//! `PING`s, a span passing on the test's clock between the runs: what a
//! test holds the other side to, that it counts a peer's frames in a span
//! (RFC 9113 section 10.5) on the Clock its caller handed it (ADR-0068,
//! amendments 2026-11-16 and 2026-11-17). Each run within what a span
//! allows and both together over it, the side under test goes on where the
//! span passed on its clock and ends the connection with
//! `ENHANCE_YOUR_CALM` where it did not. A client in memory holds a server
//! to it ([`Pinging`], [`calmed`]); a server on a connection a client
//! opened holds the client ([`answering`]).

use std::io::{Cursor, Read, Write};
use std::ops::Range;
use std::sync::{Arc, Mutex, PoisonError};

use crate::http2::PREFACE;
use crate::http2::error::ErrorCode;
use crate::http2::frame::{self, ACK, END_HEADERS, END_STREAM, Frame, Kind, MAX_FRAME_SIZE_LIMIT};

/// What is done between the two runs: a span passed on the test's clock,
/// or nothing.
pub type Between = Box<dyn FnOnce() + Send>;

/// The peer: its preface, its `SETTINGS` and a run of `PING`s; then, once
/// the server has read every octet before, [`Between`] done, a run as long
/// and the head of a `GET /`. What the server writes to it is kept.
pub struct Pinging {
    before: Cursor<Vec<u8>>,
    after: Cursor<Vec<u8>>,
    between: Option<Between>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Pinging {
    /// Runs of `pings` `PING`s each, `between` done between them.
    ///
    /// # Panics
    ///
    /// Never: a frame is written into memory.
    #[must_use]
    pub fn new(pings: u64, between: Between) -> Self {
        let mut before = PREFACE.to_vec();
        let settings = Frame::new(Kind::Settings, 0, 0, Vec::new());
        frame::write(&mut before, &settings).expect("written into memory");
        let mut after = Vec::new();
        run(&mut before, 0..pings);
        run(&mut after, pings..pings * 2);
        // GET, http, `/`: from the static table alone.
        let head = Frame::new(
            Kind::Headers,
            END_HEADERS | END_STREAM,
            1,
            vec![0x82, 0x86, 0x84],
        );
        frame::write(&mut after, &head).expect("written into memory");
        Self {
            before: Cursor::new(before),
            after: Cursor::new(after),
            between: Some(between),
            written: Arc::default(),
        }
    }

    /// What the server wrote to it, held past the connection.
    #[must_use]
    pub fn written(&self) -> Arc<Mutex<Vec<u8>>> {
        Arc::clone(&self.written)
    }
}

impl Read for Pinging {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.before.read(buf)?;
        if read > 0 {
            return Ok(read);
        }
        if let Some(between) = self.between.take() {
            between();
        }
        self.after.read(buf)
    }
}

impl Write for Pinging {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        written.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Whether `written`, what a server wrote, ends the connection with
/// `ENHANCE_YOUR_CALM`.
#[must_use]
pub fn calmed(written: &Mutex<Vec<u8>>) -> bool {
    let written = written.lock().unwrap_or_else(PoisonError::into_inner);
    let mut octets = written.as_slice();
    let calm = ErrorCode::EnhanceYourCalm.code();
    while let Ok(Some(frame)) = frame::read(&mut octets, MAX_FRAME_SIZE_LIMIT) {
        if frame.kind == Kind::Goaway && frame.word(4) == Some(calm) {
            return true;
        }
    }
    false
}

/// Serve the one request a client speaking HTTP/2 by prior knowledge sends
/// on `stream` as a server flooding it would: its `SETTINGS` and the
/// client's acknowledged, the request read to its end, a run of `pings`
/// `PING`s, [`Between`] done once the client has answered every one, a run
/// as long, and a `200` ending the request's stream; then whatever the
/// client sends, until it lets the connection go. A client that counts its
/// server's frames on the clock the test steps answers `200` where the
/// span passed between the runs, and ends the connection with
/// `ENHANCE_YOUR_CALM` before its answer where it did not.
///
/// # Panics
///
/// Where the client's preface, its request or its answers to the first run
/// could not be read, or what goes before them not written: a test's far
/// end, failing it.
pub fn answering(mut stream: impl Read + Write, pings: u64, between: Between) {
    let mut preface = [0u8; PREFACE.len()];
    stream
        .read_exact(&mut preface)
        .expect("the client's preface");
    assert_eq!(
        &preface, PREFACE,
        "a client speaking HTTP/2 by prior knowledge"
    );
    let settings = Frame::new(Kind::Settings, 0, 0, Vec::new());
    frame::write(&mut stream, &settings).expect("SETTINGS written");
    let request = loop {
        let frame = next(&mut stream).expect("the client's request");
        if frame.kind == Kind::Settings && !frame.has(ACK) {
            let acknowledged = Frame::new(Kind::Settings, ACK, 0, Vec::new());
            frame::write(&mut stream, &acknowledged).expect("SETTINGS acknowledged");
        }
        if matches!(frame.kind, Kind::Headers | Kind::Data) && frame.has(END_STREAM) {
            break frame.stream;
        }
    };
    let mut first = Vec::new();
    run(&mut first, 0..pings);
    stream.write_all(&first).expect("the first run written");
    let mut answered = 0;
    while answered < pings {
        let frame = next(&mut stream).expect("the client's answers to the first run");
        if frame.kind == Kind::Ping && frame.has(ACK) {
            answered += 1;
        }
    }
    between();
    // What the client may refuse midway and close the connection on.
    let mut second = Vec::new();
    run(&mut second, pings..pings * 2);
    // `:status 200` from the static table alone.
    let ok = Frame::new(Kind::Headers, END_HEADERS | END_STREAM, request, vec![0x88]);
    frame::write(&mut second, &ok).expect("written into memory");
    if stream.write_all(&second).is_ok() {
        while next(&mut stream).is_some() {}
    }
}

/// A `PING` numbered by each of `numbers`, written into `into`.
fn run(into: &mut Vec<u8>, numbers: Range<u64>) {
    for n in numbers {
        frame::write(into, &Frame::ping(n.to_be_bytes(), false)).expect("written into memory");
    }
}

/// The next frame on `stream`: none where it ended or broke.
fn next(stream: &mut impl Read) -> Option<Frame> {
    frame::read(stream, MAX_FRAME_SIZE_LIMIT).ok().flatten()
}

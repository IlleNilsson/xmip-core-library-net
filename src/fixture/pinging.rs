//! A client speaking HTTP/2 by prior knowledge, in memory, that sends two
//! runs of `PING`s and a request's head, a span passing on the test's
//! clock between the runs: what a test holds a server to, that it counts a
//! peer's frames in a span (RFC 9113 section 10.5) on the Clock its caller
//! handed it (ADR-0068, amendment 2026-11-16). Each run within what a span
//! allows and both together over it, the server goes on where the span
//! passed on its clock and ends the connection with `ENHANCE_YOUR_CALM`
//! where it did not ([`calmed`]).

use std::io::{Cursor, Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

use crate::http2::PREFACE;
use crate::http2::error::ErrorCode;
use crate::http2::frame::{self, END_HEADERS, END_STREAM, Frame, Kind, MAX_FRAME_SIZE_LIMIT};

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
        for n in 0..pings {
            let (first, second) = (n.to_be_bytes(), (pings + n).to_be_bytes());
            frame::write(&mut before, &Frame::ping(first, false)).expect("written into memory");
            frame::write(&mut after, &Frame::ping(second, false)).expect("written into memory");
        }
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

//! One HTTP/2 connection, either side: the settings each side announced,
//! the header compression each keeps, the connection's two windows, the
//! streams and what has arrived on them. This half writes — the preface,
//! a header block split over `HEADERS` and `CONTINUATION`, a body in
//! `DATA` as the windows allow, `RST_STREAM`, `PING` and `GOAWAY` — and
//! [`receive`](super::receive) reads.

use std::collections::BTreeMap;
use std::io::{Read, Write};

use super::error::{ErrorCode, Violation};
use super::frame::{self, END_HEADERS, END_STREAM, Frame, Kind};
use super::hpack::{Decoder, Encoder};
use super::preface::PREFACE;
use super::settings::{DEFAULT_WINDOW, Settings};
use super::stream::{State, Stream};
use super::window::Window;
use crate::NetError;

/// The largest dynamic table this side's encoder keeps, whatever the peer
/// allows.
const ENCODER_TABLE: u32 = 4096;

/// A header block still waiting for its `CONTINUATION`.
pub(super) struct Continuing {
    pub(super) stream: u32,
    pub(super) block: Vec<u8>,
    pub(super) end: bool,
}

/// One connection over `io`: a socket, or one wrapped in TLS.
pub(super) struct Connection<S> {
    pub(super) io: S,
    /// Whether this side is the client, which opens the odd streams.
    pub(super) client: bool,
    pub(super) local: Settings,
    pub(super) remote: Settings,
    pub(super) encoder: Encoder,
    pub(super) decoder: Decoder,
    /// What this side may still send on the connection.
    pub(super) send: Window,
    /// What the peer may still send on the connection.
    pub(super) receive: Window,
    pub(super) streams: BTreeMap<u32, Stream>,
    pub(super) continuing: Option<Continuing>,
    /// The highest stream either side has opened; above it every stream
    /// is idle.
    pub(super) highest: u32,
    /// The highest stream the peer opened, which a `GOAWAY` names.
    pub(super) last_peer: u32,
    /// The peer's `GOAWAY`: the last stream it will process, and why.
    pub(super) goaway: Option<(u32, ErrorCode)>,
    /// Whether this side has sent `GOAWAY`.
    pub(super) going_away: bool,
    /// Whether the peer's `SETTINGS` has arrived, which must come first.
    pub(super) settings_seen: bool,
    /// Every `PING` acknowledgement that has arrived.
    pub(super) pongs: Vec<[u8; 8]>,
    /// How often a send waited for a window to open.
    pub(super) stalls: usize,
}

impl<S: Read + Write> Connection<S> {
    /// Start a connection over `io`: a client writes the preface, and both
    /// sides their `SETTINGS`. A server has read the client's preface
    /// first.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn start(io: S, client: bool) -> Result<Self, NetError> {
        let local = Settings::ours();
        let mut connection = Self {
            io,
            client,
            local,
            remote: Settings::default(),
            encoder: Encoder::new(ENCODER_TABLE as usize, true),
            decoder: Decoder::new(local.header_table_size as usize),
            send: Window::new(DEFAULT_WINDOW),
            receive: Window::new(DEFAULT_WINDOW),
            streams: BTreeMap::new(),
            continuing: None,
            highest: 0,
            last_peer: 0,
            goaway: None,
            going_away: false,
            settings_seen: false,
            pongs: Vec::new(),
            stalls: 0,
        };
        if client {
            connection
                .io
                .write_all(PREFACE)
                .map_err(|failed| NetError::from_io("writing the preface", &failed))?;
        }
        let settings = Frame::new(Kind::Settings, 0, 0, local.encode());
        connection.emit(&settings)?;
        Ok(connection)
    }

    /// A stream opened on `id`, with the windows both sides announced.
    pub(super) fn open(&mut self, id: u32) -> &mut Stream {
        self.highest = self.highest.max(id);
        self.streams.entry(id).or_insert_with(|| {
            Stream::new(
                self.remote.initial_window_size,
                self.local.initial_window_size,
            )
        })
    }

    /// Write `frame` and flush it.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn emit(&mut self, frame: &Frame) -> Result<(), NetError> {
        frame::write(&mut self.io, frame)?;
        self.io
            .flush()
            .map_err(|failed| NetError::from_io("flushing a frame", &failed))
    }

    /// Write `fields` as one header block on `id`, over as many frames as
    /// the peer's maximum frame size asks, ending the stream where `end`
    /// says so.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn send_headers(
        &mut self,
        id: u32,
        fields: &[(String, String)],
        end: bool,
    ) -> Result<(), NetError> {
        let block = self.encoder.encode(
            fields
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        );
        let most = self.remote.max_frame_size as usize;
        let mut pieces = block.chunks(most).peekable();
        let mut kind = Kind::Headers;
        let mut first = true;
        while let Some(piece) = pieces.next().or_else(|| first.then_some(&[][..])) {
            let mut flags = if pieces.peek().is_none() {
                END_HEADERS
            } else {
                0
            };
            if first && end {
                flags |= END_STREAM;
            }
            self.emit(&Frame::new(kind, flags, id, piece.to_vec()))?;
            kind = Kind::Continuation;
            first = false;
        }
        if end {
            self.end_locally(id);
        }
        Ok(())
    }

    /// Write `body` on `id` in `DATA`, never past the connection's window,
    /// the stream's or the peer's frame size: where a window is shut, read
    /// what the peer sends until it opens — a stall, counted — and go on.
    ///
    /// # Errors
    ///
    /// Where the connection broke or closed while waiting, or the peer
    /// reset the stream or went away.
    pub(super) fn send_data(&mut self, id: u32, body: &[u8], end: bool) -> Result<(), NetError> {
        let mut rest = body;
        loop {
            let open = self.open_window(id)?;
            let most = (self.remote.max_frame_size as usize).min(open);
            if most == 0 && !rest.is_empty() {
                self.stalls += 1;
                if !self.pump()? {
                    return Err(NetError::new(
                        "the connection closed while a window was shut",
                    ));
                }
                continue;
            }
            let (piece, after) = rest.split_at(rest.len().min(most));
            let last = after.is_empty();
            let flags = if last && end { END_STREAM } else { 0 };
            self.emit(&Frame::new(Kind::Data, flags, id, piece.to_vec()))?;
            self.send.take(piece.len())?;
            if let Some(stream) = self.streams.get_mut(&id) {
                stream.send.take(piece.len())?;
            }
            rest = after;
            if last {
                break;
            }
        }
        if end {
            self.end_locally(id);
        }
        Ok(())
    }

    /// The octets `id` may send now, or why it may send none ever again.
    fn open_window(&self, id: u32) -> Result<usize, NetError> {
        let stream = self
            .streams
            .get(&id)
            .ok_or_else(|| NetError::new(format!("stream {id} is not open")))?;
        if let Some(code) = stream.reset {
            return Err(refused(id, code));
        }
        if !stream.state.sending() {
            return Err(NetError::new(format!("stream {id} is closed to sending")));
        }
        Ok(self.send.available().min(stream.send.available()))
    }

    fn end_locally(&mut self, id: u32) {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.state = stream.state.ended_locally();
        }
    }

    /// End `id` with `code`, telling the peer.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn reset(&mut self, id: u32, code: ErrorCode) -> Result<(), NetError> {
        if let Some(stream) = self.streams.get_mut(&id) {
            stream.state = State::Closed;
            stream.reset = Some(code);
        }
        self.emit(&Frame::reset(id, code))
    }

    /// Tell the peer this side is going away: nothing it opens after the
    /// last stream it opened will be processed.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn go_away(&mut self, code: ErrorCode, debug: &str) -> Result<(), NetError> {
        self.going_away = true;
        self.emit(&Frame::goaway(self.last_peer, code, debug.as_bytes()))
    }

    /// End the connection over `violation`: a `GOAWAY` carrying its code,
    /// and the failure the caller returns.
    pub(super) fn fail(&mut self, violation: Violation) -> NetError {
        let _ = self.go_away(violation.code, &violation.message);
        violation.into()
    }

    /// Send a `PING` and read until its acknowledgement comes back.
    ///
    /// # Errors
    ///
    /// Where the connection broke or closed first.
    pub(super) fn ping(&mut self, opaque: [u8; 8]) -> Result<(), NetError> {
        self.emit(&Frame::ping(opaque, false))?;
        while !self.pongs.contains(&opaque) {
            if !self.pump()? {
                return Err(NetError::new(
                    "the connection closed before the PING came back",
                ));
            }
        }
        Ok(())
    }
}

/// The failure of a stream the peer reset; one it refused, or that a
/// `GOAWAY` passed over, was never processed and may be sent again.
pub(super) fn refused(id: u32, code: ErrorCode) -> NetError {
    let mut failure = NetError::new(format!("stream {id} was reset: {code:?}"));
    if code == ErrorCode::RefusedStream {
        failure.io = Some(std::io::ErrorKind::ConnectionAborted);
    }
    failure
}

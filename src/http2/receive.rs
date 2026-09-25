//! The reading half of a [`Connection`]: one frame at a time, each type
//! handled as RFC 9113 section 6 says, a breach of the connection ended
//! with `GOAWAY` and a breach of one stream with `RST_STREAM` (section
//! 5.4).

use std::io::{Read, Write};

use super::connection::{Connection, Continuing};
use super::error::{ErrorCode, Violation};
use super::frame::{self, ACK, END_HEADERS, END_STREAM, Frame, Kind, MAX_STREAM_ID, ReadFailure};
use super::message::check;
use super::stream::State;
use crate::NetError;
use crate::http::MAX_BODY;

/// The largest header block assembled, before it is decoded.
const MAX_BLOCK: usize = 1024 * 1024;

/// A breach of the whole connection, or of one stream.
enum Breach {
    Connection(Violation),
    Stream(u32, Violation),
}

impl From<Violation> for Breach {
    fn from(violation: Violation) -> Self {
        Self::Connection(violation)
    }
}

impl<S: Read + Write> Connection<S> {
    /// Read and handle one frame: `false` where the peer closed the
    /// connection cleanly.
    ///
    /// # Errors
    ///
    /// Where the connection broke, or the peer breached the connection,
    /// which is answered with `GOAWAY` first.
    pub(super) fn pump(&mut self) -> Result<bool, NetError> {
        let frame = match frame::read(&mut self.io, self.local.max_frame_size) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Ok(false),
            Err(ReadFailure::Net(failure)) => return Err(failure),
            Err(ReadFailure::Violation(violation)) => return Err(self.fail(violation)),
        };
        match self.handle(&frame) {
            Ok(()) => Ok(true),
            Err(Breach::Connection(violation)) => Err(self.fail(violation)),
            Err(Breach::Stream(id, violation)) => {
                self.reset(id, violation.code)?;
                Ok(true)
            }
        }
    }

    fn handle(&mut self, frame: &Frame) -> Result<(), Breach> {
        if !self.settings_seen && frame.kind != Kind::Settings {
            return Err(Violation::protocol("the peer's first frame is not SETTINGS").into());
        }
        if let Some(continuing) = &self.continuing
            && (frame.kind != Kind::Continuation || frame.stream != continuing.stream)
        {
            return Err(Violation::protocol("a header block interrupted").into());
        }
        let on_connection = frame.stream == 0;
        let wrong_stream = match frame.kind {
            Kind::Settings | Kind::Ping | Kind::Goaway => !on_connection,
            Kind::Data | Kind::Headers | Kind::Priority | Kind::RstStream | Kind::Continuation => {
                on_connection
            }
            Kind::PushPromise | Kind::WindowUpdate | Kind::Unknown(_) => false,
        };
        if wrong_stream {
            let kind = frame.kind;
            return Err(Violation::protocol(format!("{kind:?} on stream {}", frame.stream)).into());
        }
        match frame.kind {
            Kind::Data => self.data(frame),
            Kind::Headers => {
                let block = frame.content()?.to_vec();
                self.block(
                    frame.stream,
                    block,
                    frame.has(END_STREAM),
                    frame.has(END_HEADERS),
                )
            }
            Kind::Continuation => self.continuation(frame),
            Kind::Priority if frame.payload.len() != 5 => Err(Breach::Stream(
                frame.stream,
                Violation::frame_size("a PRIORITY that is not 5 octets"),
            )),
            Kind::Priority | Kind::Unknown(_) => Ok(()),
            Kind::RstStream => self.rst_stream(frame),
            Kind::Settings => self.settings(frame),
            Kind::PushPromise => Err(Violation::protocol("a PUSH_PROMISE, and push is off").into()),
            Kind::Ping => self.ping_frame(frame),
            Kind::Goaway => self.goaway_frame(frame),
            Kind::WindowUpdate => self.window_update(frame),
        }
    }

    /// Whether `id` is above every stream opened: idle, where only
    /// `HEADERS` and `PRIORITY` may arrive.
    const fn idle(&self, id: u32) -> bool {
        id > self.highest
    }

    fn data(&mut self, frame: &Frame) -> Result<(), Breach> {
        let id = frame.stream;
        let length = frame.payload.len();
        self.receive.take(length)?;
        if length > 0 {
            let increment = u32::try_from(length).unwrap_or(MAX_STREAM_ID);
            self.emit(&Frame::window_update(0, increment))
                .map_err(lost)?;
            self.receive.grant(increment)?;
        }
        if self.idle(id) {
            return Err(Violation::protocol(format!("DATA on idle stream {id}")).into());
        }
        let Some(stream) = self.streams.get_mut(&id) else {
            return Err(Breach::Stream(id, closed("DATA")));
        };
        if stream.reset.is_some() {
            // Reset already: what was in flight when it was is let go.
            return Ok(());
        }
        if !stream.state.receiving() {
            return Err(Breach::Stream(id, closed("DATA")));
        }
        stream
            .receive
            .take(length)
            .map_err(|v| Breach::Stream(id, v))?;
        let content = frame.content()?;
        if stream.body.len() + content.len() > MAX_BODY {
            let over = Violation::new(ErrorCode::Cancel, "a body over the most Xmip reads");
            return Err(Breach::Stream(id, over));
        }
        stream.body.extend_from_slice(content);
        if frame.has(END_STREAM) {
            stream.state = stream.state.ended_remotely();
        } else if length > 0 {
            let increment = u32::try_from(length).unwrap_or(MAX_STREAM_ID);
            stream.receive.grant(increment)?;
            self.emit(&Frame::window_update(id, increment))
                .map_err(lost)?;
        }
        Ok(())
    }

    fn block(&mut self, id: u32, block: Vec<u8>, end: bool, whole: bool) -> Result<(), Breach> {
        if block.len() > MAX_BLOCK {
            return Err(
                Violation::new(ErrorCode::EnhanceYourCalm, "a header block over 1 MiB").into(),
            );
        }
        if !whole {
            self.continuing = Some(Continuing {
                stream: id,
                block,
                end,
            });
            return Ok(());
        }
        // Decoded whatever becomes of the stream: the table is the
        // connection's, and the peer's encoder has moved on.
        let fields = self.decoder.decode(&block)?;
        let limit = self
            .local
            .max_header_list_size
            .map_or(usize::MAX, |size| size as usize);
        check(&fields, limit).map_err(|v| Breach::Stream(id, v))?;
        if let Some(stream) = self.streams.get_mut(&id) {
            if stream.reset.is_some() {
                return Ok(());
            }
            return stream
                .headers(fields, end)
                .map_err(|v| Breach::Stream(id, v));
        }
        // Only a client opens a stream, on an odd number above the last.
        if self.client || id.is_multiple_of(2) || id <= self.last_peer {
            return Err(Violation::protocol(format!("a header block on stream {id}")).into());
        }
        self.last_peer = id;
        self.highest = self.highest.max(id);
        if self.going_away {
            return Ok(());
        }
        let open = self
            .streams
            .values()
            .filter(|s| s.state != State::Closed)
            .count();
        let most = self
            .local
            .max_concurrent_streams
            .map_or(usize::MAX, |most| most as usize);
        if open >= most {
            let refused = Violation::new(ErrorCode::RefusedStream, "too many streams at once");
            return Err(Breach::Stream(id, refused));
        }
        self.open(id)
            .headers(fields, end)
            .map_err(|v| Breach::Stream(id, v))
    }

    fn continuation(&mut self, frame: &Frame) -> Result<(), Breach> {
        let Some(mut continuing) = self.continuing.take() else {
            return Err(Violation::protocol("a CONTINUATION that continues nothing").into());
        };
        continuing.block.extend_from_slice(&frame.payload);
        let Continuing { stream, block, end } = continuing;
        self.block(stream, block, end, frame.has(END_HEADERS))
    }

    fn rst_stream(&mut self, frame: &Frame) -> Result<(), Breach> {
        let code = frame
            .word(0)
            .filter(|_| frame.payload.len() == 4)
            .ok_or_else(|| Violation::frame_size("a RST_STREAM that is not 4 octets"))?;
        if self.idle(frame.stream) {
            return Err(Violation::protocol("a RST_STREAM on an idle stream").into());
        }
        if let Some(stream) = self.streams.get_mut(&frame.stream) {
            stream.reset = Some(ErrorCode::of(code));
            stream.state = State::Closed;
        }
        Ok(())
    }

    fn settings(&mut self, frame: &Frame) -> Result<(), Breach> {
        if frame.has(ACK) {
            if !frame.payload.is_empty() {
                return Err(
                    Violation::frame_size("a SETTINGS acknowledgement with a payload").into(),
                );
            }
            return Ok(());
        }
        let before = self.remote.initial_window_size;
        self.remote.apply(&frame.payload, self.client)?;
        let delta = i64::from(self.remote.initial_window_size) - i64::from(before);
        for stream in self.streams.values_mut() {
            stream.send.shift(delta)?;
        }
        self.encoder
            .resize(self.remote.header_table_size.min(4096) as usize);
        self.settings_seen = true;
        self.emit(&Frame::new(Kind::Settings, ACK, 0, Vec::new()))
            .map_err(lost)
    }

    fn ping_frame(&mut self, frame: &Frame) -> Result<(), Breach> {
        let opaque: [u8; 8] = frame
            .payload
            .as_slice()
            .try_into()
            .map_err(|_| Violation::frame_size("a PING that is not 8 octets"))?;
        if frame.has(ACK) {
            self.pongs.push(opaque);
            return Ok(());
        }
        self.emit(&Frame::ping(opaque, true)).map_err(lost)
    }

    fn goaway_frame(&mut self, frame: &Frame) -> Result<(), Breach> {
        let (Some(last), Some(code)) = (frame.word(0), frame.word(4)) else {
            return Err(Violation::frame_size("a GOAWAY under 8 octets").into());
        };
        let last = last & MAX_STREAM_ID;
        let code = ErrorCode::of(code);
        self.goaway = Some((last, code));
        let client = self.client;
        for (id, stream) in self.streams.range_mut(last + 1..) {
            if (id % 2 == 1) == client && stream.reset.is_none() {
                stream.reset = Some(ErrorCode::RefusedStream);
            }
        }
        Ok(())
    }

    fn window_update(&mut self, frame: &Frame) -> Result<(), Breach> {
        let increment = frame
            .word(0)
            .filter(|_| frame.payload.len() == 4)
            .ok_or_else(|| Violation::frame_size("a WINDOW_UPDATE that is not 4 octets"))?
            & MAX_STREAM_ID;
        let id = frame.stream;
        if id == 0 {
            return Ok(self.send.grant(increment)?);
        }
        if self.idle(id) {
            return Err(Violation::protocol("a WINDOW_UPDATE on an idle stream").into());
        }
        match self.streams.get_mut(&id) {
            Some(stream) => stream
                .send
                .grant(increment)
                .map_err(|v| Breach::Stream(id, v)),
            None => Ok(()),
        }
    }
}

/// A frame on a stream the peer has already ended.
fn closed(what: &str) -> Violation {
    Violation::new(
        ErrorCode::StreamClosed,
        format!("{what} on a closed stream"),
    )
}

/// The connection broke while answering the peer.
fn lost(failure: NetError) -> Breach {
    Breach::Connection(Violation::new(ErrorCode::Internal, failure.message))
}

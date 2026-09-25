//! The frame of RFC 9113 section 4: nine octets of header — a 24-bit
//! length, a type, flags and a 31-bit stream identifier — and the payload,
//! with the layout of each of the ten types of section 6 written and read.

use std::io::{ErrorKind, Read, Write};

use super::error::{ErrorCode, Violation};
use crate::NetError;

/// The octets of a frame's header.
pub const HEADER_LEN: usize = 9;

/// The largest payload a peer may send before it is told otherwise
/// (`SETTINGS_MAX_FRAME_SIZE`'s initial value).
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;

/// The largest `SETTINGS_MAX_FRAME_SIZE` may be: 2^24 - 1.
pub const MAX_FRAME_SIZE_LIMIT: u32 = 16_777_215;

/// The largest stream identifier and window: 2^31 - 1.
pub const MAX_STREAM_ID: u32 = 0x7fff_ffff;

/// `END_STREAM`, on `DATA` and `HEADERS`.
pub const END_STREAM: u8 = 0x1;
/// `ACK`, on `SETTINGS` and `PING`.
pub const ACK: u8 = 0x1;
/// `END_HEADERS`, on `HEADERS`, `PUSH_PROMISE` and `CONTINUATION`.
pub const END_HEADERS: u8 = 0x4;
/// `PADDED`, on `DATA`, `HEADERS` and `PUSH_PROMISE`.
pub const PADDED: u8 = 0x8;
/// `PRIORITY`, on `HEADERS`.
pub const PRIORITY: u8 = 0x20;

/// The type of a frame (RFC 9113 section 6); one this side does not know
/// is kept by its number and ignored, as section 4.1 asks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    Goaway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl Kind {
    /// The type as the wire carries it.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Data => 0x0,
            Self::Headers => 0x1,
            Self::Priority => 0x2,
            Self::RstStream => 0x3,
            Self::Settings => 0x4,
            Self::PushPromise => 0x5,
            Self::Ping => 0x6,
            Self::Goaway => 0x7,
            Self::WindowUpdate => 0x8,
            Self::Continuation => 0x9,
            Self::Unknown(code) => code,
        }
    }

    /// The type the wire carried.
    #[must_use]
    pub const fn of(code: u8) -> Self {
        match code {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::Goaway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }
}

/// One frame: its type, flags, stream and payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: Kind,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    /// A frame of `kind` on `stream`.
    #[must_use]
    pub fn new(kind: Kind, flags: u8, stream: u32, payload: Vec<u8>) -> Self {
        Self {
            kind,
            flags,
            stream,
            payload,
        }
    }

    /// Whether `flag` is set.
    #[must_use]
    pub const fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// `RST_STREAM`: `stream` ends with `code`.
    #[must_use]
    pub fn reset(stream: u32, code: ErrorCode) -> Self {
        Self::new(
            Kind::RstStream,
            0,
            stream,
            code.code().to_be_bytes().to_vec(),
        )
    }

    /// `PING` with `opaque`, or its acknowledgement.
    #[must_use]
    pub fn ping(opaque: [u8; 8], ack: bool) -> Self {
        Self::new(Kind::Ping, if ack { ACK } else { 0 }, 0, opaque.to_vec())
    }

    /// `GOAWAY`: nothing above `last` was or will be processed, for `code`,
    /// with `debug` for whoever reads the peer's log.
    #[must_use]
    pub fn goaway(last: u32, code: ErrorCode, debug: &[u8]) -> Self {
        let mut payload = (last & MAX_STREAM_ID).to_be_bytes().to_vec();
        payload.extend_from_slice(&code.code().to_be_bytes());
        payload.extend_from_slice(debug);
        Self::new(Kind::Goaway, 0, 0, payload)
    }

    /// `WINDOW_UPDATE`: `stream` (0 for the connection) may take
    /// `increment` more octets.
    #[must_use]
    pub fn window_update(stream: u32, increment: u32) -> Self {
        let payload = (increment & MAX_STREAM_ID).to_be_bytes().to_vec();
        Self::new(Kind::WindowUpdate, 0, stream, payload)
    }

    /// The frame as the wire carries it.
    ///
    /// # Panics
    ///
    /// Never for a payload the caller sized to the peer's maximum, which
    /// is at most 2^24 - 1.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let length = u32::try_from(self.payload.len()).expect("a frame is under 2^24 octets");
        let mut out = Vec::with_capacity(HEADER_LEN + self.payload.len());
        out.extend_from_slice(&length.to_be_bytes()[1..]);
        out.push(self.kind.code());
        out.push(self.flags);
        out.extend_from_slice(&(self.stream & MAX_STREAM_ID).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// The content of a `DATA`, `HEADERS` or `PUSH_PROMISE` without its
    /// padding, and for `HEADERS` without its priority (RFC 9113 sections
    /// 6.1, 6.2 and 6.6).
    ///
    /// # Errors
    ///
    /// A `PROTOCOL_ERROR` where the padding is as long as what it pads.
    pub fn content(&self) -> Result<&[u8], Violation> {
        let mut body = &self.payload[..];
        let mut pad = 0;
        if self.has(PADDED) {
            let (&length, rest) = body
                .split_first()
                .ok_or_else(|| Violation::frame_size("a padded frame with no pad length"))?;
            pad = usize::from(length);
            body = rest;
        }
        if self.kind == Kind::Headers && self.has(PRIORITY) {
            body = body
                .get(5..)
                .ok_or_else(|| Violation::frame_size("a HEADERS too short for its priority"))?;
        }
        if pad > body.len() {
            return Err(Violation::protocol("the padding is longer than the frame"));
        }
        Ok(&body[..body.len() - pad])
    }

    /// A 32-bit field at `at` of the payload.
    #[must_use]
    pub fn word(&self, at: usize) -> Option<u32> {
        let bytes = self.payload.get(at..at + 4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Write `frame`, not flushed.
///
/// # Errors
///
/// Where the connection broke.
pub fn write(writer: &mut impl Write, frame: &Frame) -> Result<(), NetError> {
    writer
        .write_all(&frame.encode())
        .map_err(|failed| NetError::from_io("writing a frame", &failed))
}

/// Read one frame, or `None` where the connection closed cleanly between
/// two.
///
/// # Errors
///
/// Where the connection broke inside a frame, or the frame is larger than
/// `max_size`: a `FRAME_SIZE_ERROR` the caller answers with a `GOAWAY`.
pub fn read(reader: &mut impl Read, max_size: u32) -> Result<Option<Frame>, ReadFailure> {
    let mut header = [0u8; HEADER_LEN];
    let mut filled = 0;
    while filled < HEADER_LEN {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(ReadFailure::Net(NetError::new(
                    "the connection closed inside a frame header",
                )));
            }
            Ok(read) => filled += read,
            Err(failed) if failed.kind() == ErrorKind::Interrupted => {}
            Err(failed) => {
                return Err(ReadFailure::Net(NetError::from_io(
                    "reading a frame",
                    &failed,
                )));
            }
        }
    }
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]);
    if length > max_size {
        return Err(ReadFailure::Violation(Violation::frame_size(format!(
            "a frame of {length} octets, over the {max_size} this side allows"
        ))));
    }
    let stream = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) & MAX_STREAM_ID;
    let mut payload = vec![0u8; length as usize];
    reader.read_exact(&mut payload).map_err(|failed| {
        ReadFailure::Net(NetError::from_io("reading a frame's payload", &failed))
    })?;
    Ok(Some(Frame::new(
        Kind::of(header[3]),
        header[4],
        stream,
        payload,
    )))
}

/// Why a frame could not be read: the connection's failure, or the peer's
/// breach, which is answered before the connection ends.
#[derive(Debug)]
pub enum ReadFailure {
    Net(NetError),
    Violation(Violation),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_is_length_type_flags_and_a_31_bit_stream() {
        // RFC 9113 section 4.1: Length (24), Type (8), Flags (8), R (1),
        // Stream Identifier (31).
        let frame = Frame::new(Kind::Headers, END_HEADERS | END_STREAM, 3, b"abc".to_vec());
        let wire = frame.encode();
        assert_eq!(wire, [0, 0, 3, 1, 5, 0, 0, 0, 3, b'a', b'b', b'c']);
        let back = read(&mut &wire[..], DEFAULT_MAX_FRAME_SIZE)
            .expect("read")
            .expect("one");
        assert_eq!(back, frame);
        // The reserved bit is ignored on receipt.
        let reserved = [0, 0, 0, 4, 0, 0x80, 0, 0, 0];
        let back = read(&mut &reserved[..], 16_384)
            .expect("read")
            .expect("one");
        assert_eq!((back.kind, back.stream), (Kind::Settings, 0));
        assert!(read(&mut &b""[..], 16_384).expect("clean").is_none());
        assert!(matches!(
            read(&mut &wire[..4], 16_384),
            Err(ReadFailure::Net(_))
        ));
    }

    #[test]
    fn a_frame_over_the_maximum_is_a_frame_size_error() {
        let wire = Frame::new(Kind::Data, 0, 1, vec![0; 16_385]).encode();
        match read(&mut &wire[..], DEFAULT_MAX_FRAME_SIZE) {
            Err(ReadFailure::Violation(violation)) => {
                assert_eq!(violation.code, ErrorCode::FrameSize);
            }
            other => panic!("{other:?}"),
        }
        assert!(read(&mut &wire[..], 16_385).is_ok());
    }

    #[test]
    fn every_type_of_section_6_has_its_number() {
        for code in 0..=9 {
            assert_eq!(Kind::of(code).code(), code);
            assert!(!matches!(Kind::of(code), Kind::Unknown(_)));
        }
        assert_eq!(Kind::of(0xb), Kind::Unknown(0xb));
    }

    #[test]
    fn the_control_frames_have_the_layouts_of_section_6() {
        // RST_STREAM (6.4): Error Code (32).
        assert_eq!(
            Frame::reset(5, ErrorCode::Cancel).encode(),
            [0, 0, 4, 3, 0, 0, 0, 0, 5, 0, 0, 0, 8]
        );
        // PING (6.7): Opaque Data (64), ACK 0x1.
        assert_eq!(
            Frame::ping(*b"12345678", true).encode()[..9],
            [0, 0, 8, 6, 1, 0, 0, 0, 0]
        );
        // GOAWAY (6.8): R, Last-Stream-ID (31), Error Code (32), debug.
        let goaway = Frame::goaway(7, ErrorCode::Protocol, b"x");
        assert_eq!(
            goaway.encode(),
            [0, 0, 9, 7, 0, 0, 0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 1, b'x']
        );
        assert_eq!((goaway.word(0), goaway.word(4)), (Some(7), Some(1)));
        // WINDOW_UPDATE (6.9): R, Window Size Increment (31).
        assert_eq!(
            Frame::window_update(0, 1024).encode(),
            [0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 0, 4, 0]
        );
    }

    #[test]
    fn padding_and_priority_are_taken_off_what_they_surround() {
        // DATA (6.1): Pad Length (8), Data, Padding.
        let data = Frame::new(Kind::Data, PADDED, 1, vec![2, b'h', b'i', 0, 0]);
        assert_eq!(data.content().expect("content"), b"hi");
        // HEADERS (6.2): Pad Length, E + Stream Dependency (32), Weight (8),
        // the block fragment, Padding.
        let payload = vec![1, 0x80, 0, 0, 3, 16, 0x82, 0];
        let headers = Frame::new(Kind::Headers, PADDED | PRIORITY, 5, payload);
        assert_eq!(headers.content().expect("content"), [0x82]);
        let over = Frame::new(Kind::Data, PADDED, 1, vec![9, b'h']);
        assert_eq!(over.content().expect_err("over").code, ErrorCode::Protocol);
        let empty = Frame::new(Kind::Data, PADDED, 1, vec![]);
        assert_eq!(
            empty.content().expect_err("none").code,
            ErrorCode::FrameSize
        );
    }
}

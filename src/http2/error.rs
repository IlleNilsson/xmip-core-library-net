//! The error codes of RFC 9113 section 7, which a `RST_STREAM` and a
//! `GOAWAY` carry, and the violation that names one.

use crate::NetError;

/// Why a stream or a connection ended (RFC 9113 section 7).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    /// A graceful end: nothing went wrong.
    NoError,
    /// The peer broke the protocol.
    Protocol,
    /// Something went wrong on this side.
    Internal,
    /// A flow-control window was overrun or overflowed.
    FlowControl,
    /// A `SETTINGS` went unacknowledged.
    SettingsTimeout,
    /// A frame arrived on a stream already half-closed.
    StreamClosed,
    /// A frame had a size it may not have.
    FrameSize,
    /// The stream was refused before any of it was processed; safe to
    /// retry.
    RefusedStream,
    /// The stream is no longer wanted.
    Cancel,
    /// The header compression context could not be kept.
    Compression,
    /// A `CONNECT` tunnel broke.
    Connect,
    /// The peer is generating excessive load.
    EnhanceYourCalm,
    /// The TLS under the connection is not good enough.
    InadequateSecurity,
    /// The request must be made over HTTP/1.1.
    Http11Required,
    /// A code this side does not know, which it treats as `Internal`.
    Unknown(u32),
}

impl ErrorCode {
    /// The code as the wire carries it.
    #[must_use]
    pub const fn code(self) -> u32 {
        match self {
            Self::NoError => 0x0,
            Self::Protocol => 0x1,
            Self::Internal => 0x2,
            Self::FlowControl => 0x3,
            Self::SettingsTimeout => 0x4,
            Self::StreamClosed => 0x5,
            Self::FrameSize => 0x6,
            Self::RefusedStream => 0x7,
            Self::Cancel => 0x8,
            Self::Compression => 0x9,
            Self::Connect => 0xa,
            Self::EnhanceYourCalm => 0xb,
            Self::InadequateSecurity => 0xc,
            Self::Http11Required => 0xd,
            Self::Unknown(code) => code,
        }
    }

    /// The code the wire carried.
    #[must_use]
    pub const fn of(code: u32) -> Self {
        match code {
            0x0 => Self::NoError,
            0x1 => Self::Protocol,
            0x2 => Self::Internal,
            0x3 => Self::FlowControl,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSize,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::Compression,
            0xa => Self::Connect,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            other => Self::Unknown(other),
        }
    }
}

/// A breach of RFC 9113 or RFC 7541: the code the peer is told, and why.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Violation {
    pub code: ErrorCode,
    pub message: String,
}

impl Violation {
    /// A breach of `code`, saying `message`.
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// A `PROTOCOL_ERROR`.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Protocol, message)
    }

    /// A `FRAME_SIZE_ERROR`.
    #[must_use]
    pub fn frame_size(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::FrameSize, message)
    }

    /// A `COMPRESSION_ERROR`: the header block could not be decoded.
    #[must_use]
    pub fn compression(message: impl Into<String>) -> Self {
        Self::new(ErrorCode::Compression, message)
    }
}

impl From<Violation> for NetError {
    fn from(violation: Violation) -> Self {
        Self::new(format!(
            "HTTP/2 {:?} ({:#x}): {}",
            violation.code,
            violation.code.code(),
            violation.message
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_of_section_7_reads_back_as_itself() {
        for code in 0..=0xd {
            assert_eq!(ErrorCode::of(code).code(), code);
            assert!(!matches!(ErrorCode::of(code), ErrorCode::Unknown(_)));
        }
        assert_eq!(ErrorCode::of(0x42), ErrorCode::Unknown(0x42));
        let said = NetError::from(Violation::frame_size("a PING of 7 octets"));
        assert!(said.message.contains("FrameSize (0x6)"), "{said}");
    }
}

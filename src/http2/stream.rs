//! A stream of RFC 9113 section 5.1: its state, its two windows, and what
//! has arrived on it — the head, the body and the trailers.

use super::error::{ErrorCode, Violation};
use super::window::Window;

/// The states of section 5.1 a stream this side takes part in can be in,
/// once open: a stream above the highest opened is idle and has no record,
/// and the reserved states belong to server push, which this side
/// disables.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum State {
    Open,
    /// This side has sent `END_STREAM`.
    HalfClosedLocal,
    /// The peer has sent `END_STREAM`.
    HalfClosedRemote,
    Closed,
}

impl State {
    /// After this side sends `END_STREAM`.
    #[must_use]
    pub const fn ended_locally(self) -> Self {
        match self {
            Self::Open => Self::HalfClosedLocal,
            Self::HalfClosedRemote | Self::HalfClosedLocal | Self::Closed => Self::Closed,
        }
    }

    /// After the peer sends `END_STREAM`.
    #[must_use]
    pub const fn ended_remotely(self) -> Self {
        match self {
            Self::Open => Self::HalfClosedRemote,
            Self::HalfClosedLocal | Self::HalfClosedRemote | Self::Closed => Self::Closed,
        }
    }

    /// Whether the peer may still send on it.
    #[must_use]
    pub const fn receiving(self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedLocal)
    }

    /// Whether this side may still send on it.
    #[must_use]
    pub const fn sending(self) -> bool {
        matches!(self, Self::Open | Self::HalfClosedRemote)
    }
}

/// One stream: where it stands, what each side may still send on it, and
/// what arrived.
#[derive(Clone, Debug)]
pub struct Stream {
    pub state: State,
    /// What this side may still send.
    pub send: Window,
    /// What the peer may still send.
    pub receive: Window,
    /// The head, once its block is whole: the fields, pseudo-fields first.
    pub head: Option<Vec<(String, String)>>,
    pub body: Vec<u8>,
    pub trailers: Vec<(String, String)>,
    /// Why it was ended with `RST_STREAM`, by either side, or passed over
    /// by the peer's `GOAWAY`.
    pub reset: Option<ErrorCode>,
}

impl Stream {
    /// A stream opened with these windows.
    #[must_use]
    pub fn new(send: u32, receive: u32) -> Self {
        Self {
            state: State::Open,
            send: Window::new(send),
            receive: Window::new(receive),
            head: None,
            body: Vec::new(),
            trailers: Vec::new(),
            reset: None,
        }
    }

    /// A header block arrived whole: the head, a 1xx the head replaces, or
    /// the trailers, which must end the stream.
    ///
    /// # Errors
    ///
    /// A `PROTOCOL_ERROR` for trailers that do not end the stream, or a
    /// block on a stream the peer has ended (a `STREAM_CLOSED`).
    pub fn headers(&mut self, fields: Vec<(String, String)>, end: bool) -> Result<(), Violation> {
        if !self.state.receiving() {
            return Err(Violation::new(
                ErrorCode::StreamClosed,
                "HEADERS after END_STREAM",
            ));
        }
        let informational = fields
            .iter()
            .any(|(name, value)| name == ":status" && value.starts_with('1'));
        if self.head.is_none() || informational {
            if !informational {
                self.head = Some(fields);
            }
        } else if end {
            self.trailers = fields;
        } else {
            return Err(Violation::protocol(
                "a second header block that does not end the stream",
            ));
        }
        if end {
            self.state = self.state.ended_remotely();
        }
        Ok(())
    }

    /// Whether the peer has finished sending: ended, or reset.
    #[must_use]
    pub const fn finished(&self) -> bool {
        self.reset.is_some() || !self.state.receiving()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn a_stream_closes_when_both_sides_have_ended_it() {
        // Section 5.1: open, half-closed from either side, closed.
        let open = State::Open;
        assert_eq!(open.ended_locally(), State::HalfClosedLocal);
        assert_eq!(open.ended_remotely(), State::HalfClosedRemote);
        assert_eq!(open.ended_locally().ended_remotely(), State::Closed);
        assert_eq!(open.ended_remotely().ended_locally(), State::Closed);
        assert!(State::HalfClosedLocal.receiving() && !State::HalfClosedLocal.sending());
        assert!(State::HalfClosedRemote.sending() && !State::HalfClosedRemote.receiving());
        assert!(!State::Closed.sending() && !State::Closed.receiving());
    }

    #[test]
    fn a_1xx_is_passed_over_the_head_kept_and_trailers_end_the_stream() {
        let mut stream = Stream::new(10, 10);
        stream
            .headers(fields(&[(":status", "100")]), false)
            .expect("1xx");
        assert!(stream.head.is_none());
        stream
            .headers(fields(&[(":status", "200")]), false)
            .expect("head");
        let middle = stream.headers(fields(&[("x", "1")]), false);
        assert_eq!(middle.expect_err("unended").code, ErrorCode::Protocol);
        stream
            .headers(fields(&[("grpc-status", "0")]), true)
            .expect("trailers");
        assert_eq!(stream.trailers, fields(&[("grpc-status", "0")]));
        assert!(stream.finished());
        let late = stream.headers(fields(&[("x", "1")]), true);
        assert_eq!(late.expect_err("closed").code, ErrorCode::StreamClosed);
    }
}

//! What one HTTP/2 connection takes from its peer: the body octets it
//! holds for the application at once, and how many frames that carry no
//! work — `PING`, `SETTINGS`, and frames that carry nothing — it answers
//! in a span before it ends the connection with `ENHANCE_YOUR_CALM` (RFC
//! 9113 section 10.5).
//!
//! The numbers are defaults. A caller sets its own through
//! [`Server::handshake_within`](super::Server::handshake_within) and
//! [`Client::handshake_within`](super::Client::handshake_within).

use std::time::{Duration, Instant};

use super::error::{ErrorCode, Violation};
use super::frame::MAX_STREAM_ID;
use super::settings::DEFAULT_WINDOW;
use crate::MAX_BODY;

/// The body octets one connection holds by default: one body of the most
/// Xmip reads, [`MAX_BODY`], so the largest arrives whole on its own.
const BUFFERED: u32 = 64 * 1024 * 1024;

const _: () = assert!(BUFFERED as usize == MAX_BODY);

/// What one connection holds and answers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// The body octets the peer may have sent and the application not yet
    /// taken, every stream together: the connection's receive window,
    /// given back only as bodies are taken. Never under the 65 535 octets
    /// every connection starts with, nor over 2^31 - 1.
    pub buffered: u32,
    /// The span the frames below are counted over.
    pub span: Duration,
    /// The most `PING` and `SETTINGS` frames the peer may send in a span.
    pub control_frames: u32,
    /// The most frames that carry nothing the peer may send in a span: a
    /// `DATA` without octets that does not end its stream, a
    /// `CONTINUATION` without octets that does not end its block.
    pub empty_frames: u32,
}

impl Limits {
    /// One body of [`MAX_BODY`] held at once; a thousand `PING` and
    /// `SETTINGS` frames a second, and a hundred that carry nothing.
    pub const DEFAULT: Self = Self {
        buffered: BUFFERED,
        span: Duration::from_secs(1),
        control_frames: 1000,
        empty_frames: 100,
    };

    /// The connection's receive window: [`Limits::buffered`] within what a
    /// window may be.
    pub(super) fn window(&self) -> u32 {
        self.buffered.clamp(DEFAULT_WINDOW, MAX_STREAM_ID)
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a frame counts as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Count {
    /// A `PING` or a `SETTINGS`.
    Control,
    /// A frame that carries nothing.
    Empty,
}

/// The frames counted in the span that began at `since`.
#[derive(Clone, Copy, Debug)]
pub(super) struct Tally {
    since: Instant,
    control: u32,
    empty: u32,
}

impl Tally {
    /// Nothing counted, in a span that begins `now`.
    pub(super) const fn new(now: Instant) -> Self {
        Self {
            since: now,
            control: 0,
            empty: 0,
        }
    }

    /// Count one frame that arrived `now`, a new span begun where the last
    /// is over.
    ///
    /// # Errors
    ///
    /// An `ENHANCE_YOUR_CALM` where the frame is one more than `limits`
    /// allow in the span.
    pub(super) fn count(
        &mut self,
        what: Count,
        now: Instant,
        limits: &Limits,
    ) -> Result<(), Violation> {
        if now.saturating_duration_since(self.since) >= limits.span {
            *self = Self::new(now);
        }
        let (counted, most, frames) = match what {
            Count::Control => (
                &mut self.control,
                limits.control_frames,
                "PING and SETTINGS",
            ),
            Count::Empty => (&mut self.empty, limits.empty_frames, "empty"),
        };
        *counted = counted.saturating_add(1);
        if *counted > most {
            return Err(Violation::new(
                ErrorCode::EnhanceYourCalm,
                format!("more than {most} {frames} frames in {:?}", limits.span),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_span_allows_its_count_refuses_one_more_and_the_next_span_starts_over() {
        let limits = Limits {
            control_frames: 3,
            empty_frames: 1,
            ..Limits::DEFAULT
        };
        let start = Instant::now();
        let mut tally = Tally::new(start);
        for _ in 0..3 {
            tally.count(Count::Control, start, &limits).expect("within");
        }
        tally
            .count(Count::Empty, start, &limits)
            .expect("its own count");
        let calm = tally
            .count(Count::Control, start, &limits)
            .expect_err("one over");
        assert_eq!(calm.code, ErrorCode::EnhanceYourCalm);
        let next = start + limits.span;
        tally
            .count(Count::Control, next, &limits)
            .expect("a new span");
        tally
            .count(Count::Empty, next, &limits)
            .expect("a new span");
        assert!(tally.count(Count::Empty, next, &limits).is_err());
    }

    #[test]
    fn the_window_is_never_under_the_initial_one_nor_over_2_31() {
        let window = |buffered| {
            Limits {
                buffered,
                ..Limits::DEFAULT
            }
            .window()
        };
        assert_eq!(window(0), DEFAULT_WINDOW);
        assert_eq!(window(u32::MAX), MAX_STREAM_ID);
        assert_eq!(Limits::default().window(), BUFFERED);
    }
}

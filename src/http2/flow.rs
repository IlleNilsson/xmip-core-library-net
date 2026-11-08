//! The receiving side of flow control (RFC 9113 section 5.2): what the
//! peer may send is given back as the application takes it, so what a
//! connection holds for the application is bounded by its window, every
//! stream together — [`Limits::buffered`](super::Limits::buffered).
//!
//! A stream's window opens again as its body arrives, half a window at a
//! time, so one body larger than a window arrives whole; the connection's
//! window opens only as a body is taken off its stream, and at once for
//! what is never held — padding, and a frame on a stream let go. Each
//! `WINDOW_UPDATE` gives back half a window or more, never one per frame.

use std::io::{Read, Write};

use super::connection::Connection;
use super::frame::Frame;
use crate::{MAX_BODY, NetError};

impl<S: Read + Write> Connection<S> {
    /// The application took `octets` of body, or they were let go: given
    /// back to the peer on the connection once half its window waits.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn taken(&mut self, octets: usize) -> Result<(), NetError> {
        let octets = u32::try_from(octets).unwrap_or(u32::MAX);
        self.credit = self.credit.saturating_add(octets);
        let half = (self.limits.window() / 2).max(1);
        if self.credit < half {
            return Ok(());
        }
        let increment = std::mem::take(&mut self.credit);
        self.receive.grant(increment)?;
        self.emit(&Frame::window_update(0, increment))
    }

    /// Open `id`'s window to its full size again once half of it is used,
    /// while its body is under [`MAX_BODY`].
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub(super) fn refill(&mut self, id: u32) -> Result<(), NetError> {
        let full = self.local.initial_window_size;
        let Some(stream) = self.streams.get_mut(&id) else {
            return Ok(());
        };
        let available = u32::try_from(stream.receive.available()).unwrap_or(full);
        if available >= full / 2 || stream.body.len() >= MAX_BODY {
            return Ok(());
        }
        let increment = full - available;
        stream.receive.grant(increment)?;
        self.emit(&Frame::window_update(id, increment))
    }
}

//! A flow-control window (RFC 9113 section 5.2 and 6.9): what one side may
//! still send, taken by every `DATA` and given back by `WINDOW_UPDATE`.

use super::error::{ErrorCode, Violation};
use super::frame::MAX_STREAM_ID;

/// One window, on the connection or on a stream. Signed, because a
/// smaller `SETTINGS_INITIAL_WINDOW_SIZE` can take a stream's window below
/// zero (section 6.9.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Window(i64);

impl Window {
    /// A window of `size` octets.
    #[must_use]
    pub fn new(size: u32) -> Self {
        Self(i64::from(size))
    }

    /// The octets that may still be sent; none while the window is at or
    /// below zero.
    #[must_use]
    pub fn available(self) -> usize {
        usize::try_from(self.0.max(0)).unwrap_or(usize::MAX)
    }

    /// Take `octets` for a `DATA` sent or received.
    ///
    /// # Errors
    ///
    /// A `FLOW_CONTROL_ERROR` where `octets` is more than the window holds:
    /// the peer sent past what it was given.
    pub fn take(&mut self, octets: usize) -> Result<(), Violation> {
        let octets = i64::try_from(octets).unwrap_or(i64::MAX);
        if octets > self.0 {
            return Err(Violation::new(
                ErrorCode::FlowControl,
                format!("{octets} octets against a window of {}", self.0),
            ));
        }
        self.0 -= octets;
        Ok(())
    }

    /// Give back `increment` octets, as a `WINDOW_UPDATE` does.
    ///
    /// # Errors
    ///
    /// A `PROTOCOL_ERROR` for an increment of 0; a `FLOW_CONTROL_ERROR`
    /// where the window would pass 2^31 - 1.
    pub fn grant(&mut self, increment: u32) -> Result<(), Violation> {
        if increment == 0 {
            return Err(Violation::protocol("a WINDOW_UPDATE of 0"));
        }
        self.shift(i64::from(increment))
    }

    /// Move the window by the change of `SETTINGS_INITIAL_WINDOW_SIZE`,
    /// which may take it below zero.
    ///
    /// # Errors
    ///
    /// A `FLOW_CONTROL_ERROR` where it would pass 2^31 - 1.
    pub fn shift(&mut self, delta: i64) -> Result<(), Violation> {
        let moved = self.0 + delta;
        if moved > i64::from(MAX_STREAM_ID) {
            return Err(Violation::new(
                ErrorCode::FlowControl,
                format!("a window of {moved}, over 2^31 - 1"),
            ));
        }
        self.0 = moved;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_is_taken_given_back_and_never_overrun() {
        let mut window = Window::new(10);
        window.take(10).expect("all of it");
        assert_eq!(window.available(), 0);
        assert_eq!(
            window.take(1).expect_err("overrun").code,
            ErrorCode::FlowControl
        );
        window.grant(4).expect("granted");
        assert_eq!(window.available(), 4);
        assert_eq!(window.grant(0).expect_err("zero").code, ErrorCode::Protocol);
        let mut full = Window::new(MAX_STREAM_ID);
        assert_eq!(
            full.grant(1).expect_err("over").code,
            ErrorCode::FlowControl
        );
    }

    #[test]
    fn a_smaller_initial_window_can_take_a_stream_below_zero() {
        let mut window = Window::new(100);
        window.take(80).expect("taken");
        window.shift(-50).expect("shifted");
        assert_eq!(window.available(), 0);
        window.grant(40).expect("granted");
        assert_eq!(window.available(), 10);
    }
}

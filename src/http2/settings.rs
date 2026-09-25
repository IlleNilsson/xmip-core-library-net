//! The `SETTINGS` of RFC 9113 section 6.5: six parameters, each a 16-bit
//! identifier and a 32-bit value, written by one side and applied by the
//! other, and the limits each must keep.

use super::error::{ErrorCode, Violation};
use super::frame::{DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT, MAX_STREAM_ID};

/// `SETTINGS_HEADER_TABLE_SIZE`.
pub const HEADER_TABLE_SIZE: u16 = 0x1;
/// `SETTINGS_ENABLE_PUSH`.
pub const ENABLE_PUSH: u16 = 0x2;
/// `SETTINGS_MAX_CONCURRENT_STREAMS`.
pub const MAX_CONCURRENT_STREAMS: u16 = 0x3;
/// `SETTINGS_INITIAL_WINDOW_SIZE`.
pub const INITIAL_WINDOW_SIZE: u16 = 0x4;
/// `SETTINGS_MAX_FRAME_SIZE`.
pub const MAX_FRAME_SIZE: u16 = 0x5;
/// `SETTINGS_MAX_HEADER_LIST_SIZE`.
pub const MAX_HEADER_LIST_SIZE: u16 = 0x6;

/// The window every stream and the connection start with.
pub const DEFAULT_WINDOW: u32 = 65_535;

/// One side's settings. `None` is unlimited, which is the initial value of
/// the two limits that have no number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}

impl Default for Settings {
    /// The initial values of section 6.5.2, which hold until a peer's
    /// `SETTINGS` says otherwise.
    fn default() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_WINDOW,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
        }
    }
}

impl Settings {
    /// What this side announces: no push, a hundred streams at once, and
    /// a header list of at most 64 KiB; everything else as initial.
    #[must_use]
    pub fn ours() -> Self {
        Self {
            enable_push: false,
            max_concurrent_streams: Some(100),
            max_header_list_size: Some(64 * 1024),
            ..Self::default()
        }
    }

    /// The payload of a `SETTINGS` announcing every value that differs from
    /// the initial one.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let initial = Self::default();
        let mut pairs = Vec::new();
        if self.header_table_size != initial.header_table_size {
            pairs.push((HEADER_TABLE_SIZE, self.header_table_size));
        }
        if self.enable_push != initial.enable_push {
            pairs.push((ENABLE_PUSH, u32::from(self.enable_push)));
        }
        if let Some(streams) = self.max_concurrent_streams {
            pairs.push((MAX_CONCURRENT_STREAMS, streams));
        }
        if self.initial_window_size != initial.initial_window_size {
            pairs.push((INITIAL_WINDOW_SIZE, self.initial_window_size));
        }
        if self.max_frame_size != initial.max_frame_size {
            pairs.push((MAX_FRAME_SIZE, self.max_frame_size));
        }
        if let Some(size) = self.max_header_list_size {
            pairs.push((MAX_HEADER_LIST_SIZE, size));
        }
        pairs
            .into_iter()
            .flat_map(|(id, value)| id.to_be_bytes().into_iter().chain(value.to_be_bytes()))
            .collect()
    }

    /// Apply a peer's `SETTINGS` payload, as `client` or server: the
    /// identifiers this side does not know are ignored, as section 6.5.2
    /// asks.
    ///
    /// # Errors
    ///
    /// A `FRAME_SIZE_ERROR` where the payload is not whole parameters; a
    /// `PROTOCOL_ERROR` for a push value other than 0 or 1, a push a
    /// server enabled, or a frame size out of range; a
    /// `FLOW_CONTROL_ERROR` for a window over 2^31 - 1.
    pub fn apply(&mut self, payload: &[u8], client: bool) -> Result<(), Violation> {
        if !payload.len().is_multiple_of(6) {
            return Err(Violation::frame_size(format!(
                "a SETTINGS of {} octets is not whole parameters",
                payload.len()
            )));
        }
        for pair in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([pair[0], pair[1]]);
            let value = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
            self.set(id, value, client)?;
        }
        Ok(())
    }

    fn set(&mut self, id: u16, value: u32, client: bool) -> Result<(), Violation> {
        match id {
            HEADER_TABLE_SIZE => self.header_table_size = value,
            ENABLE_PUSH => {
                if value > 1 || (client && value == 1) {
                    return Err(Violation::protocol(format!(
                        "SETTINGS_ENABLE_PUSH of {value} from a {}",
                        if client { "server" } else { "client" }
                    )));
                }
                self.enable_push = value == 1;
            }
            MAX_CONCURRENT_STREAMS => self.max_concurrent_streams = Some(value),
            INITIAL_WINDOW_SIZE => {
                if value > MAX_STREAM_ID {
                    return Err(Violation::new(
                        ErrorCode::FlowControl,
                        format!("an initial window of {value}, over 2^31 - 1"),
                    ));
                }
                self.initial_window_size = value;
            }
            MAX_FRAME_SIZE => {
                if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&value) {
                    return Err(Violation::protocol(format!(
                        "a maximum frame size of {value}, outside 2^14 to 2^24 - 1"
                    )));
                }
                self.max_frame_size = value;
            }
            MAX_HEADER_LIST_SIZE => self.max_header_list_size = Some(value),
            _ => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_parameter_is_a_16_bit_identifier_and_a_32_bit_value() {
        // RFC 9113 section 6.5.1: Identifier (16), Value (32).
        let ours = Settings::ours().encode();
        assert_eq!(
            ours,
            [0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 6, 0, 1, 0, 0]
        );
        let mut read = Settings::default();
        read.apply(&ours, false).expect("applied");
        assert_eq!(read, Settings::ours());
        assert!(Settings::default().encode().is_empty());
    }

    #[test]
    fn an_unknown_identifier_is_ignored_and_a_bad_value_refused() {
        let mut settings = Settings::default();
        settings
            .apply(&[0, 0x9, 0, 0, 0, 1], true)
            .expect("ignored");
        assert_eq!(settings, Settings::default());
        let refused = [
            (&[0, 2, 0, 0, 0, 2][..], ErrorCode::Protocol, false),
            (&[0, 2, 0, 0, 0, 1], ErrorCode::Protocol, true),
            (&[0, 4, 0x80, 0, 0, 0], ErrorCode::FlowControl, false),
            (&[0, 5, 0, 0, 0x3f, 0xff], ErrorCode::Protocol, false),
            (&[0, 5, 0x01, 0, 0, 0], ErrorCode::Protocol, false),
            (&[0, 4, 0, 0, 0], ErrorCode::FrameSize, false),
        ];
        for (payload, code, client) in refused {
            let failed = Settings::default()
                .apply(payload, client)
                .expect_err("refused");
            assert_eq!(failed.code, code, "{payload:?}");
        }
        let mut largest = Settings::default();
        largest
            .apply(&[0, 5, 0, 0xff, 0xff, 0xff], false)
            .expect("2^24 - 1");
        assert_eq!(largest.max_frame_size, MAX_FRAME_SIZE_LIMIT);
    }
}

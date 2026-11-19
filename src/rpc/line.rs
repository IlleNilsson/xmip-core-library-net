//! A message framed as the Model Context Protocol's standard input and
//! output frame it: one JSON-RPC message a line, ended by a line feed, never
//! more than [`crate::MAX_BODY`]. A blank line carries no message and is
//! let go.

use std::io::{BufRead, Write};

use serde_json::Value;

use crate::read::line_within;
use crate::{MAX_BODY, NetError};

/// The next line that is not blank, its line ending taken off, as the
/// text it is — parsed by [`super::parse`], so a line that is not JSON is
/// answered rather than ending the stream; `None` where the input ended.
///
/// # Errors
///
/// Where the input fails, a line runs past [`MAX_BODY`], or it is not
/// UTF-8.
pub fn read(reader: &mut impl BufRead) -> Result<Option<String>, NetError> {
    while let Some(text) = line_within(reader, MAX_BODY)? {
        if !text.trim().is_empty() {
            return Ok(Some(text));
        }
    }

    Ok(None)
}

/// Write one message as one line, ended by a line feed, and flush it so
/// the peer sees it now.
///
/// # Errors
///
/// Where the output fails.
pub fn write(writer: &mut impl Write, message: &Value) -> Result<(), NetError> {
    write_text(writer, &message.to_string())
}

/// Write one message its sender has written as JSON text already — its
/// members in the order it wrote them — as one line, ended by a line feed,
/// and flush it.
///
/// # Errors
///
/// Where the text holds a line feed, which would end the message early, or
/// the output fails.
pub fn write_text(writer: &mut (impl Write + ?Sized), message: &str) -> Result<(), NetError> {
    if message.contains('\n') {
        return Err(NetError::new(
            "a JSON-RPC message a line holds no line feed",
        ));
    }

    writeln!(writer, "{message}")
        .and_then(|()| writer.flush())
        .map_err(|failed| NetError::from_io("writing a JSON-RPC line", &failed))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    #[test]
    fn a_message_is_one_line_and_blank_lines_between_carry_nothing() {
        let mut wire = Vec::new();

        write(&mut wire, &json!({"id": 1, "text": "a\nb"})).expect("writes");
        wire.extend_from_slice(b"\r\n   \n");
        write(&mut wire, &json!({"id": 2})).expect("writes");

        assert_eq!(String::from_utf8_lossy(&wire).lines().count(), 4);

        let mut reader = Cursor::new(wire);
        let first = read(&mut reader).expect("reads").expect("a line");

        assert_eq!(
            super::super::parse(&first),
            Ok(json!({"id": 1, "text": "a\nb"}))
        );
        assert_eq!(
            read(&mut reader).expect("reads").as_deref(),
            Some(r#"{"id":2}"#)
        );
        assert_eq!(read(&mut reader).expect("reads"), None);
    }

    #[test]
    fn a_message_written_as_text_keeps_its_order_and_holds_no_line_feed() {
        let mut wire = Vec::new();

        write_text(&mut wire, r#"{"jsonrpc":"2.0","id":1}"#).expect("writes");

        assert_eq!(wire, b"{\"jsonrpc\":\"2.0\",\"id\":1}\n");
        assert!(write_text(&mut wire, "{\n}").is_err());
    }

    #[test]
    fn a_line_that_is_not_json_is_still_a_line_and_its_answer_the_caller_s() {
        let mut reader = Cursor::new(b"{nope\n".to_vec());

        assert_eq!(read(&mut reader).expect("reads").as_deref(), Some("{nope"));
    }
}

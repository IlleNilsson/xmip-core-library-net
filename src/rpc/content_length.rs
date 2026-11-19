//! A message framed as the Language Server Protocol's base protocol frames
//! it: a block of `Name: value` header lines ended by a blank line, then
//! exactly `Content-Length` bytes of JSON, never more than
//! [`crate::MAX_BODY`].

use std::io::{BufRead, Write};

use serde_json::Value;

use crate::ceiling::within;
use crate::read::{exact, line};
use crate::{MAX_BODY, NetError};

/// What a refusal says carries a message.
const CARRIER: &str = "Xmip reads in one JSON-RPC message";

/// Read one message: `None` where the input ended cleanly before a message
/// began. A header other than `Content-Length` is read and let go.
///
/// # Errors
///
/// Where the input fails or ends inside a message, the header block has no
/// `Content-Length` or one that is no number or over [`MAX_BODY`], or the
/// body is not JSON.
pub fn read(reader: &mut impl BufRead) -> Result<Option<Value>, NetError> {
    let mut length: Option<usize> = None;

    loop {
        let Some(header) = line(reader)? else {
            return match length {
                None => Ok(None),
                Some(_) => Err(NetError::new("input ended inside a message header")),
            };
        };

        if header.is_empty() {
            break;
        }

        if let Some(value) = header.strip_prefix("Content-Length:") {
            let parsed = value.trim().parse::<usize>();
            length = Some(parsed.map_err(|_| NetError::new("Content-Length is not a number"))?);
        }
    }

    let length = length.ok_or_else(|| NetError::new("a message without Content-Length"))?;
    within(length, MAX_BODY, CARRIER)?;
    let body = exact(reader, length, "a JSON-RPC message")?;

    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|unread| NetError::new(format!("the message body is not JSON: {unread}")))
}

/// Write one message, header and body, and flush it so the peer sees it
/// now.
///
/// # Errors
///
/// Where the output fails.
pub fn write(writer: &mut impl Write, message: &Value) -> Result<(), NetError> {
    let body = message.to_string();

    write!(writer, "Content-Length: {}\r\n\r\n{body}", body.len())
        .and_then(|()| writer.flush())
        .map_err(|failed| NetError::from_io("writing a JSON-RPC message", &failed))
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;

    #[test]
    fn a_message_written_is_the_message_read_then_the_end() {
        let message = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});
        let mut wire = Vec::new();

        write(&mut wire, &message).expect("writes");

        assert!(wire.starts_with(b"Content-Length: "));

        let mut reader = Cursor::new(wire);
        let read_back = read(&mut reader).expect("reads").expect("a message");

        assert_eq!(read_back, message);
        assert!(read(&mut reader).expect("reads").is_none(), "then the end");
    }

    #[test]
    fn two_messages_back_to_back_are_read_in_order() {
        let mut wire = Vec::new();

        write(&mut wire, &json!({"id": 1})).expect("writes");
        write(&mut wire, &json!({"id": 2})).expect("writes");

        let mut reader = Cursor::new(wire);

        assert_eq!(read(&mut reader).expect("reads"), Some(json!({"id": 1})));
        assert_eq!(read(&mut reader).expect("reads"), Some(json!({"id": 2})));
    }

    #[test]
    fn other_headers_are_let_go_and_the_length_is_what_counts() {
        let body = r#"{"id":3}"#;
        let text = format!(
            "Content-Type: application/vscode-jsonrpc; charset=utf-8\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let mut reader = Cursor::new(text.into_bytes());

        assert_eq!(read(&mut reader).expect("reads"), Some(json!({"id": 3})));
    }

    #[test]
    fn a_header_block_without_a_length_is_refused() {
        let mut reader = Cursor::new(b"Content-Type: text\r\n\r\n{}".to_vec());

        assert!(read(&mut reader).is_err());
    }

    #[test]
    fn a_body_cut_short_or_claiming_more_than_xmip_reads_is_an_error() {
        let mut short = Cursor::new(b"Content-Length: 20\r\n\r\n{}".to_vec());
        let claim = format!("Content-Length: {}\r\n\r\n{{}}", MAX_BODY + 1);
        let mut over = Cursor::new(claim.into_bytes());

        assert!(read(&mut short).is_err());
        assert!(
            read(&mut over)
                .expect_err("over the ceiling")
                .message
                .contains(CARRIER)
        );
    }
}

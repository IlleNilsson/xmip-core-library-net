//! One HTTP/1.1 message as it is written: the first line, the headers,
//! the framing its body needs, the body and, where it has one, the
//! trailer.

use std::fmt::Write as _;
use std::io::Write;

use super::find;
use crate::NetError;

/// One message as it is written: its first line, headers, body and
/// trailer.
pub(super) struct Message<'a> {
    pub(super) first: &'a str,
    pub(super) headers: &'a [(String, String)],
    pub(super) body: &'a [u8],
    pub(super) trailers: &'a [(String, String)],
}

/// One message: its first line, its headers, the length, the connection
/// closing unless a header says otherwise, the blank line and the body —
/// or, where it has a trailer, the body as one chunk and the trailer after
/// the last.
pub(super) fn write_message(
    writer: &mut impl Write,
    message: &Message<'_>,
    what: &str,
) -> Result<(), NetError> {
    let lines = |fields: &[(String, String)]| {
        fields
            .iter()
            .fold(String::new(), |mut lines, (name, value)| {
                let _ = write!(lines, "{name}: {value}\r\n");
                lines
            })
    };
    let close = if find(message.headers, "connection").is_none() {
        "Connection: close\r\n"
    } else {
        ""
    };
    let (first, fields, body) = (message.first, lines(message.headers), message.body);
    let length = body.len();
    let (head, tail) = if message.trailers.is_empty() {
        let head = format!("{first}\r\n{fields}Content-Length: {length}\r\n{close}\r\n");
        (head, String::new())
    } else {
        let chunk = if body.is_empty() {
            String::new()
        } else {
            format!("{length:x}\r\n")
        };
        let head = format!("{first}\r\n{fields}Transfer-Encoding: chunked\r\n{close}\r\n{chunk}");
        let end = if body.is_empty() { "" } else { "\r\n" };
        (head, format!("{end}0\r\n{}\r\n", lines(message.trailers)))
    };
    writer
        .write_all(head.as_bytes())
        .and_then(|()| writer.write_all(body))
        .and_then(|()| writer.write_all(tail.as_bytes()))
        .and_then(|()| writer.flush())
        .map_err(|failed| NetError::from_io(&format!("writing {what}"), &failed))
}

//! One HTTP/1.1 message as it is written: the first line, the headers,
//! the framing its body needs, the body and, where it has one, the
//! trailer.

use std::io::Write;

use super::body::frames;
use super::find;
use crate::NetError;
use crate::head::write_fields;

/// One message as it is written: its first line, headers, body and
/// trailer.
pub(super) struct Message<'a> {
    pub(super) first: &'a str,
    pub(super) headers: &'a [(String, String)],
    pub(super) body: &'a [u8],
    pub(super) trailers: &'a [(String, String)],
    /// Whether the connection is said to close after this message where
    /// its headers name no `Connection` of their own; HTTP/1.1 keeps it
    /// otherwise.
    pub(super) close: bool,
    /// Whether the message is an answer that carries no body and states
    /// no length: a 1xx, a 204 or a 304.
    pub(super) bodiless: bool,
}

/// One message: its first line, its headers, the length, the connection
/// closing where the message asks and no header says otherwise, the blank
/// line and the body —
/// or, where it has a trailer, the body as one chunk and the trailer after
/// the last; an answer that carries no body writes no length and no body.
/// The framing is this writer's alone: a `Content-Length` or
/// `Transfer-Encoding` among the headers or trailers it is handed is not
/// written.
pub(super) fn write_message(
    writer: &mut impl Write,
    message: &Message<'_>,
    what: &str,
) -> Result<(), NetError> {
    let lines = |fields: &[(String, String)]| {
        let mut lines = String::new();
        write_fields(&mut lines, fields.iter().filter(|(name, _)| !frames(name)));
        lines
    };
    let close = if message.close && find(message.headers, "connection").is_none() {
        "Connection: close\r\n"
    } else {
        ""
    };
    let (first, fields, body) = (message.first, lines(message.headers), message.body);
    let length = body.len();
    let (head, tail) = if message.bodiless {
        (format!("{first}\r\n{fields}{close}\r\n"), String::new())
    } else if message.trailers.is_empty() {
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
    let body = if message.bodiless { &[][..] } else { body };
    writer
        .write_all(head.as_bytes())
        .and_then(|()| writer.write_all(body))
        .and_then(|()| writer.write_all(tail.as_bytes()))
        .and_then(|()| writer.flush())
        .map_err(|failed| NetError::from_io(&format!("writing {what}"), &failed))
}

#[cfg(test)]
mod tests {
    use crate::http::{
        Request, Response, read_request, read_response, write_request, write_response,
    };

    #[test]
    fn the_writer_alone_writes_the_framing() {
        // Until 2026-11-22 a Content-Length or Transfer-Encoding a caller
        // handed the writer was written beside the writer's own.
        let request = Request::new("POST", "/")
            .header("Host", "x")
            .header("content-length", "99")
            .header("Transfer-Encoding", "chunked")
            .body(b"abc");
        let mut written = Vec::new();
        write_request(&mut written, &request).expect("written");
        let text = String::from_utf8_lossy(&written);
        assert_eq!(text.matches("ength:").count(), 1, "{text}");
        assert!(text.contains("Content-Length: 3\r\n"), "{text}");
        assert!(!text.contains("ncoding"), "{text}");
        let read = read_request(&mut &written[..]).expect("read").expect("one");
        assert_eq!(read.body, b"abc");

        let answer = Response::new(200)
            .header("Content-Length", "1")
            .body(b"abc")
            .trailer("Transfer-Encoding", "gzip")
            .trailer("grpc-status", "0");
        let mut written = Vec::new();
        write_response(&mut written, &answer).expect("written");
        let text = String::from_utf8_lossy(&written);
        assert!(!text.contains("Content-Length"), "{text}");
        assert_eq!(text.matches("Transfer-Encoding:").count(), 1, "{text}");
        let back = read_response(&mut &written[..]).expect("read");
        assert_eq!(back.body, b"abc");
        assert_eq!(
            back.trailers,
            [("grpc-status".to_string(), "0".to_string())]
        );

        let mut written = Vec::new();
        let unchanged = Response::new(304).header("Content-Length", "7");
        write_response(&mut written, &unchanged).expect("written");
        assert!(!String::from_utf8_lossy(&written).contains("Length"));
    }
}

//! A head as the line-oriented protocols write it: lines, then a blank
//! line, then a body.
//!
//! HTTP and SMTP, and a WebSocket's opening handshake, are all shaped so,
//! and each gets the same three mistakes wrong if it writes its own reader:
//! unbounded header counts, CRLF handled in one place and LF in another, and
//! the request or status line searched as if it were a header. Nothing here
//! knows which protocol is calling.
//!
//! The transport capability held this reader until 2026-09-25, when HTTP's
//! exchange came here as [`crate::http`] and needed it below the transport.

use std::io::BufRead;

use crate::NetError;

/// The largest number of header lines read before giving up.
pub const MAX_HEADERS: usize = 200;

/// Strip exactly one trailing line ending, CRLF or LF.
#[must_use]
pub fn trim_eol(raw: &[u8]) -> &[u8] {
    let mut end = raw.len();

    if end > 0 && raw[end - 1] == b'\n' {
        end -= 1;
    }

    if end > 0 && raw[end - 1] == b'\r' {
        end -= 1;
    }

    &raw[..end]
}

/// Read the lines before the blank line that ends a head. A connection
/// that closes first ends it too, so a peer that sent nothing reads as no
/// lines at all.
///
/// # Errors
///
/// Where the connection could not be read, or sent more header lines than
/// [`MAX_HEADERS`] — which is a peer misbehaving, not a large request.
pub fn read_head(reader: &mut impl BufRead) -> Result<Vec<String>, NetError> {
    let mut lines = Vec::new();

    loop {
        let mut raw = Vec::new();
        let read = reader
            .read_until(b'\n', &mut raw)
            .map_err(|failed| NetError::from_io("reading a header line", &failed))?;

        if read == 0 {
            break;
        }

        let line = String::from_utf8_lossy(trim_eol(&raw)).to_string();

        if line.is_empty() {
            break;
        }

        if lines.len() == MAX_HEADERS {
            return Err(NetError::new("more header lines than Xmip will read"));
        }

        lines.push(line);
    }

    Ok(lines)
}

/// Find one header value in a head [`read_head`] read.
///
/// Case-insensitive, which is not a convenience: a peer sending
/// `content-length` is as correct as one sending `Content-Length`.
///
/// Skips the first line, which is the request or status line rather than a
/// header.
#[must_use]
pub fn header<'a>(lines: &'a [String], name: &str) -> Option<&'a str> {
    lines.iter().skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;

        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write;

    #[test]
    fn one_line_ending_comes_off_and_only_one() {
        assert_eq!(trim_eol(b"line\r\n"), b"line");
        assert_eq!(trim_eol(b"line\n"), b"line");
        assert_eq!(trim_eol(b"line"), b"line");
        assert_eq!(trim_eol(b"line\n\n"), b"line\n");
    }

    #[test]
    fn a_header_is_found_however_the_peer_capitalised_it() {
        let head = vec![
            "POST /orders HTTP/1.1".to_string(),
            "content-length: 8".to_string(),
        ];

        assert_eq!(header(&head, "Content-Length"), Some("8"));
    }

    #[test]
    fn the_request_line_is_not_a_header() {
        // "GET http://x/y HTTP/1.1" splits on a colon in an absolute URI and
        // would answer the wrong thing if the first line were searched.
        let head = vec!["GET http://x/y HTTP/1.1".to_string()];

        assert_eq!(header(&head, "http"), None);
    }

    #[test]
    fn a_head_ends_at_the_blank_line() {
        let mut reader = &b"POST / HTTP/1.1\r\nHost: x\r\n\r\nbody"[..];
        let head = read_head(&mut reader).expect("read");

        assert_eq!(head.len(), 2);
        assert_eq!(reader, b"body");
    }

    #[test]
    fn more_headers_than_xmip_will_read_is_refused() {
        let mut flood = String::from("POST / HTTP/1.1\r\n");

        for n in 0..=MAX_HEADERS {
            write!(flood, "X-{n}: v\r\n").expect("writing to a String cannot fail");
        }

        flood.push_str("\r\n");

        let failure = read_head(&mut flood.as_bytes()).expect_err("a peer misbehaving");

        assert!(
            failure.io.is_none(),
            "a protocol failure, not a connection's"
        );
    }
}

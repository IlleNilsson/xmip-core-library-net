//! HTTP/1.1 on the wire, both halves: a request and its answer, written and
//! read, and the one exchange of a request for its answer over whatever
//! connection it is handed — a plain socket, or one the caller wrapped in
//! TLS.
//!
//! A message is `Content-Length` framed as it is written, and closes its
//! connection unless it names its own `Connection` — `WebDAV` keeps its
//! connection for the next method, and says `keep-alive` on both sides. An
//! answer is read by its length, its chunks or its end; a 1xx, a 204 or a
//! 304 has no body at all. Both halves are here so the two cannot drift: a
//! header written one way is read the same way.
//!
//! What a capability needs to ask a service beside it — an Open Policy
//! Agent, an authorization server's introspection endpoint, a broker's
//! administration API — and what every technology riding on HTTP writes and
//! reads underneath its signature: S3, Azure Blob, Cloud Storage, AS2, AS4,
//! `WebDAV` and the rest. No TLS, no redirects, no connection pool: the
//! caller opens the connection, and the http transport is where HTTPS is.
//!
//! The [`Request`] and [`Response`] are HTTP's, not this version's:
//! [`crate::http2`] carries the same two over HTTP/2, trailers included,
//! and [`Version`] names which a connection speaks — what TLS agreed by
//! ALPN, or what a cleartext connection was told beforehand.
//!
//! One copy. Until 2026-09-24 the Open Policy Agent client, the OAuth 2.0
//! introspection client and the Redpanda Admin API client each wrote the
//! request line and read the status by hand; until 2026-09-25 the http
//! transport carried a second codec for the technologies riding on it,
//! which refused a chunked answer this one read, and a third to send a
//! Stream.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::NetError;
use crate::head::read_head;
use crate::percent::{decode, encode};
use message::{Message, write_message};

mod body;
mod message;
mod response;
mod version;

pub use response::Response;
pub use version::Version;

/// The largest body read, whether framed by its length, its chunks or the
/// connection's end.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// One request, as the asking side builds it and the answering side reads
/// it. `Host` is one of its headers, written as it is given: a signature
/// that covers it signs what travels.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path as it travels: percent-encoded, opening with `/`.
    pub path: String,
    /// The query as names and values, before encoding.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// `method` on `path`, no query, no headers, no body.
    #[must_use]
    pub fn new(method: &str, path: impl Into<String>) -> Self {
        Self {
            method: method.to_string(),
            path: path.into(),
            ..Self::default()
        }
    }

    /// With one more query parameter.
    #[must_use]
    pub fn query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_string(), value.to_string()));
        self
    }

    /// With one more header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// With `bytes` as the body.
    #[must_use]
    pub fn body(mut self, bytes: &[u8]) -> Self {
        self.body = bytes.to_vec();
        self
    }

    /// One header's value, however it was capitalised.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// One query parameter's value.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    /// The request target as the request line carries it: the path, and the
    /// query encoded and joined.
    #[must_use]
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let query: Vec<String> = self
            .query
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name, false), encode(value, false)))
            .collect();
        format!("{}?{}", self.path, query.join("&"))
    }
}

/// A connection to the first of `addresses` that accepts one within
/// `timeout`, with `timeout` on its reads and writes.
///
/// # Errors
///
/// Where none accepts, or the timeouts cannot be set.
pub fn connect(addresses: &[SocketAddr], timeout: Duration) -> Result<TcpStream, NetError> {
    let mut last = None;
    for address in addresses {
        match TcpStream::connect_timeout(address, timeout) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(timeout))
                    .and_then(|()| stream.set_write_timeout(Some(timeout)))
                    .map_err(|failed| NetError::from_io("setting the timeouts", &failed))?;
                return Ok(stream);
            }
            Err(failed) => last = Some(failed),
        }
    }
    Err(match last {
        Some(failed) => NetError::from_io("no address accepted the connection", &failed),
        None => NetError::new("there is no address to connect to"),
    })
}

/// Write `request` over `stream` and read its answer.
///
/// # Errors
///
/// Where the connection breaks, or what comes back is not an HTTP/1.x
/// answer this client can read.
pub fn exchange<S: Read + Write>(mut stream: S, request: &Request) -> Result<Response, NetError> {
    write_request(&mut stream, request)?;
    read_response(&mut BufReader::new(stream))
}

/// Write `request`, flushed: its request line, its headers, the length its
/// body has, and `Connection: close` unless it names its own `Connection`.
///
/// # Errors
///
/// Where the connection broke.
pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<(), NetError> {
    let first = format!("{} {} HTTP/1.1", request.method, request.target());
    let message = Message {
        first: &first,
        headers: &request.headers,
        body: &request.body,
        trailers: &[],
    };
    write_message(writer, &message, "the request")
}

/// Write `response`, flushed, as [`write_request`] writes a request; an
/// answer with trailers goes chunked, the trailer after its last chunk.
///
/// # Errors
///
/// Where the connection broke.
pub fn write_response(writer: &mut impl Write, response: &Response) -> Result<(), NetError> {
    let phrase = if response.reason.is_empty() {
        reason(response.status)
    } else {
        &response.reason
    };
    let first = format!("HTTP/1.1 {} {phrase}", response.status);
    let message = Message {
        first: &first,
        headers: &response.headers,
        body: &response.body,
        trailers: &response.trailers,
    };
    write_message(writer, &message, "the answer")
}

/// Read one answer.
///
/// # Errors
///
/// A connection that closed before answering, a status line that is not
/// HTTP/1.x, a transfer coding other than chunked, a broken chunk, or a
/// body over [`MAX_BODY`] or shorter than its `Content-Length`.
pub fn read_response(reader: &mut impl BufRead) -> Result<Response, NetError> {
    let head = read_head(reader)?;
    let line = head
        .first()
        .ok_or_else(|| NetError::new("the connection closed before an answer"))?;
    let not_http = || NetError::new(format!("what came back is not an HTTP answer: {line}"));
    let mut words = line
        .strip_prefix("HTTP/1.")
        .ok_or_else(not_http)?
        .splitn(3, ' ');
    let status = words
        .nth(1)
        .filter(|code| code.len() == 3)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(not_http)?;
    let bodiless = status < 200 || status == 204 || status == 304;
    let (body, trailer) = if bodiless {
        (Vec::new(), Vec::new())
    } else {
        body::read(reader, &head, true)?
    };
    Ok(Response {
        status,
        reason: words.next().unwrap_or_default().to_string(),
        headers: headers_of(&head[1..]),
        body,
        trailers: headers_of(&trailer),
    })
}

/// The answering side: one request off a connection, or `None` where the
/// peer closed without sending one.
///
/// # Errors
///
/// Where the connection broke, the request line is unreadable, or the body
/// is broken or over [`MAX_BODY`].
pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>, NetError> {
    let head = read_head(reader)?;
    let Some(line) = head.first() else {
        return Ok(None);
    };
    let mut words = line.split_whitespace();
    let (Some(method), Some(target)) = (words.next(), words.next()) else {
        return Err(NetError::new(format!(
            "a request line Xmip cannot read: {line}"
        )));
    };
    let (path, query) = split_target(target);
    let (body, _) = body::read(reader, &head, false)?;
    Ok(Some(Request {
        method: method.to_string(),
        path,
        query,
        headers: headers_of(&head[1..]),
        body,
    }))
}

/// A request target as its path, still encoded, and its query decoded —
/// what the request line carries in HTTP/1.1 and `:path` in HTTP/2.
#[must_use]
pub fn split_target(target: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(name), decode(value))
        })
        .collect();
    (path.to_string(), query)
}

/// The phrase a status is written with; one the table does not know is
/// written `Status`, which a reader ignores.
#[must_use]
pub const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        207 => "Multi-Status",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        423 => "Locked",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Header lines as names and values.
fn headers_of(lines: &[String]) -> Vec<(String, String)> {
    lines
        .iter()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

/// One header's value, however the peer capitalised it.
fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A connection that has `answer` to give and keeps what is written.
    struct Wire {
        answer: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.answer.read(buf)
        }
    }

    impl Write for Wire {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn wire(answer: &[u8]) -> Wire {
        Wire {
            answer: Cursor::new(answer.to_vec()),
            written: Vec::new(),
        }
    }

    fn answer(bytes: &[u8]) -> Result<Response, NetError> {
        read_response(&mut &bytes[..])
    }

    #[test]
    fn the_request_carries_its_headers_the_length_and_the_close() {
        let mut connection = wire(b"HTTP/1.1 204 No Content\r\n\r\n");
        let request = Request::new("POST", "/v1/data/allow")
            .header("Host", "[::1]:8181")
            .header("Content-Type", "application/json")
            .body(b"{}");

        let answer = exchange(&mut connection, &request).expect("answered");

        assert_eq!((answer.status, answer.reason.as_str()), (204, "No Content"));
        assert_eq!(
            String::from_utf8(connection.written).expect("text"),
            "POST /v1/data/allow HTTP/1.1\r\nHost: [::1]:8181\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\n\
             Connection: close\r\n\r\n{}"
        );
    }

    #[test]
    fn a_request_round_trips_through_its_own_reader() {
        let request = Request::new("PUT", "/bucket/in/1%20a.edi")
            .query("prefix", "in/")
            .header("Host", "s3.local")
            .body(b"UNA");
        let mut both = wire(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        let response = exchange(&mut both, &request).expect("exchanged");
        assert_eq!(
            (response.status, response.body.as_slice()),
            (200, &b"ok"[..])
        );
        let written = both.written;
        assert!(written.starts_with(b"PUT /bucket/in/1%20a.edi?prefix=in%2F HTTP/1.1\r\n"));
        let read = read_request(&mut &written[..]).expect("read").expect("one");
        assert_eq!(read.method, "PUT");
        assert_eq!(read.path, "/bucket/in/1%20a.edi");
        assert_eq!(read.query_value("prefix"), Some("in/"));
        assert_eq!(read.query_value("absent"), None);
        assert_eq!(read.header_value("host"), Some("s3.local"));
        assert_eq!(read.body, b"UNA");
        assert!(read_request(&mut &b""[..]).expect("closed").is_none());
        assert!(read_request(&mut &b"GET\r\n\r\n"[..]).is_err());
    }

    #[test]
    fn an_answer_is_read_by_its_length_its_chunks_or_its_end() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"result\":true}trailing";
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            9\r\n{\"result\"\r\n6;name=x\r\n:true}\r\n0\r\nX-Trailer: 1\r\n\r\n";
        let unframed = b"HTTP/1.0 200 OK\r\n\r\nto the end";

        for bytes in [&plain[..], &chunked[..]] {
            let read = answer(bytes).expect("read");
            assert_eq!(read.text().expect("text"), "{\"result\":true}");
        }
        let read = answer(unframed).expect("read");
        assert_eq!(read.text().expect("text"), "to the end");
    }

    #[test]
    fn a_body_that_is_not_utf_8_is_refused_as_text_and_kept_whole_as_bytes() {
        let binary = Response::new(200).body(&[0x7b, 0xff, 0xfe, 0x7d]);
        let refused = binary.text().expect_err("not text");
        assert!(refused.to_string().contains("not UTF-8"), "{refused}");
        assert_eq!(binary.body, [0x7b, 0xff, 0xfe, 0x7d]);
    }

    #[test]
    fn a_connection_kept_carries_the_next_message_and_no_body_is_read_past_a_204() {
        let kept = Request::new("PROPFIND", "/orders")
            .header("Host", "dav.example")
            .header("Connection", "keep-alive");
        let mut written = Vec::new();
        write_request(&mut written, &kept).expect("written");
        write_request(&mut written, &Request::new("GET", "/orders/1")).expect("written");
        let text = String::from_utf8_lossy(&written).into_owned();
        assert_eq!(text.matches("Connection:").count(), 2, "{text}");
        assert!(text.contains("Connection: keep-alive\r\n"), "{text}");
        let mut reader = &written[..];
        let first = read_request(&mut reader).expect("read").expect("one");
        assert_eq!(first.method, "PROPFIND");
        let second = read_request(&mut reader).expect("read").expect("two");
        assert_eq!(second.path, "/orders/1");
        let mut answers = Vec::new();
        let open = Response::new(204).header("Connection", "keep-alive");
        write_response(&mut answers, &open).expect("written");
        write_response(&mut answers, &Response::new(207).body(b"<a/>")).expect("written");
        assert!(answers.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        let mut reader = &answers[..];
        assert!(read_response(&mut reader).expect("204").body.is_empty());
        let multi = read_response(&mut reader).expect("207");
        assert_eq!((multi.status, multi.body.as_slice()), (207, &b"<a/>"[..]));
    }

    #[test]
    fn the_status_and_its_phrase_are_kept_and_headers_are_found_in_any_case() {
        let read =
            answer(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n").expect("read");

        assert_eq!((read.status, read.reason.as_str()), (401, "Unauthorized"));
        assert_eq!(read.header_value("www-authenticate"), Some("Basic"));

        let mut written = Vec::new();
        write_response(&mut written, &Response::new(404).body(b"<Error/>")).expect("written");
        let back = answer(&written).expect("read");
        assert_eq!((back.status, back.body.as_slice()), (404, &b"<Error/>"[..]));
    }

    #[test]
    fn what_is_not_an_http_answer_is_refused() {
        let over = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        let refused = [
            &b""[..],
            b"nonsense\r\n\r\n",
            b"SSH-2.0-OpenSSH\r\n\r\n",
            b"220 mail.example ESMTP\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort",
            b"HTTP/1.1 200 OK\r\nContent-Length: eight\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
            over.as_bytes(),
        ];
        for bytes in refused {
            assert!(answer(bytes).is_err(), "{}", String::from_utf8_lossy(bytes));
        }
    }

    #[test]
    fn an_answer_with_trailers_goes_chunked_and_reads_back_with_them() {
        for body in [&b"abc"[..], b""] {
            let sent = Response::new(200).body(body).trailer("grpc-status", "0");
            let mut written = Vec::new();
            write_response(&mut written, &sent).expect("written");
            let text = String::from_utf8_lossy(&written).into_owned();
            assert!(text.contains("Transfer-Encoding: chunked\r\n"), "{text}");
            assert!(!text.contains("Content-Length"), "{text}");
            let back = answer(&written).expect("read");
            assert_eq!(back.body, body);
            assert_eq!(back.trailer_value("GRPC-Status"), Some("0"));
        }
        assert!(
            answer(b"HTTP/1.1 200 OK\r\n\r\n")
                .expect("read")
                .trailers
                .is_empty()
        );
    }

    #[test]
    fn a_request_without_a_length_has_no_body() {
        let mut reader = &b"POST / HTTP/1.1\r\nHost: x\r\n\r\nGET /next HTTP/1.1\r\n\r\n"[..];

        let first = read_request(&mut reader).expect("read").expect("one");

        assert!(first.body.is_empty());
        assert_eq!(
            read_request(&mut reader).expect("read").expect("two").path,
            "/next"
        );
    }

    #[test]
    fn a_connection_no_address_accepts_is_refused_with_its_kind() {
        assert!(connect(&[], Duration::from_millis(50)).is_err());

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);

        let failed = connect(&[address], Duration::from_millis(500)).expect_err("refused");
        assert!(failed.io.is_some(), "{failed}");
    }
}

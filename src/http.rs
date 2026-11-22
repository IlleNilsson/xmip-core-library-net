//! HTTP/1.1 on the wire, both halves: a request and its answer, written and
//! read, and the one exchange of a request for its answer over whatever
//! connection it is handed — a plain socket, or one the caller wrapped in
//! TLS.
//!
//! A message is `Content-Length` framed as it is written, and closes its
//! connection unless it names its own `Connection` — `WebDAV` keeps its
//! connection for the next method, and says `keep-alive` on both sides. An
//! answer is read by its length, its chunks or its end; a 1xx, a 204 or a
//! 304 has no body at all, and an interim answer — a 1xx but 101 — is read
//! past to the final one. Both halves are here so the two cannot drift: a
//! header written one way is read the same way, and framing two readers
//! could read apart is refused (`body`), a request so refused answered
//! `400` ([`refuse`]).
//!
//! What a capability needs to ask a service beside it — an Open Policy
//! Agent, an authorization server's introspection endpoint, a broker's
//! administration API — and what every technology riding on HTTP writes and
//! reads underneath its signature: S3, Azure Blob, Cloud Storage, AS2, AS4,
//! `WebDAV` and the rest. No TLS, no redirects, no connection pool: the
//! caller opens the connection ([`crate::connect`]), and the http
//! transport is where HTTPS is and where a connection is kept between
//! requests ([`exchange_kept`] says whether one can be).
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

use crate::NetError;
use crate::head::{fields, read_head};
use body::Framing;
use codec::percent::{decode_pairs, encode_pairs};
use message::{Message, write_message};

mod body;
pub mod date;
mod message;
mod response;
mod version;

pub use response::Response;
pub use version::Version;

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

    /// One header's value, however it was capitalized.
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
        format!("{}?{}", self.path, encode_pairs(&self.query))
    }
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

/// Write `request` over a connection kept for the next and read its answer
/// through `connection`, the one reader the connection keeps for its life,
/// so what it read past one answer is the next one's; and say whether the
/// connection can carry another: the request says no `Connection: close` —
/// HTTP/1.1 keeps a connection unless one side says otherwise — and the
/// connection is spent where the answer closes it, was framed by the
/// connection's end, or switched it to another protocol (`101`). Until
/// 2026-11-22 each answer was read through a reader of its own, dropped
/// with whatever it had read past that answer.
///
/// # Errors
///
/// As [`exchange`].
pub fn exchange_kept<S: Read + Write>(
    connection: &mut BufReader<S>,
    request: &Request,
) -> Result<(Response, bool), NetError> {
    write(connection.get_mut(), request, false)?;
    let (answer, framing) = read_answer(connection)?;
    let closed = answer
        .header_value("connection")
        .is_some_and(|said| said.eq_ignore_ascii_case("close"));
    let spent = closed || answer.status == 101 || framing == Framing::ToEnd;
    Ok((answer, !spent))
}

/// Write `request`, flushed: its request line, its headers, the length its
/// body has, and `Connection: close` unless it names its own `Connection`.
///
/// # Errors
///
/// Where the connection broke.
pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<(), NetError> {
    write(writer, request, true)
}

/// `request` written, saying the connection closes after it where `close`
/// and the request names no `Connection` of its own.
fn write(writer: &mut impl Write, request: &Request, close: bool) -> Result<(), NetError> {
    let first = format!("{} {} HTTP/1.1", request.method, request.target());
    let message = Message {
        first: &first,
        headers: &request.headers,
        body: &request.body,
        trailers: &[],
        close,
        bodiless: false,
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
        close: true,
        bodiless: bodiless(response.status),
    };
    write_message(writer, &message, "the answer")
}

/// Read one final answer, the interim answers before it — a 1xx but 101 —
/// read past (RFC 9110 section 15.2). Until 2026-11-22 a `100 Continue` or
/// a `103 Early Hints` was taken for the answer, and the final one left on
/// the connection.
///
/// # Errors
///
/// A connection that closed before answering, a status line that is not
/// HTTP/1.x, more interim answers than Xmip reads past, a field or framing
/// two readers could read apart (`body::framing`), a broken chunk, or a
/// body over [`crate::MAX_BODY`] or shorter than its `Content-Length`.
pub fn read_response(reader: &mut impl BufRead) -> Result<Response, NetError> {
    read_answer(reader).map(|(answer, _)| answer)
}

/// The most interim answers read past before the final one: far over the
/// `100` and the `103` or two a server sends, and a bound on a server that
/// never ends them.
const MAX_INTERIM: usize = 16;

/// The final answer, as [`read_response`] reads it, and how its body was
/// framed.
fn read_answer(reader: &mut impl BufRead) -> Result<(Response, Framing), NetError> {
    for _ in 0..=MAX_INTERIM {
        let head = read_head(reader)?;
        let line = head
            .first()
            .ok_or_else(|| NetError::new("the connection closed before an answer"))?;
        let (status, reason) = status_line(line)?;
        let headers = fields(&head[1..])?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let framing = if bodiless(status) {
            Framing::Empty
        } else {
            body::framing(&headers, true)?
        };
        let (body, trailer) = body::read(reader, framing)?;
        let answer = Response {
            status,
            reason: reason.to_string(),
            headers,
            body,
            trailers: fields(&trailer)?,
        };
        return Ok((answer, framing));
    }
    Err(NetError::new("more interim answers than Xmip will read"))
}

/// The status a status line says, and its phrase.
fn status_line(line: &str) -> Result<(u16, &str), NetError> {
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
    Ok((status, words.next().unwrap_or_default()))
}

/// The answering side: one request off a connection, or `None` where the
/// peer closed without sending one.
///
/// # Errors
///
/// Where the connection broke, the request line is unreadable, a field or
/// the framing is one two readers could read apart (`body::framing`), or
/// the body is broken or over [`crate::MAX_BODY`]: each but the first the
/// peer's failure, which [`refuse`] answers.
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
    let headers = fields(&head[1..])?;
    let (body, _) = body::read(reader, body::framing(&headers, false)?)?;
    Ok(Some(Request {
        method: method.to_string(),
        path,
        query,
        headers,
        body,
    }))
}

/// The answering side's one request off `connection`, which it holds
/// whole, as [`read_request`] reads it: a request refused is answered on
/// the connection ([`refuse`]) before the refusal is returned.
///
/// # Errors
///
/// As [`read_request`].
pub fn read_request_or_refuse<S: Read + Write>(
    connection: &mut BufReader<S>,
) -> Result<Option<Request>, NetError> {
    read_request(connection).inspect_err(|failure| refuse(connection.get_mut(), failure))
}

/// Answer a request [`read_request`] refused on `writer`: `400 Bad
/// Request`, the connection said closed after it, as a server answers a
/// request it cannot read or frame (RFC 9112 sections 5.1 and 6.3). Where
/// the connection broke instead nothing is written, since nothing would
/// reach the peer; an answer that cannot be written ends the connection
/// either way. For a server whose reader and writer are apart; one that
/// holds its connection whole reads by [`read_request_or_refuse`].
pub fn refuse(writer: &mut impl Write, failure: &NetError) {
    if failure.io.is_none() {
        drop(write_response(writer, &Response::new(400)));
    }
}

/// A request target as its path, still encoded, and its query decoded —
/// what the request line carries in HTTP/1.1 and `:path` in HTTP/2.
#[must_use]
pub fn split_target(target: &str) -> (String, Vec<(String, String)>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path.to_string(), decode_pairs(query))
}

/// Whether an answer of `status` carries no body and states no length:
/// a 1xx, a 204 or a 304 (RFC 9110 sections 6.4.1 and 8.6).
const fn bodiless(status: u16) -> bool {
    status < 200 || status == 204 || status == 304
}

/// The phrase a status is written with; one the table does not know is
/// written `Status`, which a reader ignores.
#[must_use]
pub const fn reason(status: u16) -> &'static str {
    match status {
        101 => "Switching Protocols",
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

/// One header's value, however the peer capitalized it.
fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// A connection that has `chunks` to give, as they arrive: a read
    /// never runs past the end of one. It keeps what is written.
    struct Wire {
        chunks: VecDeque<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let Some(chunk) = self.chunks.front_mut() else {
                return Ok(0);
            };
            let taken = chunk.len().min(buf.len());
            buf[..taken].copy_from_slice(&chunk[..taken]);
            chunk.drain(..taken);
            if chunk.is_empty() {
                self.chunks.pop_front();
            }
            Ok(taken)
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
        apart(&[answer])
    }

    /// A connection whose `chunks` arrive one by one.
    fn apart(chunks: &[&[u8]]) -> Wire {
        Wire {
            chunks: chunks.iter().map(|chunk| chunk.to_vec()).collect(),
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
    fn an_answer_without_a_body_states_no_length() {
        let mut written = Vec::new();
        let switching = Response::new(101)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade");
        write_response(&mut written, &switching).expect("written");
        assert_eq!(
            written,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        );
        let read = read_response(&mut &written[..]).expect("read");
        assert_eq!(read.status, 101);
        assert_eq!(read.header_value("upgrade"), Some("websocket"));
    }

    #[test]
    fn a_connection_kept_carries_the_next_message_and_no_body_is_read_past_a_204() {
        let kept = Request::new("PROPFIND", "/orders")
            .header("Host", "dav.example")
            .header("Connection", "keep-alive");
        let mut written = Vec::new();
        write_request(&mut written, &kept).expect("written");
        write_request(&mut written, &Request::new("GET", "/orders/1")).expect("written");
        let text = String::from_utf8_lossy(&written);
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
        assert_eq!(read_response(&mut reader).expect("204").body, [] as [u8; 0]);
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
            crate::MAX_BODY + 1
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
            let text = String::from_utf8_lossy(&written);
            assert!(text.contains("Transfer-Encoding: chunked\r\n"), "{text}");
            assert!(!text.contains("Content-Length"), "{text}");
            let back = answer(&written).expect("read");
            assert_eq!(back.body, body);
            assert_eq!(back.trailer_value("GRPC-Status"), Some("0"));
        }
        assert_eq!(
            answer(b"HTTP/1.1 200 OK\r\n\r\n").expect("read").trailers,
            [] as [(String, String); 0]
        );
    }

    #[test]
    fn a_request_without_a_length_has_no_body() {
        let mut reader = &b"POST / HTTP/1.1\r\nHost: x\r\n\r\nGET /next HTTP/1.1\r\n\r\n"[..];

        let first = read_request(&mut reader).expect("read").expect("one");

        assert_eq!(first.body, [] as [u8; 0]);
        assert_eq!(
            read_request(&mut reader).expect("read").expect("two").path,
            "/next"
        );
    }

    #[test]
    fn a_kept_exchange_says_no_close_and_knows_when_the_connection_is_spent() {
        let request = Request::new("GET", "/").header("Host", "example");
        let cases: [(&[u8], bool); 6] = [
            (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", true),
            (b"HTTP/1.1 204 No Content\r\n\r\n", true),
            (b"HTTP/1.1 101 Switching Protocols\r\n\r\n", false),
            (
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                true,
            ),
            (
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: Close\r\n\r\n",
                false,
            ),
            (b"HTTP/1.1 200 OK\r\n\r\nto the end", false),
        ];
        for (answer, reusable) in cases {
            let mut connection = BufReader::new(wire(answer));
            let (_, kept) = exchange_kept(&mut connection, &request).expect("answered");
            assert_eq!(kept, reusable, "{}", String::from_utf8_lossy(answer));
            let written = String::from_utf8(connection.into_inner().written).expect("text");
            assert!(!written.contains("Connection:"), "{written}");
        }
    }

    #[test]
    fn interim_answers_are_read_past_and_a_kept_connection_keeps_what_it_read_ahead() {
        // Until 2026-11-22 a 100 Continue was taken for the answer, and on
        // a kept connection what was read past an answer went with it.
        let interim = &b"HTTP/1.1 100 Continue\r\n\r\n\
            HTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\n\r\n"[..];
        let first = &b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"[..];
        let second = &b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"[..];
        let request = Request::new("PUT", "/a")
            .header("Host", "example")
            .body(b"ok");
        let together = [interim, first, second].concat();
        for (connection, how) in [
            (wire(&together), "together"),
            (apart(&[interim, first, second]), "apart"),
        ] {
            let mut connection = BufReader::new(connection);
            let (answer, kept) = exchange_kept(&mut connection, &request).expect(how);
            assert_eq!(
                (answer.status, answer.body.as_slice(), kept),
                (200, &b"ok"[..], true),
                "{how}"
            );
            let (answer, kept) = exchange_kept(&mut connection, &request).expect(how);
            assert_eq!((answer.status, kept), (201, true), "{how}");
        }
    }

    #[test]
    fn a_101_is_the_final_answer_and_what_follows_it_the_new_protocol_s() {
        let mut reader = &b"HTTP/1.1 100 Continue\r\n\r\n\
            HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x00"[..];
        let switched = read_response(&mut reader).expect("read");
        assert_eq!(switched.status, 101);
        assert_eq!(reader, b"\x81\x00");
    }

    #[test]
    fn a_server_that_never_ends_its_interim_answers_is_refused() {
        let continued = "HTTP/1.1 100 Continue\r\n\r\n";
        let last = "HTTP/1.1 204 No Content\r\n\r\n";
        let within = format!("{}{last}", continued.repeat(MAX_INTERIM));
        assert_eq!(answer(within.as_bytes()).expect("read").status, 204);
        let past = format!("{}{last}", continued.repeat(MAX_INTERIM + 1));
        assert!(answer(past.as_bytes()).is_err());
    }

    #[test]
    fn a_request_refused_is_answered_400_and_a_broken_connection_not_at_all() {
        let apart = &b"POST / HTTP/1.1\r\nContent-Length : 3\r\n\r\nabc"[..];
        let mut connection = BufReader::new(wire(apart));
        read_request_or_refuse(&mut connection).expect_err("whitespace before the colon");
        let back = answer(&connection.into_inner().written).expect("an answer");
        assert_eq!(back.status, 400);
        assert_eq!(back.header_value("connection"), Some("close"));
        let good = &b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"[..];
        let mut connection = BufReader::new(wire(good));
        let read = read_request_or_refuse(&mut connection).expect("read");
        assert_eq!(read.expect("one").path, "/");
        assert_eq!(
            connection.into_inner().written,
            b"",
            "nothing to answer yet"
        );
        let broken = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let mut written = Vec::new();
        refuse(&mut written, &NetError::from_io("reading", &broken));
        assert_eq!(written, b"", "nothing reaches a broken connection");
    }
}

//! The minimal HTTP/1.1 client: one request over one connection,
//! `Connection: close`, and the answer read to its end — framed by
//! `Content-Length`, chunked, or ended by the close.
//!
//! What a capability needs to ask a service beside it — an Open Policy
//! Agent, an authorization server's introspection endpoint, a broker's
//! administration API — and nothing more: no TLS, no redirects, no
//! connection reuse. Moving a Stream over HTTP is the http transport's
//! work, not this.
//!
//! One copy. Until 2026-09-24 the Open Policy Agent client, the OAuth 2.0
//! introspection client and the Redpanda Admin API client each wrote the
//! request line and read the status by hand, and only two of them read a
//! chunked answer.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::NetError;

/// The largest answer the client reads, head and body together.
pub const MAX_ANSWER: usize = 64 * 1024 * 1024;

/// One request: the method, the target as the request line carries it, the
/// headers beyond `Host`, `Content-Length` and `Connection`, and the body.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    /// `method` on `target`, no headers, no body.
    #[must_use]
    pub fn new(method: &str, target: impl Into<String>) -> Self {
        Self {
            method: method.to_string(),
            target: target.into(),
            ..Self::default()
        }
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
}

/// One answer, the body put back together where it was chunked.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Response {
    pub status: u16,
    /// The status line as the server wrote it: `HTTP/1.1 401 Unauthorized`.
    pub status_line: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// One header's value, however it was capitalised.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The body as text, lossily.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
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

/// Write `request` to `host` over `stream` and read the answer to its end.
///
/// # Errors
///
/// Where the connection breaks, or what comes back is not an HTTP/1.x
/// answer this client can read.
pub fn exchange<S: Read + Write>(
    mut stream: S,
    host: &str,
    request: &Request,
) -> Result<Response, NetError> {
    let headers = request
        .headers
        .iter()
        .fold(String::new(), |mut lines, (name, value)| {
            let _ = write!(lines, "{name}: {value}\r\n");
            lines
        });
    let head = format!(
        "{} {} HTTP/1.1\r\nHost: {host}\r\n{headers}Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        request.method,
        request.target,
        request.body.len()
    );
    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.write_all(&request.body))
        .and_then(|()| stream.flush())
        .map_err(|failed| NetError::from_io("writing the request", &failed))?;

    // `Connection: close`: the answer is everything up to the end.
    let mut answer = Vec::new();
    let limit = u64::try_from(MAX_ANSWER).unwrap_or(u64::MAX) + 1;
    stream
        .take(limit)
        .read_to_end(&mut answer)
        .map_err(|failed| NetError::from_io("reading the answer", &failed))?;
    if answer.len() > MAX_ANSWER {
        return Err(NetError::new(format!(
            "an answer over the {MAX_ANSWER} bytes this client reads"
        )));
    }

    read_response(&answer)
}

/// The status, the headers and the body of one answer read to its end.
fn read_response(answer: &[u8]) -> Result<Response, NetError> {
    let not_http = || NetError::new("what came back is not an HTTP response");
    let split = answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(not_http)?;
    let head = String::from_utf8_lossy(&answer[..split]);
    let body = &answer[split + 4..];

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default().to_string();
    let status = status_line
        .strip_prefix("HTTP/1.")
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| NetError::new("what came back has no HTTP status"))?;
    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    let mut response = Response {
        status,
        status_line,
        headers,
        body: Vec::new(),
    };
    let chunked = response
        .header("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    response.body = if chunked {
        unchunk(body)?
    } else if let Some(length) = response.header("content-length") {
        let length = Some(length)
            .filter(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|digits| digits.parse::<usize>().ok())
            .ok_or_else(|| NetError::new(format!("a Content-Length '{length}' is not one")))?;
        body.get(..length)
            .ok_or_else(|| NetError::new("the body is shorter than its Content-Length"))?
            .to_vec()
    } else {
        body.to_vec()
    };
    Ok(response)
}

/// A chunked body, put back together.
fn unchunk(mut body: &[u8]) -> Result<Vec<u8>, NetError> {
    let broken = || NetError::new("a chunked body is broken");
    let mut whole = Vec::new();

    loop {
        let end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(broken)?;
        let line = std::str::from_utf8(&body[..end]).map_err(|_| broken())?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size, 16)
            .ok()
            .filter(|_| size.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or_else(broken)?;
        let rest = &body[end + 2..];

        if size == 0 {
            return Ok(whole);
        }

        whole.extend_from_slice(rest.get(..size).ok_or_else(broken)?);
        body = rest
            .get(size..)
            .and_then(|after| after.strip_prefix(b"\r\n"))
            .ok_or_else(broken)?;
    }
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

    #[test]
    fn the_request_carries_the_host_the_headers_the_length_and_the_close() {
        let mut connection = wire(b"HTTP/1.1 204 No Content\r\n\r\n");
        let request = Request::new("POST", "/v1/data/allow")
            .header("Content-Type", "application/json")
            .body(b"{}");

        let answer = exchange(&mut connection, "[::1]:8181", &request).expect("answered");

        assert_eq!(answer.status, 204);
        assert_eq!(
            String::from_utf8(connection.written).expect("text"),
            "POST /v1/data/allow HTTP/1.1\r\nHost: [::1]:8181\r\n\
             Content-Type: application/json\r\nContent-Length: 2\r\n\
             Connection: close\r\n\r\n{}"
        );
    }

    #[test]
    fn an_answer_is_read_by_its_length_its_chunks_or_its_end() {
        let plain = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\n{\"result\":true}trailing";
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            9\r\n{\"result\"\r\n6\r\n:true}\r\n0\r\n\r\n";
        let unframed = b"HTTP/1.0 200 OK\r\n\r\nto the end";

        for answer in [&plain[..], &chunked[..]] {
            let read = read_response(answer).expect("read");
            assert_eq!(read.text(), "{\"result\":true}");
        }
        assert_eq!(read_response(unframed).expect("read").text(), "to the end");
    }

    #[test]
    fn the_status_and_its_line_are_kept_and_headers_are_found_in_any_case() {
        let answer = read_response(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\n\r\n")
            .expect("read");

        assert_eq!(answer.status, 401);
        assert_eq!(answer.status_line, "HTTP/1.1 401 Unauthorized");
        assert_eq!(answer.header("www-authenticate"), Some("Basic"));
    }

    #[test]
    fn what_is_not_an_http_answer_is_refused() {
        assert!(read_response(b"").is_err());
        assert!(read_response(b"SSH-2.0-OpenSSH\r\n\r\n").is_err());
        assert!(read_response(b"220 mail.example ESMTP\r\n\r\n").is_err());
        assert!(read_response(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort").is_err());
        let broken =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
        assert!(read_response(broken).is_err());
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

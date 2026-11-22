//! The body a head frames: its chunks, its `Content-Length`, or the
//! connection's end, and never more than [`MAX_BODY`]; and the trailer a
//! chunked body ends with.
//!
//! **The framing is read once, here, before a body is read** ([`framing`]):
//! from every field that states it, and a head two readers could frame
//! apart refused — a `Transfer-Encoding` beside a `Content-Length`, lengths
//! that disagree, a coding but `chunked` (RFC 9112 section 6.3). Behind an
//! intermediary that framed it otherwise, a kept connection would carry a
//! request smuggled into the next. The two fields are the writer's alone
//! ([`frames`]). Until 2026-11-22 the first field of each name framed the
//! body, a `Transfer-Encoding` won over a `Content-Length` beside it, and a
//! caller's own framing fields were written beside the writer's.

use std::io::BufRead;

use crate::head::read_head;
use crate::read;
use crate::{MAX_BODY, NetError};

/// The field that states a body's length.
const CONTENT_LENGTH: &str = "content-length";

/// The field that states a body's codings, `chunked` the one read.
const TRANSFER_ENCODING: &str = "transfer-encoding";

/// How a head frames the body after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Framing {
    /// No body: a request that states no length, or an answer whose status
    /// carries none.
    Empty,
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// `Content-Length`.
    Length(usize),
    /// An answer that states neither: its body runs to the connection's end.
    ToEnd,
}

/// Whether `name` is a field that frames a body, which the writer writes
/// and a caller's is not: `Content-Length` or `Transfer-Encoding`.
pub(super) fn frames(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONTENT_LENGTH) || name.eq_ignore_ascii_case(TRANSFER_ENCODING)
}

/// The framing `fields` state, every field of each name read and each a
/// list (RFC 9110 section 5.3): `chunked` alone, or one length however
/// often it is said. An `answer` that states neither runs to the
/// connection's end; a request that states neither has no body.
///
/// # Errors
///
/// A `Transfer-Encoding` beside a `Content-Length`, a coding but `chunked`
/// or `chunked` twice, lengths that disagree, a length that is not one, or
/// one over [`MAX_BODY`]: the peer's failure, which a server answers `400`
/// (`http::refuse`).
pub(super) fn framing(fields: &[(String, String)], answer: bool) -> Result<Framing, NetError> {
    let values = |name: &'static str| {
        fields
            .iter()
            .filter(move |(field, _)| field.eq_ignore_ascii_case(name))
            .flat_map(|(_, value)| value.split(','))
            .map(|element| element.trim_matches([' ', '\t']))
    };
    let mut lengths = values(CONTENT_LENGTH);
    let length = lengths.next();
    let mut codings = values(TRANSFER_ENCODING);
    if let Some(coding) = codings.next() {
        if length.is_some() {
            return Err(NetError::new(
                "a Transfer-Encoding beside a Content-Length, which two readers frame apart",
            ));
        }
        if !coding.eq_ignore_ascii_case("chunked") || codings.next().is_some() {
            let said: Vec<&str> = values(TRANSFER_ENCODING).collect();
            return Err(NetError::new(format!(
                "a transfer coding Xmip does not read: {}",
                said.join(", ")
            )));
        }
        return Ok(Framing::Chunked);
    }
    let Some(length) = length else {
        return Ok(if answer {
            Framing::ToEnd
        } else {
            Framing::Empty
        });
    };
    if let Some(other) = lengths.find(|other| *other != length) {
        return Err(NetError::new(format!(
            "a Content-Length of {length} and of {other}, which two readers frame apart"
        )));
    }
    let bytes = Some(length)
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<usize>().ok())
        .ok_or_else(|| NetError::new(format!("a Content-Length '{length}' is not one")))?;
    within(bytes)?;
    Ok(Framing::Length(bytes))
}

/// The body `framing` frames, off `reader`, held only as it arrives, and
/// the trailer's lines beside it where it was chunked.
pub(super) fn read(
    reader: &mut impl BufRead,
    framing: Framing,
) -> Result<(Vec<u8>, Vec<String>), NetError> {
    match framing {
        Framing::Empty => Ok((Vec::new(), Vec::new())),
        Framing::Chunked => unchunk(reader),
        Framing::Length(length) => Ok((read::exact(reader, length, "the body")?, Vec::new())),
        Framing::ToEnd => Ok((read::to_end(reader, MAX_BODY)?, Vec::new())),
    }
}

/// A chunked body, put back together, and the lines of its trailer.
fn unchunk(reader: &mut impl BufRead) -> Result<(Vec<u8>, Vec<String>), NetError> {
    let broken = || NetError::new("a chunked body is broken");
    let read = |failed: std::io::Error| NetError::from_io("reading a chunk", &failed);
    let mut whole = Vec::new();

    loop {
        let line = read::line(reader)?.ok_or_else(broken)?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = Some(size)
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|digits| usize::from_str_radix(digits, 16).ok())
            .ok_or_else(broken)?;

        if size == 0 {
            return Ok((whole, read_head(reader)?));
        }

        within(whole.len().saturating_add(size))?;
        let start = whole.len();
        whole.resize(start + size, 0);
        reader.read_exact(&mut whole[start..]).map_err(read)?;
        let mut end = [0u8; 2];
        reader.read_exact(&mut end).map_err(read)?;
        if &end != b"\r\n" {
            return Err(broken());
        }
    }
}

/// Refuse a body of `length` over [`MAX_BODY`], before it is allocated
/// where the length is known first.
fn within(length: usize) -> Result<(), NetError> {
    crate::ceiling::within(length, MAX_BODY, "Xmip reads in one body")
}

#[cfg(test)]
mod tests {
    use crate::http::{read_request, read_response};

    /// Heads two readers can frame apart: an intermediary reading one way
    /// and this reader another would leave a request smuggled into the
    /// next on a kept connection.
    const APART: [&str; 10] = [
        "Content-Length: 3\r\nContent-Length: 5\r\n",
        "Content-Length: 3, 5\r\n",
        "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n",
        "Content-Length: 3\r\ntransfer-encoding: chunked\r\n",
        "Transfer-Encoding: chunked\r\nTransfer-Encoding: gzip\r\n",
        "Transfer-Encoding: chunked, chunked\r\n",
        "Content-Length : 3\r\n",
        "Host: x\r\n Content-Length: 3\r\n",
        "Content-Length\x0b: 3\r\n",
        "X-Said: a\rContent-Length: 3\r\n",
    ];

    #[test]
    fn framing_two_readers_can_read_apart_is_refused_in_a_request_and_an_answer() {
        let body = "3\r\nabc\r\n0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n";
        for fields in APART {
            let request = format!("POST / HTTP/1.1\r\n{fields}\r\n{body}");
            let refused = read_request(&mut request.as_bytes()).expect_err(fields);
            assert_eq!(refused.io, None, "the peer's failure: {fields:?}");
            let answer = format!("HTTP/1.1 200 OK\r\n{fields}\r\n{body}");
            let refused = read_response(&mut answer.as_bytes()).expect_err(fields);
            assert_eq!(refused.io, None, "the peer's failure: {fields:?}");
        }
    }

    #[test]
    fn lengths_that_agree_are_one_length() {
        for fields in [
            "Content-Length: 3\r\ncontent-length: 3\r\n",
            "Content-Length: 3, 3\r\n",
        ] {
            let request = format!("POST / HTTP/1.1\r\n{fields}\r\nabcGET");
            let read = read_request(&mut request.as_bytes()).expect(fields);
            assert_eq!(read.expect("one").body, b"abc", "{fields:?}");
        }
    }
}

//! The body a head frames: its chunks, its `Content-Length`, or the
//! connection's end, and never more than [`MAX_BODY`].

use std::io::{BufRead, Read};

use super::MAX_BODY;
use crate::NetError;
use crate::head::{header, read_head, trim_eol};

/// The body `head` frames: its chunks, its `Content-Length`, or — for an
/// answer, `to_end` — everything up to the close. A request with neither
/// has none.
pub(super) fn read(
    reader: &mut impl BufRead,
    head: &[String],
    to_end: bool,
) -> Result<Vec<u8>, NetError> {
    if let Some(codings) = header(head, "transfer-encoding") {
        if !codings.trim().eq_ignore_ascii_case("chunked") {
            return Err(NetError::new(format!(
                "a transfer coding this client does not read: {codings}"
            )));
        }
        return unchunk(reader);
    }
    if let Some(value) = header(head, "content-length") {
        let length = Some(value)
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|digits| digits.parse::<usize>().ok())
            .ok_or_else(|| NetError::new(format!("a Content-Length '{value}' is not one")))?;
        within(length)?;
        let mut bytes = vec![0u8; length];
        reader
            .read_exact(&mut bytes)
            .map_err(|failed| NetError::from_io("reading the body", &failed))?;
        return Ok(bytes);
    }
    let mut body = Vec::new();
    if to_end {
        let limit = u64::try_from(MAX_BODY).unwrap_or(u64::MAX) + 1;
        reader
            .take(limit)
            .read_to_end(&mut body)
            .map_err(|failed| NetError::from_io("reading the body", &failed))?;
        within(body.len())?;
    }
    Ok(body)
}

/// A chunked body, put back together; the trailer, where there is one, is
/// read past and dropped.
fn unchunk(reader: &mut impl BufRead) -> Result<Vec<u8>, NetError> {
    let broken = || NetError::new("a chunked body is broken");
    let read = |failed: std::io::Error| NetError::from_io("reading a chunk", &failed);
    let mut whole = Vec::new();

    loop {
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line).map_err(read)?;
        let line = std::str::from_utf8(trim_eol(&line)).map_err(|_| broken())?;
        let size = line.split(';').next().unwrap_or_default().trim();
        let size = Some(size)
            .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|digits| usize::from_str_radix(digits, 16).ok())
            .ok_or_else(broken)?;

        if size == 0 {
            read_head(reader)?;
            return Ok(whole);
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
    if length > MAX_BODY {
        return Err(NetError::new(format!(
            "a body of {length} bytes, over the {MAX_BODY} bytes Xmip reads"
        )));
    }
    Ok(())
}

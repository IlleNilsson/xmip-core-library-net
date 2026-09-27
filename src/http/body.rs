//! The body a head frames: its chunks, its `Content-Length`, or the
//! connection's end, and never more than [`MAX_BODY`]; and the trailer a
//! chunked body ends with.

use std::io::BufRead;

use crate::head::{header, read_head};
use crate::read;
use crate::{MAX_BODY, NetError};

/// The body `head` frames: its chunks, its `Content-Length`, or — for an
/// answer, `to_end` — everything up to the close. A request with neither
/// has none. The trailer's lines come beside it, where it was chunked.
pub(super) fn read(
    reader: &mut impl BufRead,
    head: &[String],
    to_end: bool,
) -> Result<(Vec<u8>, Vec<String>), NetError> {
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
        return Ok((bytes, Vec::new()));
    }
    if to_end {
        return Ok((read::to_end(reader, MAX_BODY)?, Vec::new()));
    }
    Ok((Vec::new(), Vec::new()))
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
    if length > MAX_BODY {
        return Err(NetError::new(format!(
            "a body of {length} bytes, over the {MAX_BODY} bytes Xmip reads"
        )));
    }
    Ok(())
}

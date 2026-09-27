//! Reading off a connection, never more than Xmip will hold: to a
//! delimiter, a line, or the end.
//!
//! `BufRead::read_until`, `read_line` and `Read::read_to_end` grow their
//! buffer for as long as the peer keeps sending, so a peer that never sends
//! a line ending, or never closes, makes the reader allocate without end.
//! [`until`] and [`to_end`] stop at a ceiling the caller names, and [`line`]
//! reads the line-oriented protocols' lines under [`MAX_LINE`], with one
//! policy for bytes that are not UTF-8: refused, never repaired, so what a
//! line says is what the peer sent.
//!
//! One copy. Until 2026-09-27 the head reader here, STOMP, FTP, IMAP, SMTP,
//! POP3, NATS, RESP, the SSH identification, syslog, MLLP and the
//! dot-stuffed block each read lines themselves, none of them bounded, under
//! three different UTF-8 policies; and TCP, a Unix socket, a named pipe and
//! FTP's data connection each read a connection to its end unbounded.

use std::io::{BufRead, ErrorKind, Read};

use crate::NetError;

/// The longest line read, its line ending included: far over any line a
/// protocol writes for itself, far under what would hurt to hold.
pub const MAX_LINE: usize = 64 * 1024;

/// Append to `into` up to and including the next `delimiter`, or to the
/// connection's end, and answer how many bytes were appended: zero where the
/// connection had ended already. `into` never grows past `ceiling`.
///
/// # Errors
///
/// Where the connection could not be read, or `into` would pass `ceiling`
/// before a `delimiter` arrived — a peer misbehaving, and saying so again
/// next time.
pub fn until(
    reader: &mut impl BufRead,
    delimiter: u8,
    ceiling: usize,
    into: &mut Vec<u8>,
) -> Result<usize, NetError> {
    let start = into.len();
    loop {
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(failed) if failed.kind() == ErrorKind::Interrupted => continue,
            Err(failed) => return Err(NetError::from_io("reading off a connection", &failed)),
        };
        if available.is_empty() {
            return Ok(into.len() - start);
        }
        let (take, found) = match available.iter().position(|byte| *byte == delimiter) {
            Some(at) => (at + 1, true),
            None => (available.len(), false),
        };
        if into.len() + take > ceiling {
            return Err(over(ceiling));
        }
        into.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found {
            return Ok(into.len() - start);
        }
    }
}

/// The next line, its one line ending — CRLF or LF — taken off; `None`
/// where the connection ended before it began. A last line without a line
/// ending is a line.
///
/// # Errors
///
/// Where the connection could not be read, the line ran past
/// [`MAX_LINE`], or it is not UTF-8.
pub fn line(reader: &mut impl BufRead) -> Result<Option<String>, NetError> {
    let mut raw = Vec::new();
    if until(reader, b'\n', MAX_LINE, &mut raw)? == 0 {
        return Ok(None);
    }
    let length = trim_eol(&raw).len();
    raw.truncate(length);
    String::from_utf8(raw)
        .map(Some)
        .map_err(|_| NetError::new("a line that is not UTF-8"))
}

/// Everything up to the connection's end, which must come within
/// `ceiling` bytes.
///
/// # Errors
///
/// Where the connection could not be read, or sent more than `ceiling`
/// before it ended.
pub fn to_end(reader: &mut impl Read, ceiling: usize) -> Result<Vec<u8>, NetError> {
    let limit = u64::try_from(ceiling).unwrap_or(u64::MAX).saturating_add(1);
    let mut bytes = Vec::new();
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|failed| NetError::from_io("reading a connection to its end", &failed))?;
    if bytes.len() > ceiling {
        return Err(over(ceiling));
    }
    Ok(bytes)
}

/// The refusal of a peer that sent more than `ceiling` before the end read
/// to.
fn over(ceiling: usize) -> NetError {
    NetError::new(format!(
        "more than {ceiling} bytes arrived before the end Xmip reads to"
    ))
}

/// `raw` without exactly one trailing line ending, CRLF or LF.
fn trim_eol(raw: &[u8]) -> &[u8] {
    let mut end = raw.len();

    if end > 0 && raw[end - 1] == b'\n' {
        end -= 1;
    }

    if end > 0 && raw[end - 1] == b'\r' {
        end -= 1;
    }

    &raw[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_line_ending_comes_off_and_only_one() {
        assert_eq!(trim_eol(b"line\r\n"), b"line");
        assert_eq!(trim_eol(b"line\n"), b"line");
        assert_eq!(trim_eol(b"line"), b"line");
        assert_eq!(trim_eol(b"line\n\n"), b"line\n");
    }

    #[test]
    fn lines_read_until_the_connection_ends() {
        let mut reader = &b"one\r\ntwo\nthree"[..];
        assert_eq!(line(&mut reader).expect("one").as_deref(), Some("one"));
        assert_eq!(line(&mut reader).expect("two").as_deref(), Some("two"));
        assert_eq!(line(&mut reader).expect("three").as_deref(), Some("three"));
        assert_eq!(line(&mut reader).expect("ended"), None);
    }

    #[test]
    fn a_line_that_never_ends_is_refused_at_the_ceiling() {
        let flood = vec![b'a'; MAX_LINE + 1];
        let failure = line(&mut flood.as_slice()).expect_err("a peer misbehaving");
        assert!(
            failure.io.is_none(),
            "the peer's failure, not the connection's"
        );
        let fits = [vec![b'a'; MAX_LINE - 1], b"\n".to_vec()].concat();
        assert_eq!(
            line(&mut fits.as_slice()).expect("fits").map(|l| l.len()),
            Some(MAX_LINE - 1)
        );
    }

    #[test]
    fn a_line_that_is_not_utf8_is_refused_not_repaired() {
        assert!(line(&mut &b"caf\xe9\r\n"[..]).is_err());
    }

    #[test]
    fn until_appends_up_to_its_delimiter_and_no_further() {
        let mut reader = &b"body\0next"[..];
        let mut into = b"so far ".to_vec();
        assert_eq!(until(&mut reader, 0, 64, &mut into).expect("read"), 5);
        assert_eq!(into, b"so far body\0");
        assert_eq!(reader, b"next");
        let mut small = Vec::new();
        assert!(until(&mut &b"0123456789"[..], 0, 4, &mut small).is_err());
        assert!(small.is_empty(), "nothing past the ceiling was taken");
    }

    #[test]
    fn to_end_reads_the_whole_connection_up_to_its_ceiling() {
        assert_eq!(to_end(&mut &b"whole"[..], 5).expect("fits"), b"whole");
        let failure = to_end(&mut &b"whole!"[..], 5).expect_err("one over");
        assert!(failure.io.is_none());
    }
}

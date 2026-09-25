//! The connection preface of RFC 9113 section 3.4, and telling a
//! connection that opens with it — HTTP/2 by prior knowledge — from one
//! that opens with an HTTP/1.1 request line, without losing what was read
//! to tell.

use std::io::{ErrorKind, Read, Write};

use crate::NetError;

/// What a client sends first: `PRI * HTTP/2.0`, a blank line, `SM`, a
/// blank line. An HTTP/1.1 server reads it as a request it cannot serve.
pub const PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Read from `reader` until what it sent either is the preface or cannot
/// be: whether it is, and the octets read, which the connection must be
/// read with again ([`Replayed`]). An HTTP/1.1 request parts from the
/// preface at its first octet, unless its method is `PRI`.
///
/// # Errors
///
/// Where the connection broke, or closed before sending anything.
pub fn sniff(reader: &mut impl Read) -> Result<(bool, Vec<u8>), NetError> {
    let mut read = Vec::with_capacity(PREFACE.len());
    let mut buffer = [0u8; PREFACE.len()];
    while read.len() < PREFACE.len() && PREFACE.starts_with(&read) {
        let want = PREFACE.len() - read.len();
        match reader.read(&mut buffer[..want]) {
            Ok(0) if read.is_empty() => {
                return Err(NetError::new(
                    "the connection closed before sending anything",
                ));
            }
            Ok(0) => break,
            Ok(count) => read.extend_from_slice(&buffer[..count]),
            Err(failed) if failed.kind() == ErrorKind::Interrupted => {}
            Err(failed) => return Err(NetError::from_io("reading the first octets", &failed)),
        }
    }
    Ok((read.as_slice() == PREFACE, read))
}

/// A connection read again from the start: the octets [`sniff`] took
/// first, then the connection itself. Writes go straight through.
pub struct Replayed<S> {
    first: Vec<u8>,
    at: usize,
    inner: S,
}

impl<S> Replayed<S> {
    /// `inner`, with `first` put back in front of it.
    #[must_use]
    pub const fn new(first: Vec<u8>, inner: S) -> Self {
        Self {
            first,
            at: 0,
            inner,
        }
    }
}

impl<S: Read> Read for Replayed<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.at < self.first.len() {
            let count = buf.len().min(self.first.len() - self.at);
            buf[..count].copy_from_slice(&self.first[self.at..self.at + count]);
            self.at += count;
            return Ok(count);
        }
        self.inner.read(buf)
    }
}

impl<S: Write> Write for Replayed<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_preface_is_told_from_a_request_line_and_both_are_read_again() {
        let mut wire = PREFACE.to_vec();
        wire.extend_from_slice(b"\0\0\0\x04");
        let mut reader = &wire[..];
        let (h2, first) = sniff(&mut reader).expect("sniffed");
        assert!(h2);
        let mut again = Vec::new();
        Replayed::new(first, reader)
            .read_to_end(&mut again)
            .expect("read");
        assert_eq!(again, wire);

        let request = b"GET / HTTP/1.1\r\n\r\n";
        let mut reader = &request[..];
        let (h2, first) = sniff(&mut reader).expect("sniffed");
        assert!(!h2);
        assert!(!first.is_empty() && request.starts_with(&first));
        let mut again = Vec::new();
        Replayed::new(first, reader)
            .read_to_end(&mut again)
            .expect("read");
        assert_eq!(again, request);

        let (h2, first) = sniff(&mut &b"PRI * HTTP/1.1"[..]).expect("sniffed");
        assert!(!h2);
        assert_eq!(first, b"PRI * HTTP/1.1");
        assert!(sniff(&mut &b""[..]).is_err());
    }
}

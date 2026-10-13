//! A connection read until its side ends or its peer falls silent, written
//! once for every long-lived link in the estate — the cluster's Event links
//! and the operate plane's connections.
//!
//! The socket under it carries a short read timeout; a read that waited
//! that long with nothing come is tried again, and nothing read is lost by
//! it. Between tries it looks whether its side is ending, so a stop reaches
//! a connection blocked reading within one timeout: shutting a socket from
//! another thread does not wake a blocked read on every platform. Writes
//! pass straight through.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

/// `reading`, read until `ending` says its side ends or, where `silence`
/// is given, the peer says nothing for that long.
pub struct Watched<R, E> {
    /// The connection, its socket's read timeout set short.
    pub reading: R,
    /// Whether its side is ending.
    pub ending: E,
    /// How long the peer may say nothing, where it must beat.
    pub silence: Option<Duration>,
    /// When the peer last said something.
    pub heard: Instant,
}

impl<R, E> Watched<R, E> {
    /// `reading`, watched for `ending`, the peer never taken for silent.
    pub fn new(reading: R, ending: E) -> Self {
        Self {
            reading,
            ending,
            silence: None,
            heard: Instant::now(),
        }
    }
}

impl<R: Read, E: Fn() -> bool> Read for Watched<R, E> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.reading.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    if (self.ending)() {
                        return Err(ErrorKind::ConnectionAborted.into());
                    }
                    if self
                        .silence
                        .is_some_and(|silence| self.heard.elapsed() > silence)
                    {
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "the peer fell silent",
                        ));
                    }
                }
                read => {
                    self.heard = Instant::now();
                    return read;
                }
            }
        }
    }
}

impl<R: Write, E> Write for Watched<R, E> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.reading.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.reading.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    /// A reader that times out `waits` times, then gives `bytes`.
    struct Slow {
        waits: usize,
        bytes: &'static [u8],
    }

    impl Read for Slow {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.waits > 0 {
                self.waits -= 1;
                return Err(ErrorKind::WouldBlock.into());
            }
            let count = self.bytes.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            Ok(count)
        }
    }

    #[test]
    fn a_read_that_waited_is_tried_again_and_loses_nothing() {
        let mut watched = Watched::new(
            Slow {
                waits: 3,
                bytes: b"abc",
            },
            || false,
        );
        let mut buffer = [0u8; 8];
        assert_eq!(watched.read(&mut buffer).expect("read"), 3);
        assert_eq!(&buffer[..3], b"abc");
    }

    #[test]
    fn an_ending_side_stops_waiting_and_a_silent_peer_is_said_so() {
        let looked = Cell::new(0);
        let mut ending = Watched::new(
            Slow {
                waits: 9,
                bytes: b"",
            },
            || {
                looked.set(looked.get() + 1);
                looked.get() > 2
            },
        );
        let mut buffer = [0u8; 8];
        let ended = ending.read(&mut buffer).expect_err("ended");
        assert_eq!(ended.kind(), ErrorKind::ConnectionAborted);

        let mut silent = Watched::new(
            Slow {
                waits: 9,
                bytes: b"",
            },
            || false,
        );
        silent.silence = Some(Duration::ZERO);
        silent.heard = Instant::now()
            .checked_sub(Duration::from_millis(1))
            .expect("a moment ago");
        let fell = silent.read(&mut buffer).expect_err("silent");
        assert_eq!(fell.kind(), ErrorKind::TimedOut);
    }
}

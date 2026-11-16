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
//!
//! The peer's silence is counted on the caller's clock, read through `now`
//! as `ending` is asked through its own: a Library reads no clock (ADR-0068,
//! amendments 2026-11-14 and 2026-11-15), so a caller hands in its Clock's
//! monotonic reading, and a test steps that Clock past the silence with no
//! sleep.

use std::io::{ErrorKind, Read, Write};
use std::time::Duration;

/// `reading`, read until `ending` says its side ends or, where `silence`
/// is given, the peer says nothing for that long on the clock `now` reads.
pub struct Watched<R, E, N> {
    /// The connection, its socket's read timeout set short.
    pub reading: R,
    /// Whether its side is ending.
    pub ending: E,
    /// What the time is, in nanoseconds from a moment of the caller's
    /// clock's own: `xcore::Clock::monotonic_nanos` of the Clock it was
    /// handed.
    pub now: N,
    /// How long the peer may say nothing, where it must beat.
    pub silence: Option<Duration>,
    /// When the peer last said something, as `now` read it.
    pub heard: i128,
}

impl<R, E, N: Fn() -> i128> Watched<R, E, N> {
    /// `reading`, watched for `ending` on the clock `now` reads, the peer
    /// heard now and never taken for silent.
    pub fn new(reading: R, ending: E, now: N) -> Self {
        let heard = now();
        Self {
            reading,
            ending,
            now,
            silence: None,
            heard,
        }
    }
}

impl<R: Read, E: Fn() -> bool, N: Fn() -> i128> Read for Watched<R, E, N> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.reading.read(buffer) {
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    if (self.ending)() {
                        return Err(ErrorKind::ConnectionAborted.into());
                    }
                    let now = (self.now)();
                    if self
                        .silence
                        .is_some_and(|silence| crate::passed(self.heard, now, silence))
                    {
                        return Err(std::io::Error::new(
                            ErrorKind::TimedOut,
                            "the peer fell silent",
                        ));
                    }
                }
                read => {
                    self.heard = (self.now)();
                    return read;
                }
            }
        }
    }
}

impl<R: Write, E, N> Write for Watched<R, E, N> {
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

    use xcore::Clock;
    use xcore::clock::Stepped;

    use super::*;

    /// A reader that times out `waits` times, then gives `bytes`; before
    /// each time out it lets `pass` go by on `clock`.
    struct Slow<'a> {
        waits: usize,
        bytes: &'static [u8],
        clock: &'a Stepped,
        pass: Duration,
    }

    impl Read for Slow<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.waits > 0 {
                self.waits -= 1;
                self.clock.pass(self.pass);
                return Err(ErrorKind::WouldBlock.into());
            }
            let count = self.bytes.len().min(buffer.len());
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            Ok(count)
        }
    }

    /// A reader on `clock` that times out `waits` times, each a time out
    /// of `pass`, then gives `bytes`.
    const fn slow(clock: &Stepped, waits: usize, pass: Duration) -> Slow<'_> {
        Slow {
            waits,
            bytes: b"abc",
            clock,
            pass,
        }
    }

    #[test]
    fn a_read_that_waited_is_tried_again_and_loses_nothing() {
        let clock = Stepped::default();
        let mut watched = Watched::new(
            slow(&clock, 3, Duration::ZERO),
            || false,
            || clock.monotonic_nanos(),
        );
        let mut buffer = [0u8; 8];
        assert_eq!(watched.read(&mut buffer).expect("read"), 3);
        assert_eq!(&buffer[..3], b"abc");
    }

    #[test]
    fn an_ending_side_stops_waiting() {
        let clock = Stepped::default();
        let looked = Cell::new(0);
        let ending = || {
            looked.set(looked.get() + 1);
            looked.get() > 2
        };
        let mut watched = Watched::new(slow(&clock, 9, Duration::ZERO), ending, || {
            clock.monotonic_nanos()
        });
        let mut buffer = [0u8; 8];
        let ended = watched.read(&mut buffer).expect_err("ended");
        assert_eq!(ended.kind(), ErrorKind::ConnectionAborted);
        assert_eq!(looked.get(), 3);
    }

    #[test]
    fn a_peer_silent_for_its_silence_is_said_so_and_one_heard_within_it_is_read() {
        let clock = Stepped::default();
        let silence = Duration::from_secs(30);
        let beat = Duration::from_secs(10);

        // Silent through two waits, heard at the third: within its silence.
        let mut heard = Watched::new(slow(&clock, 2, beat), || false, || clock.monotonic_nanos());
        heard.silence = Some(silence);
        let mut buffer = [0u8; 8];
        assert_eq!(heard.read(&mut buffer).expect("heard within"), 3);
        assert_eq!(heard.heard, clock.monotonic_nanos(), "heard as it read");

        // Silent through three waits: its thirty seconds passed at the third.
        let mut silent = Watched::new(slow(&clock, 9, beat), || false, || clock.monotonic_nanos());
        silent.silence = Some(silence);
        let began = clock.monotonic_nanos();
        let fell = silent.read(&mut buffer).expect_err("silent");
        assert_eq!(fell.kind(), ErrorKind::TimedOut);
        assert_eq!(
            clock.monotonic_nanos() - began,
            30_000_000_000,
            "said silent the moment its silence passed, not a wait later"
        );
    }
}

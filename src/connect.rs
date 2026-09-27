//! A TCP connection to a peer, the one way the estate opens one: every
//! address the peer's name resolves to is tried in turn, inside one
//! deadline, and the connection that answers comes back with the same
//! bound on its reads and writes, and with Nagle's algorithm off: a
//! message written as a head and then a body goes at once, rather than
//! the body waiting for the peer's delayed acknowledgement of the head —
//! forty milliseconds a message on Linux, on a connection kept open.
//!
//! One copy. Until 2026-09-27 the transport capability connected to the
//! first address a name resolved to and no other, so a host whose IPv6
//! address came first and did not answer was unreachable over IPv4 too;
//! the HTTP client tried every address, each with the whole timeout; and
//! the LDAP technology wrote the loop a third time.

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::NetError;

/// A connection to the first of the addresses `target` resolves to that
/// accepts one, all of them tried within `timeout` together, with
/// `timeout` on the connection's reads and writes. `None` waits as long as
/// the operating system does, on each address in turn.
///
/// `target` is anything that resolves: `host:port`, a socket address, or
/// the addresses a caller resolved itself.
///
/// # Errors
///
/// Where the target does not resolve, resolves to nothing, no address
/// accepted within the time, or the timeouts cannot be set. A refusal or a
/// timeout keeps its kind, which a caller that retries decides by.
pub fn connect(
    target: impl ToSocketAddrs,
    timeout: Option<Duration>,
) -> Result<TcpStream, NetError> {
    let addresses: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|failed| NetError::from_io("resolving the peer", &failed))?
        .collect();
    let deadline = timeout.map(|within| Instant::now() + within);
    let mut last = None;
    for address in &addresses {
        let attempt = match deadline {
            // bounded: the None arm: unbounded only when the caller asks for it
            None => TcpStream::connect(address),
            Some(deadline) => match deadline.checked_duration_since(Instant::now()) {
                Some(left) if !left.is_zero() => TcpStream::connect_timeout(address, left),
                _ => break,
            },
        };
        match attempt {
            Ok(stream) => {
                stream
                    .set_read_timeout(timeout)
                    .and_then(|()| stream.set_write_timeout(timeout))
                    .and_then(|()| stream.set_nodelay(true))
                    .map_err(|failed| NetError::from_io("setting the timeouts", &failed))?;
                return Ok(stream);
            }
            Err(failed) => last = Some(failed),
        }
    }
    Err(match (last, addresses.is_empty()) {
        (_, true) => NetError::new("the peer's name resolves to no address"),
        (Some(failed), false) => NetError::from_io("connecting to the peer", &failed),
        (None, false) => NetError::from_io(
            "connecting to the peer",
            &std::io::Error::from(std::io::ErrorKind::TimedOut),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn every_address_is_tried_and_the_one_that_answers_is_connected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let open = listener.local_addr().expect("address");
        let closed = TcpListener::bind("127.0.0.1:0").expect("bind");
        let refusing = closed.local_addr().expect("address");
        drop(closed);
        // Windows answers a refused loopback connect after its own retries,
        // about two seconds; the bound is generous for that.

        let stream = connect(&[refusing, open][..], Some(Duration::from_secs(10))).expect("second");

        assert_eq!(stream.peer_addr().expect("peer"), open);
        assert_eq!(
            stream.read_timeout().expect("read"),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            stream.write_timeout().expect("write"),
            Some(Duration::from_secs(10))
        );
        assert!(stream.nodelay().expect("nodelay"), "Nagle's algorithm off");
    }

    #[test]
    fn a_target_nobody_answers_is_refused_with_its_kind_and_an_empty_one_without() {
        let empty: &[SocketAddr] = &[];
        let nothing = connect(empty, Some(Duration::from_millis(50))).expect_err("empty");
        assert!(nothing.io.is_none(), "{nothing}");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        drop(listener);
        let refused = connect(address, Some(Duration::from_millis(500))).expect_err("refused");
        assert!(refused.io.is_some(), "{refused}");
        let unbounded = connect(address.to_string(), None).expect_err("refused");
        assert!(unbounded.io.is_some(), "{unbounded}");
    }
}

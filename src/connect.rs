//! A TCP connection to a peer, the one way the estate opens one: every
//! address the peer's name resolves to is tried in turn, inside one
//! deadline, and the connection that answers comes back with the same
//! bound on its reads and writes, and with Nagle's algorithm off: a
//! message written as a head and then a body goes at once, rather than
//! the body waiting for the peer's delayed acknowledgement of the head —
//! forty milliseconds a message on Linux, on a connection kept open.
//!
//! **A refusal is answered at once; only a SYN nobody answers is sent
//! again** ([`Retransmission`]). Linux does both itself. Windows asks a
//! peer that refused again, half a second at a time, as often as it would
//! send a lost SYN again — two seconds a stopped peer by default — so until
//! 2026-11-14 a node took two seconds per stopped Storage node to learn it
//! was down. There the system sends each SYN once and the connect sends
//! the next itself, after each wait of the node's `[tuning]`
//! (`crate::system::connect`).
//!
//! One copy. Until 2026-09-27 the transport capability connected to the
//! first address a name resolved to and no other, so a host whose IPv6
//! address came first and did not answer was unreachable over IPv4 too;
//! the HTTP client tried every address, each with the whole timeout; and
//! the LDAP technology wrote the loop a third time.

use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::NetError;

/// How a connect sends its SYN again where the peer does not answer it:
/// after `first`, then after twice the wait before each time, at most
/// `times` times, all inside the connect's own deadline. A refusal, or a
/// host the network says is unreachable, is never asked again: a caller
/// that retries decides by its kind.
///
/// A hardware assumption, the network's: one per process, the node's
/// `[tuning]` (`connect_retransmit`, `connect_retransmissions`), lent as
/// the node starts ([`retransmit_by`]), [`RETRANSMISSION`] until then.
/// Windows follows it. Linux answers a refusal at once and sends a SYN
/// nobody answered again itself until the deadline, by its own schedule,
/// which stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retransmission {
    /// How long a connect waits for the peer's answer before it sends its
    /// SYN again: the initial retransmission timeout. Windows takes at
    /// most 65,534 ms.
    pub first: Duration,
    /// How many times a SYN nobody answered is sent again.
    pub times: u8,
}

/// A second, RFC 6298's initial retransmission timeout and Windows' own,
/// and once: a SYN lost on its way is sent again, and a peer that answers
/// neither is given up three seconds on.
pub const RETRANSMISSION: Retransmission = Retransmission {
    first: Duration::from_secs(1),
    times: 1,
};

impl Retransmission {
    /// Each wait for the peer's answer, the first SYN's and then each one
    /// sent again: `first`, twice it, four times it, `times + 1` of them.
    pub fn waits(self) -> impl Iterator<Item = Duration> {
        (0..=u32::from(self.times))
            .map(move |sent| self.first.saturating_mul(2u32.saturating_pow(sent)))
    }
}

/// What every connect of this process retransmits by.
static RETRANSMITTING: RwLock<Retransmission> = RwLock::new(RETRANSMISSION);

/// Every connect this process makes from now on retransmits by
/// `retransmission`: the node's `[tuning]`, which the runtime lends the
/// process as it starts the node, as it lends its Parties.
pub fn retransmit_by(retransmission: Retransmission) {
    *RETRANSMITTING
        .write()
        .unwrap_or_else(PoisonError::into_inner) = retransmission;
}

/// What every connect this process makes retransmits by.
#[must_use]
pub fn retransmission() -> Retransmission {
    *RETRANSMITTING
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// A connection to the first of the addresses `target` resolves to that
/// accepts one, all of them tried within `timeout` together, with
/// `timeout` on the connection's reads and writes. `None` waits as long as
/// the operating system does, on each address in turn: on Windows, as long
/// as the process's [`retransmission`] does.
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
    connect_by(target, timeout, retransmission())
}

/// [`connect`], retransmitting by `retransmission`.
fn connect_by(
    target: impl ToSocketAddrs,
    timeout: Option<Duration>,
    retransmission: Retransmission,
) -> Result<TcpStream, NetError> {
    let addresses: Vec<SocketAddr> = target
        .to_socket_addrs()
        .map_err(|failed| NetError::from_io("resolving the peer", &failed))?
        .collect();
    let deadline = timeout.map(|within| Instant::now() + within);
    let mut last = None;
    for address in &addresses {
        let Some(attempt) = attempt(address, deadline, retransmission) else {
            break;
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
            &io::Error::from(io::ErrorKind::TimedOut),
        ),
    })
}

/// What is left of `deadline`; `None` once it has passed.
fn left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// `address` tried, the system sending its SYN again itself: `None` where
/// the deadline passed before it was.
#[cfg(not(windows))]
fn attempt(
    address: &SocketAddr,
    deadline: Option<Instant>,
    _retransmission: Retransmission,
) -> Option<io::Result<TcpStream>> {
    match deadline {
        // bounded: the None arm: unbounded only when the caller asks for it
        None => Some(TcpStream::connect(address)),
        Some(deadline) => left(deadline).map(|left| TcpStream::connect_timeout(address, left)),
    }
}

/// `address` tried, a SYN sent again after each wait nobody answered while
/// the deadline has not passed, each one a socket of its own, given up at
/// the deadline: `None` where the deadline passed before the first.
#[cfg(windows)]
fn attempt(
    address: &SocketAddr,
    deadline: Option<Instant>,
    retransmission: Retransmission,
) -> Option<io::Result<TcpStream>> {
    let mut tried = None;
    for wait in retransmission.waits() {
        let within = match deadline {
            None => None,
            Some(deadline) => match left(deadline) {
                Some(left) => Some(left),
                None => break,
            },
        };
        let attempt = crate::system::connect::attempt(address, wait, within);
        let unanswered =
            matches!(&attempt, Err(failed) if failed.kind() == io::ErrorKind::TimedOut);
        tried = Some(attempt);
        if !unanswered {
            break;
        }
    }
    tried
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn every_address_is_tried_and_the_one_that_answers_is_connected() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let open = listener.local_addr().expect("address");
        let refusing = crate::fixture::unheld();

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

        let address = crate::fixture::unheld();
        let refused = connect(address, Some(Duration::from_millis(500))).expect_err("refused");
        assert_eq!(
            refused.io,
            Some(io::ErrorKind::ConnectionRefused),
            "{refused}"
        );
        let unbounded = connect(address.to_string(), None).expect_err("refused");
        assert_eq!(
            unbounded.io,
            Some(io::ErrorKind::ConnectionRefused),
            "{unbounded}"
        );
    }

    #[test]
    fn a_refusal_ends_the_connect_with_its_kind_however_often_a_lost_syn_would_go() {
        // Refused, never timed out: how soon is the timing program's
        // (`tests/measured`).
        let address = crate::fixture::unheld();
        let patient = Retransmission {
            first: Duration::from_secs(1),
            times: 8,
        };
        let refused =
            connect_by(address, Some(Duration::from_secs(30)), patient).expect_err("refused");
        assert_eq!(
            refused.io,
            Some(io::ErrorKind::ConnectionRefused),
            "{refused}"
        );
    }

    #[test]
    fn each_wait_is_twice_the_one_before_one_more_than_the_times_sent_again() {
        let waits: Vec<_> = RETRANSMISSION.waits().collect();
        assert_eq!(waits, [Duration::from_secs(1), Duration::from_secs(2)]);
        let once = Retransmission {
            first: Duration::from_millis(250),
            times: 0,
        };
        assert_eq!(
            once.waits().collect::<Vec<_>>(),
            [Duration::from_millis(250)]
        );
        let most = Retransmission {
            first: Duration::from_millis(100),
            times: u8::MAX,
        };
        assert_eq!(most.waits().count(), 256);
        assert_eq!(
            most.waits().last(),
            Some(Duration::from_millis(100).saturating_mul(u32::MAX)),
            "saturates"
        );
    }

    #[test]
    fn the_process_retransmits_by_what_it_was_lent() {
        assert_eq!(retransmission().first, RETRANSMISSION.first);
        let lent = Retransmission {
            first: Duration::from_millis(1500),
            times: 1,
        };
        retransmit_by(lent);
        assert_eq!(retransmission(), lent);
        retransmit_by(RETRANSMISSION);
        assert_eq!(retransmission(), RETRANSMISSION);
    }
}

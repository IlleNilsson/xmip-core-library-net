//! A thread waiting in a listener's accept, stopped: woken by a
//! connection of its own and joined, the one way the estate does it. A
//! stop asks again until the thread has heard: a wake connection given up
//! before it was accepted — on a loaded machine, or with the machine's
//! ports in use — is no connection at all, and one wake lost left a
//! listener's accept waiting for good and its stop with it (the runtime's
//! operate listener held a landing's tests 41 minutes, 2026-10-20). Until
//! then each listener knocked once, and wrote its own loopback address.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// An address a connection reaches a listener at: loopback where it
/// listens on every address.
#[must_use]
pub fn wakeable(address: SocketAddr) -> SocketAddr {
    match address.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => (Ipv4Addr::LOCALHOST, address.port()).into(),
        IpAddr::V6(ip) if ip.is_unspecified() => (Ipv6Addr::LOCALHOST, address.port()).into(),
        _ => address,
    }
}

/// A connection to the listener at `address` made within `patience`:
/// whether it was, and so whether its accept was woken.
#[must_use]
pub fn knock(address: SocketAddr, patience: Duration) -> bool {
    crate::connect(wakeable(address), Some(patience)).is_ok()
}

/// `accepting` joined once it has heard `knock` — asked again for as long
/// as it has not ended, each knock that connected given `patience` to be
/// heard — and what it returned.
///
/// # Errors
///
/// Where the thread panicked, as [`JoinHandle::join`].
pub fn woken<T>(
    accepting: JoinHandle<T>,
    patience: Duration,
    mut knock: impl FnMut() -> bool,
) -> thread::Result<T> {
    while !accepting.is_finished() {
        let heard = if knock() { patience } else { Duration::ZERO };
        let until = Instant::now() + heard;
        // A connected knock ends the accept at once; one lost is asked
        // again after a moment, never in a loop that holds a processor.
        loop {
            thread::sleep(Duration::from_micros(200));
            if accepting.is_finished() || Instant::now() >= until {
                break;
            }
        }
    }
    accepting.join()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    #[test]
    fn a_wake_lost_is_asked_again_until_the_accept_has_heard() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
        let address = listener.local_addr().expect("an address");
        let stopping = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stopping);
        let accepting = thread::spawn(move || {
            loop {
                let accepted = listener.accept();
                if stopped.load(Ordering::SeqCst) {
                    return accepted.is_ok();
                }
            }
        });
        stopping.store(true, Ordering::SeqCst);
        // The first two knocks lost, as a connection given up before it
        // was accepted is; the third connects.
        let knocks = AtomicU32::new(0);
        let woke = woken(accepting, Duration::from_secs(1), || {
            knocks.fetch_add(1, Ordering::SeqCst) >= 2 && knock(address, Duration::from_secs(1))
        })
        .expect("joined");
        assert!(woke, "woken by a connection");
        assert!(knocks.load(Ordering::SeqCst) >= 3, "asked again");
    }

    #[test]
    fn every_address_is_reached_at_loopback() {
        let any: SocketAddr = "0.0.0.0:7".parse().expect("an address");
        assert_eq!(wakeable(any), "127.0.0.1:7".parse().expect("loopback"));
        let any: SocketAddr = "[::]:7".parse().expect("an address");
        assert_eq!(wakeable(any), "[::1]:7".parse().expect("loopback"));
        let one: SocketAddr = "10.0.0.1:7".parse().expect("an address");
        assert_eq!(wakeable(one), one);
    }
}

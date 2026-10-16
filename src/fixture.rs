//! A loopback address no one holds, for a test that starts something later
//! to bind it, or that wants nothing listening there: the estate's one,
//! for every test that needs one (`test-support`).
//!
//! Below every operating system's ephemeral range (Linux from 32768,
//! Windows and macOS from 49152). A port the kernel chose for `:0` and a
//! test released was taken by another test's connection before the service
//! bound it, on the CI's macOS machine (2026-10-15), and by another test's
//! node in the runtime's own tests, which then took each other's
//! deliveries (2026-10-16). The kernel never hands these out by itself,
//! each test process has a block of its own, and each call takes the next
//! port of it that binds, so no two calls in one process share one. Until
//! 2026-10-16 the service tests held this, and five other tests bound `:0`
//! and let it go.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::atomic::{AtomicU16, Ordering};

/// The first port of the first block.
const FIRST: u16 = 20_000;

/// How many ports each test process has.
const BLOCK: u16 = 100;

/// How many blocks there are: they end at 32,000, below Linux's range.
const BLOCKS: u32 = 120;

/// The next port of this process's block, counted from its first.
static NEXT: AtomicU16 = AtomicU16::new(0);

/// An address on `127.0.0.1` no one holds.
///
/// # Panics
///
/// Where every port of this process's block is held.
#[must_use]
pub fn unheld() -> SocketAddr {
    unheld_on(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// An address on `ip`, a loopback address, no one holds.
///
/// # Panics
///
/// Where every port of this process's block is held.
#[must_use]
pub fn unheld_on(ip: IpAddr) -> SocketAddr {
    let block = u16::try_from(std::process::id() % BLOCKS).expect("under BLOCKS");
    let first = FIRST + block * BLOCK;
    (0..BLOCK)
        .map(|_| first + NEXT.fetch_add(1, Ordering::Relaxed) % BLOCK)
        .find_map(|port| TcpListener::bind((ip, port)).ok())
        .expect("a port of this process's block no one holds")
        .local_addr()
        .expect("its address")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_two_calls_share_a_port_and_none_is_ephemeral() {
        let one = unheld();
        let two = unheld();
        assert_ne!(one, two);
        assert!(one.ip().is_loopback());
        assert!(one.port() >= FIRST && one.port() < 32_768, "{one}");
        TcpListener::bind(one).expect("free to bind");
    }
}

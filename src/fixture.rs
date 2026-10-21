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
//!
//! A block is held, not only chosen. Its first port is listened on for as
//! long as the process runs, and a process whose block another holds takes
//! the next block free. Until 2026-10-21 a block was the process id's
//! alone, so two test programs run at once shared one whenever their ids
//! met in it, each counting from the block's first port: a port one had
//! found free, the other found free too, and bound first (the runtime's
//! plane test, 2026-10-20).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU16, Ordering};

/// The first port of the first block.
const FIRST: u16 = 20_000;

/// How many ports each test process has, its first holding the block.
const BLOCK: u16 = 100;

/// How many blocks there are: they end at 32,000, below Linux's range.
const BLOCKS: u32 = 120;

/// The next port of this process's block, counted from its second.
static NEXT: AtomicU16 = AtomicU16::new(0);

/// The block this process holds: its first port, and the listener on it
/// that holds the block until the process ends.
static HELD: OnceLock<(u16, TcpListener)> = OnceLock::new();

/// An address on `127.0.0.1` no one holds.
///
/// # Panics
///
/// Where every port of this process's block is held, or every block is.
#[must_use]
pub fn unheld() -> SocketAddr {
    unheld_on(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// An address on `ip`, a loopback address, no one holds.
///
/// # Panics
///
/// Where every port of this process's block is held, or every block is.
#[must_use]
pub fn unheld_on(ip: IpAddr) -> SocketAddr {
    let first = block();
    (1..BLOCK)
        .map(|_| first + 1 + NEXT.fetch_add(1, Ordering::Relaxed) % (BLOCK - 1))
        .find_map(|port| TcpListener::bind((ip, port)).ok())
        .expect("a port of this process's block no one holds")
        .local_addr()
        .expect("its address")
}

/// The first port of the block this process holds: the process id's, or
/// the next after it that no other process holds.
fn block() -> u16 {
    HELD.get_or_init(|| {
        let own = std::process::id() % BLOCKS;
        (0..BLOCKS)
            .map(|step| {
                let block = u16::try_from((own + step) % BLOCKS).expect("under BLOCKS");
                FIRST + block * BLOCK
            })
            .find_map(|first| {
                TcpListener::bind((Ipv4Addr::LOCALHOST, first))
                    .ok()
                    .map(|holding| (first, holding))
            })
            .expect("a block no other process holds")
    })
    .0
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

    #[test]
    fn the_block_is_held_while_the_process_runs() {
        let address = unheld();
        let first = block();
        assert!(
            address.port() > first && address.port() < first + BLOCK,
            "{address}"
        );
        assert!(
            TcpListener::bind((Ipv4Addr::LOCALHOST, first)).is_err(),
            "another process finds the block held"
        );
    }
}

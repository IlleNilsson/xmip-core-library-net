//! The IEEE 802.15.4 interface's calls into Linux (`crate::ieee802154`): an
//! `AF_IEEE802154` datagram socket made, the interface asked where it is on
//! the air (`SIOCGIFADDR`), the socket bound there, a payload sent to a
//! short address on the interface's PAN, and the next one read with the
//! short address that sent it, waited for by `poll`.
//!
//! No crate the estate depends on lays out an 802.15.4 socket address:
//! `nix`, `rustix` and `socket2` each make one only through an unsafe
//! constructor. So it is laid out here, as the kernel's
//! `include/net/af_ieee802154.h` lays out `struct sockaddr_ieee802154`, its
//! size held at compile time, and the interface's answer is read from its
//! bytes. A frame from an extended address, which no Location here names,
//! is passed over as nothing heard.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::ieee802154::Address;

/// `IEEE802154_ADDR_SHORT`: a short address on a PAN.
const SHORT: libc::c_int = 2;

/// `AF_IEEE802154`, as a socket address's family field holds it.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the family is 36"
)]
const FAMILY: libc::sa_family_t = libc::AF_IEEE802154 as libc::sa_family_t;

/// `struct sockaddr_ieee802154`: the family, the two bytes the alignment of
/// `struct ieee802154_addr_sa` leaves, then that structure — the mode, the
/// PAN and a union of an extended and a short address — and two bytes of
/// padding at its end; every number in the host's order.
#[repr(C)]
#[derive(Clone, Copy)]
struct SocketAddress {
    family: libc::sa_family_t,
    mode: libc::c_int,
    pan: u16,
    /// The union: a short address in its first two bytes.
    address: [u8; 8],
}

const _: () = assert!(size_of::<SocketAddress>() == 20);

/// The length every call is handed: the whole structure.
#[allow(clippy::cast_possible_truncation, reason = "twenty bytes")]
const LENGTH: libc::socklen_t = size_of::<SocketAddress>() as libc::socklen_t;

impl SocketAddress {
    /// The short address `at`.
    fn of(at: Address) -> Self {
        let mut address = [0; 8];
        address[..2].copy_from_slice(&at.short.to_ne_bytes());
        Self {
            family: FAMILY,
            mode: SHORT,
            pan: at.pan,
            address,
        }
    }

    /// The short address it names; `None` for an extended one.
    fn short(&self) -> Option<u16> {
        (self.family == FAMILY && self.mode == SHORT)
            .then(|| u16::from_ne_bytes([self.address[0], self.address[1]]))
    }
}

/// `struct ifreq`: the interface's name, then the union an answer is
/// written in, as large and as aligned as the C library's.
#[repr(C, align(8))]
struct InterfaceRequest {
    name: [u8; libc::IFNAMSIZ],
    answer: [u8; size_of::<libc::ifreq>() - libc::IFNAMSIZ],
}

const _: () = assert!(size_of::<InterfaceRequest>() == size_of::<libc::ifreq>());
const _: () = assert!(align_of::<InterfaceRequest>() >= align_of::<libc::ifreq>());

/// `SIOCGIFADDR`, as `ioctl` takes a request on this C library.
#[allow(clippy::cast_possible_truncation, reason = "0x8915")]
#[allow(clippy::unnecessary_cast, reason = "a request is a c_int on musl")]
const SIOCGIFADDR: libc::Ioctl = libc::SIOCGIFADDR as libc::Ioctl;

/// A datagram socket bound to where `interface` is on the air, and that.
///
/// # Errors
/// A name no interface could have (`InvalidInput`), then the kernel's:
/// `EAFNOSUPPORT` where it carries no 802.15.4 sockets, `ENODEV` where no
/// interface has the name, `ENOTTY` where it is not an 802.15.4 one, and
/// `EADDRNOTAVAIL` where it has no PAN or short address yet.
pub(crate) fn opened(interface: &str) -> io::Result<(OwnedFd, Address)> {
    let name = interface.as_bytes();
    if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    // SAFETY: socket(2) is handed no pointer.
    let raw = unsafe {
        libc::socket(
            libc::AF_IEEE802154,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` was just made, is open and is owned by nothing else;
    // the `OwnedFd` closes it once, as it drops.
    let socket = unsafe { OwnedFd::from_raw_fd(raw) };
    let mut request = InterfaceRequest {
        name: [0; libc::IFNAMSIZ],
        answer: [0; size_of::<libc::ifreq>() - libc::IFNAMSIZ],
    };
    request.name[..name.len()].copy_from_slice(name);
    // SAFETY: SIOCGIFADDR reads one `struct ifreq` and writes it back;
    // `request` is one, as large and as aligned, its name ending in a zero,
    // writable, and outliving the call, which keeps no pointer to it.
    let asked = unsafe { libc::ioctl(socket.as_raw_fd(), SIOCGIFADDR, &raw mut request) };
    if asked < 0 {
        return Err(io::Error::last_os_error());
    }
    let address = answered(&request.answer)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EADDRNOTAVAIL))?;
    let bound = SocketAddress::of(address);
    // SAFETY: `bound` is a `sockaddr_ieee802154` of `LENGTH` bytes, read
    // during the call and outliving it.
    let result = unsafe { libc::bind(socket.as_raw_fd(), (&raw const bound).cast(), LENGTH) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((socket, address))
}

/// The short address and PAN an interface's answer to `SIOCGIFADDR` names,
/// read from its bytes as `struct sockaddr_ieee802154` lays them out; the
/// kernel writes the first twelve.
fn answered(answer: &[u8]) -> Option<Address> {
    let at = |range: std::ops::Range<usize>| answer.get(range);
    let family = u16::from_ne_bytes(at(0..2)?.try_into().ok()?);
    let mode = libc::c_int::from_ne_bytes(at(4..8)?.try_into().ok()?);
    if family != FAMILY || mode != SHORT {
        return None;
    }
    Some(Address {
        pan: u16::from_ne_bytes(at(8..10)?.try_into().ok()?),
        short: u16::from_ne_bytes(at(10..12)?.try_into().ok()?),
    })
}

/// `payload`, one frame's, sent from `socket` to `to`.
///
/// # Errors
/// The kernel's refusal of the send.
pub(crate) fn sent(socket: &OwnedFd, to: Address, payload: &[u8]) -> io::Result<()> {
    let address = SocketAddress::of(to);
    // SAFETY: `payload` is readable for its length and `address` is a
    // `sockaddr_ieee802154` of `LENGTH` bytes; both outlive the call, which
    // keeps neither.
    let sent = unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            payload.as_ptr().cast(),
            payload.len(),
            0,
            (&raw const address).cast(),
            LENGTH,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The next frame's payload read into `buffer`, its length and the short
/// address that sent it, waiting at most `timeout` for it; `None` where none
/// came, the wait was interrupted, or the frame came from an extended
/// address. A wait of zero looks once.
///
/// # Errors
/// The kernel's refusal of the wait or the read.
pub(crate) fn received(
    socket: &OwnedFd,
    buffer: &mut [u8],
    timeout: Duration,
) -> io::Result<Option<(usize, u16)>> {
    let mut ready = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let milliseconds =
        libc::c_int::try_from(timeout.as_nanos().div_ceil(1_000_000)).unwrap_or(libc::c_int::MAX);
    // SAFETY: `ready` is one writable `pollfd`, outliving the call.
    let woken = unsafe { libc::poll(&raw mut ready, 1, milliseconds) };
    if woken < 0 {
        return quiet(io::Error::last_os_error());
    }
    if woken == 0 {
        return Ok(None);
    }
    let mut from = SocketAddress::of(Address { pan: 0, short: 0 });
    let mut length = LENGTH;
    // SAFETY: `buffer` is writable for its length and `from` for `length`
    // bytes, which the call reads and writes back; all outlive the call,
    // which keeps none of them.
    let read = unsafe {
        libc::recvfrom(
            socket.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            libc::MSG_DONTWAIT,
            (&raw mut from).cast(),
            &raw mut length,
        )
    };
    let Ok(read) = usize::try_from(read) else {
        return quiet(io::Error::last_os_error());
    };
    Ok(from.short().map(|source| (read.min(buffer.len()), source)))
}

/// A wait that ended with nothing to read: `None`; any other failure is
/// the read's.
fn quiet(error: io::Error) -> io::Result<Option<(usize, u16)>> {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted => Ok(None),
        _ => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_address_is_laid_out_as_the_kernel_reads_it() {
        let at = SocketAddress::of(Address {
            pan: 0xbeef,
            short: 0x0002,
        });
        assert_eq!(at.short(), Some(2));
        let mut answer = [0u8; 24];
        answer[..2].copy_from_slice(&FAMILY.to_ne_bytes());
        answer[4..8].copy_from_slice(&SHORT.to_ne_bytes());
        answer[8..10].copy_from_slice(&0xbeef_u16.to_ne_bytes());
        answer[10..12].copy_from_slice(&1_u16.to_ne_bytes());
        assert_eq!(
            answered(&answer),
            Some(Address {
                pan: 0xbeef,
                short: 1
            })
        );
        answer[4] = 3;
        assert_eq!(answered(&answer), None, "an extended address");
        assert_eq!(answered(&answer[..6]), None, "cut off");
    }

    /// Why the boundary is a datagram socket: a user makes one with no
    /// capability, where a raw socket, which writes the MAC header itself,
    /// asks for `CAP_NET_RAW` (the kernel's `ieee802154_create`). Held
    /// where the kernel makes 802.15.4 sockets and the test has no such
    /// capability; said and skipped elsewhere.
    #[test]
    fn a_raw_socket_asks_for_a_capability_a_datagram_socket_does_not() {
        let made = |kind: libc::c_int| {
            // SAFETY: socket(2) is handed no pointer.
            let raw = unsafe { libc::socket(libc::AF_IEEE802154, kind | libc::SOCK_CLOEXEC, 0) };
            if raw < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `raw` was just made and is owned by nothing else; the
            // `OwnedFd` closes it once, as it drops at the end of this call.
            drop(unsafe { OwnedFd::from_raw_fd(raw) });
            Ok(())
        };
        match made(libc::SOCK_DGRAM) {
            Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => {
                println!("802.15.4 sockets: SKIPPED: the kernel makes none here");
                return;
            }
            made => made.expect("a datagram socket asks for no capability"),
        }
        match made(libc::SOCK_RAW) {
            Ok(()) => println!("a raw socket: SKIPPED: this test holds CAP_NET_RAW"),
            Err(error) => assert_eq!(error.raw_os_error(), Some(libc::EPERM), "{error}"),
        }
    }
}

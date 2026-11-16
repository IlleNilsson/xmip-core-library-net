//! The TCP connect's calls into Windows (`crate::connect`), one attempt at
//! one address: a socket made for it, told to send its SYN once and wait
//! `wait` for the answer (`SIO_TCP_INITIAL_RTO`, its SYN retransmissions
//! none: the system's own ask a refusing peer again for two seconds) and to
//! end on an ICMP error that the host is unreachable, as Linux ends it
//! (`TCP_FAIL_CONNECT_ON_ICMP_ERROR`); then connected by `ConnectEx`, its
//! end waited for on an event within the caller's time
//! (`super::overlapped`).
//!
//! **`ConnectEx`, never a socket polled.** Measured on 2026-11-14 over four
//! hundred refused loopback connects each: one begun without blocking and
//! waited for with `select` or `WSAPoll` came back in 0.2 ms or, on about
//! half of them, in 10 to 13 ms, its failure reaching the socket's state
//! only then whatever the timer resolution; a blocking one in 0.2 to 1.2
//! ms, and `ConnectEx` in 0.09 to 0.42 ms, every time. A blocking connect
//! is bounded only by the system's wait for a SYN, which Windows never
//! keeps under 300 ms, so a caller's shorter time would pass; `ConnectEx`
//! is cancelled at the caller's time, to the millisecond.
#![allow(unsafe_code)]

use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::windows::io::{FromRawSocket, RawSocket};
use std::sync::{Once, OnceLock};
use std::time::Duration;

use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0, INVALID_SOCKET, IPPROTO_TCP,
    LPFN_CONNECTEX, SIO_GET_EXTENSION_FUNCTION_POINTER, SIO_TCP_INITIAL_RTO,
    SO_UPDATE_CONNECT_CONTEXT, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_IN6_0,
    SOCKET, SOCKET_ERROR, SOL_SOCKET, TCP_FAIL_CONNECT_ON_ICMP_ERROR,
    TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS, TCP_INITIAL_RTO_PARAMETERS, WSA_FLAG_NO_HANDLE_INHERIT,
    WSA_FLAG_OVERLAPPED, WSADATA, WSAGetLastError, WSAID_CONNECTEX, WSAIoctl, WSASocketW,
    WSAStartup, bind, setsockopt,
};

use super::overlapped::{Event, On, waited};

/// No SYN retransmissions, as the structure's byte holds it: `mstcpip.h`
/// writes `(USHORT) -2`, of which `MaxSynRetransmissions` keeps the low
/// byte, 254 (Go writes it `^uint8(1)`). Windows 10 1709 and later; older
/// ones read it as a count, and go on asking.
const NO_SYN_RETRANSMISSIONS: u8 = TCP_INITIAL_RTO_NO_SYN_RETRANSMISSIONS.to_le_bytes()[0];

/// An `Rtt` Windows reads as a time: 0 is its default and `0xFFFF` the
/// administrator's.
const LONGEST_RTT: u16 = 0xFFFE;

/// A connection to `address`, its SYN sent once and its answer waited for
/// `wait` — at least a millisecond and at most [`LONGEST_RTT`] of them, and
/// never under 300 ms, Windows' least — the attempt given up after
/// `within` where it is bounded. Where Windows takes neither the wait nor
/// `ConnectEx` for the socket — a layered provider that refuses them — the
/// standard library connects within the time instead: slower to say a
/// peer refused, never unbounded.
///
/// # Errors
///
/// Where no socket is made, the peer refused, the network said the host is
/// unreachable, no answer came within `wait` — the system's timeout — or
/// none within `within`.
pub(crate) fn attempt(
    address: &SocketAddr,
    wait: Duration,
    within: Option<Duration>,
) -> io::Result<TcpStream> {
    let (stream, socket) = made(address)?;
    let connect_ex = connect_ex(socket);
    let Some(connect_ex) = connect_ex.filter(|_| answered_once(socket, wait)) else {
        drop(stream);
        return TcpStream::connect_timeout(address, within.map_or(wait, |within| within.min(wait)));
    };
    ended_on_unreachable(socket);
    Name::unspecified(address).bind(socket)?;
    let name = Name::of(address);
    let event = Event::new()?;
    waited(On::Socket(socket), &event, within, None, |overlapped| {
        // SAFETY: `name` holds a socket address of its length and outlives
        // the operation, as does `overlapped`, which `waited` ends before
        // it returns; nothing is sent with the connect.
        unsafe {
            connect_ex(
                socket,
                name.pointer(),
                name.length,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                overlapped,
            )
        }
    })?;
    connected(socket)?;
    Ok(stream)
}

/// A socket for `address`'s family, owned by the stream made of it.
fn made(address: &SocketAddr) -> io::Result<(TcpStream, SOCKET)> {
    started();
    let family = if address.is_ipv4() { AF_INET } else { AF_INET6 };
    let flags = WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT;
    // SAFETY: no protocol information is passed; the socket returned is
    // owned by the stream made of it below, which closes it.
    let socket = unsafe {
        WSASocketW(
            i32::from(family),
            SOCK_STREAM,
            IPPROTO_TCP,
            std::ptr::null(),
            0,
            flags,
        )
    };
    if socket == INVALID_SOCKET {
        return Err(last());
    }
    let raw = socket as RawSocket;
    // SAFETY: `socket` was just made, is open and is owned by nothing else;
    // the stream closes it once, as it drops.
    let stream = unsafe { TcpStream::from_raw_socket(raw) };
    Ok((stream, socket))
}

/// Winsock 2.2 started for this process, once, before its first socket: a
/// target given as a socket address is never looked up, so the standard
/// library may not have started it yet. Never cleaned up, as the standard
/// library never cleans up its own before the process ends.
fn started() {
    static STARTED: Once = Once::new();
    STARTED.call_once(|| {
        let mut data = WSADATA::default();
        // SAFETY: `data` is writable and outlives the call. A failure
        // shows as the socket's own, which Windows then refuses to make.
        unsafe { WSAStartup(0x0202, &raw mut data) };
    });
}

/// `ConnectEx`, asked of `socket`'s provider once a process and kept;
/// `None` where it gives none.
fn connect_ex(socket: SOCKET) -> LPFN_CONNECTEX {
    static CONNECT_EX: OnceLock<LPFN_CONNECTEX> = OnceLock::new();
    if let Some(kept) = CONNECT_EX.get() {
        return *kept;
    }
    let identifier = WSAID_CONNECTEX;
    let mut function: LPFN_CONNECTEX = None;
    let mut returned = 0u32;
    let asked = u32::try_from(size_of_val(&identifier)).unwrap_or(u32::MAX);
    let given = u32::try_from(size_of::<LPFN_CONNECTEX>()).unwrap_or(u32::MAX);
    // SAFETY: the identifier and the function pointer are alive for the
    // call, their sizes given; no overlapped operation.
    let found = unsafe {
        WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            (&raw const identifier).cast(),
            asked,
            (&raw mut function).cast(),
            given,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if found != 0 || function.is_none() {
        return None;
    }
    *CONNECT_EX.get_or_init(|| function)
}

/// `socket`'s SYN sent once, its answer waited for `wait`: whether Windows
/// took it. A refusal, which Windows otherwise answers by asking again
/// after half a second, as often as its retransmissions allow, ends the
/// connect at once.
fn answered_once(socket: SOCKET, wait: Duration) -> bool {
    let parameters = TCP_INITIAL_RTO_PARAMETERS {
        Rtt: u16::try_from(wait.as_millis()).map_or(LONGEST_RTT, |rtt| rtt.clamp(1, LONGEST_RTT)),
        MaxSynRetransmissions: NO_SYN_RETRANSMISSIONS,
    };
    let size = u32::try_from(size_of::<TCP_INITIAL_RTO_PARAMETERS>()).unwrap_or(u32::MAX);
    let mut returned = 0u32;
    // SAFETY: `parameters` is the structure the control code reads, alive
    // for the call, its size given; no output buffer, no overlapped
    // operation and no completion routine.
    let set = unsafe {
        WSAIoctl(
            socket,
            SIO_TCP_INITIAL_RTO,
            (&raw const parameters).cast(),
            size,
            std::ptr::null_mut(),
            0,
            &raw mut returned,
            std::ptr::null_mut(),
            None,
        )
    };
    set == 0
}

/// `socket`'s connect ended by an ICMP error saying the host is unreachable,
/// as Linux ends one, where Windows otherwise waits out its retransmissions;
/// Windows 10 2004 and later. Where it is refused, the wait stands.
fn ended_on_unreachable(socket: SOCKET) {
    let on: u32 = 1;
    let size = i32::try_from(size_of::<u32>()).unwrap_or(i32::MAX);
    // SAFETY: `on` is the DWORD the option reads, alive for the call, its
    // size given.
    unsafe {
        setsockopt(
            socket,
            IPPROTO_TCP,
            TCP_FAIL_CONNECT_ON_ICMP_ERROR,
            (&raw const on).cast(),
            size,
        )
    };
}

/// `socket`, connected by `ConnectEx`, made a connected socket as every
/// other call reads one: its peer, its shutdown, its options.
fn connected(socket: SOCKET) -> io::Result<()> {
    // SAFETY: the option takes no value; `socket` is open, its stream's.
    let updated = unsafe {
        setsockopt(
            socket,
            SOL_SOCKET,
            SO_UPDATE_CONNECT_CONTEXT,
            std::ptr::null(),
            0,
        )
    };
    if updated == SOCKET_ERROR {
        Err(last())
    } else {
        Ok(())
    }
}

/// A socket address as Windows reads one, of either family, and its length.
struct Name {
    address: Address,
    length: i32,
}

/// The address itself.
#[repr(C)]
union Address {
    v4: SOCKADDR_IN,
    v6: SOCKADDR_IN6,
}

impl Name {
    fn of(address: &SocketAddr) -> Self {
        let (address, size) = match address {
            SocketAddr::V4(v4) => (
                Address {
                    v4: SOCKADDR_IN {
                        sin_family: AF_INET,
                        sin_port: v4.port().to_be(),
                        sin_addr: IN_ADDR {
                            S_un: IN_ADDR_0 {
                                S_addr: u32::from_ne_bytes(v4.ip().octets()),
                            },
                        },
                        sin_zero: [0; 8],
                    },
                },
                size_of::<SOCKADDR_IN>(),
            ),
            SocketAddr::V6(v6) => (
                Address {
                    v6: SOCKADDR_IN6 {
                        sin6_family: AF_INET6,
                        sin6_port: v6.port().to_be(),
                        sin6_flowinfo: v6.flowinfo(),
                        sin6_addr: IN6_ADDR {
                            u: IN6_ADDR_0 {
                                Byte: v6.ip().octets(),
                            },
                        },
                        Anonymous: SOCKADDR_IN6_0 {
                            sin6_scope_id: v6.scope_id(),
                        },
                    },
                },
                size_of::<SOCKADDR_IN6>(),
            ),
        };
        Self {
            address,
            length: i32::try_from(size).unwrap_or(i32::MAX),
        }
    }

    /// Any address of `address`'s family, the system choosing its port:
    /// what `ConnectEx` asks a socket be bound to first.
    fn unspecified(address: &SocketAddr) -> Self {
        let any: SocketAddr = match address {
            SocketAddr::V4(_) => (std::net::Ipv4Addr::UNSPECIFIED, 0).into(),
            SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0).into(),
        };
        Self::of(&any)
    }

    /// The address as the system's calls take it.
    const fn pointer(&self) -> *const SOCKADDR {
        (&raw const self.address).cast::<SOCKADDR>()
    }

    /// `socket` bound to this address.
    fn bind(&self, socket: SOCKET) -> io::Result<()> {
        // SAFETY: `address` holds a socket address of `length` bytes and
        // outlives the call; `socket` is open, its stream's.
        let bound = unsafe { bind(socket, self.pointer(), self.length) };
        if bound == SOCKET_ERROR {
            Err(last())
        } else {
            Ok(())
        }
    }
}

/// The calling thread's last Winsock error.
fn last() -> io::Error {
    // SAFETY: reads the calling thread's last error and nothing else.
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Whether `socket`'s connect is set to end on an unreachable host:
    /// read before it connects, as Windows says it only until then.
    fn ends_on_unreachable(socket: SOCKET) -> bool {
        use windows_sys::Win32::Networking::WinSock::getsockopt;
        let mut on: u32 = 0;
        let mut size = i32::try_from(size_of::<u32>()).expect("fits");
        // SAFETY: `on` and `size` are writable and outlive the call, `size`
        // saying how much `on` holds; Windows writes one byte of it.
        let read = unsafe {
            getsockopt(
                socket,
                IPPROTO_TCP,
                TCP_FAIL_CONNECT_ON_ICMP_ERROR,
                (&raw mut on).cast(),
                &raw mut size,
            )
        };
        read == 0 && on != 0
    }

    #[test]
    fn the_byte_is_the_one_windows_reads_as_no_retransmissions() {
        assert_eq!(NO_SYN_RETRANSMISSIONS, 254);
    }

    #[test]
    fn a_socket_made_for_an_attempt_takes_its_wait_connect_ex_and_the_unreachable_rule() {
        let address = crate::fixture::unheld();
        let (_stream, socket) = made(&address).expect("made");
        assert!(connect_ex(socket).is_some(), "ConnectEx given");
        assert!(!ends_on_unreachable(socket), "off until it is set");
        ended_on_unreachable(socket);
        assert!(ends_on_unreachable(socket));
        for wait in [Duration::ZERO, Duration::from_secs(1), Duration::MAX] {
            assert!(answered_once(socket, wait), "{wait:?}");
        }
    }

    #[test]
    fn an_attempt_connects_bounded_and_unbounded_on_either_family() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let open = listener.local_addr().expect("address");
        for within in [Some(Duration::from_secs(5)), None] {
            let stream = attempt(&open, Duration::from_secs(1), within).expect("connected");
            assert_eq!(stream.peer_addr().expect("peer"), open, "{within:?}");
        }
        let v6 = TcpListener::bind("[::1]:0").expect("bind");
        let open = v6.local_addr().expect("address");
        let stream = attempt(&open, Duration::from_secs(1), None).expect("connected");
        assert_eq!(stream.peer_addr().expect("peer"), open);
    }

    #[test]
    fn a_refusal_is_said_with_its_kind_bounded_and_unbounded() {
        let nobody = crate::fixture::unheld();
        for within in [Some(Duration::from_secs(5)), None] {
            let refused = attempt(&nobody, Duration::from_secs(1), within).expect_err("refused");
            assert_eq!(
                refused.kind(),
                io::ErrorKind::ConnectionRefused,
                "{refused}"
            );
        }
    }
}

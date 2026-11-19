//! Network primitives the capabilities share, one copy of each: an address
//! as a transport writes it ([`address`]), an authority as a URI writes it
//! ([`authority`]), a network in prefix notation ([`Network`]), a hardware
//! address in IEEE 802 notation ([`mac`]),
//! a target as a URI writes it — scheme, authority, path, query and
//! fragment — read once ([`Target`]), a filesystem path as a URI's path
//! ([`uri`]), a TCP connection to every
//! address a peer resolves to in turn ([`connect`]), a refusal answered at
//! once and a SYN nobody answered sent again as the node's `[tuning]` says
//! ([`Retransmission`]), reading off a connection
//! under a ceiling ([`read`]), a length-prefixed frame as Xmip's node-to-node
//! protocols write one ([`frame`]) and the one refusal of a size over a ceiling
//! ([`ceiling`]), a head as the line-oriented protocols write
//! it ([`head`]), the code their replies open with ([`reply`]), the most a
//! connection is read for ([`MAX_BODY`]), and HTTP on the wire, both
//! halves, with the exchange of a request for its answer: HTTP/1.1
//! ([`http`], to an [`Endpoint`]) and HTTP/2 with its header compression
//! ([`http2`]), and gRPC's framing of a message on it ([`grpc`]); and a
//! long-lived connection read until its side ends ([`watched`]); and a
//! named local endpoint, where it is on this system and the named pipe
//! itself, made, accepted, connected to, read and written ([`pipe`]); and,
//! on Unix, a path a listener binds, claimed before it is bound, so
//! another's or a file of another kind refuses it and only the listener's
//! own file goes with it (`socket_file`); and a
//! listener's
//! accept woken by its stop until it has heard ([`accepting`]); and a login
//! a server is offered, with the check it is handed to admit one
//! ([`login`]); JSON-RPC 2.0, its messages and both its framings, by a
//! `Content-Length` header and one message a line (`rpc`, the `rpc` feature); on Windows, the one wait for an overlapped operation every
//! call into Windows here and a serial port's take (`system::overlapped`);
//! and, for tests
//! alone, a loopback address no one holds (`fixture`, `test-support`).
//!
//! Until 2026-09-22 identification and authorization each carried a network
//! type, and authorization read the peer's address under `address` while
//! identification wrote `peer.address`, so an address rule never matched a
//! peer identified by its reverse name; the name is
//! `context::property::PEER_ADDRESS` since 2026-09-24, below every layer that
//! writes or reads it. Until 2026-09-24 the authority, the
//! MAC notation, percent-encoding and the HTTP client were each written
//! three or four times. Until 2026-09-25 the http transport carried a
//! second HTTP/1.1 codec and a second URL reader, and the transport
//! capability the head reader.
//! Until 2026-09-27 a dozen technologies read lines themselves, unbounded,
//! and eleven restated the body ceiling. Until 2026-09-28 the transport
//! capability worded the refusal of a size over a ceiling, and this crate's
//! reader and HTTP body each worded their own; and twenty technologies
//! read their targets' schemes, and ten their queries, by hand.

pub mod accepting;
pub mod address;
pub mod authority;
pub mod ceiling;
mod connect;
mod endpoint;
#[cfg(any(test, feature = "test-support"))]
pub mod fixture;
pub mod frame;
pub mod grpc;
pub mod head;
pub mod http;
pub mod http2;
pub mod login;
pub mod mac;
mod network;
pub mod pipe;
pub mod read;
pub mod reply;
#[cfg(feature = "rpc")]
pub mod rpc;
#[cfg(unix)]
pub mod socket_file;
#[cfg(windows)]
pub mod system;
mod target;
pub mod uri;
pub mod watched;

pub use connect::{RETRANSMISSION, Retransmission, connect, retransmission, retransmit_by};
pub use endpoint::{Endpoint, Schemes};
pub use network::Network;
pub use target::{PATH_SCHEME, Target, scheme_of};

/// The largest single Stream, body or message Xmip reads off one connection,
/// whatever frames it: a peer claiming four gigabytes must not get four
/// gigabytes allocated. A protocol that states a maximum of its own keeps
/// it, named for that protocol; every other ceiling on what a connection
/// carries is this one.
pub const MAX_BODY: usize = 64 * 1024 * 1024;

/// Why text is not the address or network it was read as, why a connection
/// did not give the answer asked of it, or why what a peer sent is not what
/// its protocol says — HTTP here, SSH in `xmip-core-library-ssh`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetError {
    /// What was wrong, in words.
    pub message: String,
    /// The operating system's kind, where the failure was the connection's;
    /// a caller that retries decides by it.
    pub io: Option<std::io::ErrorKind>,
}

impl NetError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            io: None,
        }
    }

    /// A connection's failure while `doing`, keeping its kind.
    #[must_use]
    pub fn from_io(doing: &str, error: &std::io::Error) -> Self {
        Self {
            message: format!("{doing}: {error}"),
            io: Some(error.kind()),
        }
    }
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for NetError {}

/// Bytes a peer sent that are not the encoding its protocol says: the
/// peer's failure, never the connection's, so nothing retries it.
impl From<codec::CodecError> for NetError {
    fn from(error: codec::CodecError) -> Self {
        Self::new(error.message)
    }
}

/// Whether `span` has passed from the reading `since` to the reading `now`
/// of one monotonic clock, in nanoseconds: what a watched connection's
/// silence and an HTTP/2 connection's span of frames end by. A Library
/// reads no clock (ADR-0068, amendments 2026-11-14 and 2026-11-15): both
/// readings are its caller's, `xcore::Clock::monotonic_nanos` of the Clock
/// the caller was handed.
pub(crate) fn passed(since: i128, now: i128, span: std::time::Duration) -> bool {
    u128::try_from(now.saturating_sub(since)).is_ok_and(|apart| apart >= span.as_nanos())
}

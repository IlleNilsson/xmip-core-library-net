#![forbid(unsafe_code)]

//! Network primitives the capabilities share, one copy of each: an address
//! as a transport writes it ([`address`]), an authority as a URI writes it
//! ([`authority`]), a network in prefix notation ([`Network`]), a hardware
//! address in IEEE 802 notation ([`mac`]), percent-encoding ([`percent`]),
//! a filesystem path as a URI's path ([`uri`]), a head as the
//! line-oriented protocols write it ([`head`]), and HTTP/1.1 on the wire,
//! both halves, with the exchange of a request for its answer ([`http`],
//! to an [`Endpoint`]).
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

pub mod address;
pub mod authority;
mod endpoint;
pub mod head;
pub mod http;
pub mod mac;
mod network;
pub mod percent;
pub mod uri;

pub use endpoint::Endpoint;
pub use network::Network;

/// Why text is not the address or network it was read as, or why a
/// connection did not give the answer asked of it.
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

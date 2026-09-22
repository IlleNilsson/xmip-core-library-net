#![forbid(unsafe_code)]

//! Network primitives the capabilities share: an address as a transport
//! writes it, a network in prefix notation, and the name the socket peer's
//! address travels under.
//!
//! One copy of each. Until 2026-09-22 identification and authorization each
//! carried a network type, and authorization read the peer's address under
//! `address` while identification wrote `peer.address`, so an address rule
//! never matched a peer identified by its reverse name.

pub mod address;
mod network;

pub use network::Network;

/// The name the socket peer's address travels under — `192.0.2.10:4711`,
/// `[2001:db8::1]:443` or a bare address: the arrival property a transport
/// writes, the evidence identification records it as, and the fact
/// authorization reads.
pub const PEER_ADDRESS: &str = "peer.address";

/// Why text is not the address or network it was read as.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetError {
    /// What was wrong, in words.
    pub message: String,
}

impl NetError {
    /// A failure saying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl core::error::Error for NetError {}

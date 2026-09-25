//! Which HTTP a connection speaks, and the identifier ALPN agrees it by.

/// The version of HTTP a connection speaks, which TLS agrees by ALPN
/// (RFC 7301) and a cleartext connection knows beforehand.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Version {
    /// HTTP/1.1, this module; what a connection speaks unless something
    /// agreed otherwise.
    #[default]
    Http11,
    /// HTTP/2, [`crate::http2`].
    Http2,
}

impl Version {
    /// The protocol identifier ALPN offers and agrees it by, from the IANA
    /// registry RFC 7301 keeps.
    #[must_use]
    pub const fn alpn(self) -> &'static [u8] {
        match self {
            Self::Http11 => b"http/1.1",
            Self::Http2 => b"h2",
        }
    }

    /// The version a handshake agreed: HTTP/2 where ALPN chose `h2`,
    /// HTTP/1.1 where it chose that or nothing at all.
    #[must_use]
    pub fn agreed(protocol: Option<&[u8]>) -> Self {
        if protocol == Some(Self::Http2.alpn()) {
            Self::Http2
        } else {
            Self::Http11
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_what_alpn_agreed_and_http_1_1_otherwise() {
        assert_eq!(Version::agreed(Some(b"h2")), Version::Http2);
        assert_eq!(Version::agreed(Some(b"http/1.1")), Version::Http11);
        assert_eq!(Version::agreed(None), Version::Http11);
        assert_eq!(Version::default().alpn(), b"http/1.1");
    }
}

//! Where a plain HTTP server is: an `http://host[:port][/path]` URL, read
//! once for the minimal client in [`crate::http`].

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::NetError;
use crate::authority;

/// An `http://` URL: the host, the port, and the path under it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    host: String,
    port: u16,
    path: String,
}

impl Endpoint {
    /// Read `url`, with `default_port` where it names none and `/` where it
    /// names no path.
    ///
    /// # Errors
    ///
    /// Refuses anything but `http://`, saying so — the client speaks plain
    /// HTTP/1.1 and no TLS — and an authority [`authority::parse`] refuses.
    pub fn parse(url: &str, default_port: u16) -> Result<Self, NetError> {
        let rest = url.strip_prefix("http://").ok_or_else(|| {
            NetError::new(format!(
                "'{url}' is not an http:// URL, and this client speaks plain HTTP/1.1 only"
            ))
        })?;
        let (written, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        let (host, port) = authority::parse(written)
            .map_err(|failed| NetError::new(format!("'{url}': {failed}")))?;

        Ok(Self {
            host: host.to_string(),
            port: port.unwrap_or(default_port),
            path: path.to_string(),
        })
    }

    /// The host, without brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The path, opening with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port` as a `Host` header writes it, an IPv6 host in brackets.
    #[must_use]
    pub fn authority(&self) -> String {
        format!("{}:{}", authority::bracketed(&self.host), self.port)
    }

    /// Whether the endpoint names this machine: `localhost`, or an address
    /// in `127.0.0.0/8` or `::1`. A name is never resolved to find out.
    #[must_use]
    pub fn names_loopback(&self) -> bool {
        self.host.eq_ignore_ascii_case("localhost")
            || self
                .host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    }

    /// The addresses the host resolves to.
    ///
    /// # Errors
    ///
    /// Where the host does not resolve.
    pub fn resolve(&self) -> Result<Vec<SocketAddr>, NetError> {
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map(Iterator::collect)
            .map_err(|failed| {
                NetError::from_io(&format!("'{}' does not resolve", self.host), &failed)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_endpoint_is_a_host_a_port_and_a_path() {
        let plain = Endpoint::parse("http://opa.example:8282", 8181).expect("an endpoint");
        let based = Endpoint::parse("http://127.0.0.1/opa/", 8181).expect("an endpoint");
        let six = Endpoint::parse("http://[::1]:9000/oauth/introspect", 80).expect("v6");

        assert_eq!(
            (plain.host(), plain.port(), plain.path()),
            ("opa.example", 8282, "/")
        );
        assert_eq!((based.port(), based.path()), (8181, "/opa/"));
        assert_eq!((six.host(), six.port()), ("::1", 9000));
        assert_eq!(six.path(), "/oauth/introspect");
        assert_eq!(six.authority(), "[::1]:9000");
    }

    #[test]
    fn loopback_is_read_off_the_endpoint_and_a_name_is_never_resolved() {
        let loopback = |text: &str| {
            Endpoint::parse(text, 80)
                .expect("an endpoint")
                .names_loopback()
        };

        assert!(loopback("http://127.0.0.1:8181"));
        assert!(loopback("http://127.9.9.9"));
        assert!(loopback("http://LOCALHOST:8181"));
        assert!(loopback("http://[::1]:8181"));
        assert!(!loopback("http://opa.example:8181"));
        assert!(!loopback("http://10.0.0.5:8181"));
    }

    #[test]
    fn an_endpoint_this_client_cannot_speak_to_is_refused_saying_why() {
        let refused = |text: &str| Endpoint::parse(text, 80).expect_err("refused").message;

        assert!(refused("https://opa.example").contains("plain HTTP/1.1 only"));
        assert!(refused("ftp://opa.example").contains("not an http:// URL"));
        assert!(refused("http://:8181").contains("names no host"));
        assert!(refused("http://opa.example:agent").contains("a port that is not one"));
        assert!(refused("http://[::1:8181").contains("bracket"));
    }
}

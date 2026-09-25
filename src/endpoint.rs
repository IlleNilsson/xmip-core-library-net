//! Where an HTTP server is: an `http://` or `https://` URL — a host, a port
//! and a path — read once, for [`crate::http`] and for every technology that
//! rides on HTTP.
//!
//! One reading. Until 2026-09-25 the http transport read its targets with a
//! parser of its own, `HttpTarget`, beside this one, and the Peppol loopback
//! cut a path off a URL a third way.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use crate::NetError;
use crate::authority;

/// An `http://` or `https://` URL: the host, the port, and the path under
/// it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Endpoint {
    secure: bool,
    host: String,
    port: Option<u16>,
    path: String,
}

impl Endpoint {
    /// Read `url`: `/` where it names no path, and the scheme's port — 80,
    /// or 443 for `https://` — where it names none and [`Self::or_port`]
    /// gives none.
    ///
    /// # Errors
    ///
    /// Refuses a scheme that is neither `http://` nor `https://`, and an
    /// authority [`authority::parse`] refuses.
    pub fn parse(url: &str) -> Result<Self, NetError> {
        let (secure, rest) = if let Some(rest) = url.strip_prefix("https://") {
            (true, rest)
        } else if let Some(rest) = url.strip_prefix("http://") {
            (false, rest)
        } else {
            return Err(NetError::new(format!(
                "'{url}' is not an http:// or https:// URL"
            )));
        };
        let (written, path) = match rest.find('/') {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, "/"),
        };
        let (host, port) = authority::parse(written)
            .map_err(|failed| NetError::new(format!("'{url}': {failed}")))?;

        Ok(Self {
            secure,
            host: host.to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// The same endpoint with `port` where the URL named none: the port a
    /// service beside the node listens on by convention, such as an Open
    /// Policy Agent's 8181.
    #[must_use]
    pub fn or_port(mut self, port: u16) -> Self {
        self.port.get_or_insert(port);
        self
    }

    /// The same endpoint, refused where it asks for TLS: [`crate::http`]
    /// speaks plain HTTP/1.1 over whatever connection it is handed, and a
    /// capability that opens its own connection has no TLS to open.
    ///
    /// # Errors
    ///
    /// Where the URL is `https://`.
    pub fn plain(self) -> Result<Self, NetError> {
        if self.secure {
            return Err(NetError::new(format!(
                "'https://{}' asks for TLS, and this client speaks plain HTTP/1.1 only",
                self.address()
            )));
        }
        Ok(self)
    }

    /// Whether the URL is `https://`.
    #[must_use]
    pub const fn secure(&self) -> bool {
        self.secure
    }

    /// The host, without brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port: the one the URL names, else the one [`Self::or_port`]
    /// gave, else the scheme's.
    #[must_use]
    pub const fn port(&self) -> u16 {
        match self.port {
            Some(port) => port,
            None => self.scheme_port(),
        }
    }

    /// The path, opening with `/`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// The authority as a `Host` header writes it (RFC 9110 section 7.2):
    /// the host, an IPv6 host in brackets, and the port unless it is the
    /// scheme's own.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.port() == self.scheme_port() {
            authority::bracketed(&self.host)
        } else {
            self.address()
        }
    }

    /// `host:port` as a connection or a bind is given it, an IPv6 host in
    /// brackets and the port always written.
    #[must_use]
    pub fn address(&self) -> String {
        format!("{}:{}", authority::bracketed(&self.host), self.port())
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
        (self.host.as_str(), self.port())
            .to_socket_addrs()
            .map(Iterator::collect)
            .map_err(|failed| {
                NetError::from_io(&format!("'{}' does not resolve", self.host), &failed)
            })
    }

    const fn scheme_port(&self) -> u16 {
        if self.secure { 443 } else { 80 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(url: &str) -> Endpoint {
        Endpoint::parse(url).expect("an endpoint")
    }

    #[test]
    fn an_endpoint_is_a_host_a_port_and_a_path() {
        let plain = read("http://opa.example:8282").or_port(8181);
        let based = read("http://127.0.0.1/opa/").or_port(8181);
        let six = read("http://[::1]:9000/oauth/introspect");

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
    fn the_scheme_gives_the_port_and_the_host_header_leaves_its_own_port_out() {
        let http = read("http://example.com/x");
        let https = read("https://example.com/x");
        let other = read("https://example.com:8443/x");

        assert_eq!((http.port(), http.secure()), (80, false));
        assert_eq!((https.port(), https.secure()), (443, true));
        assert_eq!(http.address(), "example.com:80");
        assert_eq!(https.address(), "example.com:443");
        assert_eq!(https.authority(), "example.com");
        assert_eq!(other.authority(), "example.com:8443");
        assert_eq!(read("http://[::1]").authority(), "[::1]");
        assert_eq!(read("http://example.com:80").authority(), "example.com");
    }

    #[test]
    fn loopback_is_read_off_the_endpoint_and_a_name_is_never_resolved() {
        let loopback = |text: &str| read(text).names_loopback();

        assert!(loopback("http://127.0.0.1:8181"));
        assert!(loopback("http://127.9.9.9"));
        assert!(loopback("http://LOCALHOST:8181"));
        assert!(loopback("http://[::1]:8181"));
        assert!(!loopback("http://opa.example:8181"));
        assert!(!loopback("http://10.0.0.5:8181"));
    }

    #[test]
    fn an_endpoint_that_is_not_one_is_refused_saying_why() {
        let refused = |text: &str| Endpoint::parse(text).expect_err("refused").message;

        assert!(refused("ftp://opa.example").contains("not an http:// or https:// URL"));
        assert!(refused("opa.example/orders").contains("not an http://"));
        assert!(refused("http://:8181").contains("names no host"));
        assert!(refused("http:///orders").contains("names no host"));
        assert!(refused("http://opa.example:agent").contains("a port that is not one"));
        assert!(refused("http://[::1:8181").contains("bracket"));
    }

    #[test]
    fn a_client_without_tls_refuses_https_saying_so() {
        let refused = read("https://opa.example").plain().expect_err("refused");

        assert!(refused.message.contains("plain HTTP/1.1 only"), "{refused}");
        assert!(read("http://opa.example").plain().is_ok());
    }
}

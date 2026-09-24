//! An authority as a URI writes it (RFC 3986 section 3.2): a host, and a
//! port where one is given — `example.com`, `example.com:8080`, `[::1]`,
//! `[::1]:8080`.
//!
//! One reading. Until 2026-09-24 the transport capability read it for every
//! transport, and the Open Policy Agent client and the OAuth 2.0
//! introspection client each read it again, one keeping the colons of an
//! IPv6 host inside its brackets and the other stripping brackets it never
//! checked were closed.

use crate::NetError;

/// The host and the port text, brackets taken off an IPv6 literal.
fn parts(authority: &str) -> (&str, Option<&str>) {
    if let Some((host, after)) = authority
        .strip_prefix('[')
        .and_then(|bracketed| bracketed.split_once(']'))
    {
        return (host, after.strip_prefix(':'));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    }
}

/// The host without its port, and without the brackets an IPv6 literal
/// carries.
#[must_use]
pub fn host_of(authority: &str) -> &str {
    parts(authority).0
}

/// The authority with `default` as its port where it does not carry one.
///
/// The bracket check is what keeps `[::1]` from being read as
/// host-and-port.
#[must_use]
pub fn with_default_port(authority: &str, default: u16) -> String {
    if parts(authority).1.is_some() {
        authority.to_string()
    } else {
        format!("{authority}:{default}")
    }
}

/// The host, brackets off, and the port where one is given.
///
/// # Errors
///
/// Where a bracket is opened and not closed, the host is empty, or the
/// port is not a number from 0 to 65535.
pub fn parse(authority: &str) -> Result<(&str, Option<u16>), NetError> {
    let refused = |why: &str| NetError::new(format!("the authority '{authority}' {why}"));

    if authority.starts_with('[') && !authority.contains(']') {
        return Err(refused("opens a bracket it does not close"));
    }
    let (host, port) = parts(authority);
    if host.is_empty() {
        return Err(refused("names no host"));
    }
    let port = port
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| refused("names a port that is not one"))
        })
        .transpose()?;

    Ok((host, port))
}

/// The host as a `Host` header or a URI writes it: an IPv6 literal in
/// brackets, anything else as it is.
#[must_use]
pub fn bracketed(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_port_is_added_only_when_none_is_given() {
        assert_eq!(with_default_port("example.com", 80), "example.com:80");
        assert_eq!(
            with_default_port("example.com:8080", 80),
            "example.com:8080"
        );
        assert_eq!(with_default_port("[::1]", 80), "[::1]:80");
        assert_eq!(with_default_port("[::1]:8080", 80), "[::1]:8080");
    }

    #[test]
    fn the_host_is_read_without_its_port_or_brackets() {
        assert_eq!(host_of("example.com:8080"), "example.com");
        assert_eq!(host_of("example.com"), "example.com");
        assert_eq!(host_of("[::1]:8080"), "::1");
        assert_eq!(host_of("[::1]"), "::1");
    }

    #[test]
    fn an_authority_is_a_host_and_an_optional_port() {
        assert_eq!(
            parse("opa.example:8282").expect("read"),
            ("opa.example", Some(8282))
        );
        assert_eq!(parse("127.0.0.1").expect("read"), ("127.0.0.1", None));
        assert_eq!(parse("[::1]:9000").expect("read"), ("::1", Some(9000)));
        assert_eq!(parse("[::1]").expect("read"), ("::1", None));
    }

    #[test]
    fn an_authority_that_is_not_one_is_refused_saying_why() {
        let refused = |text: &str| parse(text).expect_err("refused").message;

        assert!(refused(":8181").contains("names no host"));
        assert!(refused("opa.example:agent").contains("a port that is not one"));
        assert!(refused("opa.example:70000").contains("a port that is not one"));
        assert!(refused("[::1:8181").contains("bracket"));
    }

    #[test]
    fn an_ipv6_host_is_bracketed_and_nothing_else_is() {
        assert_eq!(bracketed("::1"), "[::1]");
        assert_eq!(bracketed("opa.example"), "opa.example");
    }
}

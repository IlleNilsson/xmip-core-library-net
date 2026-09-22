//! An address as a transport writes it.

use std::net::{IpAddr, SocketAddr};

use crate::NetError;

/// Read an address as a transport writes it: bare, with a port, or an IPv6
/// address in brackets with or without one.
///
/// # Errors
///
/// Where the text is none of those.
pub fn parse(text: &str) -> Result<IpAddr, NetError> {
    let text = text.trim();

    if let Ok(address) = text.parse::<IpAddr>() {
        return Ok(address);
    }
    if let Ok(socket) = text.parse::<SocketAddr>() {
        return Ok(socket.ip());
    }
    if let Some(inner) = text
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        && let Ok(address) = inner.parse::<IpAddr>()
    {
        return Ok(address);
    }

    Err(NetError::new(format!(
        "the peer address {text:?} is not an IP address"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_is_read_bare_with_a_port_and_in_brackets() {
        let four: IpAddr = "192.0.2.10".parse().expect("v4");
        let six: IpAddr = "2001:db8::1".parse().expect("v6");

        assert_eq!(parse("192.0.2.10").expect("bare"), four);
        assert_eq!(parse(" 192.0.2.10:4711 ").expect("port"), four);
        assert_eq!(parse("2001:db8::1").expect("bare"), six);
        assert_eq!(parse("[2001:db8::1]").expect("brackets"), six);
        assert_eq!(parse("[2001:db8::1]:443").expect("port"), six);
    }

    #[test]
    fn text_that_is_no_address_is_refused_and_named() {
        let error = parse("not-an-address").expect_err("refused");
        assert!(error.message.contains("not-an-address"), "{error}");
    }
}

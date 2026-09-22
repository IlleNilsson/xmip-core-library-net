//! A network in prefix notation, and whether an address falls inside it.
//!
//! `10.0.0.0/8`, `192.168.1.0/24`, `2001:db8::/32`, or a bare address for the
//! one-host network. Standard library addresses; the arithmetic is a mask.
//! A trusted-proxy list and an authorization rule are both written in it.

use std::fmt;
use std::net::IpAddr;

use crate::NetError;

/// A range of addresses, as a prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    /// `address/prefix`, or a bare address.
    ///
    /// # Errors
    ///
    /// When the address does not parse or the prefix is longer than the
    /// address family allows.
    pub fn parse(text: &str) -> Result<Self, NetError> {
        let text = text.trim();
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };

        let address: IpAddr = address
            .parse()
            .map_err(|_| NetError::new(format!("'{text}' is not a network as address/prefix")))?;
        let widest = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            None => widest,
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|p| *p <= widest)
                .ok_or_else(|| {
                    NetError::new(format!("'{text}' has a prefix longer than {widest} bits"))
                })?,
        };

        Ok(Self { address, prefix })
    }

    /// Whether an address is inside this network. An address of the other
    /// family never is.
    #[must_use]
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                // The high `prefix` bits, set; a shift by the full width is
                // what `prefix == 0` would need, so it is its own case.
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn network(text: &str) -> Network {
        Network::parse(text).expect("a network")
    }

    fn address(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    #[test]
    fn a_v4_prefix_contains_its_hosts_and_nothing_else() {
        let lan = network("192.168.1.0/24");

        assert!(lan.contains(address("192.168.1.77")));
        assert!(!lan.contains(address("192.168.2.1")));
        assert!(
            !lan.contains(address("::ffff:192.168.1.77")),
            "other family"
        );
        assert!(network("0.0.0.0/0").contains(address("8.8.8.8")));
        assert!(
            network("10.1.2.3").contains(address("10.1.2.3")),
            "one host"
        );
        assert!(!network("10.1.2.3").contains(address("10.1.2.4")));
    }

    #[test]
    fn a_v6_prefix_masks_the_full_width() {
        let documentation = network("2001:db8::/32");

        assert!(documentation.contains(address("2001:db8:1::1")));
        assert!(!documentation.contains(address("2001:db9::1")));
        assert!(network("::/0").contains(address("fe80::1")));
        assert_eq!(documentation.to_string(), "2001:db8::/32");
    }

    #[test]
    fn a_prefix_too_long_for_the_family_is_refused() {
        assert!(Network::parse("10.0.0.0/33").is_err());
        assert!(Network::parse("2001:db8::/129").is_err());
        assert!(Network::parse("partner-x.example").is_err());
    }
}

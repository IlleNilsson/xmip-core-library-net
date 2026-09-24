//! A hardware address in the notation IEEE 802 writes it: two hex digits an
//! octet, colon-separated — `00:1b:44:11:3a:b7`.
//!
//! Read in the four spellings the stacks use — colons, hyphens, the dotted
//! form of four digits a group (`001b.4411.3ab7`), or the digits alone
//! (`001B44113AB7`) — in either case, and written in one: lowercase,
//! colons. Any number of octets, because a DHCP client's hardware address
//! is as long as its link says; a 48-bit address is six of them, and a
//! reader that needs six checks the count.
//!
//! One copy. Until 2026-09-24 the Ethernet frame, the DHCP message and the
//! MAC identifier each read and wrote it, and each took a different set of
//! spellings: the DHCP message one digit an octet, the identifier the
//! dotted form and the bare digits, the frame neither.

use crate::NetError;

/// `bytes` as colon-separated lowercase hex pairs.
#[must_use]
pub fn notation(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| codec::hex::encode(&[*byte]))
        .collect::<Vec<_>>()
        .join(":")
}

/// The octets `text` names: colon-, hyphen- or dot-separated, or the digits
/// alone.
///
/// # Errors
///
/// Where the text is empty, a group is not two hex digits (four in the
/// dotted form), or the digits alone are not whole octets.
pub fn parse(text: &str) -> Result<Vec<u8>, NetError> {
    let text = text.trim();
    let refused = || NetError::new(format!("{text:?} is not a hardware address"));

    let (groups, width): (Vec<&str>, usize) = if text.contains('.') {
        (text.split('.').collect(), 4)
    } else if text.contains([':', '-']) {
        (text.split([':', '-']).collect(), 2)
    } else {
        (vec![text], text.len())
    };
    if text.is_empty() {
        return Err(refused());
    }

    let mut octets = Vec::with_capacity(groups.len() * width / 2);
    for group in groups {
        if group.len() != width {
            return Err(refused());
        }
        octets.extend(codec::hex::decode(group).map_err(|_| refused())?);
    }

    Ok(octets)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADDRESS: [u8; 6] = [0x00, 0x1b, 0x44, 0x11, 0x3a, 0xb7];

    #[test]
    fn an_address_is_read_in_each_spelling_and_written_in_one() {
        for spelling in [
            "00:1b:44:11:3a:b7",
            "00-1B-44-11-3A-B7",
            "001b.4411.3ab7",
            "001B44113AB7",
            " 00:1B:44:11:3a:b7 ",
        ] {
            assert_eq!(parse(spelling).expect(spelling), ADDRESS, "{spelling}");
        }

        assert_eq!(notation(&ADDRESS), "00:1b:44:11:3a:b7");
        assert_eq!(parse("aa-bb").expect("two octets"), vec![0xaa, 0xbb]);
        assert_eq!(notation(&[]), "");
    }

    #[test]
    fn what_is_not_the_notation_is_refused() {
        for broken in [
            "",
            "0:1b:44:11:3a:b7",
            "00:1b:44:11:3a:zz",
            "00:1b:44:11:3a:+b",
            "001b44113ab",
            "001b.4411.3ab",
            "00:1b::11:3a:b7",
        ] {
            assert!(parse(broken).is_err(), "{broken:?}");
        }
    }
}

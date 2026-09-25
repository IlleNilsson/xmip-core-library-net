//! The Huffman coding of RFC 7541 section 5.2 over the code of Appendix B:
//! a string packed most significant bit first and padded with the high bits
//! of `EOS`, and unpacked by walking the code's tree.

use std::sync::OnceLock;

use super::code::{CODES, EOS};
use crate::http2::error::Violation;

/// The octets `input` takes once encoded, without encoding it.
#[must_use]
pub fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input
        .iter()
        .map(|&octet| usize::from(CODES[usize::from(octet)].1))
        .sum();
    bits.div_ceil(8)
}

/// Append `input`, encoded.
pub fn encode(input: &[u8], out: &mut Vec<u8>) {
    let mut pending: u64 = 0;
    let mut held = 0u32;
    for &octet in input {
        let (code, bits) = CODES[usize::from(octet)];
        pending = (pending << bits) | u64::from(code);
        held += u32::from(bits);
        while held >= 8 {
            held -= 8;
            out.push(low_octet(pending >> held));
        }
    }
    if held > 0 {
        // The padding is the most significant bits of EOS: all ones.
        let pad = 8 - held;
        out.push(low_octet((pending << pad) | ((1 << pad) - 1)));
    }
}

/// `input`, decoded.
///
/// # Errors
///
/// A `COMPRESSION_ERROR` where the input holds `EOS`, a code that is not
/// one, or padding longer than seven bits or not the high bits of `EOS`
/// (section 5.2).
pub fn decode(input: &[u8]) -> Result<Vec<u8>, Violation> {
    let tree = tree();
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut node = 0usize;
    let mut depth = 0u32;
    let mut all_ones = true;
    for &octet in input {
        for shift in (0..8).rev() {
            let bit = (octet >> shift) & 1;
            all_ones &= bit == 1;
            depth += 1;
            match tree[node][usize::from(bit)] {
                Branch::Node(next) => node = next,
                Branch::Leaf(EOS) => {
                    return Err(Violation::compression("a Huffman string holds EOS"));
                }
                Branch::Leaf(symbol) => {
                    out.push(u8::try_from(symbol).unwrap_or_default());
                    node = 0;
                    depth = 0;
                    all_ones = true;
                }
                Branch::None => return Err(Violation::compression("not a Huffman code")),
            }
        }
    }
    if depth > 7 || !all_ones {
        return Err(Violation::compression(
            "a Huffman string padded with other than the high bits of EOS",
        ));
    }
    Ok(out)
}

#[derive(Clone, Copy)]
enum Branch {
    None,
    Node(usize),
    Leaf(usize),
}

/// The code as a binary tree, built once: each node's branch for a 0 and
/// for a 1.
fn tree() -> &'static [[Branch; 2]] {
    static TREE: OnceLock<Vec<[Branch; 2]>> = OnceLock::new();
    TREE.get_or_init(|| {
        let mut nodes = vec![[Branch::None; 2]];
        for (symbol, &(code, bits)) in CODES.iter().enumerate() {
            let mut node = 0;
            for level in (0..bits).rev() {
                let bit = usize::from((code >> level) & 1 == 1);
                if level == 0 {
                    nodes[node][bit] = Branch::Leaf(symbol);
                    break;
                }
                node = if let Branch::Node(next) = nodes[node][bit] {
                    next
                } else {
                    nodes.push([Branch::None; 2]);
                    nodes[node][bit] = Branch::Node(nodes.len() - 1);
                    nodes.len() - 1
                };
            }
        }
        nodes
    })
}

fn low_octet(bits: u64) -> u8 {
    u8::try_from(bits & 0xff).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect()
    }

    #[test]
    fn the_strings_of_appendix_c_4_and_c_6_encode_as_printed() {
        let printed = [
            ("www.example.com", "f1e3 c2e5 f23a 6ba0 ab90 f4ff"),
            ("no-cache", "a8eb 1064 9cbf"),
            ("custom-key", "25a8 49e9 5ba9 7d7f"),
            ("custom-value", "25a8 49e9 5bb8 e8b4 bf"),
            ("302", "6402"),
            ("private", "aec3 771a 4b"),
            (
                "Mon, 21 Oct 2013 20:13:21 GMT",
                "d07a be94 1054 d444 a820 0595 040b 8166 e082 a62d 1bff",
            ),
            (
                "https://www.example.com",
                "9d29 ad17 1863 c78f 0b97 c8e9 ae82 ae43 d3",
            ),
            ("gzip", "9bd9 ab"),
        ];
        for (text, wire) in printed {
            let mut out = Vec::new();
            encode(text.as_bytes(), &mut out);
            assert_eq!(out, hex(wire), "{text}");
            assert_eq!(encoded_len(text.as_bytes()), out.len(), "{text}");
            assert_eq!(decode(&out).expect("decoded"), text.as_bytes(), "{text}");
        }
    }

    #[test]
    fn every_octet_round_trips_and_bad_padding_is_refused() {
        let every: Vec<u8> = (0..=255).collect();
        let mut out = Vec::new();
        encode(&every, &mut out);
        assert_eq!(decode(&out).expect("decoded"), every);
        // '0' is 00000 in five bits; three zero bits of padding are not EOS.
        assert!(decode(&[0b0000_0000]).is_err());
        // A whole octet of ones is padding longer than seven bits.
        assert!(decode(&[0b0000_0111, 0xff]).is_err());
        // EOS itself, thirty ones.
        assert!(decode(&[0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(decode(&[]).expect("empty").is_empty());
    }
}

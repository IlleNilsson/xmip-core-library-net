//! The string literal of RFC 7541 section 5.2: a Huffman flag, the length
//! in a seven-bit prefix, and the octets, raw or Huffman-coded.

use super::{huffman, integer};
use crate::http2::error::Violation;

/// Append `text`, Huffman-coded where `huffman` asks for it and the code
/// is no longer than the octets themselves.
pub fn encode(text: &str, huffman: bool, out: &mut Vec<u8>) {
    let bytes = text.as_bytes();
    let coded = huffman::encoded_len(bytes);
    if huffman && coded <= bytes.len() {
        integer::encode(coded, 7, 0x80, out);
        huffman::encode(bytes, out);
    } else {
        integer::encode(bytes.len(), 7, 0, out);
        out.extend_from_slice(bytes);
    }
}

/// The string at the start of `input`, and the octets it took.
///
/// # Errors
///
/// A `COMPRESSION_ERROR` where the input ends inside it, its Huffman code
/// is broken, or it is not UTF-8.
pub fn decode(input: &[u8]) -> Result<(String, usize), Violation> {
    let coded = input.first().is_some_and(|&octet| octet & 0x80 != 0);
    let (length, at) = integer::decode(input, 7)?;
    let end = at
        .checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or_else(|| Violation::compression("the block ends inside a string"))?;
    let raw = &input[at..end];
    let bytes = if coded {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    let text = String::from_utf8(bytes)
        .map_err(|_| Violation::compression("a header string that is not UTF-8"))?;
    Ok((text, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_is_its_length_and_its_octets_raw_or_coded() {
        let mut raw = Vec::new();
        encode("custom-key", false, &mut raw);
        assert_eq!(raw[0], 0x0a);
        assert_eq!(&raw[1..], b"custom-key");
        let mut coded = Vec::new();
        encode("custom-key", true, &mut coded);
        assert_eq!(coded[0], 0x88);
        for wire in [raw, coded] {
            assert_eq!(
                decode(&wire).expect("read"),
                ("custom-key".to_string(), wire.len())
            );
        }
        assert!(decode(&[0x05, b'a']).is_err());
        assert!(decode(&[0x01, 0xff]).is_err());
    }
}

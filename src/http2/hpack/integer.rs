//! The integer representation of RFC 7541 section 5.1: a value in an
//! N-bit prefix, and where it does not fit, the rest in seven-bit groups
//! least significant first.

use crate::http2::error::Violation;

/// The largest value read: an index, a length or a table size is never
/// near it, and a value past it is an attack rather than a header.
const LARGEST: usize = u32::MAX as usize;

/// Append `value` in a `prefix`-bit prefix, the octet's higher bits taken
/// from `flags`.
pub fn encode(value: usize, prefix: u8, flags: u8, out: &mut Vec<u8>) {
    let limit = (1usize << prefix) - 1;
    if value < limit {
        out.push(flags | u8::try_from(value).unwrap_or(u8::MAX));
        return;
    }
    out.push(flags | u8::try_from(limit).unwrap_or(u8::MAX));
    let mut rest = value - limit;
    while rest >= 128 {
        out.push(u8::try_from(rest % 128).unwrap_or(0) | 0x80);
        rest /= 128;
    }
    out.push(u8::try_from(rest).unwrap_or(0));
}

/// The value in a `prefix`-bit prefix at the start of `input`, and the
/// octets it took.
///
/// # Errors
///
/// A `COMPRESSION_ERROR` where the input ends inside the value, or the
/// value passes 2^32 - 1.
pub fn decode(input: &[u8], prefix: u8) -> Result<(usize, usize), Violation> {
    let truncated = || Violation::compression("the block ends inside an integer");
    let limit = (1usize << prefix) - 1;
    let first = usize::from(*input.first().ok_or_else(truncated)?) & limit;
    if first < limit {
        return Ok((first, 1));
    }
    let mut value = limit;
    let mut shift = 0u32;
    for (at, &octet) in input.iter().enumerate().skip(1) {
        let group = usize::from(octet & 0x7f)
            .checked_shl(shift)
            .filter(|_| shift < 32)
            .ok_or_else(|| Violation::compression("an integer over 2^32 - 1"))?;
        value = value
            .checked_add(group)
            .filter(|&value| value <= LARGEST)
            .ok_or_else(|| Violation::compression("an integer over 2^32 - 1"))?;
        if octet & 0x80 == 0 {
            return Ok((value, at + 1));
        }
        shift += 7;
    }
    Err(truncated())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn written(value: usize, prefix: u8) -> Vec<u8> {
        let mut out = Vec::new();
        encode(value, prefix, 0, &mut out);
        out
    }

    #[test]
    fn the_integers_of_appendix_c_1() {
        // C.1.1: 10 in a 5-bit prefix.
        assert_eq!(written(10, 5), [0b0_1010]);
        // C.1.2: 1337 in a 5-bit prefix.
        assert_eq!(written(1337, 5), [0b1_1111, 0b1001_1010, 0b0000_1010]);
        // C.1.3: 42 from an octet boundary.
        assert_eq!(written(42, 8), [0b0010_1010]);
        assert_eq!(decode(&[0b1110_1010], 5).expect("10"), (10, 1));
        assert_eq!(
            decode(&[0x1f, 0x9a, 0x0a, 0xff], 5).expect("1337"),
            (1337, 3)
        );
        assert_eq!(decode(&[42], 8).expect("42"), (42, 1));
    }

    #[test]
    fn a_value_at_the_limit_continues_and_a_broken_one_is_refused() {
        assert_eq!(written(31, 5), [31, 0]);
        for value in [0, 30, 31, 127, 128, 4096, 1 << 20, LARGEST] {
            assert_eq!(decode(&written(value, 5), 5).expect("read").0, value);
        }
        assert!(decode(&[], 5).is_err());
        assert!(decode(&[0x1f, 0x80], 5).is_err());
        assert!(decode(&[0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01], 5).is_err());
    }
}

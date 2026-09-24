//! Percent-encoding (RFC 3986 section 2.1): every byte outside the
//! unreserved set written as `%XX`, and the escapes read back.
//!
//! Written with RFC 3986's unreserved set and nothing more, which is what
//! S3's canonical form and a form body alike accept: `a b` is `a%20b`, never
//! `a+b`, and a `/` is kept only where the caller says it separates the
//! segments of a path. Read in two ways, over one walk: [`decode`] leaves a
//! `%` that two hex digits do not follow as it is, as the WHATWG URL
//! parser does, for a far end that takes what it is sent; [`decode_strict`]
//! refuses it, for a credential or a form Xmip must not guess at. What a `+`
//! means is the form's, not the URI's, and stays with the form.
//!
//! One copy. Until 2026-09-24 the http transport, the API-key identifier,
//! the form shape and the OAuth 2.0 introspection client each carried their
//! own, and the three readers took `%+f` as the byte `0x0f`, because
//! `u8::from_str_radix` takes a sign.

use std::fmt;

/// A `%` that two hex digits do not follow, at byte `at` of the text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokenEscape {
    /// Where the `%` is, counted in bytes from the start.
    pub at: usize,
}

impl fmt::Display for BrokenEscape {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a % without two hex digits at byte {}", self.at)
    }
}

impl std::error::Error for BrokenEscape {}

/// `text` with every byte outside the unreserved set as `%XX`, and `/` kept
/// where it separates the segments of a path.
#[must_use]
pub fn encode(text: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        let plain = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~')
            || (keep_slash && byte == b'/');
        if plain {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&codec::hex::encode(&[byte]).to_ascii_uppercase());
        }
    }
    out
}

/// `%XX` back to bytes, lossily where they are not UTF-8; a `%` that two
/// hex digits do not follow is left as it is.
#[must_use]
pub fn decode(text: &str) -> String {
    let decoded = walk(text.as_bytes(), false).unwrap_or_else(|_| text.as_bytes().to_vec());
    String::from_utf8_lossy(&decoded).into_owned()
}

/// `%XX` back to bytes, refusing a `%` that two hex digits do not follow.
///
/// # Errors
///
/// At the first such `%`, saying where it is.
pub fn decode_strict(text: &[u8]) -> Result<Vec<u8>, BrokenEscape> {
    walk(text, true)
}

/// The one walk: each escape decoded, and a broken one refused where
/// `strict` says so and kept as written where it does not.
fn walk(text: &[u8], strict: bool) -> Result<Vec<u8>, BrokenEscape> {
    let mut out = Vec::with_capacity(text.len());
    let mut at = 0;
    while at < text.len() {
        let escaped = (text[at] == b'%')
            .then(|| text.get(at + 1..at + 3))
            .flatten()
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .and_then(|digits| codec::hex::decode(digits).ok());
        match escaped {
            Some(byte) => {
                out.extend(byte);
                at += 3;
            }
            None if strict && text[at] == b'%' => return Err(BrokenEscape { at }),
            None => {
                out.push(text[at]);
                at += 1;
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_keeps_the_unreserved_and_the_path_slash() {
        assert_eq!(encode("in/a b+c.edi", true), "in/a%20b%2Bc.edi");
        assert_eq!(encode("in/", false), "in%2F");
        assert_eq!(encode("a+b/c=d.e-f", false), "a%2Bb%2Fc%3Dd.e-f");
        assert_eq!(encode("räksmörgås", false), "r%C3%A4ksm%C3%B6rg%C3%A5s");
    }

    #[test]
    fn decoding_leaves_a_broken_escape_as_written() {
        assert_eq!(decode("in%2Fa%20b"), "in/a b");
        assert_eq!(decode("r%C3%A4k"), "räk");
        assert_eq!(decode("%zz%4"), "%zz%4");
        assert_eq!(decode("%+f"), "%+f", "a sign is not a hex digit");
        assert_eq!(decode("a+b"), "a+b", "a plus is the form's, not the URI's");
    }

    #[test]
    fn strict_decoding_refuses_a_broken_escape_where_it_is() {
        assert_eq!(decode_strict(b"k-1%2Bz").expect("read"), b"k-1+z");
        assert_eq!(decode_strict(b"x%zz"), Err(BrokenEscape { at: 1 }));
        assert_eq!(decode_strict(b"ab%4"), Err(BrokenEscape { at: 2 }));
        assert_eq!(decode_strict(b"%+f"), Err(BrokenEscape { at: 0 }));
        assert_eq!(
            BrokenEscape { at: 7 }.to_string(),
            "a % without two hex digits at byte 7"
        );
    }
}

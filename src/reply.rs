//! The code a line-oriented server's reply opens with: three digits, the
//! first of them 1 to 5, then a space, a hyphen where more lines of the same
//! reply follow, or nothing (RFC 5321 section 4.2, RFC 959 section 4.2).
//!
//! One copy. Until 2026-09-27 FTP and SMTP each read the code themselves,
//! and only FTP's refused a code outside 100 to 599.

use crate::NetError;

/// The code `line` opens with, and whether the reply continues on the next
/// line (a hyphen after the code).
///
/// # Errors
///
/// Where `line` does not open with a reply code: three digits from 100 to
/// 599, followed by a space, a hyphen or the line's end.
pub fn code(line: &str) -> Result<(u16, bool), NetError> {
    let not_one = || NetError::new(format!("{line:?} does not open with a reply code"));
    let digits = line.get(..3).ok_or_else(not_one)?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(not_one());
    }
    let code: u16 = digits.parse().map_err(|_| not_one())?;
    if !(100..600).contains(&code) {
        return Err(not_one());
    }
    match line.as_bytes().get(3) {
        None | Some(b' ') => Ok((code, false)),
        Some(b'-') => Ok((code, true)),
        Some(_) => Err(not_one()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_code_opens_a_reply_line_and_says_whether_it_continues() {
        assert_eq!(code("220 ready").expect("220"), (220, false));
        assert_eq!(code("250-first").expect("250-"), (250, true));
        assert_eq!(code("354").expect("bare"), (354, false));
    }

    #[test]
    fn what_is_not_a_reply_code_is_refused() {
        for line in [
            "", "22", "hello", "999 no", "099 no", "+12 no", "2200 no", "22x ok",
        ] {
            assert!(code(line).is_err(), "{line:?}");
        }
    }
}

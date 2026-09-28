//! A size against the most a protocol, or Xmip, carries whole.
//!
//! A ceiling is a fact about the protocol, written where it comes from
//! (ADR-0028, amendment 2026-09-09; ADR-0051 clause 2): the number is the
//! technology's — one datagram's 65 507 bytes, one SQS message's 256 KiB,
//! [`crate::MAX_BODY`] where the protocol states none — and so is the
//! phrase that says what carries it. The refusal is one sentence
//! everywhere: every technology's send, encoder and loopback, the
//! Playground, the HTTP body and [`crate::read`] word it here.

use crate::NetError;

/// `Ok` when `size` bytes fit under `ceiling`; otherwise the refusal,
/// `"<size> bytes is over the <ceiling> <carrier>"`, where `carrier` says
/// what holds that many: `"one datagram carries"`, `"Xmip reads in one
/// body"`.
///
/// # Errors
/// Where `size` is over `ceiling`: the peer's or the payload's failure, not
/// the connection's, so it will say the same thing next time.
pub fn within(size: usize, ceiling: usize, carrier: &str) -> Result<(), NetError> {
    if size > ceiling {
        return Err(NetError::new(format!(
            "{size} bytes is over the {ceiling} {carrier}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_at_the_ceiling_fits_and_one_byte_over_is_refused_permanently() {
        assert!(within(8, 8, "one test frame carries").is_ok());
        let error = within(9, 8, "one test frame carries").expect_err("over");
        assert_eq!(
            error.message,
            "9 bytes is over the 8 one test frame carries"
        );
        assert!(
            error.io.is_none(),
            "the payload's failure, not the connection's"
        );
    }
}

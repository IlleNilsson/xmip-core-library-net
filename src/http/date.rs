//! The moment a header carries, as RFC 1123 writes it:
//! `Tue, 08 Sep 2026 12:00:00 GMT`, RFC 9110's `HTTP-date`, what `Date`
//! and Azure's `x-ms-date` take. It is written off `codec::civil`, the
//! estate's one civil calendar; s3 and azure-blob each carried the clock
//! until 2026-09-14, and this file until 2026-09-24. A header format is
//! HTTP's: the http transport held it until 2026-09-28, when it came here
//! beside the codec that writes the header, so a crate that signs a header
//! reaches it without the transport.
//!
//! `x-amz-date`, the basic ISO 8601 `20260908T120000Z`, lived here beside
//! it until 2026-09-24; it is AWS's, and is written by the signer in
//! `xmip-core-transport-aws` that reads it.
//!
//! The moment is a parameter, seconds since the Unix epoch: this reads no
//! clock (ADR-0068, amendment 2026-11-14).

use codec::civil::CivilTime;

/// The moment `unix_seconds` after the epoch as RFC 1123 writes it:
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
#[must_use]
pub fn rfc1123(unix_seconds: i64) -> String {
    const DAYS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let moment = CivilTime::from_unix(unix_seconds);
    let weekday = DAYS[moment.weekday() as usize % 7];
    let month = MONTHS[(moment.month as usize + 11) % 12];
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        moment.day, moment.year, moment.hour, moment.minute, moment.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_date_is_written_as_rfc_1123_writes_it() {
        assert_eq!(rfc1123(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(rfc1123(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(rfc1123(1_800_000_000), "Fri, 15 Jan 2027 08:00:00 GMT");
    }
}

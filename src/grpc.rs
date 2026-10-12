//! gRPC on HTTP/2, the parts every caller of it shares, once: a message
//! as gRPC frames it on a stream — one byte saying whether it is
//! compressed, four bytes of its length big-endian, the message — and
//! the status codes its `grpc-status` trailer carries, by name.
//!
//! What a message is — protobuf, or JSON as `application/grpc+json`
//! says — is the caller's; the connection is [`crate::http2`]'s, and
//! TLS agrees `h2` by ALPN. The gRPC logic technology frames with this,
//! and so does the operate plane between a surface and a node.

use crate::NetError;

/// The content type of a gRPC request and its answer.
pub const CONTENT_TYPE: &str = "application/grpc";

/// The content type of a gRPC call whose messages are JSON.
pub const CONTENT_TYPE_JSON: &str = "application/grpc+json";

/// The trailer an answer's status is carried in.
pub const STATUS: &str = "grpc-status";

/// The trailer a non-zero status's words are carried in.
pub const MESSAGE: &str = "grpc-message";

/// The status codes, by the names gRPC gives them, in code order.
pub const CODES: [&str; 17] = [
    "OK",
    "CANCELLED",
    "UNKNOWN",
    "INVALID_ARGUMENT",
    "DEADLINE_EXCEEDED",
    "NOT_FOUND",
    "ALREADY_EXISTS",
    "PERMISSION_DENIED",
    "RESOURCE_EXHAUSTED",
    "FAILED_PRECONDITION",
    "ABORTED",
    "OUT_OF_RANGE",
    "UNIMPLEMENTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DATA_LOSS",
    "UNAUTHENTICATED",
];

/// The code a status name, or a code already, stands for: `UNKNOWN`'s
/// where it is neither.
#[must_use]
pub fn code(name: &str) -> u8 {
    CODES
        .iter()
        .position(|known| *known == name)
        .and_then(|code| u8::try_from(code).ok())
        .or_else(|| name.parse::<u8>().ok())
        .unwrap_or(2)
}

/// `message` as one length-prefixed frame, not compressed.
///
/// # Errors
///
/// A message over four gigabytes, which no frame holds.
pub fn frame(message: &[u8]) -> Result<Vec<u8>, NetError> {
    let length = u32::try_from(message.len())
        .map_err(|_| NetError::new("a message over 4 GiB does not fit a gRPC frame"))?;
    let mut out = Vec::with_capacity(5 + message.len());
    out.push(0);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// The first message in a body of frames, and whether it was flagged
/// compressed.
///
/// # Errors
///
/// A body shorter than a frame's prefix, or than the length it claims.
pub fn unframe(body: &[u8]) -> Result<(&[u8], bool), NetError> {
    let Some((prefix, rest)) = body.split_first_chunk::<5>() else {
        return Err(NetError::new(
            "the body is shorter than a gRPC frame prefix",
        ));
    };
    let compressed = prefix[0] != 0;
    let length = u32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]) as usize;
    rest.get(..length)
        .map(|message| (message, compressed))
        .ok_or_else(|| {
            NetError::new(format!(
                "the frame claims {length} bytes, the body has fewer"
            ))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_round_trips_through_its_frame() {
        let framed = frame(b"{}").expect("framed");
        assert_eq!(framed, b"\0\0\0\0\x02{}");
        assert_eq!(unframe(&framed).expect("read"), (&b"{}"[..], false));
    }

    #[test]
    fn a_short_body_is_refused_in_words() {
        assert!(unframe(b"\0\0").is_err());
        assert!(unframe(b"\0\0\0\0\x09{}").is_err());
    }

    #[test]
    fn a_status_is_read_by_its_name_or_its_number() {
        assert_eq!(code("OK"), 0);
        assert_eq!(code("UNIMPLEMENTED"), 12);
        assert_eq!(code("14"), 14);
        assert_eq!(code("no such status"), 2);
    }
}

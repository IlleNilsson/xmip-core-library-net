//! A frame as Xmip's own node-to-node protocols write one: its length,
//! four bytes big-endian, then that many bytes, never more than
//! [`crate::MAX_BODY`].
//!
//! Xmip Storage's wire and the Event link between nodes both speak in
//! these frames; what a frame holds is each protocol's. [`write`] puts one
//! frame on a connection in one write, [`append`] adds one to what is
//! about to be written, and [`read`] takes one off, telling
//! a peer that closed between frames ([`None`]) from one that broke off
//! inside one, by [`crate::read::header`].

use std::io::{Read, Write};

use crate::ceiling::within;
use crate::read::header;
use crate::{MAX_BODY, NetError};

/// What a refusal says carries a frame.
const CARRIER: &str = "Xmip carries in one frame";

/// Write `bytes` as one frame and flush it.
///
/// # Errors
///
/// Where `bytes` are over [`MAX_BODY`], or the connection fails.
pub fn write(connection: &mut impl Write, bytes: &[u8]) -> Result<(), NetError> {
    let mut frame = Vec::with_capacity(4 + bytes.len());
    append(&mut frame, bytes)?;
    connection
        .write_all(&frame)
        .and_then(|()| connection.flush())
        .map_err(|failed| NetError::from_io("writing a frame", &failed))
}

/// Append `bytes` to `out` as one frame, so several frames go out in one
/// write.
///
/// # Errors
///
/// Where `bytes` are over [`MAX_BODY`].
pub fn append(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), NetError> {
    within(bytes.len(), MAX_BODY, CARRIER)?;
    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Read one frame: its bytes, or `None` where the connection ended cleanly
/// before a frame began.
///
/// # Errors
///
/// Where the connection fails or ends inside a frame, or the frame says it
/// is over [`MAX_BODY`].
pub fn read(connection: &mut impl Read) -> Result<Option<Vec<u8>>, NetError> {
    let Some(length) = header::<4>(connection, "a frame's length")? else {
        return Ok(None);
    };
    let length = u32::from_be_bytes(length) as usize;
    within(length, MAX_BODY, CARRIER)?;
    let mut bytes = vec![0u8; length];
    connection
        .read_exact(&mut bytes)
        .map_err(|failed| NetError::from_io("reading a frame", &failed))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;

    #[test]
    fn a_frame_crosses_as_it_was_and_a_close_between_frames_is_none() {
        let mut wire = Vec::new();
        write(&mut wire, b"one").expect("written");
        write(&mut wire, b"").expect("an empty frame");
        let mut reading = wire.as_slice();

        assert_eq!(read(&mut reading).expect("read"), Some(b"one".to_vec()));
        assert_eq!(read(&mut reading).expect("read"), Some(Vec::new()));
        assert_eq!(read(&mut reading).expect("a clean close"), None);
    }

    #[test]
    fn a_frame_cut_short_or_claiming_too_much_is_refused() {
        let mut wire = Vec::new();
        write(&mut wire, b"whole").expect("written");
        let cut = &wire[..wire.len() - 1];
        assert_eq!(
            read(&mut &cut[..]).expect_err("cut short").io,
            Some(ErrorKind::UnexpectedEof)
        );

        let claims = u32::MAX.to_be_bytes();
        let refused = read(&mut &claims[..]).expect_err("over the ceiling");
        assert!(
            refused.message.contains("Xmip carries in one frame"),
            "{refused:?}"
        );
    }
}

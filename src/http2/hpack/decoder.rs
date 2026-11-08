//! The decoding side of RFC 7541 section 6: a header block read field by
//! field, indexed or literal, into the list it carries, keeping the
//! dynamic table the encoder on the other side keeps.
//!
//! A list is decoded under a limit, `SETTINGS_MAX_HEADER_LIST_SIZE`, its
//! size counted as it is read, each field at its name, its value and 32
//! octets (section 4.1). Once the count passes the limit no field is kept,
//! and the rest of the block is still read, so the dynamic table stays in
//! step with the peer's encoder: RFC 9113 section 10.5.1 asks a header
//! block over what a side handles to be processed all the same, unless the
//! connection is closed. Being over is no breach of HPACK, so it is no
//! `COMPRESSION_ERROR`; the caller refuses the stream, and the connection
//! goes on. An indexed field referenced a million times costs a million
//! lookups and nothing held.

use std::borrow::Cow;

use super::table::{Table, cost};
use super::{integer, literal};
use crate::http2::error::Violation;

/// A header block decoded under a limit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Decoded {
    /// Every field, in order, within the limit.
    Fields(Vec<(String, String)>),
    /// The size the list came to, over the limit: no field was kept, and
    /// the table was kept in step all the same.
    Over(usize),
}

/// One side's decoder: its dynamic table, and the most a size update from
/// the encoder may set it to — the `SETTINGS_HEADER_TABLE_SIZE` this side
/// announced.
#[derive(Clone, Debug)]
pub struct Decoder {
    table: Table,
    limit: usize,
}

impl Decoder {
    /// A decoder whose table may hold at most `limit` octets.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            table: Table::new(limit),
            limit,
        }
    }

    /// The dynamic table as it stands.
    #[must_use]
    pub const fn table(&self) -> &Table {
        &self.table
    }

    /// Every field of `block`, in order, while the list's size stays
    /// within `most` octets; past it, the size alone.
    ///
    /// # Errors
    ///
    /// A `COMPRESSION_ERROR` where a field is broken, an index is past the
    /// table, or a size update comes after a field or over the limit
    /// (section 4.2).
    pub fn decode(&mut self, block: &[u8], most: usize) -> Result<Decoded, Violation> {
        let mut fields = Vec::new();
        let mut size = 0usize;
        let mut field_seen = false;
        let mut at = 0;
        while at < block.len() {
            let rest = &block[at..];
            let first = rest[0];
            if first & 0xe0 == 0x20 {
                if field_seen {
                    return Err(Violation::compression(
                        "a table size update after the first field",
                    ));
                }
                at += self.size_update(rest)?;
                continue;
            }
            field_seen = true;
            let (field, used) = self.field(rest)?;
            at += used;
            size = size.saturating_add(cost(&field.0, &field.1));
            if size <= most {
                fields.push((field.0.into_owned(), field.1.into_owned()));
            } else if !fields.is_empty() {
                fields = Vec::new();
            }
        }
        if size > most {
            return Ok(Decoded::Over(size));
        }
        Ok(Decoded::Fields(fields))
    }

    /// One field at the start of `input`, borrowed from the table where it
    /// is indexed, and the octets it took; a field with incremental
    /// indexing (01) is added to the table on the way.
    fn field<'a>(&'a mut self, input: &[u8]) -> Result<(Field<'a>, usize), Violation> {
        let first = input[0];
        if first & 0x80 != 0 {
            let (index, used) = integer::decode(input, 7)?;
            let (name, value) = self.table.get(index)?;
            return Ok(((Cow::Borrowed(name), Cow::Borrowed(value)), used));
        }
        if first & 0x40 != 0 {
            let (name, value, used) = self.literal(input, 6)?;
            let (name, value) = (name.into_owned(), value);
            self.table.insert(name.clone(), value.clone());
            return Ok(((Cow::Owned(name), Cow::Owned(value)), used));
        }
        // Without indexing (0000) and never indexed (0001) read alike;
        // neither touches the table.
        let (name, value, used) = self.literal(input, 4)?;
        Ok(((name, Cow::Owned(value)), used))
    }

    /// A dynamic table size update (001), and the octets it took.
    fn size_update(&mut self, input: &[u8]) -> Result<usize, Violation> {
        let (size, used) = integer::decode(input, 5)?;
        if size > self.limit {
            return Err(Violation::compression(format!(
                "a table size of {size}, over the {} announced",
                self.limit
            )));
        }
        self.table.resize(size);
        Ok(used)
    }

    /// A literal field whose name is indexed in a `prefix`-bit prefix, or
    /// follows as a string where the index is 0.
    fn literal(
        &self,
        input: &[u8],
        prefix: u8,
    ) -> Result<(Cow<'_, str>, String, usize), Violation> {
        let (index, mut at) = integer::decode(input, prefix)?;
        let name = if index == 0 {
            let (name, used) = literal::decode(&input[at..])?;
            at += used;
            Cow::Owned(name)
        } else {
            Cow::Borrowed(self.table.get(index)?.0)
        };
        let (value, used) = literal::decode(&input[at..])?;
        Ok((name, value, at + used))
    }
}

/// A field as it is read: borrowed from the table, or owned where the
/// block spelled it.
type Field<'a> = (Cow<'a, str>, Cow<'a, str>);

#[cfg(test)]
mod tests {
    use super::*;

    /// Every field of `block`, under no limit.
    fn all(decoder: &mut Decoder, block: &[u8]) -> Result<Vec<(String, String)>, Violation> {
        match decoder.decode(block, usize::MAX)? {
            Decoded::Fields(fields) => Ok(fields),
            Decoded::Over(size) => panic!("{size} octets over no limit"),
        }
    }

    #[test]
    fn a_size_update_goes_first_and_stays_under_the_limit() {
        let mut decoder = Decoder::new(4096);
        // 0x3f 0xe1 0x1f: a size update to 4096.
        assert!(all(&mut decoder, &[0x3f, 0xe1, 0x1f, 0x82]).is_ok());
        assert!(all(&mut decoder, &[0x20]).is_ok());
        assert_eq!(decoder.table().max_size(), 0);
        assert!(all(&mut decoder, &[0x82, 0x20]).is_err());
        assert!(all(&mut decoder, &[0x3f, 0xe2, 0x1f]).is_err());
        assert!(all(&mut decoder, &[0x80]).is_err());
        assert!(all(&mut decoder, &[0xbe]).is_err());
    }

    /// A literal with incremental indexing of a new name `x`, its value
    /// `value` octets long: one entry of the dynamic table, at index 62.
    fn indexed_entry(value: usize) -> Vec<u8> {
        let mut block = vec![0x40, 0x01, b'x'];
        integer::encode(value, 7, 0, &mut block);
        block.resize(block.len() + value, b'v');
        block
    }

    #[test]
    fn a_bomb_of_references_to_one_entry_is_counted_and_never_held() {
        // A 4 000-octet entry referenced 250 000 times: about a gigabyte
        // decoded, from a block of a quarter of a megabyte.
        let mut block = indexed_entry(4000);
        block.resize(block.len() + 250_000, 0xbe);
        let mut decoder = Decoder::new(4096);
        let Decoded::Over(size) = decoder.decode(&block, 64 * 1024).expect("decoded") else {
            panic!("a gigabyte within 64 KiB");
        };
        assert_eq!(size, 250_001 * (1 + 4000 + 32));
        // The table kept in step: the entry is there for the next block.
        let next = all(&mut decoder, &[0xbe]).expect("in step");
        assert_eq!(next, [("x".to_string(), "v".repeat(4000))]);
    }

    #[test]
    fn a_list_at_its_limit_is_kept_and_one_octet_over_is_not() {
        // :method GET is 7 + 3 + 32 = 42 octets.
        let mut decoder = Decoder::new(4096);
        let kept = decoder.decode(&[0x82, 0x82], 84).expect("decoded");
        assert_eq!(
            kept,
            Decoded::Fields(vec![(":method".into(), "GET".into()); 2])
        );
        let over = decoder.decode(&[0x82, 0x82], 83).expect("decoded");
        assert_eq!(over, Decoded::Over(84));
        assert!(
            decoder.decode(&[0x82, 0x80], 10).is_err(),
            "still checked when over"
        );
    }
}

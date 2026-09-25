//! The decoding side of RFC 7541 section 6: a header block read field by
//! field, indexed or literal, into the list it carries, keeping the
//! dynamic table the encoder on the other side keeps.

use super::table::Table;
use super::{integer, literal};
use crate::http2::error::Violation;

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

    /// Every field of `block`, in order.
    ///
    /// # Errors
    ///
    /// A `COMPRESSION_ERROR` where a field is broken, an index is past the
    /// table, or a size update comes after a field or over the limit
    /// (section 4.2).
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, Violation> {
        let mut fields = Vec::new();
        let mut at = 0;
        while at < block.len() {
            let rest = &block[at..];
            let first = rest[0];
            at += if first & 0x80 != 0 {
                let (index, used) = integer::decode(rest, 7)?;
                let (name, value) = self.table.get(index)?;
                fields.push((name.to_string(), value.to_string()));
                used
            } else if first & 0x40 != 0 {
                let (name, value, used) = self.literal(rest, 6)?;
                self.table.insert(name.clone(), value.clone());
                fields.push((name, value));
                used
            } else if first & 0x20 != 0 {
                if !fields.is_empty() {
                    return Err(Violation::compression(
                        "a table size update after the first field",
                    ));
                }
                let (size, used) = integer::decode(rest, 5)?;
                if size > self.limit {
                    return Err(Violation::compression(format!(
                        "a table size of {size}, over the {} announced",
                        self.limit
                    )));
                }
                self.table.resize(size);
                used
            } else {
                // Without indexing (0000) and never indexed (0001) read
                // alike; neither touches the table.
                let (name, value, used) = self.literal(rest, 4)?;
                fields.push((name, value));
                used
            };
        }
        Ok(fields)
    }

    /// A literal field whose name is indexed in a `prefix`-bit prefix, or
    /// follows as a string where the index is 0.
    fn literal(&self, input: &[u8], prefix: u8) -> Result<(String, String, usize), Violation> {
        let (index, mut at) = integer::decode(input, prefix)?;
        let name = if index == 0 {
            let (name, used) = literal::decode(&input[at..])?;
            at += used;
            name
        } else {
            self.table.get(index)?.0.to_string()
        };
        let (value, used) = literal::decode(&input[at..])?;
        Ok((name, value, at + used))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_size_update_goes_first_and_stays_under_the_limit() {
        let mut decoder = Decoder::new(4096);
        // 0x3f 0xe1 0x1f: a size update to 4096.
        assert!(decoder.decode(&[0x3f, 0xe1, 0x1f, 0x82]).is_ok());
        assert!(decoder.decode(&[0x20]).is_ok());
        assert_eq!(decoder.table().max_size(), 0);
        assert!(decoder.decode(&[0x82, 0x20]).is_err());
        assert!(decoder.decode(&[0x3f, 0xe2, 0x1f]).is_err());
        assert!(decoder.decode(&[0x80]).is_err());
        assert!(decoder.decode(&[0xbe]).is_err());
    }
}

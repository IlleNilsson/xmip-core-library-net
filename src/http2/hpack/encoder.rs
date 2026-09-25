//! The encoding side of RFC 7541 section 6: a header list written as a
//! block, each field indexed where the table holds it whole, otherwise a
//! literal added to the table, its name indexed where the table holds
//! that — the representations Appendix C shows.

use super::table::{Found, Table};
use super::{integer, literal};

/// One side's encoder: its dynamic table, whether strings are Huffman-coded,
/// and a size change the next block must announce.
#[derive(Clone, Debug)]
pub struct Encoder {
    table: Table,
    huffman: bool,
    pending: Option<usize>,
}

impl Encoder {
    /// An encoder with a table of `max_size` octets, Huffman-coding its
    /// strings where `huffman` says so.
    #[must_use]
    pub fn new(max_size: usize, huffman: bool) -> Self {
        Self {
            table: Table::new(max_size),
            huffman,
            pending: None,
        }
    }

    /// The dynamic table as it stands.
    #[must_use]
    pub const fn table(&self) -> &Table {
        &self.table
    }

    /// Hold the table to `max_size` octets — what the peer's
    /// `SETTINGS_HEADER_TABLE_SIZE` allows — and announce it at the start
    /// of the next block (section 4.2).
    pub fn resize(&mut self, max_size: usize) {
        if max_size != self.table.max_size() {
            self.table.resize(max_size);
            self.pending = Some(max_size);
        }
    }

    /// `fields` as one header block.
    #[must_use]
    pub fn encode<'a>(&mut self, fields: impl IntoIterator<Item = (&'a str, &'a str)>) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(size) = self.pending.take() {
            integer::encode(size, 5, 0x20, &mut out);
        }
        for (name, value) in fields {
            match self.table.find(name, value) {
                Some(Found::Field(index)) => integer::encode(index, 7, 0x80, &mut out),
                Some(Found::Name(index)) => {
                    integer::encode(index, 6, 0x40, &mut out);
                    literal::encode(value, self.huffman, &mut out);
                    self.table.insert(name.to_string(), value.to_string());
                }
                None => {
                    out.push(0x40);
                    literal::encode(name, self.huffman, &mut out);
                    literal::encode(value, self.huffman, &mut out);
                    self.table.insert(name.to_string(), value.to_string());
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http2::hpack::Decoder;

    #[test]
    fn a_smaller_table_is_announced_once_at_the_start_of_the_next_block() {
        let mut encoder = Encoder::new(4096, false);
        let mut decoder = Decoder::new(4096);
        let first = encoder.encode([("x-a", "1")]);
        decoder.decode(&first).expect("first");
        encoder.resize(0);
        let second = encoder.encode([("x-a", "1")]);
        assert_eq!(second[0], 0x20);
        assert_eq!(
            decoder.decode(&second).expect("second"),
            [("x-a".into(), "1".into())]
        );
        assert_eq!(decoder.table().size(), 0);
        assert_ne!(encoder.encode([("x-a", "1")])[0], 0x20);
    }
}

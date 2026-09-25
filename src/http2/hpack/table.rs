//! The header table of RFC 7541 section 2.3: the static table of Appendix
//! A at indices 1 to 61, and the dynamic table after it, newest first,
//! each entry counted at its name, its value and 32 octets, the oldest
//! evicted to make room (section 4).

use std::collections::VecDeque;

use crate::http2::error::Violation;

/// The static table of Appendix A, index 1 first.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// What an entry costs beside its name and value (section 4.1).
const OVERHEAD: usize = 32;

/// Where a field was found: the index of the whole field, or only of its
/// name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Found {
    Field(usize),
    Name(usize),
}

/// The static table and one side's dynamic table.
#[derive(Clone, Debug)]
pub struct Table {
    entries: VecDeque<(String, String)>,
    size: usize,
    max_size: usize,
}

impl Table {
    /// An empty dynamic table of at most `max_size` octets.
    #[must_use]
    pub fn new(max_size: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    /// The octets the dynamic table holds.
    #[must_use]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// The octets it may hold.
    #[must_use]
    pub const fn max_size(&self) -> usize {
        self.max_size
    }

    /// The dynamic entries, newest first.
    pub fn dynamic(&self) -> impl Iterator<Item = &(String, String)> {
        self.entries.iter()
    }

    /// The field at `index`, static or dynamic.
    ///
    /// # Errors
    ///
    /// A `COMPRESSION_ERROR` for 0 or an index past the table's end.
    pub fn get(&self, index: usize) -> Result<(&str, &str), Violation> {
        if let Some(&(name, value)) = index.checked_sub(1).and_then(|at| STATIC.get(at)) {
            return Ok((name, value));
        }
        index
            .checked_sub(STATIC.len() + 1)
            .and_then(|at| self.entries.get(at))
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .ok_or_else(|| Violation::compression(format!("no header at index {index}")))
    }

    /// Where `name` and `value` are: the whole field wherever it is, else
    /// the name, the static table before the dynamic one.
    #[must_use]
    pub fn find(&self, name: &str, value: &str) -> Option<Found> {
        let dynamic = || self.entries.iter().enumerate();
        let at_static = |at: usize| at + 1;
        let at_dynamic = |at: usize| at + STATIC.len() + 1;
        STATIC
            .iter()
            .position(|&(n, v)| n == name && v == value)
            .map(|at| Found::Field(at_static(at)))
            .or_else(|| {
                dynamic()
                    .find(|(_, (n, v))| n == name && v == value)
                    .map(|(at, _)| Found::Field(at_dynamic(at)))
            })
            .or_else(|| {
                STATIC
                    .iter()
                    .position(|&(n, _)| n == name)
                    .map(|at| Found::Name(at_static(at)))
            })
            .or_else(|| {
                dynamic()
                    .find(|(_, (n, _))| n == name)
                    .map(|(at, _)| Found::Name(at_dynamic(at)))
            })
    }

    /// Add a field at the front, evicting the oldest until it fits; one
    /// larger than the whole table empties it and is not added (section
    /// 4.4).
    pub fn insert(&mut self, name: String, value: String) {
        let cost = name.len() + value.len() + OVERHEAD;
        self.evict(self.max_size.saturating_sub(cost));
        if cost <= self.max_size {
            self.size += cost;
            self.entries.push_front((name, value));
        }
    }

    /// Change the size it may hold, evicting what no longer fits (section
    /// 4.3).
    pub fn resize(&mut self, max_size: usize) {
        self.max_size = max_size;
        self.evict(max_size);
    }

    fn evict(&mut self, room: usize) {
        while self.size > room {
            match self.entries.pop_back() {
                Some((name, value)) => self.size -= name.len() + value.len() + OVERHEAD,
                None => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_static_table_is_appendix_a_and_the_dynamic_follows_it() {
        let mut table = Table::new(4096);
        assert_eq!(table.get(1).expect("1"), (":authority", ""));
        assert_eq!(table.get(61).expect("61"), ("www-authenticate", ""));
        assert!(table.get(0).is_err());
        assert!(table.get(62).is_err());
        table.insert("custom-key".into(), "custom-header".into());
        assert_eq!(table.get(62).expect("62"), ("custom-key", "custom-header"));
        assert_eq!(table.size(), 55);
        assert_eq!(table.find(":method", "GET"), Some(Found::Field(2)));
        assert_eq!(table.find(":method", "PUT"), Some(Found::Name(2)));
        assert_eq!(
            table.find("custom-key", "custom-header"),
            Some(Found::Field(62))
        );
        assert_eq!(table.find("custom-key", "other"), Some(Found::Name(62)));
        assert_eq!(table.find("x-other", ""), None);
    }

    #[test]
    fn the_oldest_is_evicted_and_an_entry_larger_than_the_table_empties_it() {
        let mut table = Table::new(100);
        table.insert("a".into(), "1".repeat(20)); // 53
        table.insert("b".into(), "2".repeat(20)); // 53: evicts a
        assert_eq!(table.dynamic().count(), 1);
        assert_eq!(table.get(62).expect("b").0, "b");
        table.resize(40);
        assert_eq!((table.size(), table.dynamic().count()), (0, 0));
        table.resize(100);
        table.insert("c".into(), "3".repeat(10));
        table.insert("d".into(), "4".repeat(100));
        assert_eq!((table.size(), table.dynamic().count()), (0, 0));
    }
}

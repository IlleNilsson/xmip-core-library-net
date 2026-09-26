//! One HTTP answer, whichever version carried it: its status and phrase,
//! its headers, its body put back together and its trailers.

use super::{find, reason};
use crate::NetError;

/// One answer, the body put back together where it was chunked.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    /// The phrase after the status, as the server wrote it:
    /// `Unauthorized`. HTTP/2 carries none, and [`reason`] fills it.
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The fields after the body: HTTP/2's trailing `HEADERS`, or the
    /// trailer of a chunked HTTP/1.1 answer — where gRPC puts its status.
    pub trailers: Vec<(String, String)>,
}

impl Response {
    /// `status`, with the phrase [`reason`] writes it with.
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            reason: reason(status).to_string(),
            ..Self::default()
        }
    }

    /// With one more header.
    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// With `bytes` as the body.
    #[must_use]
    pub fn body(mut self, bytes: &[u8]) -> Self {
        self.body = bytes.to_vec();
        self
    }

    /// With one more trailer field.
    #[must_use]
    pub fn trailer(mut self, name: &str, value: &str) -> Self {
        self.trailers.push((name.to_string(), value.to_string()));
        self
    }

    /// One header's value, however it was capitalised.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// One trailer field's value, however it was capitalised.
    #[must_use]
    pub fn trailer_value(&self, name: &str) -> Option<&str> {
        find(&self.trailers, name)
    }

    /// The body as UTF-8 text, for an answer a protocol writes as text — a
    /// service's XML or JSON, an error's detail. A payload is bytes and is
    /// read from [`Response::body`]; nothing here decodes it lossily.
    ///
    /// # Errors
    ///
    /// Where the body is not UTF-8, naming the first byte that is not.
    pub fn text(&self) -> Result<&str, NetError> {
        std::str::from_utf8(&self.body).map_err(|refused| {
            NetError::new(format!(
                "the answer's body is not UTF-8 text: {refused} (status {})",
                self.status
            ))
        })
    }
}

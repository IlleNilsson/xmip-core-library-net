//! The asking side of HTTP/2: a connection started with the preface, a
//! request sent on a new odd stream, its answer read back whole — head,
//! body and trailers — and one request after another on the same
//! connection until either side goes away.

use std::io::{ErrorKind, Read, Write};

use super::connection::{Connection, refused};
use super::error::ErrorCode;
use super::frame::MAX_STREAM_ID;
use super::message::{request_fields, response_of};
use crate::NetError;
use crate::http::{Request, Response};

/// A client connection over `S`: a socket, or one TLS agreed `h2` on.
pub struct Client<S: Read + Write> {
    connection: Connection<S>,
    scheme: String,
    next: u32,
}

impl<S: Read + Write> Client<S> {
    /// Start a connection over `io` for a service at `scheme` — `http` or
    /// `https`, which each request's `:scheme` names.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub fn handshake(io: S, scheme: &str) -> Result<Self, NetError> {
        Ok(Self {
            connection: Connection::start(io, true)?,
            scheme: scheme.to_string(),
            next: 1,
        })
    }

    /// Send `request` on a stream of its own and read its answer.
    ///
    /// # Errors
    ///
    /// Where the connection broke or closed before the answer ended, the
    /// server reset the stream, or it has gone away — a refusal that
    /// carries `ConnectionAborted`, since nothing was processed and the
    /// request may be sent again on a new connection.
    pub fn send(&mut self, request: &Request) -> Result<Response, NetError> {
        if let Some((last, code)) = self.connection.goaway {
            let mut failure = NetError::new(format!(
                "the server went away ({code:?}) after stream {last}; the request was not sent"
            ));
            failure.io = Some(ErrorKind::ConnectionAborted);
            return Err(failure);
        }
        let id = self.next;
        if id > MAX_STREAM_ID {
            return Err(NetError::new("the connection has used every stream it has"));
        }
        self.next += 2;
        self.connection.open(id);
        let fields = request_fields(&self.scheme, request);
        let bodiless = request.body.is_empty();
        self.connection.send_headers(id, &fields, bodiless)?;
        if !bodiless {
            self.connection.send_data(id, &request.body, true)?;
        }
        while self
            .connection
            .streams
            .get(&id)
            .is_some_and(|stream| !stream.finished())
        {
            if !self.connection.pump()? {
                self.connection.streams.remove(&id);
                return Err(NetError::new(
                    "the connection closed before the answer ended",
                ));
            }
        }
        let stream = self
            .connection
            .streams
            .remove(&id)
            .ok_or_else(|| NetError::new("the stream was lost"))?;
        if let Some(code) = stream.reset {
            return Err(refused(id, code));
        }
        let head = stream
            .head
            .ok_or_else(|| NetError::new("the answer ended without a head"))?;
        Ok(response_of(head, stream.body, stream.trailers)?)
    }

    /// Send a `PING` and wait for it to come back: whether the connection
    /// is still alive.
    ///
    /// # Errors
    ///
    /// Where it is not.
    pub fn ping(&mut self) -> Result<(), NetError> {
        let opaque = u64::from(self.next).to_be_bytes();
        self.connection.ping(opaque)
    }

    /// How often a request's body waited for the server to open a window.
    #[must_use]
    pub const fn stalls(&self) -> usize {
        self.connection.stalls
    }

    /// Say goodbye with a `GOAWAY` and let the connection go. A server
    /// already gone is not a failure: every answer was read.
    pub fn close(mut self) {
        let _ = self.connection.go_away(ErrorCode::NoError, "");
    }
}

/// Send `request` over `io` on a connection of its own, for a service at
/// `scheme`, and read its answer: the HTTP/2 counterpart of
/// [`crate::http::exchange`].
///
/// # Errors
///
/// As [`Client::send`].
pub fn exchange<S: Read + Write>(
    io: S,
    scheme: &str,
    request: &Request,
) -> Result<Response, NetError> {
    let mut client = Client::handshake(io, scheme)?;
    let response = client.send(request)?;
    client.close();
    Ok(response)
}

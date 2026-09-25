//! The answering side of HTTP/2: a connection whose preface has been
//! read, each request taken whole off its stream as it ends, answered on
//! the same stream — head, body and trailers — and a `GOAWAY` when this
//! side is done.

use std::collections::BTreeSet;
use std::io::{Read, Write};

use super::connection::Connection;
use super::error::ErrorCode;
use super::message::{carried, request_of, response_fields};
use super::preface::PREFACE;
use crate::NetError;
use crate::http::{Request, Response};

/// The frames read after this side's `GOAWAY` while the client finishes,
/// so the connection is not closed under what it is still sending.
const DRAIN: usize = 1024;

/// A server connection over `S`.
pub struct Server<S: Read + Write> {
    connection: Connection<S>,
    /// The streams taken off and not yet answered.
    answering: BTreeSet<u32>,
}

impl<S: Read + Write> Server<S> {
    /// Read the client's preface off `io` and answer with this side's
    /// `SETTINGS`. A connection [`sniff`](super::sniff) looked at is read
    /// through [`Replayed`](super::Replayed), from its first octet.
    ///
    /// # Errors
    ///
    /// Where the connection broke, or did not open with the preface.
    pub fn handshake(mut io: S) -> Result<Self, NetError> {
        let mut preface = [0u8; PREFACE.len()];
        io.read_exact(&mut preface)
            .map_err(|failed| NetError::from_io("reading the preface", &failed))?;
        if &preface != PREFACE {
            return Err(NetError::new(
                "the connection did not open with the HTTP/2 preface",
            ));
        }
        Ok(Self {
            connection: Connection::start(io, false)?,
            answering: BTreeSet::new(),
        })
    }

    /// The next request whose stream the client has ended, and the stream
    /// to answer it on; `None` where the client went away or closed the
    /// connection.
    ///
    /// # Errors
    ///
    /// Where the connection broke, or the client breached it.
    pub fn next_request(&mut self) -> Result<Option<(u32, Request)>, NetError> {
        loop {
            let ready = self
                .connection
                .streams
                .iter()
                .find(|(id, stream)| stream.finished() && !self.answering.contains(id))
                .map(|(&id, _)| id);
            if let Some(id) = ready {
                let taken = self.connection.streams.get_mut(&id).and_then(|stream| {
                    let body = std::mem::take(&mut stream.body);
                    stream
                        .head
                        .take()
                        .filter(|_| stream.reset.is_none())
                        .map(|head| (head, body))
                });
                match taken.map(|(head, body)| request_of(head, body)) {
                    Some(Ok(request)) => {
                        self.answering.insert(id);
                        return Ok(Some((id, request)));
                    }
                    Some(Err(malformed)) => self.connection.reset(id, malformed.code)?,
                    // Reset, by the client or by this side.
                    None => {}
                }
                self.connection.streams.remove(&id);
                continue;
            }
            if self.connection.goaway.is_some() || !self.connection.pump()? {
                return Ok(None);
            }
        }
    }

    /// Answer the request taken off `stream` with `response`: its head,
    /// its body as the windows allow, and its trailers.
    ///
    /// # Errors
    ///
    /// Where the connection broke, or the client reset the stream.
    pub fn respond(&mut self, stream: u32, response: &Response) -> Result<(), NetError> {
        if !self.answering.remove(&stream) {
            return Err(NetError::new(format!(
                "no request waits on stream {stream}"
            )));
        }
        let head = response_fields(response);
        let trailers = carried(&response.trailers);
        let bodiless = response.body.is_empty();
        let answered = self
            .connection
            .send_headers(stream, &head, bodiless && trailers.is_empty())
            .and_then(|()| {
                if bodiless {
                    return Ok(());
                }
                self.connection
                    .send_data(stream, &response.body, trailers.is_empty())
            })
            .and_then(|()| {
                if trailers.is_empty() {
                    return Ok(());
                }
                self.connection.send_headers(stream, &trailers, true)
            });
        self.connection.streams.remove(&stream);
        answered
    }

    /// How often an answer's body waited for the client to open a window.
    #[must_use]
    pub const fn stalls(&self) -> usize {
        self.connection.stalls
    }

    /// Take no new stream: a `GOAWAY` naming the last one taken, which can
    /// still be answered. The client opens anything else on a new
    /// connection.
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub fn go_away(&mut self) -> Result<(), NetError> {
        self.connection.go_away(ErrorCode::NoError, "")
    }

    /// Go away gracefully: a `GOAWAY` naming the last stream taken, where
    /// [`Server::go_away`] has not sent one, then what the client still
    /// sends read until it closes — so the connection is not closed under
    /// unread octets, which would reset it and lose the answer's tail. A
    /// client already gone is not a failure: every answer was written.
    pub fn close(mut self) {
        if !self.connection.going_away {
            let _ = self.go_away();
        }
        for _ in 0..DRAIN {
            if !matches!(self.connection.pump(), Ok(true)) {
                break;
            }
        }
    }
}

/// Serve every request `io` carries with `answer`, until the client goes
/// away or closes: how many were answered.
///
/// # Errors
///
/// As [`Server::handshake`], [`Server::next_request`] and
/// [`Server::respond`].
pub fn serve<S: Read + Write>(
    io: S,
    mut answer: impl FnMut(&Request) -> Response,
) -> Result<usize, NetError> {
    let mut server = Server::handshake(io)?;
    let mut answered = 0;
    while let Some((stream, request)) = server.next_request()? {
        server.respond(stream, &answer(&request))?;
        answered += 1;
    }
    server.close();
    Ok(answered)
}

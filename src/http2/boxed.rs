//! HTTP/2 over a connection of any kind, its code compiled here, once:
//! [`Client`] and [`Server`] are generic over what they ride on, so each
//! crate that names a connection of its own compiles them again with its
//! own profile — a crate's tests unoptimized, where this crate's code is
//! optimized for every build. A caller that boxes its connection asks the
//! code compiled here. Measured 2026-10-21 in the runtime's tests: an
//! operate call on a node's local endpoint took about 0.4 ms of the
//! caller's processor time compiled in the runtime and about 0.13 ms
//! compiled as it ships (open problem 35).

use std::io::{Read, Write};

use super::{Client, Server};
use crate::NetError;
use crate::http::{Request, Response};

/// A connection's two directions.
pub trait Duplex: Read + Write {}

impl<T: Read + Write> Duplex for T {}

/// A connection of any kind, sendable to another thread, living `'a`.
pub type Boxed<'a> = Box<dyn Duplex + Send + 'a>;

/// [`Client`] over a [`Boxed`] connection.
pub struct BoxedClient<'a>(Client<Boxed<'a>>);

impl<'a> BoxedClient<'a> {
    /// As [`Client::handshake`].
    ///
    /// # Errors
    ///
    /// Where the connection broke.
    pub fn handshake(io: Boxed<'a>, scheme: &str) -> Result<Self, NetError> {
        Client::handshake(io, scheme).map(Self)
    }

    /// As [`Client::send`].
    ///
    /// # Errors
    ///
    /// As [`Client::send`].
    pub fn send(&mut self, request: &Request) -> Result<Response, NetError> {
        self.0.send(request)
    }

    /// As [`Client::close`].
    pub fn close(self) {
        self.0.close();
    }
}

/// [`Server`] over a [`Boxed`] connection.
pub struct BoxedServer<'a>(Server<Boxed<'a>>);

impl<'a> BoxedServer<'a> {
    /// As [`Server::handshake`].
    ///
    /// # Errors
    ///
    /// Where the connection broke or did not begin with the preface.
    pub fn handshake(io: Boxed<'a>) -> Result<Self, NetError> {
        Server::handshake(io).map(Self)
    }

    /// As [`Server::next_request`].
    ///
    /// # Errors
    ///
    /// As [`Server::next_request`].
    pub fn next_request(&mut self) -> Result<Option<(u32, Request)>, NetError> {
        self.0.next_request()
    }

    /// As [`Server::respond`].
    ///
    /// # Errors
    ///
    /// As [`Server::respond`].
    pub fn respond(&mut self, stream: u32, response: &Response) -> Result<(), NetError> {
        self.0.respond(stream, response)
    }

    /// As [`Server::close`].
    pub fn close(self) {
        self.0.close();
    }
}

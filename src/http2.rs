//! HTTP/2 on the wire, RFC 9113, both halves: a [`Client`] that sends a
//! request on a stream and reads its answer, and a [`Server`] that takes
//! requests off their streams and answers them — the same [`Request`] and
//! [`Response`] HTTP/1.1 carries, so a caller does not care which version
//! a connection speaks. Header blocks are compressed with HPACK, RFC 7541
//! ([`hpack`]).
//!
//! What is here: the connection preface ([`PREFACE`], and [`sniff`] to
//! tell it from an HTTP/1.1 request line), the ten frame types of section
//! 6 ([`frame`]), the settings and their acknowledgement ([`settings`]),
//! the stream states of section 5.1, flow control on the connection and
//! on each stream ([`window`]) — a body that meets a shut window waits,
//! reading what the peer sends, until a `WINDOW_UPDATE` opens it — and
//! the errors of section 7 ([`error`]), a breach of a stream answered
//! with `RST_STREAM` and of the connection with `GOAWAY`. A peer's
//! `GOAWAY` is honoured: a stream above the last it names was not
//! processed, and the request fails as refused rather than lost.
//!
//! Synchronous and hand-written, like every protocol in the estate: one
//! thread reads and writes, and a request waits for its answer. Server
//! push is off, which a client announces and a server never tries.
//!
//! No TLS here, as for HTTP/1.1: the caller opens the connection, and
//! `xmip-core-library-tls` agrees `h2` by ALPN ([`Version`]). Over
//! cleartext a connection speaks HTTP/2 only by prior knowledge; RFC 9113
//! removed the `Upgrade` from HTTP/1.1, and so is there none here.
//!
//! [`Request`]: crate::http::Request
//! [`Response`]: crate::http::Response
//! [`Version`]: crate::http::Version

mod client;
mod connection;
pub mod error;
pub mod frame;
pub mod hpack;
mod message;
mod preface;
mod receive;
mod server;
pub mod settings;
mod stream;
pub mod window;

pub use client::{Client, exchange};
pub use preface::{PREFACE, Replayed, sniff};
pub use server::{Server, serve};

#[cfg(test)]
mod tests {
    use super::error::ErrorCode;
    use super::frame::{self, ACK, Frame, Kind};
    use super::*;
    use crate::http::{Request, Response};
    use std::io::{ErrorKind, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread::JoinHandle;
    use std::time::Duration;

    const WAIT: Option<Duration> = Some(Duration::from_secs(10));

    /// A loopback connection: the far end handed to `far` on its own
    /// thread, the near end returned.
    fn pair<T: Send + 'static>(
        far: impl FnOnce(TcpStream) -> T + Send + 'static,
    ) -> (TcpStream, JoinHandle<T>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address");
        let serving = std::thread::spawn(move || {
            let (socket, _) = listener.accept().expect("accept");
            socket.set_read_timeout(WAIT).expect("timeout");
            far(socket)
        });
        let near = TcpStream::connect(address).expect("connect");
        near.set_read_timeout(WAIT).expect("timeout");
        (near, serving)
    }

    #[test]
    fn a_request_and_its_answer_round_trip_on_one_connection() {
        let (near, far) = pair(|socket| {
            serve(socket, |request| {
                let mut body = request.body.clone();
                body.reverse();
                Response::new(200)
                    .header("Content-Type", "text/plain")
                    .body(&body)
                    .trailer("x-checksum", &request.body.len().to_string())
            })
            .expect("served")
        });
        let mut client = Client::handshake(near, "http").expect("handshake");
        let posted = Request::new("POST", "/orders")
            .query("id", "7")
            .header("Host", "example")
            .body(b"abc");
        let answer = client.send(&posted).expect("answered");
        assert_eq!((answer.status, answer.reason.as_str()), (200, "OK"));
        assert_eq!(answer.body, b"cba");
        assert_eq!(answer.header_value("content-type"), Some("text/plain"));
        assert_eq!(answer.trailer_value("x-checksum"), Some("3"));
        let empty = client.send(&Request::new("GET", "/")).expect("second");
        assert!(empty.body.is_empty());
        client.ping().expect("pong");
        client.close();
        assert_eq!(far.join().expect("thread"), 2);
    }

    #[test]
    fn a_body_past_the_window_stalls_and_resumes_both_ways() {
        let big: Vec<u8> = (0..300_000u32)
            .map(|i| u8::try_from(i % 251).expect("byte"))
            .collect();
        let sent = big.clone();
        let (near, far) = pair(move |socket| {
            let mut server = Server::handshake(socket).expect("handshake");
            let (id, request) = server.next_request().expect("read").expect("one");
            assert_eq!(request.body, sent);
            server
                .respond(id, &Response::new(200).body(&sent))
                .expect("answered");
            let stalls = server.stalls();
            server.close();
            stalls
        });
        let mut client = Client::handshake(near, "http").expect("handshake");
        let answer = client
            .send(&Request::new("PUT", "/big").body(&big))
            .expect("answered");
        assert_eq!(answer.body, big);
        assert!(client.stalls() > 0, "the request never met a shut window");
        client.close();
        assert!(
            far.join().expect("thread") > 0,
            "the answer never met a shut window"
        );
    }

    #[test]
    fn a_goaway_lets_the_taken_stream_finish_and_refuses_the_next() {
        let (near, far) = pair(|socket| {
            let mut server = Server::handshake(socket).expect("handshake");
            let (id, _) = server.next_request().expect("read").expect("one");
            server.go_away().expect("going away");
            server.respond(id, &Response::new(204)).expect("answered");
            assert!(server.next_request().expect("read").is_none());
        });
        let mut client = Client::handshake(near, "http").expect("handshake");
        assert_eq!(
            client
                .send(&Request::new("GET", "/1"))
                .expect("first")
                .status,
            204
        );
        let refused = client.send(&Request::new("GET", "/2")).expect_err("gone");
        assert_eq!(refused.io, Some(ErrorKind::ConnectionAborted), "{refused}");
        drop(client);
        far.join().expect("thread");
    }

    #[test]
    fn a_stream_above_the_goaways_last_is_refused_as_not_processed() {
        let (near, far) = pair(|mut socket| {
            let mut preface = [0u8; 24];
            socket.read_exact(&mut preface).expect("preface");
            assert_eq!(&preface, PREFACE);
            frame::write(&mut socket, &Frame::new(Kind::Settings, 0, 0, Vec::new())).expect("s");
            frame::write(&mut socket, &Frame::goaway(0, ErrorCode::NoError, b"bye")).expect("g");
            let _ = socket.read_to_end(&mut Vec::new());
        });
        let mut client = Client::handshake(near, "https").expect("handshake");
        let refused = client.send(&Request::new("GET", "/")).expect_err("refused");
        assert_eq!(refused.io, Some(ErrorKind::ConnectionAborted), "{refused}");
        drop(client);
        far.join().expect("thread");
    }

    /// What a server answers a client that writes `frames` after its
    /// preface and `SETTINGS`: every frame, up to the connection's end.
    fn answered(frames: &[Frame]) -> Vec<Frame> {
        let (mut near, far) = pair(|socket| {
            let _ = serve(socket, |_| Response::new(200));
        });
        near.write_all(PREFACE).expect("preface");
        frame::write(&mut near, &Frame::new(Kind::Settings, 0, 0, Vec::new())).expect("settings");
        for sent in frames {
            frame::write(&mut near, sent).expect("frame");
        }
        near.flush().expect("flush");
        let mut back = Vec::new();
        while let Ok(Some(frame)) = frame::read(&mut near, 1 << 20) {
            let goaway = frame.kind == Kind::Goaway;
            back.push(frame);
            if goaway {
                break;
            }
        }
        drop(near);
        far.join().expect("thread");
        back
    }

    #[test]
    fn a_ping_is_answered_and_a_malformed_one_ends_the_connection() {
        let back = answered(&[
            Frame::ping(*b"xmip-h2!", false),
            Frame::new(Kind::Ping, 0, 0, vec![0; 7]),
        ]);
        let kinds: Vec<Kind> = back.iter().map(|frame| frame.kind).collect();
        assert_eq!(
            kinds,
            [Kind::Settings, Kind::Settings, Kind::Ping, Kind::Goaway]
        );
        assert!(back[1].has(ACK) && back[2].has(ACK));
        assert_eq!(back[2].payload, b"xmip-h2!");
        assert_eq!(back[3].word(4), Some(ErrorCode::FrameSize.code()));
    }

    #[test]
    fn a_window_update_of_zero_resets_its_stream_and_data_on_an_idle_one_ends_all() {
        let request = hpack::Encoder::new(4096, false).encode([
            (":method", "POST"),
            (":scheme", "http"),
            (":path", "/"),
        ]);
        let back = answered(&[
            Frame::new(Kind::Headers, frame::END_HEADERS, 1, request),
            Frame::window_update(1, 0),
            Frame::new(Kind::Data, 0, 9, b"x".to_vec()),
        ]);
        let reset = back
            .iter()
            .find(|frame| frame.kind == Kind::RstStream)
            .expect("reset");
        assert_eq!(
            (reset.stream, reset.word(0)),
            (1, Some(ErrorCode::Protocol.code()))
        );
        let goaway = back.last().expect("goaway");
        assert_eq!(goaway.kind, Kind::Goaway);
        assert_eq!(goaway.word(4), Some(ErrorCode::Protocol.code()));
    }

    #[test]
    fn a_header_block_split_over_continuation_is_read_whole() {
        let block = hpack::Encoder::new(4096, true).encode([
            (":method", "GET"),
            (":scheme", "http"),
            (":path", "/split"),
            (":authority", "example"),
        ]);
        let (first, rest) = block.split_at(3);
        let back = answered(&[
            Frame::new(Kind::Headers, frame::END_STREAM, 1, first.to_vec()),
            Frame::new(Kind::Continuation, frame::END_HEADERS, 1, rest.to_vec()),
            Frame::goaway(0, ErrorCode::NoError, b""),
        ]);
        let head = back
            .iter()
            .find(|frame| frame.kind == Kind::Headers)
            .expect("answer");
        assert_eq!(head.stream, 1);
        assert!(head.has(frame::END_STREAM));
    }
}

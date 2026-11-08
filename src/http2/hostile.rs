//! A hostile peer, frame by frame, on a connection in memory: each attack
//! of RFC 9113 section 10.5 and RFC 7541 section 7.3 written as the frames
//! that make it, and what the connection holds, answers and refuses
//! counted from its state and from what it wrote — never from a clock.

use std::cell::RefCell;
use std::io::{Cursor, Read, Write};
use std::rc::Rc;
use std::time::Duration;

use super::connection::Connection;
use super::error::ErrorCode;
use super::frame::{self, ACK, END_HEADERS, END_STREAM, Frame, Kind};
use super::hpack::{integer, table};
use super::{Limits, PREFACE, Server};

/// What the peer sends, read off in order, and what this side wrote.
struct Scripted {
    input: Cursor<Vec<u8>>,
    output: Rc<RefCell<Vec<u8>>>,
}

impl Read for Scripted {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(buf)
    }
}

impl Write for Scripted {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A peer that sends its `SETTINGS`, then `frames`; and what this side
/// writes, shared.
fn peer(frames: &[Frame]) -> (Scripted, Rc<RefCell<Vec<u8>>>) {
    let mut input = Vec::new();
    frame::write(&mut input, &Frame::new(Kind::Settings, 0, 0, Vec::new())).expect("settings");
    for sent in frames {
        frame::write(&mut input, sent).expect("frame");
    }
    let output = Rc::new(RefCell::new(Vec::new()));
    let scripted = Scripted {
        input: Cursor::new(input),
        output: Rc::clone(&output),
    };
    (scripted, output)
}

/// A server connection that has read every frame `frames` holds, or
/// ended the connection over one; whether it ended it.
fn served(frames: &[Frame], limits: Limits) -> (Connection<Scripted>, Vec<Frame>, bool) {
    let (scripted, output) = peer(frames);
    let mut connection = Connection::start(scripted, false, limits).expect("started");
    let ended = loop {
        match connection.pump() {
            Ok(true) => {}
            Ok(false) => break false,
            Err(_) => break true,
        }
    };
    let written = written(&output.borrow());
    (connection, written, ended)
}

/// Every frame in `bytes`.
fn written(mut bytes: &[u8]) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Ok(Some(frame)) = frame::read(&mut bytes, frame::MAX_FRAME_SIZE_LIMIT) {
        frames.push(frame);
    }
    frames
}

/// The code of the `GOAWAY` among `frames`.
fn goaway(frames: &[Frame]) -> Option<u32> {
    frames
        .iter()
        .find(|frame| frame.kind == Kind::Goaway)
        .and_then(|frame| frame.word(4))
}

/// The frames of `kind` on `stream` among `frames`.
fn count(frames: &[Frame], kind: Kind, stream: u32) -> usize {
    frames
        .iter()
        .filter(|frame| frame.kind == kind && frame.stream == stream)
        .count()
}

/// A request's head from the static table alone: `:method` GET or POST,
/// `:scheme` http, `:path` /.
fn head(id: u32, post: bool, flags: u8) -> Frame {
    let method = if post { 0x83 } else { 0x82 };
    Frame::new(
        Kind::Headers,
        END_HEADERS | flags,
        id,
        vec![method, 0x86, 0x84],
    )
}

/// Limits whose span no test outlives, so a count is never reset by time.
fn counted(control_frames: u32, empty_frames: u32) -> Limits {
    Limits {
        span: Duration::from_secs(3600),
        control_frames,
        empty_frames,
        ..Limits::DEFAULT
    }
}

#[test]
fn a_header_block_that_references_one_entry_a_quarter_million_times_holds_nothing() {
    // One 4 000-octet entry, then 250 000 references to it: about a
    // gigabyte decoded from a block of a quarter of a megabyte.
    let mut block = vec![0x40, 0x01, b'x'];
    integer::encode(4000, 7, 0, &mut block);
    block.resize(block.len() + 4000, b'v');
    block.resize(block.len() + 250_000, 0xbe);
    let pieces: Vec<&[u8]> = block.chunks(16_384).collect();
    let mut frames = vec![Frame::new(Kind::Headers, 0, 1, pieces[0].to_vec())];
    for (at, piece) in pieces.iter().enumerate().skip(1) {
        let flags = if at == pieces.len() - 1 {
            END_HEADERS
        } else {
            0
        };
        frames.push(Frame::new(Kind::Continuation, flags, 1, piece.to_vec()));
    }
    frames.push(Frame::new(Kind::Data, END_STREAM, 1, b"abc".to_vec()));
    frames.push(head(3, false, END_STREAM));
    let (connection, written, ended) = served(&frames, Limits::DEFAULT);

    assert!(!ended, "the connection goes on");
    assert_eq!(goaway(&written), None);
    let resets: Vec<_> = written
        .iter()
        .filter(|frame| frame.kind == Kind::RstStream)
        .map(|frame| (frame.stream, frame.word(0)))
        .collect();
    let closed = Some(ErrorCode::StreamClosed.code());
    assert_eq!(resets, [(1, Some(ErrorCode::Protocol.code())), (1, closed)]);
    let held: usize = connection
        .streams
        .values()
        .flat_map(|stream| stream.head.iter().flatten())
        .map(|(name, value)| table::cost(name, value))
        .sum();
    // :method GET, :scheme http and :path /, at 32 octets each beside.
    assert_eq!(held, 42 + 43 + 38, "only stream 3's head is held");
    assert!(connection.streams[&3].finished());
}

#[test]
fn bodies_on_every_stream_together_are_held_to_the_connections_window() {
    // Ten streams of 64 000 octets each, none ended, against a window of
    // 256 KiB: the peer that sends past it is refused.
    let limits = Limits {
        buffered: 256 * 1024,
        ..Limits::DEFAULT
    };
    let mut frames = Vec::new();
    for id in (1..20).step_by(2) {
        frames.push(head(id, true, 0));
        for _ in 0..4 {
            frames.push(Frame::new(Kind::Data, 0, id, vec![0; 16_000]));
        }
    }
    let (connection, written, ended) = served(&frames, limits);

    assert!(ended);
    assert_eq!(goaway(&written), Some(ErrorCode::FlowControl.code()));
    let held: usize = connection.streams.values().map(|s| s.body.len()).sum();
    assert!(held <= 256 * 1024, "{held} octets held");
    assert_eq!(held, 4 * 64_000, "every octet the window allowed is held");
    assert_eq!(
        count(&written, Kind::WindowUpdate, 0),
        1,
        "only the opening"
    );
    let refills: usize = (1..20)
        .step_by(2)
        .map(|id| count(&written, Kind::WindowUpdate, id))
        .sum();
    assert_eq!(refills, 4, "one per stream, never one per frame");
}

#[test]
fn a_body_taken_gives_its_window_back_so_the_next_one_fits() {
    // Two bodies of 90 000 octets through a window of 100 000: the second
    // fits only because the first was taken.
    let limits = Limits {
        buffered: 100_000,
        ..Limits::DEFAULT
    };
    let mut frames = Vec::new();
    for id in [1, 3] {
        frames.push(head(id, true, 0));
        for piece in 0..6 {
            let (size, flags) = if piece == 5 {
                (10_000, END_STREAM)
            } else {
                (16_000, 0)
            };
            frames.push(Frame::new(Kind::Data, flags, id, vec![1; size]));
        }
    }
    let (mut scripted, output) = peer(&frames);
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(scripted.input.get_ref());
    scripted.input = Cursor::new(wire);
    let mut server = Server::handshake_within(scripted, limits).expect("handshake");
    for id in [1, 3] {
        let (stream, request) = server.next_request().expect("read").expect("a request");
        assert_eq!((stream, request.body.len()), (id, 90_000));
    }
    let written = written(&output.borrow());
    let given: Vec<_> = written
        .iter()
        .filter(|frame| frame.kind == Kind::WindowUpdate && frame.stream == 0)
        .map(|frame| frame.word(0))
        .collect();
    // The opening, then each body as it was taken.
    assert_eq!(given, [Some(100_000 - 65_535), Some(90_000), Some(90_000)]);
}

#[test]
fn an_acknowledgement_of_a_ping_never_sent_is_let_go() {
    let frames: Vec<Frame> = (0..10_000u64)
        .map(|n| Frame::ping(n.to_be_bytes(), true))
        .collect();
    let (connection, written, ended) = served(&frames, counted(u32::MAX, u32::MAX));

    assert!(!ended);
    assert!(connection.outstanding.is_empty(), "nothing kept for them");
    assert_eq!(count(&written, Kind::Ping, 0), 0, "nothing answered");
}

/// The peer that floods with `flood` is told to calm down once it passes
/// the fifty its kind allows, and answered at most fifty times.
fn calmed(before: &[Frame], flood: &Frame) {
    let mut frames = before.to_vec();
    frames.extend(std::iter::repeat_n(flood.clone(), 10_000));
    let (_, written, ended) = served(&frames, counted(50, 50));

    assert!(ended, "{:?}", flood.kind);
    assert_eq!(goaway(&written), Some(ErrorCode::EnhanceYourCalm.code()));
    let answers = written
        .iter()
        .filter(|frame| frame.kind == flood.kind && frame.has(ACK))
        .count();
    assert!(answers <= 50, "{answers} answers to {:?}", flood.kind);
}

#[test]
fn a_flood_of_pings_settings_or_empty_frames_is_told_to_calm_down() {
    calmed(&[], &Frame::ping(*b"floodpng", false));
    calmed(&[], &Frame::new(Kind::Ping, ACK, 0, vec![0; 8]));
    calmed(&[], &Frame::new(Kind::Settings, 0, 0, Vec::new()));
    calmed(
        &[head(1, true, 0)],
        &Frame::new(Kind::Data, 0, 1, Vec::new()),
    );
    let open = Frame::new(Kind::Headers, 0, 1, vec![0x82]);
    calmed(&[open], &Frame::new(Kind::Continuation, 0, 1, Vec::new()));
}

#[test]
fn empty_frames_that_end_something_are_not_counted() {
    let mut frames = Vec::new();
    for id in (1..100).step_by(2) {
        frames.push(head(id, true, 0));
        frames.push(Frame::new(Kind::Data, END_STREAM, id, Vec::new()));
    }
    let (_, written, ended) = served(&frames, counted(50, 0));
    assert!(!ended, "{:?}", goaway(&written));
}

#[test]
fn a_ping_this_side_sent_is_waited_for_and_its_answer_taken() {
    let (scripted, _) = peer(&[Frame::ping(*b"answered", true)]);
    let mut connection = Connection::start(scripted, true, Limits::DEFAULT).expect("started");
    connection.ping(*b"answered").expect("answered");
    assert_eq!(connection.outstanding, [] as [[u8; 8]; 0]);
}

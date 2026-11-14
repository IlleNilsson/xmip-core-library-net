//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): the network primitives held to a time. A plain `cargo test` leaves
//! it out; the landing runs it after every other test of the module, alone,
//! one test at a time (`cargo test --test measured --all-features --
//! --test-threads=1`), so what is measured is Xmip's work and not its
//! neighbors':
//!
//! - a target read per Message costs a scan of it, five microseconds a read;
//! - a named pipe's bounded accept gives up soon after its wait;
//! - a connect nobody listens for is refused within two milliseconds,
//!   Windows included, however often a lost SYN would be sent again, and
//!   one a listener answers is as quick, each the fastest of five over a
//!   hundred rounds (`xcore::latency::spread`). Until 2026-11-14 each was
//!   the quickest of five rounds alone, which one busy moment slowed
//!   whole: a landing saw 11 ms.

use std::hint::black_box;
use std::net::{SocketAddr, TcpListener};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use xcore::latency::{Spread, spread};
use xmip_core_library_net::pipe::{Listener, path_of};
use xmip_core_library_net::{
    NetError, RETRANSMISSION, Retransmission, Target, connect, fixture, retransmit_by,
};

/// How many connects of each kind are timed.
const ROUNDS: usize = 100;

/// [`ROUNDS`] connects to `address`, `after` each one untimed, their
/// spread printed under `what`; and the last one's outcome.
fn connects(what: &str, address: SocketAddr, after: impl Fn()) -> (Spread, Result<(), NetError>) {
    let mut outcome = Ok(());
    let taken = (0..ROUNDS)
        .map(|_| {
            let began = Instant::now();
            outcome = connect(address, Some(Duration::from_secs(5))).map(drop);
            let took = began.elapsed();
            after();
            took
        })
        .collect();
    (spread(what, taken), outcome)
}

#[test]
fn a_connect_nobody_listens_for_is_refused_at_once_and_one_answered_as_quick() {
    // Until 2026-11-14 Windows asked a refusing peer again for two seconds
    // (`connect`); Linux answered at once. The fastest of five is the
    // connect's own time: a busy machine preempts some rounds.
    let bound = Duration::from_millis(2);
    let (refused, said) = connects("a connect refused", fixture::unheld(), || {});
    let error = said.expect_err("nobody listens");
    assert_eq!(
        error.io,
        Some(std::io::ErrorKind::ConnectionRefused),
        "{error}"
    );
    assert!(refused.fastest_of_five < bound, "refused: {refused:?}");

    // Each connection taken off the listener's backlog, so none waits for
    // room in it.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bound");
    let address = listener.local_addr().expect("address");
    let (answered, said) = connects("a connect answered", address, || {
        // bounded: the connect just timed is in the backlog already
        drop(listener.accept().expect("taken"));
    });
    said.expect("answered");
    assert!(answered.fastest_of_five < bound, "answered: {answered:?}");

    // However often a lost SYN would be sent again, a refusal is not asked
    // again: a process lent eight retransmissions is refused as soon. The
    // program runs one test at a time, so no other connect reads the loan.
    retransmit_by(Retransmission {
        first: Duration::from_secs(1),
        times: 8,
    });
    let what = "a connect refused, eight retransmissions lent";
    let (patient, said) = connects(what, fixture::unheld(), || {});
    retransmit_by(RETRANSMISSION);
    let error = said.expect_err("nobody listens");
    assert_eq!(
        error.io,
        Some(std::io::ErrorKind::ConnectionRefused),
        "{error}"
    );
    assert!(patient.fastest_of_five < bound, "refused: {patient:?}");
}

#[test]
fn a_target_read_per_message_costs_a_scan_of_it() {
    // The fastest of five rounds is the read's own cost: a busy machine
    // preempts some rounds, a slower read slows every one.
    let rounds = (0..20)
        .map(|_| {
            let began = Instant::now();
            for _ in 0..2_000 {
                let text = black_box("mqtt://[::1]:1883/a/b?x=1#f");
                let target = Target::under(&["mqtt"], text);
                black_box(target.expect("read").segments().expect("segments"));
            }
            began.elapsed()
        })
        .collect();
    let read = spread("two thousand targets read", rounds);
    // Generous for a debug build: five microseconds a read.
    assert!(read.fastest_of_five < Duration::from_millis(10), "{read:?}");
}

fn fresh(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    let count = COUNTER.fetch_add(1, Ordering::Relaxed);
    path_of(&format!(
        "xmip-net-measured-{name}-{}-{count}",
        std::process::id()
    ))
}

#[test]
fn an_accept_nobody_answers_gives_up_soon_after_its_wait() {
    // The fastest of five over twenty rounds; until 2026-11-14 each of three
    // was held alone.
    let listener = Listener::bind(&fresh("nobody"), &[]).expect("made");
    let waited = (0..20)
        .map(|_| {
            let began = Instant::now();
            let Err(error) = listener.accept(Some(Duration::from_millis(50))) else {
                panic!("an accept returned with nobody there");
            };
            let waited = began.elapsed();
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
            waited
        })
        .collect();
    let waited = spread("an accept nobody answers, given up", waited);
    assert!(
        waited.fastest_of_five < Duration::from_millis(500),
        "waited {waited:?}"
    );
}

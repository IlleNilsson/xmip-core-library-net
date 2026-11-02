//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): the network primitives held to a time. A plain `cargo test` leaves
//! it out; the landing runs it after every other test of the module, alone,
//! one test at a time (`cargo test --test measured --all-features --
//! --test-threads=1`), so what is measured is Xmip's work and not its
//! neighbors':
//!
//! - a target read per Message costs a scan of it, five microseconds a read;
//! - a named pipe's bounded accept gives up soon after its wait.

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use xmip_core_library_net::Target;
use xmip_core_library_net::pipe::{Listener, path_of};

#[test]
fn a_target_read_per_message_costs_a_scan_of_it() {
    // The fastest of five rounds is the read's own cost: a busy machine
    // preempts some rounds, a slower read slows every one.
    let fastest = (0..5)
        .map(|_| {
            let began = Instant::now();
            for _ in 0..2_000 {
                let text = black_box("mqtt://[::1]:1883/a/b?x=1#f");
                let target = Target::under(&["mqtt"], text);
                black_box(target.expect("read").segments().expect("segments"));
            }
            began.elapsed()
        })
        .min()
        .expect("five rounds");
    // Generous for a debug build: five microseconds a read.
    assert!(fastest < Duration::from_millis(10), "{fastest:?}");
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
    let listener = Listener::bind(&fresh("nobody"), &[]).expect("made");
    for _ in 0..3 {
        let began = Instant::now();
        let Err(error) = listener.accept(Some(Duration::from_millis(50))) else {
            panic!("an accept returned with nobody there");
        };
        let waited = began.elapsed();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut, "{error}");
        assert!(waited < Duration::from_millis(500), "waited {waited:?}");
    }
}

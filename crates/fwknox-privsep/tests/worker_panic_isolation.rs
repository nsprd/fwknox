// SPDX-License-Identifier: AGPL-3.0-or-later

//! Regression test: a panic inside the user-supplied validator in
//! `run_crypto_worker` must NOT tear down the worker loop. A single
//! malformed packet (e.g., one that trips a parser bug in
//! fwknox-proto) must not become a daemon-wide `DoS`.

use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use fwknox_privsep::{
    make_socketpair, recv_msg, run_crypto_worker, send_msg, CaptureMsg, CryptoMsg,
};

#[test]
fn panic_in_validator_does_not_kill_worker() {
    // (cw -> cr) is the "capture -> crypto" channel.
    // (pw -> pr) is the "crypto -> parent" channel.
    let (cw, cr) = make_socketpair().unwrap();
    let (pw, pr) = make_socketpair().unwrap();
    cr.set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    pr.set_read_timeout(Some(Duration::from_millis(1000)))
        .unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let stop_c = Arc::clone(&stop);
    let calls_c = Arc::clone(&calls);

    let handle = thread::spawn(move || {
        let validate = move |_msg: CaptureMsg| -> CryptoMsg {
            let n = calls_c.fetch_add(1, Ordering::SeqCst);
            assert!(n != 0, "simulated validator panic");
            CryptoMsg::NoMatch {
                source_ip: "127.0.0.1".parse().unwrap(),
            }
        };
        let _ = run_crypto_worker(&cr, &pw, validate, || stop_c.load(Ordering::SeqCst));
    });

    let pkt = CaptureMsg::Packet {
        source_ip: "127.0.0.1".parse().unwrap(),
        data: vec![1, 2, 3],
    };

    // Packet 1: validator panics. If the worker is robust, the loop
    // swallows the panic and keeps going.
    send_msg(&cw, &pkt).unwrap();
    thread::sleep(Duration::from_millis(100));

    // Packet 2: must be processed and produce a NoMatch reply.
    send_msg(&cw, &pkt).unwrap();

    let reply: CryptoMsg =
        recv_msg(&pr).expect("worker must still be alive after a validator panic");
    assert!(
        matches!(reply, CryptoMsg::NoMatch { .. }),
        "unexpected reply: {reply:?}"
    );

    stop.store(true, Ordering::SeqCst);
    let _ = handle.join();
    assert!(
        calls.load(Ordering::SeqCst) >= 2,
        "validator should have been invoked at least twice (got {})",
        calls.load(Ordering::SeqCst)
    );
}

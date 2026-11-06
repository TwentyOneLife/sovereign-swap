//! The daemon API must survive a connection flood (a slowloris-style DoS: open many connections and
//! never finish a request). Without a cap the per-connection thread model spawns unbounded threads
//! and exhausts memory. The cap closes connections over the limit instead, so the daemon stays up.

use std::io::Read;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use sovereign_swap::daemon::Daemon;

#[test]
fn connection_cap_survives_a_flood() {
    let dir = std::env::temp_dir().join(format!(
        "swap-dos-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let (addr, _token) = Daemon::open(&dir)
        .expect("open daemon")
        .spawn()
        .expect("spawn api");

    // Open well over the cap (140 > 128), each connection established but never sending a request so
    // the server thread blocks reading it. The server accepts up to the cap and drops the rest.
    let mut held = Vec::new();
    for _ in 0..140 {
        if let Ok(s) = TcpStream::connect(&addr) {
            held.push(s);
        }
    }
    thread::sleep(Duration::from_millis(600));

    // A further connection is over the cap: the server closes it (read returns 0, EOF) rather than
    // serving it or hanging. This is the property that bounds thread/memory use under a flood.
    let mut extra = TcpStream::connect(&addr).expect("connect extra");
    extra
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut buf = [0u8; 16];
    let n = extra.read(&mut buf).unwrap_or(0);
    assert_eq!(
        n, 0,
        "a connection over the cap must be closed, not served or left hanging"
    );

    drop(held);
    let _ = std::fs::remove_dir_all(&dir);
}

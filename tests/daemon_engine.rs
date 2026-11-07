//! The daemon driving the engine through its HTTP API (design 0009, M4a): two daemons over regtest
//! nodes and a real relay, where a maker publishes an offer through `POST /offers` and a taker
//! discovers it over the relay through `GET /offers`. Full swap settlement over a relay is already
//! covered by `lab_e2e`; this proves the API -> engine -> relay path is wired.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use common::{binaries, Node};
use sovereign_swap::daemon::Daemon;
use sovereign_swap::relay_server::{RelayConfig, RelayServer};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn daemon(btc: &str, xbtc: &str, relay: &str) -> (String, String) {
    let n = NEXT.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("sovswap-dengine-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Config is seeded the way StartOS does it: write settings.json, then the daemon reads it on open
    // and brings the engine up. There is no runtime settings endpoint.
    let settings = format!(
        r#"{{"btc_node":"{btc}","xbtc_node":"{xbtc}","relays":["{relay}"],"signer":"hot",
            "btc_conf":1,"xbtc_conf":1,"margin_blocks":2,
            "btc_rpc_user":"u","btc_rpc_pass":"p","xbtc_rpc_user":"u","xbtc_rpc_pass":"p"}}"#
    );
    std::fs::write(dir.join("settings.json"), settings).unwrap();
    let (addr, token) = Daemon::open(&dir).unwrap().spawn().unwrap();
    // The engine starts synchronously on open when the settings are complete; confirm it is up.
    let (_, status) = request(&addr, "GET", "/status", &token, "");
    assert!(
        status.contains("\"engine\":true"),
        "engine did not start: {status}"
    );
    (addr, token)
}

fn request(addr: &str, method: &str, path: &str, token: &str, body: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(1500)))
        .ok();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_millis(2000);
    while Instant::now() < deadline {
        match sock.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (
        status,
        text.split("\r\n\r\n").nth(1).unwrap_or("").to_owned(),
    )
}

#[test]
fn a_maker_publishes_and_a_taker_discovers_over_the_relay() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(20));
    core.mine(101);
    knots.mine(101);
    let relay = RelayServer::new(RelayConfig::default())
        .spawn("127.0.0.1:0")
        .unwrap();

    let (btc_addr, xbtc_addr) = (
        core.rpc.host_port().to_owned(),
        knots.rpc.host_port().to_owned(),
    );
    let (maker, maker_tok) = daemon(&btc_addr, &xbtc_addr, &relay);
    let (taker, taker_tok) = daemon(&btc_addr, &xbtc_addr, &relay);

    // Let both engines' relay subscriptions register before the offer is published.
    std::thread::sleep(Duration::from_millis(500));

    // Publish a 0.5 BTC offer via the API. The daemon sizes the timelocks to the amount from
    // policy, so this is accepted where a fixed 40/20 default would be rejected as too short.
    let offer =
        r#"{"sell_chain":"xbtc","amount_sat":50000000,"price":0.997,"min_amount_sat":50000000}"#;
    let (code, body) = request(&maker, "POST", "/offers", &maker_tok, offer);
    assert_eq!(code, 200, "publish failed: {body}");

    // The taker discovers it over the relay. Each GET /offers drives a tick, so poll.
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = false;
    while Instant::now() < deadline {
        let (_, list) = request(&taker, "GET", "/offers", &taker_tok, "");
        // The market row needs taker_chain too: the web UI renders it (o.taker_chain), so a missing
        // field throws and the Market table renders empty with no Take button.
        if list.contains("\"amount_sat\":50000000")
            && list.contains("\"sell_chain\":\"xbtc\"")
            && list.contains("\"taker_chain\":\"btc\"")
        {
            seen = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        seen,
        "taker never discovered the maker's offer over the relay through the API"
    );
}

//! P5 end-to-end: drive the whole lent-marker split through the daemon's HTTP API against a forked
//! pair. POST /split/build -> the user signs their input -> POST /split/submit -> the daemon co-signs
//! the marker and broadcasts. The move is accepted on Blake2b and rejected on SHA256 for MISSING INPUTS
//! (the marker is absent there), so it is non-replayable. This certifies the fund-touching handler path
//! (marker auto-scan, co-sign on the original base64, broadcast, change-taint) that the unit tests and
//! the pure-logic regtest cannot reach. Needs BTC_BITCOIND + XBTC_BITCOIND; skips otherwise.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use common::ForkedPair;
use sovereign_swap::daemon::Daemon;
use sovereign_swap::relay_server::{RelayConfig, RelayServer};

static NEXT: AtomicU32 = AtomicU32::new(0);

fn request(addr: &str, method: &str, path: &str, token: &str, body: &str) -> (u16, String) {
    let mut sock = TcpStream::connect(addr).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        len = body.len(),
    );
    sock.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(45);
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
fn split_build_sign_submit_through_the_daemon() {
    const FORK: u32 = 110;
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    // The engine needs a relay; the split path needs the fee address + fork-height settings. The fee
    // address is a plain regtest address we control (not silent-payment, which /split/build refuses).
    let relay = RelayServer::new(RelayConfig::default())
        .spawn("127.0.0.1:0")
        .unwrap();
    let fee_addr = xbtc.new_bech32_address();
    let dir = std::env::temp_dir().join(format!(
        "sovswap-split-dae-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let settings = format!(
        r#"{{"btc_node":"http://127.0.0.1:{bp}","xbtc_node":"http://127.0.0.1:{xp}","relays":["{relay}"],
            "signer":"hot","btc_conf":1,"xbtc_conf":1,"margin_blocks":2,
            "btc_rpc_user":"u","btc_rpc_pass":"p","xbtc_rpc_user":"u","xbtc_rpc_pass":"p",
            "fee_enabled":true,"fee_xbtc_address":"{fee_addr}","split_fork_height":{FORK}}}"#,
        bp = btc.rpc_port,
        xp = xbtc.rpc_port,
    );
    std::fs::write(dir.join("settings.json"), settings).unwrap();
    let (addr, token) = Daemon::open(&dir).unwrap().spawn().unwrap();
    let (_, status) = request(&addr, "GET", "/status", &token, "");
    assert!(
        status.contains("\"engine\":true"),
        "engine did not start: {status}"
    );

    // Fund the daemon's swap funding wallet (reused for markers) with a Blake2b-Coin: a coinbase mined
    // to it is post-fork, so Blake2b-only; mature it. The /split/build auto-scan then finds it.
    let swap_wallet_name = xbtc
        .call("listwallets", json!([]))
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w.as_str())
        .find(|w| w.starts_with("swap-") && !w.ends_with("-watch"))
        .expect("daemon created a swap wallet")
        .to_owned();
    let marker_addr = xbtc
        .rpc
        .wallet(&swap_wallet_name)
        .call("getnewaddress", json!(["", "bech32"]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    xbtc.call("generatetoaddress", json!([1, marker_addr]));
    xbtc.mine(101); // mature the marker coinbase

    let sha = pair.knots_sha_coin_txid(); // the user's pre-fork SHA-Coin (fixture 'w' wallet)
    let dest = xbtc.new_bech32_address();

    // 1) build the unsigned split
    let (code, body) = request(
        &addr,
        "POST",
        "/split/build",
        &token,
        &format!(r#"{{"sha_coins":[{{"txid":"{sha}","vout":0}}],"dest":"{dest}"}}"#),
    );
    assert_eq!(code, 200, "build failed: {body}");
    let built: Value = serde_json::from_str(&body).unwrap();
    let job_id = built["job_id"].as_str().unwrap();
    let psbt = built["psbt"].as_str().unwrap();

    // 2) the user signs their SHA-Coin input ('w' owns it; it does not own the marker). Core finalizes
    // the input it can satisfy, so this input arrives finalized; /split/submit accepts that.
    let signed = xbtc
        .wallet()
        .call("walletprocesspsbt", json!([psbt]))
        .unwrap();
    let signed_psbt = signed["psbt"].as_str().unwrap();

    // 3) submit: the daemon validates, co-signs the marker, finalizes and broadcasts
    let (code, body) = request(
        &addr,
        "POST",
        "/split/submit",
        &token,
        &format!(r#"{{"job_id":"{job_id}","psbt":"{signed_psbt}"}}"#),
    );
    assert_eq!(code, 200, "submit failed: {body}");
    let out: Value = serde_json::from_str(&body).unwrap();
    let txid = out["txid"].as_str().unwrap();

    // The move is live on Blake2b; on SHA256 it is rejected for missing inputs (the marker is absent).
    let hex = xbtc.call("getrawtransaction", json!([txid]));
    let hex = hex.as_str().expect("split tx is on the Blake2b node");
    let reject = btc.call("testmempoolaccept", json!([[hex]]));
    assert_eq!(reject[0]["allowed"], json!(false), "SHA256 must reject it");
    let reason = reject[0]["reject-reason"].as_str().unwrap_or("");
    assert!(
        reason.contains("missing") || reason.contains("inputs-missingorspent"),
        "SHA256 reject reason should be missing inputs, got: {reason}"
    );
}

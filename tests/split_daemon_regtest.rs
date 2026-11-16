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

    // #312: the funding-view replay pre-check over the daemon's own (hot) Blake2b funding wallet. Its
    // only UTXO is the post-fork Blake2b coinbase above, which does NOT exist on the BTC node, so it
    // is safe and nothing is flagged. This also proves the handler checks the xbtc wallet against the
    // OTHER chain (btc): were it checked against xbtc itself, that coin would read as unspent/replayable.
    let (code, body) = request(
        &addr,
        "POST",
        "/funding/survey",
        &token,
        r#"{"chain":"xbtc"}"#,
    );
    assert_eq!(code, 200, "funding survey failed: {body}");
    let fv: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        fv["unverified"],
        json!(false),
        "both nodes reachable: {body}"
    );
    assert_eq!(
        fv["output_only"],
        json!(false),
        "hot funding has a wallet: {body}"
    );
    assert!(
        fv["replayable"].as_array().unwrap().is_empty(),
        "a post-fork Blake2b coin is not cross-chain replayable: {body}"
    );
    assert!(
        fv["safe_sat"].as_u64().unwrap() > 0,
        "the matured marker coinbase is safe funds: {body}"
    );

    let sha = pair.knots_sha_coin_txid(); // the user's pre-fork SHA-Coin (fixture 'w' wallet)
    let dest = xbtc.new_bech32_address();

    // 0) /split/scan resolves the coin's ADDRESS to its coins, each classified. The coin's address holds
    // only pre-fork coinbases here, so every coin should come back needs_split=true.
    let coin_addr = xbtc.call("getrawtransaction", json!([sha, true]))["vout"][0]["scriptPubKey"]
        ["address"]
        .as_str()
        .unwrap()
        .to_owned();
    let (code, body) = request(
        &addr,
        "POST",
        "/split/scan",
        &token,
        &format!(r#"{{"address":"{coin_addr}"}}"#),
    );
    assert_eq!(code, 202, "scan start failed: {body}");
    let started: Value = serde_json::from_str(&body).unwrap();
    let scan_id = started["scan_id"].as_str().unwrap().to_owned();
    // The scan runs async on a background thread (#206); poll GET /split/scan/{id} until it is done.
    let scanned = {
        let mut out = None;
        for _ in 0..120 {
            std::thread::sleep(Duration::from_millis(500));
            let (code, body) = request(&addr, "GET", &format!("/split/scan/{scan_id}"), &token, "");
            assert_eq!(code, 200, "scan poll failed: {body}");
            let v: Value = serde_json::from_str(&body).unwrap();
            match v["status"].as_str() {
                Some("done") => {
                    out = Some(v);
                    break;
                }
                Some("error") => panic!("scan errored: {}", v["error"]),
                _ => {}
            }
        }
        out.expect("scan did not finish within the poll window")
    };
    let scoins = scanned["coins"].as_array().unwrap();
    assert!(!scoins.is_empty(), "scan found the address's coins");
    assert!(
        scoins.iter().all(|c| c["needs_split"] == json!(true)),
        "pre-fork coins at this address need protecting"
    );
    assert!(
        scoins.iter().any(|c| c["txid"] == json!(sha)),
        "the known coin is in the scan"
    );

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

/// #314: a pre-fork SHA-Coin held in the DAEMON's own hot funding wallet (not the user's) is split with
/// the daemon signing the coin itself. The user cannot sign it (the key is on the engine host), so the
/// build reports `daemon_signed`, the unsigned PSBT is submitted straight through, and the daemon
/// `walletprocesspsbt` signs both the coin and the marker. The daemon also picks the destination itself
/// (a funding-wallet address), so there is no path to move a hot coin to an arbitrary address.
#[test]
fn split_signs_a_coin_held_in_the_daemon_hot_funding_wallet() {
    const FORK: u32 = 110;
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    let relay = RelayServer::new(RelayConfig::default())
        .spawn("127.0.0.1:0")
        .unwrap();
    let fee_addr = xbtc.new_bech32_address();
    let dir = std::env::temp_dir().join(format!(
        "sovswap-split-hot-{}-{}",
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

    let swap_wallet_name = xbtc
        .call("listwallets", json!([]))
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w.as_str())
        .find(|w| w.starts_with("swap-") && !w.ends_with("-watch"))
        .expect("daemon created a swap wallet")
        .to_owned();
    let swap = xbtc.rpc.wallet(&swap_wallet_name);

    // A matured post-fork Blake2b-Coin in the swap wallet, to lend as the marker.
    let marker_addr = swap
        .call("getnewaddress", json!(["", "bech32"]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    xbtc.call("generatetoaddress", json!([1, marker_addr]));
    xbtc.mine(101);

    // Make the DAEMON's hot funding wallet own the pre-fork SHA-Coin: import the mining wallet's PRIVATE
    // descriptors into it at timestamp 0 so it rescans and can sign the existing block-60 coinbase, without
    // any on-chain move (which would itself separate the coin and defeat the test).
    let descs = xbtc
        .wallet()
        .call("listdescriptors", json!([true]))
        .unwrap();
    let to_import: Vec<Value> = descs["descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| {
            let mut e = json!({"desc": d["desc"], "timestamp": 0, "active": false});
            if !d["range"].is_null() {
                e["range"] = d["range"].clone();
            }
            e
        })
        .collect();
    let res = swap.call("importdescriptors", json!([to_import])).unwrap();
    assert!(
        res.as_array()
            .unwrap()
            .iter()
            .all(|r| r["success"] == json!(true)),
        "importing the coin's descriptors into the funding wallet failed: {res}"
    );

    let sha = pair.knots_sha_coin_txid();
    let owned = swap.call("listunspent", json!([1])).unwrap();
    assert!(
        owned
            .as_array()
            .unwrap()
            .iter()
            .any(|u| u["txid"] == json!(sha)),
        "the funding wallet now holds the pre-fork coin to split: {owned}"
    );
    assert!(
        !xbtc.call("gettxout", json!([sha, 0])).is_null(),
        "the coin is unspent before the split"
    );

    // #314 drain guard: a daemon-signed job must NOT honor a caller-supplied external destination,
    // otherwise /split/build + /split/submit would move a hot-wallet coin anywhere. The address must come
    // from a FRESH wallet: importing the coin's descriptors above made every 'w' address ismine on the
    // funding wallet, so an external address has to be one the funding wallet does not know.
    xbtc.call("createwallet", json!(["external314"]));
    let external = xbtc
        .rpc
        .wallet("external314")
        .call("getnewaddress", json!(["", "bech32"]))
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned();
    let (code, body) = request(
        &addr,
        "POST",
        "/split/build",
        &token,
        &format!(r#"{{"sha_coins":[{{"txid":"{sha}","vout":0}}],"dest":"{external}"}}"#),
    );
    assert_eq!(code, 200, "build with an external dest failed: {body}");
    let built_ext: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        built_ext["daemon_signed"],
        json!(true),
        "a hot funding-wallet coin is still daemon-signed when an external dest is supplied: {body}"
    );
    let decoded = xbtc.call("decodepsbt", json!([built_ext["psbt"].as_str().unwrap()]));
    let vouts = decoded["tx"]["vout"].as_array().unwrap();
    assert!(
        vouts
            .iter()
            .all(|o| o["scriptPubKey"]["address"].as_str() != Some(external.as_str())),
        "the daemon must ignore a caller-supplied external dest for a daemon-signed split: {decoded}"
    );
    let out0 = vouts[0]["scriptPubKey"]["address"].as_str().unwrap();
    assert!(
        swap.call("getaddressinfo", json!([out0])).unwrap()["ismine"]
            .as_bool()
            .unwrap_or(false),
        "the separated value must return to the funding wallet (output 0 ismine), got {out0}"
    );

    // Build with NO dest: for a daemon-owned coin the daemon must pick a funding-wallet address itself.
    let (code, body) = request(
        &addr,
        "POST",
        "/split/build",
        &token,
        &format!(r#"{{"sha_coins":[{{"txid":"{sha}","vout":0}}]}}"#),
    );
    assert_eq!(code, 200, "build failed: {body}");
    let built: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        built["daemon_signed"],
        json!(true),
        "a hot funding-wallet coin must be flagged daemon_signed: {body}"
    );
    let job_id = built["job_id"].as_str().unwrap();
    let psbt = built["psbt"].as_str().unwrap();

    // Submit the UNSIGNED PSBT straight through: the daemon signs both the coin and the marker.
    let (code, body) = request(
        &addr,
        "POST",
        "/split/submit",
        &token,
        &format!(r#"{{"job_id":"{job_id}","psbt":"{psbt}"}}"#),
    );
    assert_eq!(code, 200, "submit failed: {body}");
    let out: Value = serde_json::from_str(&body).unwrap();
    let txid = out["txid"].as_str().unwrap();

    // The daemon actually spent the coin the user could not sign.
    assert!(
        xbtc.call("gettxout", json!([sha, 0])).is_null(),
        "the pre-fork coin must be spent by the split the daemon signed"
    );
    // And the move is non-replayable: SHA256 rejects it for the missing marker input.
    let hex = xbtc.call("getrawtransaction", json!([txid]));
    let hex = hex.as_str().expect("split tx is on the Blake2b node");
    let reject = btc.call("testmempoolaccept", json!([[hex]]));
    assert_eq!(
        reject[0]["allowed"],
        json!(false),
        "SHA256 must reject the daemon-signed split (missing marker input)"
    );
}

//! M2b: the engine's funding wallet holds no private keys; an external signer signs. Proves funding
//! keys never live on the engine host. Here the "external signer" is a separate regtest wallet,
//! standing in for a cold device.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use bitcoin::Amount;
use serde_json::{json, Value};

use bitcoin::hashes::Hash;
use bitcoin::PubkeyHash;
use common::{binaries, Node};
use sovereign_swap::daemon::Daemon;
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode, FundingSigner, NodeError};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::{Client, RpcError};
use sovereign_swap::signer::RemoteSigner;

/// Signs by delegating to a separate key-holding wallet, as a cold device would.
struct ExternalSigner {
    signer_wallet: Client,
}

impl FundingSigner for ExternalSigner {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError> {
        let r = self
            .signer_wallet
            .call("walletprocesspsbt", json!([unsigned_psbt]))
            .map_err(NodeError::Rpc)?;
        if r["complete"] != true {
            return Err(NodeError::Unexpected(
                "external signer did not complete".into(),
            ));
        }
        Ok(r["psbt"].as_str().unwrap().to_owned())
    }
}

/// The other chain's UTXO view; here nothing is shared, so the guard always passes.
struct NoOtherChain;
impl UtxoLookup for NoOtherChain {
    type Error = RpcError;
    fn is_unspent(&self, _: &bitcoin::OutPoint) -> Result<bool, RpcError> {
        Ok(false)
    }
}

#[test]
fn the_engine_wallet_holds_no_keys_and_an_external_signer_funds_the_lock() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);

    // A key-holding "cold" signer wallet, and the engine's watch-only funding wallet "fund" built
    // from the signer's public descriptors (no private keys).
    node.call("createwallet", json!(["signer"]));
    let signer = node.rpc.wallet("signer");
    let descriptors = signer.call("listdescriptors", json!([])).unwrap();
    node.call("createwallet", json!(["fund", true, true, "", false, true])); // watch-only, blank, descriptors
    let fund_wallet = node.rpc.wallet("fund");
    let imports: Vec<serde_json::Value> = descriptors["descriptors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| json!({"desc": d["desc"], "timestamp": "now", "active": true, "internal": d["internal"], "range": 100}))
        .collect();
    fund_wallet
        .call("importdescriptors", json!([imports]))
        .unwrap();
    assert_eq!(
        fund_wallet.call("getwalletinfo", json!([])).unwrap()["private_keys_enabled"],
        false,
        "engine wallet must hold no keys"
    );

    // Fund the watch-only wallet, then let the engine build+fund a lock through the external signer.
    let addr = fund_wallet.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([addr, 1.0]))
        .unwrap();
    node.mine(1);

    let chain = ChainNode::open(node.rpc.clone(), "fund")
        .unwrap()
        .with_signer(Box::new(ExternalSigner {
            signer_wallet: signer,
        }));
    let contract = Contract {
        secret_hash: [3; 32],
        claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        refund_pkh: PubkeyHash::from_byte_array([2; 20]),
        lock_blocks: 20,
    };
    let amount = Amount::from_sat(500_000);
    let (tx, _fee) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, None)
        .expect("external signer funds the lock");
    chain
        .broadcast(&tx)
        .expect("the externally-signed lock is a valid, broadcastable transaction");
    contract
        .find_lock_output(&tx, amount)
        .expect("the lock output is present");
}

/// A signer that must never be called (used where the refusal happens before signing).
struct UnusedSigner;
impl FundingSigner for UnusedSigner {
    fn sign(&self, _: &str) -> Result<String, NodeError> {
        panic!("signer must not be reached");
    }
}

/// Picks the active wpkh receive (external) and change (internal) output descriptors from a wallet's
/// `listdescriptors` reply, the public descriptors the watch-only funding wallet imports.
fn wpkh_descriptors(listed: &Value) -> (String, String) {
    let mut receive = None;
    let mut change = None;
    for d in listed["descriptors"].as_array().unwrap() {
        let desc = d["desc"].as_str().unwrap_or("");
        if desc.starts_with("wpkh(") {
            if d["internal"].as_bool().unwrap_or(false) {
                change = Some(desc.to_owned());
            } else {
                receive = Some(desc.to_owned());
            }
        }
    }
    (
        receive.expect("a wpkh receive descriptor"),
        change.expect("a wpkh change descriptor"),
    )
}

/// Reads one HTTP request off `stream` and returns its body (by Content-Length).
fn read_http_body(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().ok()?;
            }
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).ok()?;
    Some(body)
}

/// A mock cold signer HTTP endpoint implementing the design-0012 protocol: `getsignerinfo` answers,
/// and `signfundingpsbt` bridges to a key-holding regtest wallet's `walletprocesspsbt`, as a real
/// signer would sign with the user's funding keys. Returns the port it listens on.
fn spawn_mock_signer(signer_wallet: Client) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(body) = read_http_body(&mut stream) else {
                continue;
            };
            let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let result = match req["method"].as_str().unwrap_or("") {
                "getsignerinfo" => json!({ "version": "mock-signer" }),
                "signfundingpsbt" => {
                    let psbt = req["params"][0]["psbt"].as_str().unwrap_or("");
                    let signed = signer_wallet
                        .call("walletprocesspsbt", json!([psbt]))
                        .expect("mock signer signs");
                    json!({ "psbt": signed["psbt"], "complete": signed["complete"] })
                }
                _ => Value::Null,
            };
            let reply = json!({ "result": result, "error": Value::Null, "id": 0 }).to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    port
}

#[test]
fn a_cold_lock_is_funded_end_to_end_through_a_remote_signer() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);

    // A key-holding signer wallet; its public descriptors drive the watch-only funding wallet.
    node.call("createwallet", json!(["coldsigner"]));
    let signer_wallet = node.rpc.wallet("coldsigner");
    let (receive, change) =
        wpkh_descriptors(&signer_wallet.call("listdescriptors", json!([])).unwrap());

    // The signer lives behind an HTTP endpoint reached over the ordinary node transport.
    let port = spawn_mock_signer(signer_wallet);
    let signer = RemoteSigner::new(
        Client::connect(&format!("http://127.0.0.1:{port}"), "u", "p", None, None).unwrap(),
        "btc",
    );
    signer.probe().expect("the mock signer is reachable");

    // Provision the cold chain: a watch-only funding wallet imported from the account descriptors.
    let chain = ChainNode::open_cold(
        node.rpc.clone(),
        "coldfund",
        &receive,
        &change,
        Box::new(signer),
    )
    .expect("cold provisioning");
    let fund_wallet = node.rpc.wallet("coldfund");
    assert_eq!(
        fund_wallet.call("getwalletinfo", json!([])).unwrap()["private_keys_enabled"],
        false,
        "the cold funding wallet must be watch-only"
    );

    // Give the watch-only wallet a coin, then let the engine build + remotely-sign + finalise a lock.
    let addr = fund_wallet.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([addr, 1.0]))
        .unwrap();
    node.mine(1);

    let contract = Contract {
        secret_hash: [5; 32],
        claim_pkh: PubkeyHash::from_byte_array([6; 20]),
        refund_pkh: PubkeyHash::from_byte_array([7; 20]),
        lock_blocks: 20,
    };
    let amount = Amount::from_sat(500_000);
    let (tx, _fee) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, None)
        .expect("the remote signer funds the lock");
    chain.broadcast(&tx).expect("the lock is broadcastable");
    node.mine(1);
    contract
        .find_lock_output(&tx, amount)
        .expect("the lock output is present");
    // The lock is confirmed on chain, not merely held in memory (txindex=1 in the harness).
    let txid = tx.compute_txid().to_string();
    let confirmations = node.call("getrawtransaction", json!([txid, true]))["confirmations"]
        .as_u64()
        .unwrap_or_default();
    assert!(
        confirmations >= 1,
        "the lock must be confirmed, not just broadcast"
    );

    // Restart safety: re-opening the same cold chain after several addresses are used must not fail
    // on a descriptor re-import (design 0012). Advance the keypool, then re-provision.
    for _ in 0..6 {
        let _ = fund_wallet.call("getnewaddress", json!([])).unwrap();
    }
    ChainNode::open_cold(
        node.rpc.clone(),
        "coldfund",
        &receive,
        &change,
        Box::new(UnusedSigner),
    )
    .map(|_| ())
    .expect("re-opening an existing cold funding wallet must succeed");
}

#[test]
fn open_cold_refuses_a_funding_wallet_that_holds_keys() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(1);
    // A hot wallet (keys enabled) wrongly reused under a cold config.
    ChainNode::open(node.rpc.clone(), "waskeys").unwrap();
    let dummy = "wpkh(tpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupfe8yV8ekZ9iQLdM2GQpj1eZ4yZ6Z6Z6Z6/0/*)";
    let err = ChainNode::open_cold(
        node.rpc.clone(),
        "waskeys",
        dummy,
        dummy,
        Box::new(UnusedSigner),
    )
    .map(|_| ())
    .unwrap_err();
    match err {
        NodeError::Unexpected(m) => assert!(
            m.contains("private keys enabled"),
            "expected a watch-only refusal, got: {m}"
        ),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_daemon_refuses_a_cold_start_when_the_signer_is_unreachable() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(1);
    let node_addr = node.rpc.host_port();
    // A loopback port with nothing listening: the signer probe is refused at once.
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let dir = std::env::temp_dir().join(format!("sovswap-colddaemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Both chains point at the one regtest node; btc is cold with an unreachable signer, xbtc hot. A
    // dummy relay lets start_engine reach node opening (nodes open before the relay connects).
    let settings = format!(
        r#"{{"btc_node":"{node_addr}","xbtc_node":"{node_addr}","relays":["ws://127.0.0.1:1"],
            "signer":"hot","btc_conf":1,"xbtc_conf":1,"margin_blocks":2,
            "btc_rpc_user":"u","btc_rpc_pass":"p","xbtc_rpc_user":"u","xbtc_rpc_pass":"p",
            "btc_funding":{{"mode":"cold","signer_endpoint":"http://127.0.0.1:{dead}",
            "signer_user":"u","signer_pass":"p","signer_ca":"",
            "descriptor_receive":"wpkh(x/0/*)","descriptor_change":"wpkh(x/1/*)"}}}}"#
    );
    std::fs::write(dir.join("settings.json"), settings).unwrap();
    let daemon = Daemon::open(&dir).unwrap();
    let err = daemon.start_engine().unwrap_err();
    assert!(
        err.to_lowercase().contains("signer"),
        "expected a signer refusal, got: {err}"
    );
    // No hot fallback: the probe fails before provisioning, so no funding wallet was ever created.
    let wallets = node.call("listwallets", json!([]));
    assert!(
        wallets
            .as_array()
            .unwrap()
            .iter()
            .all(|w| !w.as_str().unwrap_or("").starts_with("swap-")),
        "a refused cold start must not create a funding wallet: {wallets}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

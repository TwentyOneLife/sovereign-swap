//! `sovereign-swap-signer`: the reference cold funding signer (design 0012). It holds the funding
//! keys in a bitcoind wallet and signs the funding PSBTs a sovereign-swap daemon in cold mode
//! forwards to it, after checking a refusal policy. The daemon's funding wallet is watch-only; this
//! service's wallet is the keyed counterpart (same account xpub). See `signer_server` for the
//! protocol, the policy, and the two LAN/onion deployment shapes.
//!
//! Configuration is read from the environment so no address or secret lives in the source:
//!
//! - `SIGNER_BITCOIND`: bitcoind RPC endpoint holding the keys. `host:port`, `http://...`,
//!   `https://...`, or an `.onion` (then set `SIGNER_TOR_SOCKS`). Default `http://127.0.0.1:8332`.
//! - `SIGNER_RPC_USER`, `SIGNER_RPC_PASS`: bitcoind RPC credentials (required).
//! - `SIGNER_RPC_CA`: path to a PEM Root CA to verify an `https://` LAN endpoint (optional; required
//!   for a non-onion HTTPS endpoint).
//! - `SIGNER_TOR_SOCKS`: Tor SOCKS proxy `host:port` for an `.onion` endpoint (optional).
//! - `SIGNER_WALLET`: name of the bitcoind wallet holding the funding private keys (required).
//! - `SIGNER_CHAIN`: `btc` or `xbtc`, the chain this signer serves (default `btc`). A request tagged
//!   otherwise is refused.
//! - `SIGNER_BIND`: address to serve on (default `127.0.0.1:8789`). Loopback only unless
//!   `SIGNER_TRUST_NETWORK=1` (set that only behind an authenticated boundary, e.g. a TLS proxy or a
//!   Tor onion, as the signer holds keys).
//! - `SIGNER_AUTH_USER`, `SIGNER_AUTH_PASS`: HTTP Basic credentials the daemon must present to this
//!   endpoint (required; the daemon stores them as the signer endpoint auth).
//! - `SIGNER_MAX_SATS`: outflow ceiling per PSBT, in sats (optional but strongly recommended): the
//!   most value allowed to leave the wallet (non-change outputs plus fee).

use std::process;

use bitcoin::Network;
use serde_json::json;

use sovereign_swap::rpc::Client;
use sovereign_swap::signer_server::{SignerConfig, SignerPolicy, SignerService};

fn require(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fail(&format!("{key} must be set")))
}

fn fail(msg: &str) -> ! {
    eprintln!("sovereign-swap-signer: {msg}");
    process::exit(1);
}

/// The wallet's network, from `getblockchaininfo`, so output scripts decode to the right addresses.
fn detect_network(client: &Client) -> Network {
    let info = client
        .call("getblockchaininfo", json!([]))
        .unwrap_or_else(|e| fail(&format!("cannot reach bitcoind: {e:?}")));
    match info["chain"].as_str() {
        Some("main") => Network::Bitcoin,
        Some("test") | Some("testnet4") => Network::Testnet,
        Some("signet") => Network::Signet,
        Some("regtest") => Network::Regtest,
        other => fail(&format!("unknown chain from bitcoind: {other:?}")),
    }
}

fn main() -> std::io::Result<()> {
    let node =
        std::env::var("SIGNER_BITCOIND").unwrap_or_else(|_| "http://127.0.0.1:8332".to_owned());
    let rpc_user = require("SIGNER_RPC_USER");
    let rpc_pass = require("SIGNER_RPC_PASS");
    let wallet_name = require("SIGNER_WALLET");
    let auth_user = require("SIGNER_AUTH_USER");
    let auth_pass = require("SIGNER_AUTH_PASS");
    let chain = std::env::var("SIGNER_CHAIN").unwrap_or_else(|_| "btc".to_owned());
    if !matches!(chain.as_str(), "btc" | "xbtc") {
        fail(&format!("SIGNER_CHAIN must be btc or xbtc, got {chain:?}"));
    }
    let bind = std::env::var("SIGNER_BIND").unwrap_or_else(|_| "127.0.0.1:8789".to_owned());
    let max_outflow_sats = match std::env::var("SIGNER_MAX_SATS") {
        Ok(v) => Some(
            v.parse::<u64>()
                .unwrap_or_else(|_| fail("SIGNER_MAX_SATS must be a whole number of sats")),
        ),
        Err(_) => None,
    };

    // The signer holds keys; refuse an off-loopback bind unless the operator vouches for the boundary
    // (a TLS proxy or an authenticated Tor onion in front), mirroring the daemon API's own guard.
    let host = bind.rsplit_once(':').map(|(h, _)| h).unwrap_or(&bind);
    let loopback = matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]");
    let trust_network = std::env::var("SIGNER_TRUST_NETWORK").as_deref() == Ok("1");
    if !loopback && !trust_network {
        fail(&format!(
            "refusing to bind {bind}: the signer holds keys and is loopback-only (set \
             SIGNER_TRUST_NETWORK=1 only behind an authenticated boundary, e.g. a TLS proxy or onion)"
        ));
    }

    let ca = match std::env::var("SIGNER_RPC_CA") {
        Ok(path) => Some(
            std::fs::read_to_string(&path)
                .unwrap_or_else(|e| fail(&format!("SIGNER_RPC_CA {path}: {e}"))),
        ),
        Err(_) => None,
    };
    let socks = std::env::var("SIGNER_TOR_SOCKS").ok();

    let client = Client::connect(&node, &rpc_user, &rpc_pass, ca.as_deref(), socks.as_deref())
        .unwrap_or_else(|e| fail(&format!("bad bitcoind endpoint: {e:?}")));
    let network = detect_network(&client);
    let wallet = client.wallet(&wallet_name);

    let service = SignerService::new(
        wallet,
        SignerConfig {
            chain: chain.clone(),
            auth_user,
            auth_pass,
            network,
            policy: SignerPolicy { max_outflow_sats },
        },
    );
    service.preflight().unwrap_or_else(|e| fail(&e));

    let ceiling = max_outflow_sats
        .map(|c| format!("{c} sat"))
        .unwrap_or_else(|| "none (set SIGNER_MAX_SATS)".to_owned());
    eprintln!(
        "sovereign-swap-signer on {bind}: chain {chain}, wallet {wallet_name} on {network}, outflow ceiling {ceiling}"
    );
    service.serve(&bind)
}

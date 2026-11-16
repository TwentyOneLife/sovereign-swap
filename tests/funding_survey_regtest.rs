//! #312: the funding-view replay pre-check over REAL nodes. `survey_replay` must agree with the
//! runtime guard's predicate: a funding UTXO still unspent on the OTHER chain is replayable, one
//! already spent there is safe. Proven against a live `gettxout` (the `Client` UtxoLookup) on a
//! forked pair. Needs BTC_BITCOIND + XBTC_BITCOIND; skips otherwise.

mod common;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{OutPoint, Transaction};
use serde_json::{json, Map, Value};

use common::ForkedPair;
use sovereign_swap::replay::survey_replay;
use sovereign_swap::rpc::Client;

fn as_btc(sat: u64) -> f64 {
    sat as f64 / 1e8
}

fn output(addr: &str, sat: u64) -> Value {
    let mut o = Map::new();
    o.insert(addr.to_owned(), json!(as_btc(sat)));
    Value::Object(o)
}

/// Sign (with `wallet`) a wallet-funded spend of exactly `inputs`, returning the finalized tx. The fee
/// comes out of the single output, so no extra inputs are pulled in.
fn signed_spend(wallet: &Client, inputs: Value, outputs: Value) -> Transaction {
    let psbt = wallet
        .call(
            "walletcreatefundedpsbt",
            json!([inputs, outputs, 0, {"add_inputs": false, "subtractFeeFromOutputs": [0]}]),
        )
        .unwrap();
    let signed = wallet
        .call("walletprocesspsbt", json!([psbt["psbt"].as_str().unwrap()]))
        .unwrap();
    let hex = wallet
        .call("finalizepsbt", json!([signed["psbt"]]))
        .unwrap();
    assert!(
        hex["complete"].as_bool().unwrap_or(false),
        "wallet could not sign: {hex}"
    );
    deserialize_hex(hex["hex"].as_str().unwrap()).unwrap()
}

fn op(txid: &str, vout: u32) -> OutPoint {
    OutPoint {
        txid: txid.parse().unwrap(),
        vout,
    }
}

#[test]
fn funding_survey_flags_prefork_coins_and_clears_after_a_cross_chain_spend() {
    const FORK: u32 = 110;
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    // Survey the BTC funding wallet's coins against the OTHER chain (xbtc), exactly as the runtime
    // guard checks at swap time. A Core-owned pre-fork coinbase is a legacy/ECDSA coin present on both
    // chains (replayable); a post-fork SHA256 coinbase exists only on btc (safe).
    let sha = pair.core_sha_coin_txid(); // block 5, Core-owned, legacy sighash: replayable on both
    let safe = btc.coinbase_txid(FORK as u64); // first post-fork btc block: SHA256-only
    let sha_val = ForkedPair::value_sat(btc, &sha, 0);
    let safe_val = ForkedPair::value_sat(btc, &safe, 0);
    let utxos = vec![(op(&sha, 0), sha_val), (op(&safe, 0), safe_val)];

    let s = survey_replay(&utxos, &xbtc.rpc);
    assert!(!s.unverified, "the xbtc node answered every lookup");
    assert_eq!(
        s.replayable,
        vec![(op(&sha, 0), sha_val)],
        "the pre-fork coin is replayable"
    );
    assert_eq!(s.replayable_sat, sha_val);
    assert_eq!(s.safe_sat, safe_val, "the post-fork SHA256 coin is safe");

    // Spend the pre-fork coin's twin on the OTHER chain (xbtc). The Core wallet owns the key and signs
    // with the legacy sighash, which is valid on both chains, so the same tx mines on xbtc (the replay
    // the guard exists to stop, used here to set up the "already spent on the other chain" state).
    let dest = btc.new_bech32_address();
    let spend = signed_spend(
        &btc.wallet(),
        json!([{"txid": sha, "vout": 0}]),
        output(&dest, sha_val),
    );
    xbtc.mine_tx(&spend)
        .expect("a legacy-signed pre-fork spend is valid on xbtc (consensus)");

    // The twin is now spent on xbtc, so the funding view stops flagging the coin: it matches what the
    // guard would now allow.
    let s2 = survey_replay(&utxos, &xbtc.rpc);
    assert!(!s2.unverified);
    assert!(
        s2.replayable.is_empty(),
        "flag clears once the twin is spent on the other chain"
    );
    assert_eq!(s2.safe_sat, sha_val + safe_val, "both coins are now safe");
}

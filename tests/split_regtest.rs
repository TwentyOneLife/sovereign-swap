//! P0: validate the coin-split core (P1 classifier, P2 builder, P3 survey, P5c verify) against REAL
//! Core + Knots BLAKE2b nodes arranged as a forked pair that shares history below the fork and diverges
//! above it (`common::ForkedPair`). The unit tests in `src/split.rs` use mocks; this proves the same
//! logic on live nodes, and that a Blake2b separating move is genuinely NON-replayable - at CONSENSUS,
//! not merely rejected by mempool policy - rather than rejected for some unrelated reason.
//!
//! Two signers matter (established empirically): Core's wallet signs a pre-fork coin with the standard
//! SIGHASH_ALL, which is valid on BOTH chains (REPLAYABLE - the premise); the Knots wallet signs with
//! the fork's unified sighash (flag 0x20), which Core rejects at consensus (so Knots-wallet spends are
//! already non-replayable by signature). The marker (Method 2) blocks replay at input resolution,
//! independent of the signer - which is why it protects a legacy-signed coin too.
//!
//! Needs BTC_BITCOIND + XBTC_BITCOIND (scripts/test-in-container.sh); skips silently otherwise.

mod common;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::Transaction;
use serde_json::{json, Map, Value};

use std::str::FromStr;

use common::{ForkedPair, Node};
use sovereign_swap::rpc::Client;
use sovereign_swap::split::{
    build_split_psbt, classify, exists_on_node, prepare_input, require_txindex, survey_wallet,
    verify_marker, verify_separation, CoinKind, NodeTxSource, WalletUtxo, DEFAULT_MAX_LOOKUPS,
};

const FORK: u32 = 110;

fn as_btc(sat: u64) -> f64 {
    bitcoin::Amount::from_sat(sat).to_btc()
}

/// One `{address: amount_btc}` output object (dynamic address key).
fn output(addr: &str, sat: u64) -> Value {
    let mut o = Map::new();
    o.insert(addr.to_owned(), json!(as_btc(sat)));
    Value::Object(o)
}

/// Sign (with `wallet`) and finalize a wallet-funded spend of exactly `inputs`, returning the tx.
fn signed_spend(wallet: &Client, inputs: Value, outputs: Value) -> Transaction {
    let psbt = wallet
        .call(
            "walletcreatefundedpsbt",
            json!([inputs, outputs, 0, {"add_inputs": false, "subtractFeeFromOutputs": [0]}]),
        )
        .unwrap();
    finalize(wallet, psbt["psbt"].as_str().unwrap())
}

fn finalize(wallet: &Client, psbt: &str) -> Transaction {
    let signed = wallet.call("walletprocesspsbt", json!([psbt])).unwrap();
    let hex = wallet
        .call("finalizepsbt", json!([signed["psbt"]]))
        .unwrap();
    assert!(
        hex["complete"].as_bool().unwrap_or(false),
        "wallet could not fully sign: {hex}"
    );
    deserialize_hex(hex["hex"].as_str().unwrap()).unwrap()
}

#[test]
fn split_core_against_real_forked_nodes() {
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    // --- fork boundary (also asserted inside ForkedPair::start) ---
    assert_eq!(
        btc.block_hash((FORK - 1) as u64),
        xbtc.block_hash((FORK - 1) as u64)
    );
    assert_ne!(btc.block_hash(FORK as u64), xbtc.block_hash(FORK as u64));

    // --- classify on a live node (mirror of the mock unit tests) ---
    let src = NodeTxSource::new(&xbtc.rpc).unwrap();
    let core_sha = pair.core_sha_coin_txid();
    let knots_sha = pair.knots_sha_coin_txid();
    let blake = pair.blake2b_coin_txid();
    for sha in [&core_sha, &knots_sha] {
        assert_eq!(
            classify(&src, FORK, sha, DEFAULT_MAX_LOOKUPS).unwrap(),
            CoinKind::ShaCoin,
            "a pre-fork coinbase is a replayable SHA-Coin"
        );
    }
    assert_eq!(
        classify(&src, FORK, &blake, DEFAULT_MAX_LOOKUPS).unwrap(),
        CoinKind::Blake2bCoin,
        "a post-fork coinbase is a Blake2b-Coin"
    );

    // --- P3 survey (the known coins): SHA-Coins to split + a Blake2b-Coin ingredient ---
    let survey = survey_wallet(
        &src,
        FORK,
        &[
            WalletUtxo {
                txid: knots_sha.clone(),
                vout: 0,
                value_sat: ForkedPair::value_sat(xbtc, &knots_sha, 0),
            },
            WalletUtxo {
                txid: blake.clone(),
                vout: 0,
                value_sat: ForkedPair::value_sat(xbtc, &blake, 0),
            },
        ],
        DEFAULT_MAX_LOOKUPS,
    )
    .unwrap();
    assert_eq!(survey.to_split.len(), 1);
    assert_eq!(survey.ingredients.len(), 1);
    assert!(survey.can_split());

    // --- NEGATIVE CONTROL: the replay premise. A Core-wallet (standard sighash) spend of a Core-owned
    // pre-fork coin must be valid on BOTH chains. If it weren't, "rejected on Core" below would prove
    // nothing. Not broadcast. Also shows Knots still accepts a legacy sighash after activation. ---
    let core_val = ForkedPair::value_sat(btc, &core_sha, 0);
    let to = btc.new_bech32_address();
    let replayable = signed_spend(
        &btc.wallet(),
        json!([{"txid": core_sha, "vout": 0}]),
        Value::Array(vec![output(&to, core_val)]),
    );
    assert!(
        btc.accept(&replayable).is_ok(),
        "a legacy-signed pre-fork spend is valid on SHA256"
    );
    assert!(
        xbtc.accept(&replayable).is_ok(),
        "...and on Blake2b: a stock-signer pre-fork coin IS replayable (the premise)"
    );

    // --- CONSENSUS FACT: a Knots-wallet (fork sighash) spend of a Knots pre-fork coin is rejected by
    // Core at CONSENSUS, not just policy - so Knots/Shrike-wallet spends are genuinely non-replayable.
    // Use a DIFFERENT coin than the split, and check mine_tx (generateblock, consensus) not mempool. ---
    let other = pair.knots_other_sha_coin_txid();
    let other_val = ForkedPair::value_sat(xbtc, &other, 0);
    let to2 = xbtc.new_bech32_address();
    let fork_signed = signed_spend(
        &xbtc.wallet(),
        json!([{"txid": other, "vout": 0}]),
        Value::Array(vec![output(&to2, other_val)]),
    );
    let consensus = btc
        .mine_tx(&fork_signed)
        .expect_err("Core must reject a fork-sighash spend at consensus");
    assert!(
        consensus.contains("script-verify") || consensus.contains("script-verify-flag"),
        "expected a script-verify consensus failure (fork sighash invalid on SHA256), got: {consensus}"
    );

    // --- P2 build + the real non-replayability proof. TWO owners: the user is CORE's wallet (a stock
    // legacy signer, the primary audience, whose pre-fork spend is replayable) holding `core_sha`; the
    // marker is a Knots-owned Blake2b-Coin we LEND. The move is on Blake2b, so both prevouts are read
    // from the xbtc node (`core_sha` exists there via the mirror). The user signs their input FIRST,
    // then we co-sign the marker LAST - the real /split/build + /split/submit order. ---
    // The marker must be genuinely Blake2b-only on the SHA256 node; a mirrored SHA-Coin is refused.
    assert!(
        verify_marker(&btc.rpc, &core_sha).is_err(),
        "a mirrored SHA-Coin is not a valid marker"
    );
    verify_marker(&btc.rpc, &blake).expect("the Blake2b-Coin is a valid marker (absent on SHA256)");
    // Kind is DERIVED on-chain (no caller tag).
    let user_sha = prepare_input(&xbtc.rpc, FORK, &core_sha, 0).unwrap();
    assert_eq!(user_sha.input.kind, CoinKind::ShaCoin);
    let marker = prepare_input(&xbtc.rpc, FORK, &blake, 0).unwrap();
    assert_eq!(marker.input.kind, CoinKind::Blake2bCoin);
    let parse = |s: String| bitcoin::Address::from_str(&s).unwrap().assume_checked();
    let dest = parse(xbtc.new_bech32_address());
    let fee_addr = parse(xbtc.new_bech32_address());
    let marker_change = parse(xbtc.new_bech32_address());
    let psbt =
        build_split_psbt(&[user_sha, marker], &dest, &fee_addr, &marker_change, 2_000).unwrap();
    // User (Core wallet) signs their SHA-Coin input; then we (Knots wallet) co-sign the marker + finalize.
    let user_signed = btc
        .wallet()
        .call("walletprocesspsbt", json!([psbt]))
        .unwrap();
    let split_tx = finalize(&xbtc.wallet(), user_signed["psbt"].as_str().unwrap());

    assert!(
        xbtc.accept(&split_tx).is_ok(),
        "the separating tx must be valid on Blake2b"
    );
    // On SHA256 the Blake2b-Coin input does not exist: rejected for MISSING INPUTS at mempool AND at
    // consensus (a miner could not include it either), which is what makes the move non-replayable.
    let reject = btc
        .accept(&split_tx)
        .expect_err("the split must be rejected on SHA256");
    assert!(
        reject.contains("missing") || reject.contains("inputs-missingorspent"),
        "SHA256 must reject the split for missing inputs, got: {reject}"
    );
    assert!(
        btc.mine_tx(&split_tx).is_err(),
        "SHA256 must not be able to mine the split either (consensus)"
    );

    // Broadcast on Blake2b and confirm it deep enough.
    let txid = xbtc
        .call("sendrawtransaction", json!([serialize_hex(&split_tx)]))
        .as_str()
        .unwrap()
        .to_owned();
    xbtc.mine(12);

    // The broadcast separating tx itself classifies as a Blake2b-Coin (it spends one).
    let src = NodeTxSource::new(&xbtc.rpc).unwrap();
    assert_eq!(
        classify(&src, FORK, &txid, DEFAULT_MAX_LOOKUPS).unwrap(),
        CoinKind::Blake2bCoin
    );

    // --- P5c verify, using the SHARED existence fn against the real SHA256 node (txindex synced here) ---
    require_txindex(&btc.rpc).expect("Core here runs txindex=1");
    let tx = xbtc.call("getrawtransaction", json!([txid, true]));
    let confirmations = tx["confirmations"].as_u64().unwrap() as u32;
    let vin: Vec<(String, u32)> = tx["vin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| {
            (
                i["txid"].as_str().unwrap().to_owned(),
                i["vout"].as_u64().unwrap() as u32,
            )
        })
        .collect();
    let sep = verify_separation(&vin, confirmations, |t| exists_on_node(&btc.rpc, t)).unwrap();
    assert!(sep.separated, "the Blake2b-Coin input is absent on SHA256");
    assert_eq!(sep.sha256_only_input.as_deref(), Some(blake.as_str()));
    assert!(sep.deep_enough && sep.is_final());
}

/// The verify safety guard: on a SHA256 node WITHOUT a synced txindex, `getrawtransaction` returns -5
/// for any confirmed tx not in the mempool, which would make a replayable input look absent. verify must
/// refuse (error), never report a separation. So `require_txindex` must fail on such a node.
#[test]
fn split_verify_refuses_without_a_synced_txindex() {
    let Some((core, _)) = common::binaries() else {
        return;
    };
    let noindex = Node::start_with(&core, None, false);
    noindex.mine(1);
    assert!(!noindex.txindex_synced());
    assert!(
        require_txindex(&noindex.rpc).is_err(),
        "verify must refuse a SHA256 node without a synced txindex"
    );
}

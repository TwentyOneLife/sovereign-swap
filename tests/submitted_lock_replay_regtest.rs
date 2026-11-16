//! #313: the cross-chain replay guard on a USER-submitted signed funding PSBT. On the descriptor-backed
//! Interactive and output-only paths the user builds/signs the lock out of band and submits it; the
//! daemon finalizes and broadcasts it. Before #313 that broadcast ran no replay guard, so a lock funded
//! from a pre-fork coin still spendable on the other chain could be replayed there (a loss path, #74).
//!
//! `finalize_submitted_lock` now runs `check_inputs` over the inputs the user actually signed, against
//! the OTHER chain, the same predicate the swap-time guard in `fund()` uses. Proven over a forked pair:
//! a lock funded from a replayable Core-owned pre-fork coin is refused; one funded from a post-fork
//! (other-chain-absent) coin is accepted. Needs BTC_BITCOIND + XBTC_BITCOIND; skips otherwise.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, PubkeyHash};
use serde_json::json;

use common::ForkedPair;
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::ChainNode;
use sovereign_swap::rpc::Client;

/// A throwaway HTLC contract; only its lock address and amount matter here.
fn contract() -> Contract {
    Contract {
        secret_hash: [7; 32],
        claim_pkh: PubkeyHash::from_byte_array([8; 20]),
        refund_pkh: PubkeyHash::from_byte_array([9; 20]),
        lock_blocks: 20,
    }
}

/// Build an unsigned PSBT that funds the lock from exactly `coin` (no extra inputs; change absorbs the
/// fee), then sign it with `wallet` (the user's own wallet). Returns `(pending_unsigned, signed)`, the
/// pair `finalize_submitted_lock` is handed.
fn user_funds_the_lock(
    wallet: &Client,
    coin: &str,
    lock_addr: &str,
    amount: Amount,
) -> (String, String) {
    let created = wallet
        .call(
            "walletcreatefundedpsbt",
            json!([
                [{"txid": coin, "vout": 0}],
                { lock_addr: amount.to_btc() },
                0,
                {"add_inputs": false}
            ]),
        )
        .unwrap();
    let pending = created["psbt"].as_str().unwrap().to_owned();
    let signed = wallet.call("walletprocesspsbt", json!([pending])).unwrap();
    assert_eq!(
        signed["complete"], true,
        "the user's wallet fully signs the lock"
    );
    (pending, signed["psbt"].as_str().unwrap().to_owned())
}

#[test]
fn a_submitted_lock_funded_from_a_replayable_coin_is_refused() {
    const FORK: u32 = 110;
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    let chain = ChainNode::open(btc.rpc.clone(), "guardtest").expect("open funding node");
    let contract = contract();
    let lock_addr = chain.address(&contract).to_string();

    // The user funds the lock from a Core-owned pre-fork coinbase (block 5): a legacy/ECDSA SHA-Coin
    // present on BOTH chains, so a Core-wallet spend replays onto xbtc. That is exactly the loss path
    // the guard exists to stop.
    let sha = pair.core_sha_coin_txid();
    let sha_val = ForkedPair::value_sat(btc, &sha, 0);
    let (pending, signed) = user_funds_the_lock(
        &btc.wallet(),
        &sha,
        &lock_addr,
        Amount::from_sat(sha_val / 2),
    );

    let err = chain
        .finalize_submitted_lock(
            &pending,
            &signed,
            &contract,
            Amount::from_sat(sha_val / 2),
            &xbtc.rpc,
        )
        .expect_err("a lock funded from a replayable coin must be refused");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("spendable on the other chain"),
        "the refusal must name the replay risk: {msg}"
    );
    assert!(
        msg.contains("Split the coin first"),
        "the refusal must tell the user how to recover (split, do not broadcast): {msg}"
    );
}

#[test]
fn a_submitted_lock_funded_from_a_safe_coin_is_accepted() {
    const FORK: u32 = 110;
    let Some(pair) = ForkedPair::start(FORK) else {
        return;
    };
    let btc = &pair.btc;
    let xbtc = &pair.xbtc;

    let chain = ChainNode::open(btc.rpc.clone(), "guardtest").expect("open funding node");
    let contract = contract();
    let lock_addr = chain.address(&contract).to_string();

    // A post-fork Core coinbase exists only on btc (the chains diverge past the fork), so its outpoint
    // is absent on xbtc: the guard sees it as safe and the submitted lock is accepted.
    let safe = btc.coinbase_txid(FORK as u64);
    let safe_val = ForkedPair::value_sat(btc, &safe, 0);
    let amount = Amount::from_sat(safe_val / 2);
    let (pending, signed) = user_funds_the_lock(&btc.wallet(), &safe, &lock_addr, amount);

    let tx = chain
        .finalize_submitted_lock(&pending, &signed, &contract, amount, &xbtc.rpc)
        .expect("a lock funded from a non-replayable coin finalizes");
    contract
        .find_lock_output(&tx, amount)
        .expect("the committed lock output is present in the finalized tx");
}

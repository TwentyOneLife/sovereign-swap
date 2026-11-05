//! Contract and replay tests against real regtest nodes.
//!
//! Needs `BTC_BITCOIND` (Bitcoin Core) and `XBTC_BITCOIND` (Bitcoin Knots BLAKE2b); without them the
//! tests are skipped with a note. `scripts/test-in-container.sh` provides both.

mod common;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::ecdsa;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{Amount, OutPoint, PublicKey, Sequence, Transaction, Txid, Witness};
use common::{binaries, Node};
use serde_json::json;

use sovereign_swap::htlc::{extract_preimage, unsigned_spend, Contract, Spend};
use sovereign_swap::replay::{check_inputs, ReplayError};

const LOCK_BLOCKS: u16 = 10;
const AMOUNT: Amount = Amount::from_sat(100_000);
const FEE: Amount = Amount::from_sat(2_000);

struct Party {
    key: SecretKey,
    pubkey: PublicKey,
}

fn party(byte: u8) -> Party {
    let key = SecretKey::from_slice(&[byte; 32]).unwrap();
    Party {
        pubkey: PublicKey::new(key.public_key(&Secp256k1::new())),
        key,
    }
}

fn contract_for(preimage: &[u8], claimer: &Party, refunder: &Party) -> Contract {
    Contract {
        secret_hash: sha256::Hash::hash(preimage).to_byte_array(),
        claim_pkh: claimer.pubkey.pubkey_hash(),
        refund_pkh: refunder.pubkey.pubkey_hash(),
        lock_blocks: LOCK_BLOCKS,
    }
}

/// A claim built by hand, for preimages and hash types the library refuses to produce.
fn raw_claim(
    contract: &Contract,
    spend: &Spend,
    claimer: &Party,
    preimage: &[u8],
    hashtype: u8,
) -> Transaction {
    let mut tx = unsigned_spend(spend, Sequence::ENABLE_RBF_NO_LOCKTIME).unwrap();
    let digest = contract.sighash(&tx, 0, spend.value);
    let sig =
        Secp256k1::new().sign_ecdsa(&Message::from_digest(digest.to_byte_array()), &claimer.key);
    let mut sig = ecdsa::Signature {
        signature: sig,
        sighash_type: EcdsaSighashType::All,
    }
    .to_vec();
    *sig.last_mut().unwrap() = hashtype;
    tx.input[0].witness = Witness::from_slice(&[
        sig,
        claimer.pubkey.to_bytes(),
        preimage.to_vec(),
        vec![1],
        contract.script().into_bytes(),
    ]);
    tx
}

/// Every contract scenario of `docs/edge-cases.md` that needs a chain, on one node.
fn contract_scenarios(node: &Node) {
    let secp = Secp256k1::new();
    let (maker, taker) = (party(1), party(2));
    let spend = |outpoint| Spend {
        outpoint,
        value: AMOUNT,
        destination: node.destination(),
        fee: FEE,
    };

    // Claim with the right secret; the other side reads it back from the chain.
    let preimage = [7u8; 32];
    let contract = contract_for(&preimage, &taker, &maker);
    let s = spend(node.fund(&contract, AMOUNT));
    let wrong = raw_claim(&contract, &s, &taker, &[8u8; 32], 0x01);
    assert!(
        node.accept(&wrong).unwrap_err().contains("EQUALVERIFY"),
        "claim_wrong_preimage_rejected"
    );
    let relabelled = raw_claim(&contract, &s, &taker, &preimage, 0x21);
    assert!(node.accept(&relabelled).is_err(), "hashtype_0x21_rejected");
    let claim = contract.claim(&secp, &s, &taker.key, &preimage).unwrap();
    node.accept(&claim).expect("claim_with_preimage_accepted");
    node.send(&claim);
    let mined: Transaction = deserialize_hex(
        node.call(
            "getrawtransaction",
            json!([claim.compute_txid().to_string()]),
        )
        .as_str()
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        extract_preimage(&mined, &contract),
        Some(preimage),
        "extract_preimage_from_chain"
    );

    // A secret of the wrong length fails the size check even where its hash matches. Mined
    // directly so that only consensus decides, not mempool policy.
    for len in [33usize, 300] {
        let long = vec![5u8; len];
        let contract = contract_for(&long, &taker, &maker);
        let s = spend(node.fund(&contract, AMOUNT));
        let claim = raw_claim(&contract, &s, &taker, &long, 0x01);
        assert!(
            node.mine_tx(&claim).is_err(),
            "oversized_preimage_{len}_rejected_by_consensus"
        );
    }

    // Refund: rejected before the lock expires, accepted after.
    let contract = contract_for(&[3u8; 32], &taker, &maker);
    let s = spend(node.fund(&contract, AMOUNT));
    let refund = contract.refund(&secp, &s, &maker.key).unwrap();
    assert_eq!(
        node.accept(&refund),
        Err("non-BIP68-final".into()),
        "refund_before_csv_rejected"
    );
    node.mine(u32::from(LOCK_BLOCKS));
    node.accept(&refund).expect("refund_after_csv_accepted");
    node.send(&refund);
}

#[test]
fn regtest_contract_on_btc() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);
    assert_eq!(node.header_len(node.height()), 80);
    contract_scenarios(&node);
}

#[test]
fn regtest_contract_on_xbtc() {
    let Some((_, xbtc)) = binaries() else { return };
    // Activate early: before activation the wallet already signs for the fork and blocks reject it.
    let node = Node::start(&xbtc, Some(20));
    node.mine(101);
    assert_eq!(node.header_len(19), 80, "pre-fork header");
    assert_eq!(
        node.header_len(node.height()),
        164,
        "BLAKE2b header, fork active"
    );
    contract_scenarios(&node);
}

/// BTC and xBTC share history up to the fork. A BTC transaction spending a shared coin is valid on
/// xBTC too; the guard must refuse to sign one.
#[test]
fn regtest_replay_shared_coinbase() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    const FORK: u64 = 150;
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(FORK as u32));
    core.mine(FORK as u32 - 1);
    for height in 1..FORK {
        let hash = core.call("getblockhash", json!([height]));
        let block = core.call("getblock", json!([hash, 0]));
        assert!(
            knots.call("submitblock", json!([block])).is_null(),
            "shared block {height}"
        );
    }
    assert_eq!(
        knots.call("getbestblockhash", json!([])),
        core.call("getbestblockhash", json!([]))
    );
    knots.call("generatetoaddress", json!([1, core.new_address()]));
    core.mine(1);
    assert_eq!(
        knots.header_len(FORK),
        164,
        "xBTC split off with a BLAKE2b block"
    );
    assert_ne!(
        knots.call("getbestblockhash", json!([])),
        core.call("getbestblockhash", json!([]))
    );

    // Spend the coinbase of shared block 1 from the BTC wallet, legacy signature.
    let hash1 = core.call("getblockhash", json!([1]));
    let coinbase: Txid = core.call("getblock", json!([hash1, 1]))["tx"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let shared = OutPoint {
        txid: coinbase,
        vout: 0,
    };
    let raw = core
        .wallet()
        .call(
            "createrawtransaction",
            json!([[{"txid": coinbase.to_string(), "vout": 0}], {core.new_address(): 49.999}]),
        )
        .unwrap();
    let signed = core
        .wallet()
        .call("signrawtransactionwithwallet", json!([raw]))
        .unwrap();
    let tx: Transaction = deserialize_hex(signed["hex"].as_str().unwrap()).unwrap();

    knots
        .accept(&tx)
        .expect("the BTC transaction is valid on xBTC: replay is real");
    assert!(
        matches!(check_inputs(&tx, &knots.rpc), Err(ReplayError::SpendableOnOtherChain(o)) if o == shared)
    );

    // A coin created on BTC after the split does not exist on xBTC.
    core.send(&tx);
    let fresh = OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    };
    let raw = core
        .wallet()
        .call(
            "createrawtransaction",
            json!([[{"txid": fresh.txid.to_string(), "vout": 0}], {core.new_address(): 49.998}]),
        )
        .unwrap();
    let signed = core
        .wallet()
        .call("signrawtransactionwithwallet", json!([raw]))
        .unwrap();
    let tx2: Transaction = deserialize_hex(signed["hex"].as_str().unwrap()).unwrap();
    assert!(
        check_inputs(&tx2, &knots.rpc).is_ok(),
        "coin unique to BTC passes the guard"
    );
}

/// The steps of `docs/guides/separating-coins.md`, on a shared history: a Knots wallet sends its
/// shared coins to itself; the transaction is valid on xBTC only, and afterwards the BTC copies
/// are untouched while the xBTC copies are spent.
#[test]
fn regtest_separating_coins_as_the_guide_says() {
    let Some((btc, xbtc)) = binaries() else {
        return;
    };
    const FORK: u64 = 150;
    let core = Node::start(&btc, None);
    let knots = Node::start(&xbtc, Some(FORK as u32));
    knots.call("createwallet", json!(["coins"]));
    let wallet = knots.rpc.wallet("coins");
    let shared = wallet.call("getnewaddress", json!([])).unwrap();
    core.call("generatetoaddress", json!([FORK - 1, shared]));
    for height in 1..FORK {
        let hash = core.call("getblockhash", json!([height]));
        knots.call(
            "submitblock",
            json!([core.call("getblock", json!([hash, 0]))]),
        );
    }
    knots.mine(10);
    core.mine(10);
    let hash1 = core.call("getblockhash", json!([1]));
    let coin1: Txid = core.call("getblock", json!([hash1, 1]))["tx"][0]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        !core
            .call("gettxout", json!([coin1.to_string(), 0]))
            .is_null(),
        "step 2: shared coin"
    );

    // Step 4: build without broadcasting.
    let to = wallet.call("getnewaddress", json!([])).unwrap();
    let built = wallet
        .call(
            "sendall",
            json!([[to], null, "unset", 2, {"add_to_wallet": false}]),
        )
        .unwrap();
    let tx: Transaction = deserialize_hex(built["hex"].as_str().unwrap()).unwrap();
    assert!(tx.input.iter().any(|i| i.previous_output.txid == coin1));

    // Step 5: invalid on BTC, valid on xBTC.
    assert!(core.accept(&tx).is_err(), "step 5: BTC must reject it");
    knots.accept(&tx).expect("step 5: xBTC accepts it");

    // Steps 6 and 7.
    knots.send(&tx);
    assert!(
        knots
            .call("gettxout", json!([coin1.to_string(), 0]))
            .is_null(),
        "xBTC copy spent"
    );
    assert!(
        !core
            .call("gettxout", json!([coin1.to_string(), 0]))
            .is_null(),
        "BTC copy untouched"
    );
}

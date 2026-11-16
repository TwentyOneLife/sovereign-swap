//! #247: the node's SPV proof bundle for a confirmed lock must verify against the node's own
//! `verifytxoutproof`, so a client that does not trust the daemon can confirm a lock exists on-chain
//! (raw tx + Merkle proof + header). Runs against a regtest node; skipped when the binaries absent.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, OutPoint, PubkeyHash};
use common::{binaries, Node};
use serde_json::json;
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::RpcError;

struct NoOtherChain;
impl UtxoLookup for NoOtherChain {
    type Error = RpcError;
    fn is_unspent(&self, _: &OutPoint) -> Result<bool, RpcError> {
        Ok(false)
    }
}

#[test]
fn spv_proof_of_a_confirmed_lock_verifies_against_the_node() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);

    // A funded hot funding wallet, so the engine's node can build and sign a real lock tx.
    let chain = ChainNode::open(node.rpc.clone(), "fund").unwrap();
    let fund = node.rpc.wallet("fund");
    let addr = fund.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([addr, 1.0]))
        .unwrap();
    node.mine(1);

    let contract = Contract {
        secret_hash: [3; 32],
        claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        refund_pkh: PubkeyHash::from_byte_array([2; 20]),
        lock_blocks: 20,
    };
    let amount = Amount::from_sat(500_000);

    // Fund the lock and confirm it one block deep.
    let (tx, _) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, None)
        .expect("the wallet signer funds the lock");
    chain.broadcast(&tx).expect("the funded lock broadcasts");
    let vout = contract
        .find_lock_output(&tx, amount)
        .expect("the HTLC output is present");
    node.mine(1);
    let height = node.height() as u32;
    let outpoint = OutPoint {
        txid: tx.compute_txid(),
        vout,
    };

    // The bundle carries the txid, the raw tx, the Merkle proof and the block header.
    let proof = chain
        .spv_proof(outpoint, height)
        .expect("a confirmed lock yields a proof");
    assert_eq!(proof["txid"], tx.compute_txid().to_string());
    assert_eq!(proof["height"], height);
    for field in ["raw_tx", "txout_proof", "block_header", "block_hash"] {
        assert!(
            proof[field].as_str().is_some_and(|s| !s.is_empty()),
            "proof is missing {field}"
        );
    }

    // The gold standard: the node validates its own Merkle proof and names exactly this txid, which
    // is what an untrusting client checks (the proof binds the tx into a block whose header it has).
    let verified = node.call(
        "verifytxoutproof",
        json!([proof["txout_proof"].as_str().unwrap()]),
    );
    let ids: Vec<String> = verified
        .as_array()
        .expect("verifytxoutproof returns an array of txids")
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, vec![tx.compute_txid().to_string()]);
}

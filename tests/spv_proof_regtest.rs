//! #247: the node's SPV proof bundle for a confirmed lock must verify against the node's own
//! `verifytxoutproof`, so a client that does not trust the daemon can confirm a lock exists on-chain
//! (raw tx + Merkle proof + header). Exercised on BOTH chains: BTC (SHA256), whose header is the
//! classic 80 bytes, and BTC (Blake2b), whose post-fork header is extended - the bundle must carry
//! whichever the chain uses, so a light client checks the right header and PoW. Runs against regtest
//! nodes; skipped when the binaries are absent.

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

/// Fund and confirm one HTLC lock on `node`, then assert its SPV bundle carries the raw tx, the
/// Merkle proof and the header, and that the proof verifies against the node's own
/// `verifytxoutproof` (naming exactly this txid - the check an untrusting client performs).
/// Returns the header length in bytes so the caller can assert the per-chain header shape.
fn spv_round_trips(node: &Node) -> usize {
    // A funded hot funding wallet, so the node can build and sign a real lock tx.
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

    // The served header must be exactly the block's, so assert it matches what the node reports.
    let served = proof["block_header"].as_str().unwrap().len() / 2;
    assert_eq!(served, node.header_len(height as u64));
    served
}

#[test]
fn spv_proof_verifies_on_the_sha256_chain_with_an_80_byte_header() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);
    assert_eq!(
        spv_round_trips(&node),
        80,
        "BTC (SHA256) headers are the classic 80 bytes"
    );
}

#[test]
fn spv_proof_verifies_on_the_blake2b_chain_with_an_extended_header() {
    let Some((_, knots)) = binaries() else { return };
    // Activate the Blake2b fork early, then mine past it (and past coinbase maturity) so the lock
    // confirms in a post-fork block whose header is the extended Blake2b form, not 80 bytes.
    const FORK: u32 = 110;
    let node = Node::start(&knots, Some(FORK));
    node.mine(115);
    assert!(
        spv_round_trips(&node) > 80,
        "BTC (Blake2b) post-fork headers are extended, longer than 80 bytes"
    );
}

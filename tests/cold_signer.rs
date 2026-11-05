//! M2b: the engine's funding wallet holds no private keys; an external signer signs. Proves funding
//! keys never live on the engine host. Here the "external signer" is a separate regtest wallet,
//! standing in for a cold device.

mod common;

use bitcoin::Amount;
use serde_json::json;

use bitcoin::hashes::Hash;
use bitcoin::PubkeyHash;
use common::{binaries, Node};
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainNode, FundingSigner, NodeError};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::{Client, RpcError};

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
    let tx = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain)
        .expect("external signer funds the lock");
    chain
        .broadcast(&tx)
        .expect("the externally-signed lock is a valid, broadcastable transaction");
    contract
        .find_lock_output(&tx, amount)
        .expect("the lock output is present");
}

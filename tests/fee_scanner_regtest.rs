//! Design 0013 stage 2, the case that matters: the daemon-side fee scanner, in SCAN-ONLY mode,
//! detects a silent-payment fee output in a transaction it was NOT a party to. The operator holds
//! only its scan key and the fee address; it never sees the swap's share or proof. It finds the fee
//! purely by reading the chain (`getblock` verbosity 3) and re-deriving the shared secret.
//!
//! A test covering only the operator's own swaps would pass a broken design, so this builds the fee
//! from an outside payer's lock and the scanner rediscovers it from the block alone. Runs against a
//! regtest node; skipped when the binaries are absent. Regtest keys only.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, OutPoint, PubkeyHash};
use common::{binaries, Node};
use serde_json::json;

use sovereign_swap::feescan::{scan_range, ScanConfig};
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode, FeeDest};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::RpcError;
use sovereign_swap::silentpayments::SilentPaymentAddress;

struct NoOtherChain;
impl UtxoLookup for NoOtherChain {
    type Error = RpcError;
    fn is_unspent(&self, _: &OutPoint) -> Result<bool, RpcError> {
        Ok(false)
    }
}

fn hex_of(sk: &SecretKey) -> String {
    sk.secret_bytes().to_lower_hex_string()
}

#[test]
fn scanner_detects_a_fee_it_was_not_a_party_to() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);

    // An outside payer with its own funded wallet (hot signer, BIP352-aware) builds and broadcasts a
    // lock that carries the operator's silent-payment fee. The operator (the scanner) is not a party
    // to this transaction: it never receives the share or the proof, only the public chain.
    let chain = ChainNode::open(node.rpc.clone(), "payer").unwrap();
    let payer = node.rpc.wallet("payer");
    let addr = payer.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([addr, 1.0]))
        .unwrap();
    node.mine(1);

    // The operator's regtest silent payment fee address and the matching scan secret key.
    let secp = Secp256k1::new();
    let scan = SecretKey::from_slice(&[0x44; 32]).unwrap();
    let spend = SecretKey::from_slice(&[0x55; 32]).unwrap();
    let recipient = SilentPaymentAddress {
        scan: PublicKey::from_secret_key(&secp, &scan),
        spend: PublicKey::from_secret_key(&secp, &spend),
        network: Network::Regtest,
    };

    let contract = Contract {
        secret_hash: [9; 32],
        claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        refund_pkh: PubkeyHash::from_byte_array([2; 20]),
        lock_blocks: 20,
    };
    let amount = Amount::from_sat(500_000);
    let fee = Amount::from_sat(2_000);
    let height_before = node.height() as u32;

    let dest = FeeDest::SilentPayment(recipient);
    let (tx, _proof) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, Some((fee, &dest)))
        .expect("the outside payer funds a lock carrying the operator fee");
    chain.broadcast(&tx).expect("the funded lock broadcasts");

    // A decoy taproot output in the same block that is NOT the operator's fee: it must not count.
    let decoy = node
        .wallet()
        .call("getnewaddress", json!(["", "bech32m"]))
        .unwrap();
    node.wallet()
        .call("sendtoaddress", json!([decoy, 0.5]))
        .unwrap();
    node.mine(1);

    let txid = tx.compute_txid();

    // Build the operator's scan config from its address and scan key, exactly as the daemon does.
    let cfg = ScanConfig::new(&recipient.encode(), &hex_of(&scan), height_before + 1)
        .expect("the scan key matches the address")
        .expect("configured to scan");

    // Walk the chain from before the fee block with the operator key, through the same getblock-3
    // path the daemon thread uses. The lock transaction carries several taproot outputs (the fee and
    // the wallet's taproot change) plus a decoy taproot payment in the same block, so a correct
    // scanner finds exactly the one the shared secret derives, by amount and derivation, not position.
    let (hits, tip) = scan_range(&node.rpc, &cfg, &secp, height_before).unwrap();
    assert!(tip >= node.height() as u32 - 1, "the scan reached the tip");
    assert_eq!(
        hits.len(),
        1,
        "the scanner finds exactly the operator's fee, not the decoy or the change"
    );
    let (_, hit) = hits[0];
    assert_eq!(hit.outpoint.txid, txid, "the hit is in the payer's lock tx");
    assert_eq!(
        hit.value, fee,
        "the hit carries the exact fee amount in sats"
    );
    let matched = &tx.output[hit.outpoint.vout as usize];
    assert!(
        matched.script_pubkey.is_p2tr() && matched.value == fee,
        "the matched output is the taproot fee output of the lock"
    );

    // An unrelated operator (a different scan and spend key) collects nothing in the same range.
    let other_scan = SecretKey::from_slice(&[0x66; 32]).unwrap();
    let other_spend = SecretKey::from_slice(&[0x77; 32]).unwrap();
    let other = SilentPaymentAddress {
        scan: PublicKey::from_secret_key(&secp, &other_scan),
        spend: PublicKey::from_secret_key(&secp, &other_spend),
        network: Network::Regtest,
    };
    let other_cfg = ScanConfig::new(&other.encode(), &hex_of(&other_scan), height_before + 1)
        .unwrap()
        .unwrap();
    let (none, _) = scan_range(&node.rpc, &other_cfg, &secp, height_before).unwrap();
    assert!(none.is_empty(), "an unrelated address collects no fee");
}

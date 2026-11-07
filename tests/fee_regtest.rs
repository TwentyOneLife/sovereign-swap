//! M2b (design 0010): the hot WalletSigner adds a silent payment fee output to a lock, a
//! counterparty verifies it from the share and proof, and the operator finds it by scanning. Runs
//! against a regtest node; skipped when the binaries are absent.

mod common;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, Network, OutPoint, PubkeyHash};
use common::{binaries, Node};
use serde_json::json;

use bitcoin::hashes::Hash;
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode, FeeDest};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::RpcError;
use sovereign_swap::silentpayments::{
    input_pubkey, scan_outputs, verify_fee, SilentPaymentAddress,
};

struct NoOtherChain;
impl UtxoLookup for NoOtherChain {
    type Error = RpcError;
    fn is_unspent(&self, _: &OutPoint) -> Result<bool, RpcError> {
        Ok(false)
    }
}

#[test]
fn wallet_signer_pays_a_silent_payment_fee_that_verifies_and_scans() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    node.mine(101);

    // The engine's funding wallet (hot: holds keys, so it can be BIP352-aware here), funded.
    let chain = ChainNode::open(node.rpc.clone(), "fund").unwrap();
    let fund = node.rpc.wallet("fund");
    let addr = fund.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([addr, 1.0]))
        .unwrap();
    node.mine(1);

    // The operator's regtest silent payment address.
    let secp = Secp256k1::new();
    let scan = SecretKey::from_slice(&[0x11; 32]).unwrap();
    let spend = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let recipient = SilentPaymentAddress {
        scan: PublicKey::from_secret_key(&secp, &scan),
        spend: PublicKey::from_secret_key(&secp, &spend),
        network: Network::Regtest,
    };

    let contract = Contract {
        secret_hash: [3; 32],
        claim_pkh: PubkeyHash::from_byte_array([1; 20]),
        refund_pkh: PubkeyHash::from_byte_array([2; 20]),
        lock_blocks: 20,
    };
    let amount = Amount::from_sat(500_000);
    let fee = Amount::from_sat(2_000);

    // Fund the lock with the fee. The hot signer derives its input keys, builds the fee output and
    // the share+proof, and signs.
    let dest = FeeDest::SilentPayment(recipient);
    let (tx, proof) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, Some((fee, &dest)))
        .expect("the wallet signer funds the lock with a fee");
    chain.broadcast(&tx).expect("the funded lock broadcasts");
    contract
        .find_lock_output(&tx, amount)
        .expect("the HTLC output is present");
    let proof = proof.expect("a fee was requested, so a proof is returned");

    // A counterparty, from the lock's inputs (authenticated by the proof's prevouts) and the share
    // and proof, confirms the fee output is present for at least the required amount.
    let mut pubkeys = Vec::new();
    let mut outpoints = Vec::new();
    for input in &tx.input {
        outpoints.push(input.previous_output);
        let prevout = proof
            .prevouts
            .iter()
            .find(|t| t.compute_txid() == input.previous_output.txid)
            .expect("proof carries each input's prevout tx");
        let txout = &prevout.output[input.previous_output.vout as usize];
        if let Some(pk) = input_pubkey(&txout.script_pubkey, &input.script_sig, &input.witness) {
            pubkeys.push(pk);
        }
    }
    let proof_bytes: [u8; 64] = proof.proof.as_slice().try_into().unwrap();
    assert!(
        verify_fee(
            &secp,
            &pubkeys,
            &outpoints,
            &recipient,
            &proof.share.serialize(),
            &proof_bytes,
            &tx.output,
            fee,
        ),
        "the counterparty verifies the fee output"
    );
    // Requiring more than was paid must fail.
    assert!(!verify_fee(
        &secp,
        &pubkeys,
        &outpoints,
        &recipient,
        &proof.share.serialize(),
        &proof_bytes,
        &tx.output,
        fee + Amount::from_sat(1),
    ));

    // The operator, scanning with its scan key, finds the same output as its own.
    let tx_outputs: Vec<_> = tx
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_p2tr())
        .map(|o| {
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&o.script_pubkey.as_bytes()[2..34])
                .unwrap()
        })
        .collect();
    let found = scan_outputs(
        &secp,
        &scan,
        &recipient.spend,
        &pubkeys,
        &outpoints,
        &tx_outputs,
    )
    .expect("scan succeeds");
    assert_eq!(found.len(), 1, "the operator finds exactly its fee output");
}

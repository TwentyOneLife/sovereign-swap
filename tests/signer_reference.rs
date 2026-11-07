//! The reference cold signer (`signer_server`) driven by the real `RemoteSigner` client (design
//! 0012): proves the two interoperate over the actual node transport.
//!
//! Two always-run cases need no bitcoind (the probe reachability and auth, and a chain-mismatch
//! refusal, both decided before any wallet call). The two regtest cases (gated on the node binaries,
//! like the rest of the suite) run a real round trip: a KEYED bitcoind wallet signs a funding PSBT
//! the engine builds against a watch-only wallet imported from that wallet's public descriptors, and
//! the ceiling policy both passes a lock under it and refuses one over it.

mod common;

use bitcoin::hashes::Hash;
use bitcoin::{Amount, Network, PubkeyHash};
use serde_json::{json, Value};

use common::{binaries, Node};
use sovereign_swap::htlc::Contract;
use sovereign_swap::node::{ChainBackend, ChainNode, FundingSigner, NodeError, SignerError};
use sovereign_swap::replay::UtxoLookup;
use sovereign_swap::rpc::{Client, RpcError};
use sovereign_swap::signer::RemoteSigner;
use sovereign_swap::signer_server::{SignerConfig, SignerPolicy, SignerService};

/// The other chain's UTXO view; nothing is shared here, so the replay guard always passes.
struct NoOtherChain;
impl UtxoLookup for NoOtherChain {
    type Error = RpcError;
    fn is_unspent(&self, _: &bitcoin::OutPoint) -> Result<bool, RpcError> {
        Ok(false)
    }
}

/// Picks the active wpkh receive (external) and change (internal) output descriptors from a wallet's
/// `listdescriptors`, i.e. the public descriptors a watch-only funding wallet imports.
fn wpkh_descriptors(listed: &Value) -> (String, String) {
    let mut receive = None;
    let mut change = None;
    for d in listed["descriptors"].as_array().unwrap() {
        let desc = d["desc"].as_str().unwrap_or("");
        if desc.starts_with("wpkh(") {
            if d["internal"].as_bool().unwrap_or(false) {
                change = Some(desc.to_owned());
            } else {
                receive = Some(desc.to_owned());
            }
        }
    }
    (
        receive.expect("a wpkh receive descriptor"),
        change.expect("a wpkh change descriptor"),
    )
}

/// A `SignerConfig` for a regtest `btc` signer with the given outflow ceiling.
fn btc_config(max_outflow_sats: Option<u64>) -> SignerConfig {
    SignerConfig {
        chain: "btc".to_owned(),
        auth_user: "sign-user".to_owned(),
        auth_pass: "sign-pass".to_owned(),
        network: Network::Regtest,
        policy: SignerPolicy { max_outflow_sats },
    }
}

/// A `RemoteSigner` for `chain`, reaching the spawned service at `addr` with the given Basic creds.
fn remote(addr: &str, chain: &'static str, user: &str, pass: &str) -> RemoteSigner {
    let client = Client::connect(&format!("http://{addr}"), user, pass, None, None).unwrap();
    RemoteSigner::new(client, chain)
}

// --- always-run: no bitcoind needed ------------------------------------------------------------

#[test]
fn the_probe_succeeds_and_getsignerinfo_needs_no_node() {
    // The service's bitcoind client points at an unused loopback port; getsignerinfo must not touch
    // it. A client with matching Basic creds probes successfully.
    let dead = Client::new("127.0.0.1:1", "x", "x");
    let addr = SignerService::new(dead, btc_config(Some(1_000_000)))
        .spawn("127.0.0.1:0")
        .unwrap();
    remote(&addr, "btc", "sign-user", "sign-pass")
        .probe()
        .expect("a conforming reference signer answers getsignerinfo");
}

#[test]
fn wrong_basic_credentials_are_rejected() {
    let dead = Client::new("127.0.0.1:1", "x", "x");
    let addr = SignerService::new(dead, btc_config(Some(1_000_000)))
        .spawn("127.0.0.1:0")
        .unwrap();
    // A 401 maps to Unreachable (an auth failure is "not usable", never a silent success).
    let err = remote(&addr, "btc", "wrong", "creds").probe().unwrap_err();
    assert!(
        matches!(err, NodeError::Signer(SignerError::Unreachable(_))),
        "expected unreachable on bad auth, got {err:?}"
    );
}

#[test]
fn a_chain_mismatch_is_refused_before_any_node_call() {
    // The service serves btc; a RemoteSigner tagged xbtc must be refused, with no bitcoind call (the
    // client points at a dead port, so a refusal that reached the wallet would hang or error).
    let dead = Client::new("127.0.0.1:1", "x", "x");
    let addr = SignerService::new(dead, btc_config(Some(1_000_000)))
        .spawn("127.0.0.1:0")
        .unwrap();
    // Any syntactically valid PSBT; the chain check happens before it is even parsed.
    let psbt = empty_psbt();
    let err = remote(&addr, "xbtc", "sign-user", "sign-pass")
        .sign(&psbt)
        .unwrap_err();
    match err {
        NodeError::Signer(SignerError::Refused { message, .. }) => {
            assert!(message.contains("serves btc"), "{message}");
        }
        other => panic!("expected a chain-mismatch refusal, got {other:?}"),
    }
}

/// A base64 PSBT over a one-input, one-output transaction, enough to exercise the paths that run
/// before any signing (the chain check parses nothing; the ceiling parses this).
fn empty_psbt() -> String {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    Psbt::from_unsigned_tx(tx).unwrap().to_string()
}

// --- regtest: a real keyed wallet signs through the reference signer ---------------------------

/// Stands up a regtest node with a keyed signer wallet and a watch-only funding wallet imported from
/// its descriptors, then returns the funded `ChainNode` (cold, driven by the reference signer at
/// `ceiling`) plus the node, so a test can build and sign a lock through it.
fn cold_chain_through_reference_signer(node: &Node, ceiling: Option<u64>) -> ChainNode {
    node.mine(101);

    node.call("createwallet", json!(["coldsigner"]));
    let signer_wallet = node.rpc.wallet("coldsigner");
    let (receive, change) =
        wpkh_descriptors(&signer_wallet.call("listdescriptors", json!([])).unwrap());

    // The reference signer service, pointed at the KEYED wallet, behind its HTTP endpoint.
    let service = SignerService::new(signer_wallet, btc_config(ceiling));
    service
        .preflight()
        .expect("the keyed signer wallet passes preflight");
    let addr = service.spawn("127.0.0.1:0").unwrap();
    let signer = remote(&addr, "btc", "sign-user", "sign-pass");
    signer.probe().expect("the reference signer is reachable");

    // Provision the cold chain: a watch-only funding wallet from the account descriptors.
    let chain = ChainNode::open_cold(
        node.rpc.clone(),
        "coldfund",
        &receive,
        &change,
        Box::new(signer),
    )
    .expect("cold provisioning");
    let fund_wallet = node.rpc.wallet("coldfund");
    assert_eq!(
        fund_wallet.call("getwalletinfo", json!([])).unwrap()["private_keys_enabled"],
        false,
        "the cold funding wallet must be watch-only"
    );

    // Give the watch-only wallet a 1 BTC coin to fund from.
    let fund_addr = fund_wallet.call("getnewaddress", json!([])).unwrap();
    node.wallet()
        .call("sendtoaddress", json!([fund_addr, 1.0]))
        .unwrap();
    node.mine(1);
    chain
}

fn a_contract(secret: u8) -> Contract {
    Contract {
        secret_hash: [secret; 32],
        claim_pkh: PubkeyHash::from_byte_array([secret.wrapping_add(1); 20]),
        refund_pkh: PubkeyHash::from_byte_array([secret.wrapping_add(2); 20]),
        lock_blocks: 20,
    }
}

#[test]
fn the_reference_signer_funds_a_cold_lock_under_the_ceiling() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    // Ceiling 0.01 BTC against a 1 BTC coin: a 0.005 lock passes ONLY because change (~0.995) is
    // excluded from the outflow. A total-output ceiling would wrongly refuse here.
    let chain = cold_chain_through_reference_signer(&node, Some(1_000_000));

    let contract = a_contract(5);
    let amount = Amount::from_sat(500_000);
    let (tx, _fee) = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, None)
        .expect("the reference signer funds the lock");
    chain.broadcast(&tx).expect("the lock is broadcastable");
    node.mine(1);
    contract
        .find_lock_output(&tx, amount)
        .expect("the lock output is present");
    let txid = tx.compute_txid().to_string();
    let confirmations = node.call("getrawtransaction", json!([txid, true]))["confirmations"]
        .as_u64()
        .unwrap_or_default();
    assert!(confirmations >= 1, "the lock must be confirmed on chain");
}

#[test]
fn the_reference_signer_refuses_a_lock_over_the_ceiling() {
    let Some((btc, _)) = binaries() else { return };
    let node = Node::start(&btc, None);
    // Ceiling 0.001 BTC, below the 0.005 lock: the outflow exceeds it, so the signer refuses and the
    // engine surfaces a Refused error rather than funding.
    let chain = cold_chain_through_reference_signer(&node, Some(100_000));

    let contract = a_contract(9);
    let amount = Amount::from_sat(500_000);
    let err = chain
        .fund(&contract, amount, 2, 1, &NoOtherChain, None)
        .expect_err("a lock over the ceiling must be refused");
    match err {
        NodeError::Signer(SignerError::Refused { message, .. }) => {
            assert!(
                message.contains("ceiling"),
                "expected a ceiling refusal, got: {message}"
            );
        }
        other => panic!("expected a ceiling refusal, got {other:?}"),
    }
}

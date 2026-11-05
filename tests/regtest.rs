//! Contract and replay tests against real regtest nodes.
//!
//! Needs `BTC_BITCOIND` (Bitcoin Core) and `XBTC_BITCOIND` (Bitcoin Knots BLAKE2b); without them the
//! tests are skipped with a note. `scripts/test-in-container.sh` provides both.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::ecdsa;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::{
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, Txid, Witness,
};
use serde_json::{json, Value};

use sovereign_swap::htlc::{extract_preimage, unsigned_spend, Contract, Spend};
use sovereign_swap::replay::{check_inputs, ReplayError};
use sovereign_swap::rpc::{Client, RpcError};

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

struct Node {
    child: Child,
    datadir: PathBuf,
    rpc: Client,
}

impl Node {
    /// `fork_height` set means a Knots BLAKE2b node with the fork activating at that height.
    fn start(binary: &str, fork_height: Option<u32>) -> Node {
        let base = 20_000 + (std::process::id() % 2_000) as u16 * 10;
        let n = NEXT_PORT.fetch_add(2, Ordering::SeqCst);
        let (rpc_port, p2p_port) = (base + n, base + n + 1);
        let datadir = std::env::temp_dir().join(format!("sovswap-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&datadir).unwrap();
        let mut conf = format!(
            "regtest=1\n[regtest]\nrpcport={rpc_port}\nport={p2p_port}\nrpcuser=u\nrpcpassword=p\n\
             listen=0\nconnect=0\ndnsseed=0\nfallbackfee=0.0001\ntxindex=1\nprinttoconsole=0\n"
        );
        if let Some(h) = fork_height {
            conf.push_str(&format!("testactivationheight=blake2b@{h}\n"));
        }
        std::fs::write(datadir.join("bitcoin.conf"), conf).unwrap();
        let child = Command::new(binary)
            .arg(format!("-datadir={}", datadir.display()))
            .spawn()
            .unwrap();
        let rpc = Client::new(&format!("127.0.0.1:{rpc_port}"), "u", "p");
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match rpc.call("getblockchaininfo", json!([])) {
                Ok(_) => break,
                Err(e) if Instant::now() > deadline => panic!("{binary} did not start: {e:?}"),
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        }
        Node {
            child,
            datadir,
            rpc,
        }
    }

    fn call(&self, method: &str, params: Value) -> Value {
        self.rpc
            .call(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    fn wallet(&self) -> Client {
        if self
            .call("listwallets", json!([]))
            .as_array()
            .unwrap()
            .is_empty()
        {
            self.call("createwallet", json!(["w"]));
        }
        self.rpc.wallet("w")
    }

    fn new_address(&self) -> String {
        self.wallet()
            .call("getnewaddress", json!([]))
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn mine(&self, blocks: u32) {
        let address = self.new_address();
        self.call("generatetoaddress", json!([blocks, address]));
    }

    fn height(&self) -> u64 {
        self.call("getblockcount", json!([])).as_u64().unwrap()
    }

    fn header_len(&self, height: u64) -> usize {
        let hash = self.call("getblockhash", json!([height]));
        self.call("getblockheader", json!([hash, false]))
            .as_str()
            .unwrap()
            .len()
            / 2
    }

    /// Mempool policy and consensus: `Err(reason)` when the node would not accept `tx`.
    fn accept(&self, tx: &Transaction) -> Result<(), String> {
        let r = &self.call("testmempoolaccept", json!([[serialize_hex(tx)]]))[0];
        if r["allowed"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(r["reject-reason"].as_str().unwrap_or_default().to_owned())
        }
    }

    /// Consensus only: mines `tx` into a block directly, bypassing mempool policy.
    fn mine_tx(&self, tx: &Transaction) -> Result<(), String> {
        let address = self.new_address();
        match self
            .rpc
            .call("generateblock", json!([address, [serialize_hex(tx)]]))
        {
            Ok(_) => Ok(()),
            Err(RpcError::Rpc { message, .. }) => Err(message),
            Err(e) => panic!("generateblock: {e:?}"),
        }
    }

    fn send(&self, tx: &Transaction) {
        self.call("sendrawtransaction", json!([serialize_hex(tx)]));
        self.mine(1);
    }

    /// Locks `amount` in `contract` from the node wallet and confirms it.
    fn fund(&self, contract: &Contract, amount: Amount) -> OutPoint {
        let address = Address::from_script(&contract.script_pubkey(), Network::Regtest).unwrap();
        let txid = self
            .wallet()
            .call(
                "sendtoaddress",
                json!([address.to_string(), amount.to_btc()]),
            )
            .unwrap();
        let tx: Transaction = deserialize_hex(
            self.call("getrawtransaction", json!([txid]))
                .as_str()
                .unwrap(),
        )
        .unwrap();
        self.mine(1);
        let vout = contract
            .find_lock_output(&tx, amount)
            .expect("wallet locked the agreed amount");
        OutPoint {
            txid: tx.compute_txid(),
            vout,
        }
    }

    fn destination(&self) -> ScriptBuf {
        let info = self
            .wallet()
            .call("getaddressinfo", json!([self.new_address()]))
            .unwrap();
        ScriptBuf::from_hex(info["scriptPubKey"].as_str().unwrap()).unwrap()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.rpc.call("stop", json!([]));
        let deadline = Instant::now() + Duration::from_secs(30);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = self.child.kill();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

fn binaries() -> Option<(String, String)> {
    match (
        std::env::var("BTC_BITCOIND"),
        std::env::var("XBTC_BITCOIND"),
    ) {
        (Ok(btc), Ok(xbtc)) => Some((btc, xbtc)),
        _ => {
            eprintln!("skipped: set BTC_BITCOIND and XBTC_BITCOIND (scripts/test-in-container.sh)");
            None
        }
    }
}

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

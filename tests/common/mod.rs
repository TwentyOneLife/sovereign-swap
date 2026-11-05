//! Regtest nodes for the integration tests.
#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction};
use serde_json::{json, Value};

use sovereign_swap::htlc::Contract;
use sovereign_swap::rpc::{Client, RpcError};

static NEXT_PORT: AtomicU16 = AtomicU16::new(0);

pub struct Node {
    child: Child,
    datadir: PathBuf,
    pub rpc: Client,
}

impl Node {
    /// `fork_height` set means a Knots BLAKE2b node with the fork activating at that height.
    pub fn start(binary: &str, fork_height: Option<u32>) -> Node {
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

    pub fn call(&self, method: &str, params: Value) -> Value {
        self.rpc
            .call(method, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    /// The test's own mining wallet, apart from any wallet an engine creates.
    pub fn wallet(&self) -> Client {
        let loaded = self.call("listwallets", json!([]));
        if !loaded.as_array().unwrap().iter().any(|w| w == "w") {
            self.call("createwallet", json!(["w"]));
        }
        self.rpc.wallet("w")
    }

    pub fn new_address(&self) -> String {
        self.wallet()
            .call("getnewaddress", json!([]))
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    pub fn mine(&self, blocks: u32) {
        let address = self.new_address();
        self.call("generatetoaddress", json!([blocks, address]));
    }

    pub fn height(&self) -> u64 {
        self.call("getblockcount", json!([])).as_u64().unwrap()
    }

    pub fn header_len(&self, height: u64) -> usize {
        let hash = self.call("getblockhash", json!([height]));
        self.call("getblockheader", json!([hash, false]))
            .as_str()
            .unwrap()
            .len()
            / 2
    }

    /// Mempool policy and consensus: `Err(reason)` when the node would not accept `tx`.
    pub fn accept(&self, tx: &Transaction) -> Result<(), String> {
        let r = &self.call("testmempoolaccept", json!([[serialize_hex(tx)]]))[0];
        if r["allowed"].as_bool().unwrap() {
            Ok(())
        } else {
            Err(r["reject-reason"].as_str().unwrap_or_default().to_owned())
        }
    }

    /// Consensus only: mines `tx` into a block directly, bypassing mempool policy.
    pub fn mine_tx(&self, tx: &Transaction) -> Result<(), String> {
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

    pub fn send(&self, tx: &Transaction) {
        self.call("sendrawtransaction", json!([serialize_hex(tx)]));
        self.mine(1);
    }

    /// Locks `amount` in `contract` from the node wallet and confirms it.
    pub fn fund(&self, contract: &Contract, amount: Amount) -> OutPoint {
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

    pub fn destination(&self) -> ScriptBuf {
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

pub fn binaries() -> Option<(String, String)> {
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

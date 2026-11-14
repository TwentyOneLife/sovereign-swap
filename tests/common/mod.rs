//! Regtest nodes for the integration tests.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction};
use serde_json::{json, Value};

use sovereign_swap::electrum::ElectrumBackend;
use sovereign_swap::htlc::Contract;
use sovereign_swap::rpc::{Client, RpcError};

/// `n` distinct free loopback ports. All are bound at once (so they differ), then released just before
/// the caller hands them to a child process. Because the OS never hands out a port that is currently in
/// use, this collides far less than a computed per-pid counter (whose fixed-width buckets overlap once a
/// binary spawns enough nodes); a caller's retry loop heals the rare bind-time race.
fn free_ports(n: usize) -> Vec<u16> {
    let held: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind a free loopback port"))
        .collect();
    held.iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect()
    // `held` is dropped here, freeing the ports for the child to bind.
}

pub struct Node {
    child: Child,
    datadir: PathBuf,
    pub rpc: Client,
    pub rpc_port: u16,
}

impl Node {
    /// `fork_height` set means a Knots BLAKE2b node with the fork activating at that height. Runs with
    /// `txindex=1` (what every existing test and our btc-blake node use).
    pub fn start(binary: &str, fork_height: Option<u32>) -> Node {
        Node::start_with(binary, fork_height, true)
    }

    /// As [`Node::start`], but with `txindex` selectable: the split-verify safety guard
    /// (`split::require_txindex`) must refuse on a node whose txindex is off, so that path needs a
    /// `txindex=0` node to test against.
    pub fn start_with(binary: &str, fork_height: Option<u32>, txindex: bool) -> Node {
        // Each attempt takes OS-assigned free ports; if bitcoind still fails to bind (a rare race, or a
        // port grabbed between release and bind), the node does not come up and the loop retries with
        // fresh ports, so a collision self-heals instead of flaking.
        for _ in 0..8 {
            let ports = free_ports(2);
            let (rpc_port, p2p_port) = (ports[0], ports[1]);
            let datadir =
                std::env::temp_dir().join(format!("sovswap-{}-{rpc_port}", std::process::id()));
            std::fs::create_dir_all(&datadir).unwrap();
            let ti = u8::from(txindex);
            let mut conf = format!(
                "regtest=1\n[regtest]\nrpcport={rpc_port}\nport={p2p_port}\nrpcuser=u\nrpcpassword=p\n\
                 listen=0\nconnect=0\ndnsseed=0\nfallbackfee=0.0001\ntxindex={ti}\nprinttoconsole=0\n"
            );
            if let Some(h) = fork_height {
                conf.push_str(&format!("testactivationheight=blake2b@{h}\n"));
            }
            std::fs::write(datadir.join("bitcoin.conf"), conf).unwrap();
            let mut child = Command::new(binary)
                .arg(format!("-datadir={}", datadir.display()))
                .spawn()
                .unwrap();
            let rpc = Client::new(&format!("127.0.0.1:{rpc_port}"), "u", "p");
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if child.try_wait().ok().flatten().is_some() {
                    break; // bitcoind exited (a port clash); the outer loop tries a fresh port
                }
                match rpc.call("getblockchaininfo", json!([])) {
                    Ok(_) => {
                        return Node {
                            child,
                            datadir,
                            rpc,
                            rpc_port,
                        }
                    }
                    Err(_) if Instant::now() > deadline => {
                        let _ = child.kill();
                        break;
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(200)),
                }
            }
            let _ = child.kill();
            let _ = child.wait();
            let _ = std::fs::remove_dir_all(&datadir);
        }
        panic!("{binary} did not start after retries");
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

    /// A bech32 (P2WPKH) address, so coinbases mined to it are spent with a predictable ECDSA sighash
    /// (the split fixture relies on the signer's sighash: legacy = replayable, the fork's = not).
    pub fn new_bech32_address(&self) -> String {
        self.wallet()
            .call("getnewaddress", json!(["", "bech32"]))
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Mine `blocks` to a fresh bech32 address of this node's wallet, returning that address.
    pub fn mine_bech32(&self, blocks: u32) -> String {
        let a = self.new_bech32_address();
        self.call("generatetoaddress", json!([blocks, a]));
        a
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

    pub fn block_hash(&self, height: u64) -> String {
        self.call("getblockhash", json!([height]))
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Raw serialized block at `height` (verbosity 0), for mirroring to the other node.
    pub fn block_hex(&self, height: u64) -> String {
        let h = self.block_hash(height);
        self.call("getblock", json!([h, 0]))
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// The coinbase txid of the block at `height`.
    pub fn coinbase_txid(&self, height: u64) -> String {
        let h = self.block_hash(height);
        self.call("getblock", json!([h, 1]))["tx"][0]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// Submit a raw block mined on another node; returns `submitblock`'s result (null/empty on success).
    pub fn submit_block(&self, hex: &str) -> Value {
        self.call("submitblock", json!([hex]))
    }

    /// `true` if this node has a block at `height` (the other chain may not, past the fork).
    pub fn has_block(&self, height: u64) -> bool {
        self.rpc.call("getblockhash", json!([height])).is_ok()
    }

    /// `getindexinfo`-reported txindex sync state (for the verify safety-guard test).
    pub fn txindex_synced(&self) -> bool {
        self.call("getindexinfo", json!(["txindex"]))["txindex"]["synced"]
            .as_bool()
            .unwrap_or(false)
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

/// A Fulcrum Electrum server launched against a `Node`'s regtest bitcoind, for the E1 ChainBackend
/// regtest. Present only when `FULCRUM_BIN` is set (scripts/fetch-nodes.sh + test-in-container.sh);
/// the live-Electrum test skips otherwise. Serves plaintext Electrum on `port`.
pub struct Fulcrum {
    child: Child,
    datadir: PathBuf,
    pub port: u16,
}

impl Fulcrum {
    pub fn start(node: &Node) -> Option<Fulcrum> {
        let binary = std::env::var("FULCRUM_BIN").ok()?;
        let port = free_ports(1)[0];
        let datadir = std::env::temp_dir().join(format!("fulcrum-{}-{port}", std::process::id()));
        std::fs::create_dir_all(&datadir).unwrap();
        let conf = format!(
            "datadir = {dd}\nbitcoind = 127.0.0.1:{rpc}\nrpcuser = u\nrpcpassword = p\n\
             tcp = 127.0.0.1:{port}\npolltime = 1\n",
            dd = datadir.display(),
            rpc = node.rpc_port,
        );
        std::fs::write(datadir.join("fulcrum.conf"), &conf).unwrap();
        let log = datadir.join("fulcrum.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(&binary)
            .arg(datadir.join("fulcrum.conf"))
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .unwrap();
        // Ready once it answers server.version on the Electrum port (i.e. synced and listening).
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) {
                let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
                let probe = b"{\"id\":1,\"method\":\"server.version\",\"params\":[]}\n";
                let mut buf = [0u8; 32];
                if s.write_all(probe).is_ok() && s.read(&mut buf).map(|r| r > 0).unwrap_or(false) {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline,
                "Fulcrum did not become ready; log:\n{}",
                std::fs::read_to_string(&log).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(300));
        }
        Some(Fulcrum {
            child,
            datadir,
            port,
        })
    }
}

impl Drop for Fulcrum {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

/// Connect an `ElectrumBackend` to a just-started Fulcrum, retrying briefly. Fulcrum can momentarily
/// refuse connections while it (re)binds its listener during startup, so an immediate connect right
/// after the readiness probe occasionally fails with "Connection refused" (#155). Retrying removes
/// that race without masking a genuinely unreachable server (it still fails after the deadline).
pub fn connect_electrum(host: &str, port: u16, network: Network) -> ElectrumBackend {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match ElectrumBackend::connect(host, port, None, network) {
            Ok(be) => return be,
            Err(e) => {
                assert!(
                    Instant::now() < deadline,
                    "electrum connect kept failing: {e:?}"
                );
                std::thread::sleep(Duration::from_millis(250));
            }
        }
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

/// A deterministic forked pair for the coin-split tests: a Core (SHA256) node and a Knots (BLAKE2b)
/// node sharing byte-identical history below `fork_height` and diverging above it, like the mainnet
/// fork. Built WITHOUT P2P (`submitblock` mirroring, no peering race). The pre-fork range is split
/// between the two wallets: Core mines the low part, Knots the high part, each block mirrored to the
/// other node. So Core OWNS some pre-fork coinbases (the stock legacy signer, whose spends are
/// replayable) and Knots owns others (the Blake2b signer, whose spends use the fork sighash). Each
/// pre-fork coinbase is a SHA-Coin present on BOTH chains under one txid; a post-fork Knots coinbase is
/// a Blake2b-Coin that exists only on `xbtc`.
pub struct ForkedPair {
    pub btc: Node,
    pub xbtc: Node,
    pub fork_height: u32,
    /// Fresh bech32 addresses are needed to find the coinbases later; instead we fix the blocks the
    /// known coins come from. Coinbase heights: Core owns 1..split_at, Knots owns split_at..fork_height.
    split_at: u32,
}

impl ForkedPair {
    /// Blocks mined past the fork on each side; also the coinbase maturity window, so a pre-fork
    /// coinbase is spendable on both chains and a post-fork coinbase matures.
    pub const MATURITY: u32 = 110;

    /// Build the pair, or `None` when the node binaries are unset (the test then skips). `fork_height`
    /// must be above ~65 so the fixed coin heights below (5, 60, 61) fall in their intended ranges.
    pub fn start(fork_height: u32) -> Option<ForkedPair> {
        let (core, knots) = binaries()?;
        let btc = Node::start(&core, None);
        let xbtc = Node::start(&knots, Some(fork_height));
        let split_at = 50u32; // Core mines 1..50, Knots mines 50..fork_height-1

        // Core mines the low pre-fork blocks to its own wallet, each mirrored to Knots (verified both
        // directions work below the fork). Mining to bech32 so the coinbase is P2WPKH (ECDSA).
        btc.mine_bech32(split_at);
        for h in 1..=split_at as u64 {
            let r = xbtc.submit_block(&btc.block_hex(h));
            assert!(r.is_null(), "mirror Core block {h} to Knots failed: {r}");
        }
        // Knots mines the rest of the pre-fork range to its wallet, each mirrored back to Core. Every
        // block in 1..fork_height thus exists on BOTH chains (boundary = exactly fork_height), so no
        // unmirrored sub-fork coin exists (that would be the mainnet 961,632-639 gap).
        xbtc.mine_bech32(fork_height - 1 - split_at);
        for h in (split_at as u64 + 1)..fork_height as u64 {
            let r = btc.submit_block(&xbtc.block_hex(h));
            assert!(r.is_null(), "mirror Knots block {h} to Core failed: {r}");
        }
        assert_eq!(
            btc.block_hash((fork_height - 1) as u64),
            xbtc.block_hash((fork_height - 1) as u64),
            "shared pre-fork tip must be identical on both nodes"
        );
        assert!(
            !btc.has_block(fork_height as u64),
            "Core must not have any block at the fork height yet"
        );

        // Post-fork each side mines its own chain: Knots makes BLAKE2b blocks (Blake2b-Coins); Core makes
        // SHA256 blocks so its tip advances (pre-fork coinbases mature there too) and it holds
        // SHA256-only coins.
        xbtc.mine_bech32(Self::MATURITY);
        btc.mine_bech32(Self::MATURITY);
        assert_ne!(
            btc.block_hash(fork_height as u64),
            xbtc.block_hash(fork_height as u64),
            "post-fork blocks must diverge between the two chains"
        );
        Some(ForkedPair {
            btc,
            xbtc,
            fork_height,
            split_at,
        })
    }

    /// A pre-fork coinbase OWNED BY CORE (the stock legacy signer): a SHA-Coin present on both chains
    /// whose Core-wallet spend is replayable. Used for the negative control.
    pub fn core_sha_coin_txid(&self) -> String {
        self.btc.coinbase_txid(5)
    }

    /// A pre-fork coinbase OWNED BY KNOTS: a SHA-Coin present on both chains. Used for the split (built
    /// on the single Knots wallet) - block 60 is in the Knots-mined range (split_at..fork_height).
    pub fn knots_sha_coin_txid(&self) -> String {
        assert!(60 > self.split_at && 60 < self.fork_height);
        self.xbtc.coinbase_txid(60)
    }

    /// Another Knots-owned pre-fork coinbase (block 61), for the consensus check that a Knots-signed
    /// spend is rejected by Core - a different coin than the split's, so mining it would not confound.
    pub fn knots_other_sha_coin_txid(&self) -> String {
        self.xbtc.coinbase_txid(61)
    }

    /// A post-fork coinbase OWNED BY KNOTS (a Blake2b-Coin, only on `xbtc`): the separating marker.
    pub fn blake2b_coin_txid(&self) -> String {
        self.xbtc.coinbase_txid(self.fork_height as u64)
    }

    /// The value (sats) of outpoint `txid:vout` as the given node sees it.
    pub fn value_sat(node: &Node, txid: &str, vout: u32) -> u64 {
        let v = node.call("gettxout", json!([txid, vout]));
        (v["value"].as_f64().unwrap() * 1e8).round() as u64
    }
}

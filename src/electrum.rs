//! Electrum protocol client for the E1 `ChainBackend` (design 0016). A line-delimited JSON-RPC client
//! over TCP, optionally through a SOCKS5 proxy for a Tor onion, mirroring `rpc.rs`'s transport. The
//! `ElectrumBackend` that implements `ChainBackend` on top of this client lands next (see 0016); this
//! module is the self-contained, unit-testable core: the client and the `scripthash` primitive.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::DisplayHex;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use crate::htlc::{extract_preimage, Contract};
use crate::node::{ChainBackend, NodeError};
use crate::socks::socks5_connect;
use crate::swap::{FeeState, LockView, SpendView};

/// Budget for opening the socket (direct connect, or the whole SOCKS handshake).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Budget for one request/response.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// The Electrum `scripthash` for a scriptPubKey: `SHA-256(scriptPubKey)`, byte-reversed, lower hex.
/// Every `blockchain.scripthash.*` query addresses a contract's output script by this value.
pub fn scripthash(script: &ScriptBuf) -> String {
    let mut bytes = sha256::Hash::hash(script.as_bytes()).to_byte_array();
    bytes.reverse();
    bytes[..].to_lower_hex_string()
}

/// A minimal Electrum (ElectrumX / Fulcrum / Shulcrum) JSON-RPC client over a single socket. One call
/// writes one line and reads one line; a `Mutex` serialises calls so the id/response stay paired.
pub struct ElectrumClient {
    stream: Mutex<BufReader<TcpStream>>,
    next_id: AtomicU64,
}

impl ElectrumClient {
    /// Connects to `host:port` directly, or through `socks` (a SOCKS5 proxy, as a Tor onion needs).
    /// Plain TCP, framed by newlines; TLS for a clearnet LAN server is a later step (design 0016).
    pub fn connect(host: &str, port: u16, socks: Option<&str>) -> Result<Self, NodeError> {
        let stream = match socks {
            Some(proxy) => socks5_connect(proxy, host, port, CONNECT_TIMEOUT)
                .map_err(|e| NodeError::Unexpected(format!("electrum socks connect: {e}")))?,
            None => {
                let addr = (host, port)
                    .to_socket_addrs()
                    .map_err(|e| NodeError::Unexpected(format!("electrum address: {e}")))?
                    .next()
                    .ok_or_else(|| NodeError::Unexpected("electrum: no address resolved".into()))?;
                TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
                    .map_err(|e| NodeError::Unexpected(format!("electrum connect: {e}")))?
            }
        };
        stream
            .set_read_timeout(Some(CALL_TIMEOUT))
            .map_err(|e| NodeError::Unexpected(e.to_string()))?;
        Ok(Self {
            stream: Mutex::new(BufReader::new(stream)),
            next_id: AtomicU64::new(1),
        })
    }

    /// One JSON-RPC call: write a single request line, read one response line. A JSON-RPC `error`
    /// field is the server's typed refusal; anything else is returned as the `result`.
    pub fn call(&self, method: &str, params: Value) -> Result<Value, NodeError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = json!({"id": id, "method": method, "params": params}).to_string();
        line.push('\n');
        let mut guard = self.stream.lock().expect("electrum lock");
        guard
            .get_mut()
            .write_all(line.as_bytes())
            .map_err(|e| NodeError::Unexpected(format!("electrum write: {e}")))?;
        // Read until the reply carrying our id arrives, skipping any server-pushed notification: a
        // subscription (e.g. blockchain.headers.subscribe) pushes updates as id-less messages, which
        // would otherwise be mistaken for this call's response and desync every later call.
        loop {
            let mut resp = String::new();
            let read = guard
                .read_line(&mut resp)
                .map_err(|e| NodeError::Unexpected(format!("electrum read: {e}")))?;
            if read == 0 {
                return Err(NodeError::Unexpected("electrum: connection closed".into()));
            }
            let v: Value = serde_json::from_str(resp.trim())
                .map_err(|e| NodeError::Unexpected(format!("electrum parse: {e}")))?;
            if v.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
                return Err(NodeError::Unexpected(format!("electrum {method}: {err}")));
            }
            return Ok(v.get("result").cloned().unwrap_or(Value::Null));
        }
    }
}

/// Reads chain data and broadcasts over an Electrum server (Fulcrum for BTC, Shulcrum for xBTC): the
/// second `ChainBackend` (design 0016), which removes the user's full-node requirement. Funding and
/// signing are deliberately absent, exactly as the trait is.
pub struct ElectrumBackend {
    client: ElectrumClient,
    network: Network,
}

impl ElectrumBackend {
    /// Connects to an Electrum server for `network`, directly or through a SOCKS proxy (Tor onion).
    pub fn connect(
        host: &str,
        port: u16,
        socks: Option<&str>,
        network: Network,
    ) -> Result<Self, NodeError> {
        Ok(Self {
            client: ElectrumClient::connect(host, port, socks)?,
            network,
        })
    }
}

impl ChainBackend for ElectrumBackend {
    fn network(&self) -> Network {
        self.network
    }

    fn height(&self) -> Result<u32, NodeError> {
        self.client
            .call("blockchain.headers.subscribe", json!([]))?
            .get("height")
            .and_then(Value::as_u64)
            .map(|h| h as u32)
            .ok_or_else(|| NodeError::Unexpected("electrum: no height in headers.subscribe".into()))
    }

    fn get_tx(&self, txid: Txid) -> Result<Transaction, NodeError> {
        let r = self.client.call(
            "blockchain.transaction.get",
            json!([txid.to_string(), false]),
        )?;
        let hex = r.as_str().ok_or_else(|| {
            NodeError::Unexpected("electrum: transaction.get returned no hex".into())
        })?;
        deserialize_hex(hex).map_err(|e| NodeError::Unexpected(format!("electrum tx decode: {e}")))
    }

    fn watch_contract(&self, _contract: &Contract) -> Result<(), NodeError> {
        // Electrum is query-based: nothing to register; lock_view queries the scripthash live.
        Ok(())
    }

    fn lock_view(
        &self,
        contract: &Contract,
        amount: Amount,
        ours: &[ScriptBuf],
    ) -> Result<Option<LockView>, NodeError> {
        let spk = contract.script_pubkey();
        let sh = scripthash(&spk);
        let tip = self.height()?;
        let history = self
            .client
            .call("blockchain.scripthash.get_history", json!([sh]))?;
        let entries = history.as_array().cloned().unwrap_or_default();

        // Fetch each tx touching the address once, keeping its block height (<=0 means unconfirmed).
        let mut txs: Vec<(Transaction, i64)> = Vec::with_capacity(entries.len());
        for e in &entries {
            let Some(txid) = e
                .get("tx_hash")
                .and_then(Value::as_str)
                .and_then(|s| s.parse::<Txid>().ok())
            else {
                continue;
            };
            let height = e.get("height").and_then(Value::as_i64).unwrap_or(-1);
            txs.push((self.get_tx(txid)?, height));
        }

        // The lock output: a tx output paying the contract address. Prefer the one holding the agreed
        // amount (sets amount_ok), else the first seen, mirroring ChainNode.
        let mut exact: Option<(OutPoint, Amount, i64)> = None;
        let mut first: Option<(OutPoint, Amount, i64)> = None;
        for (tx, height) in &txs {
            let txid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                if o.script_pubkey == spk {
                    let hit = (
                        OutPoint {
                            txid,
                            vout: vout as u32,
                        },
                        o.value,
                        *height,
                    );
                    first.get_or_insert(hit);
                    if o.value == amount {
                        exact.get_or_insert(hit);
                    }
                }
            }
        }
        let amount_ok = exact.is_some();
        let Some((outpoint, value, f_height)) = exact.or(first) else {
            return Ok(None);
        };
        let confirmed_height = (f_height > 0).then_some(f_height as u32);

        // The spend: a tx whose input spends the lock outpoint.
        let spend = txs.iter().find_map(|(tx, height)| {
            tx.input
                .iter()
                .any(|i| i.previous_output == outpoint)
                .then(|| SpendView {
                    preimage: extract_preimage(tx, contract),
                    depth: if *height > 0 {
                        tip.saturating_sub(*height as u32) + 1
                    } else {
                        0
                    },
                    ours: tx.output.iter().any(|o| ours.contains(&o.script_pubkey)),
                })
        });

        Ok(Some(LockView {
            outpoint,
            value,
            amount_ok,
            confirmed_height,
            spend,
            // The backend never knows a swap's fee terms; the engine sets the counterparty lock's fee
            // state after verifying it (design 0010), identical to ChainNode.
            fee: FeeState::NotRequired,
        }))
    }

    fn broadcast(&self, tx: &Transaction) -> Result<(), NodeError> {
        match self.client.call(
            "blockchain.transaction.broadcast",
            json!([serialize_hex(tx)]),
        ) {
            Ok(_) => Ok(()),
            // An already-known transaction counts as success, as the trait requires.
            Err(NodeError::Unexpected(m)) if m.contains("already") => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn estimate_fee_sat_vb(&self, conf_target: u16) -> Option<u64> {
        // `blockchain.estimatefee` returns BTC/kvB, or -1 when it cannot estimate; convert to sat/vB.
        let btc_per_kvb = self
            .client
            .call("blockchain.estimatefee", json!([conf_target]))
            .ok()?
            .as_f64()?;
        if btc_per_kvb <= 0.0 {
            return None;
        }
        let sat_vb = (btc_per_kvb * 100_000.0).round() as u64;
        (sat_vb > 0).then_some(sat_vb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{PubkeyHash, Sequence, TxIn, TxOut, Witness};
    use std::net::TcpListener;

    /// A one-connection in-process Electrum server: each request line is answered by `handler`
    /// (method, params) -> result. Returns the port the client connects to.
    fn mock_server<F>(handler: F) -> u16
    where
        F: Fn(&str, &Value) -> Value + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let Ok((stream, _)) = listener.accept() else {
                return;
            };
            let mut writer = stream.try_clone().unwrap();
            let reader = BufReader::new(stream);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(req) = serde_json::from_str::<Value>(&line) else {
                    break;
                };
                let result = handler(req["method"].as_str().unwrap_or(""), &req["params"]);
                let mut out =
                    json!({"id": req["id"], "result": result, "error": Value::Null}).to_string();
                out.push('\n');
                if writer.write_all(out.as_bytes()).is_err() {
                    break;
                }
            }
        });
        port
    }

    #[test]
    fn lock_view_reads_a_funded_then_claimed_lock_via_electrum() {
        // A contract whose secret is [1u8; 32], so its claim preimage is known.
        let secret = [1u8; 32];
        let contract = Contract {
            secret_hash: sha256::Hash::hash(&secret).to_byte_array(),
            claim_pkh: PubkeyHash::from_byte_array([0x11; 20]),
            refund_pkh: PubkeyHash::from_byte_array([0x22; 20]),
            lock_blocks: 144,
        };
        let spk = contract.script_pubkey();
        let amount = Amount::from_sat(50_000);

        // Funding tx: one output paying the contract address.
        let funding = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: amount,
                script_pubkey: spk.clone(),
            }],
        };
        let funding_txid = funding.compute_txid();
        let lock = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        // Claim tx: spends the lock with a witness extract_preimage accepts (5 items: sig, pubkey,
        // preimage, selector [1], script), paying an address we own.
        let ours = ScriptBuf::from(vec![0x51]); // OP_TRUE marker we own
        let claim = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: lock,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[
                    &[0u8; 72][..],
                    &[0u8; 33][..],
                    &secret[..],
                    &[1u8][..],
                    contract.script().as_bytes(),
                ]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ours.clone(),
            }],
        };
        let claim_txid = claim.compute_txid();

        let funding_hex = serialize_hex(&funding);
        let claim_hex = serialize_hex(&claim);
        let (tip, hf, hs) = (200u32, 100i64, 150i64);
        let fund_id = funding_txid.to_string();
        let claim_id = claim_txid.to_string();

        let port = mock_server(move |method, params| match method {
            "blockchain.headers.subscribe" => json!({ "height": tip }),
            "blockchain.scripthash.get_history" => json!([
                { "tx_hash": fund_id, "height": hf },
                { "tx_hash": claim_id, "height": hs },
            ]),
            "blockchain.transaction.get" => {
                if params[0].as_str() == Some(fund_id.as_str()) {
                    json!(funding_hex)
                } else {
                    json!(claim_hex)
                }
            }
            "blockchain.estimatefee" => json!(0.0001),
            "blockchain.transaction.broadcast" => json!(claim_id),
            _ => Value::Null,
        });

        let be = ElectrumBackend::connect("127.0.0.1", port, None, Network::Regtest).unwrap();

        assert_eq!(be.height().unwrap(), tip);
        assert_eq!(be.get_tx(funding_txid).unwrap(), funding);
        assert_eq!(be.estimate_fee_sat_vb(1), Some(10)); // 0.0001 BTC/kvB * 100_000 = 10 sat/vB
        be.broadcast(&claim).unwrap();

        let view = be.lock_view(&contract, amount, &[ours]).unwrap().unwrap();
        assert_eq!(view.outpoint, lock);
        assert_eq!(view.value, amount);
        assert!(view.amount_ok);
        assert_eq!(view.confirmed_height, Some(hf as u32));
        let spend = view.spend.expect("the claim is detected as a spend");
        assert_eq!(spend.preimage, Some(secret));
        assert_eq!(spend.depth, tip - hs as u32 + 1);
        assert!(spend.ours);
    }

    #[test]
    fn scripthash_matches_a_known_p2pkh_vector() {
        // A fixed P2PKH scriptPubKey; the expected value is its Electrum scripthash
        // (reverse(sha256(script)), lower hex), verified independently.
        let spk =
            ScriptBuf::from_hex("76a91476a04053bda0a88bda5177b86a15c3b29f55987388ac").unwrap();
        assert_eq!(
            scripthash(&spk),
            "71b6a00546326a622c2a484e88a81909706a0cce15009aa87fd9a6569ca84c93"
        );
    }

    #[test]
    fn scripthash_is_reversed_not_raw_sha256() {
        let spk = ScriptBuf::from_hex("0014000102030405060708090a0b0c0d0e0f1011121314").unwrap();
        let raw = sha256::Hash::hash(spk.as_bytes()).to_byte_array()[..].to_lower_hex_string();
        assert_ne!(
            scripthash(&spk),
            raw,
            "scripthash must be byte-reversed, not raw sha256"
        );
    }
}

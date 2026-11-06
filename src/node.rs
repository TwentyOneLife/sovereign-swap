//! One chain as the engine sees it: the user's own node, a funding wallet and a watch-only wallet.
//!
//! The watch-only wallet holds the swap contracts' addresses, so the node itself tracks locks,
//! spends, confirmations and reorgs for us.

use std::collections::HashSet;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use crate::htlc::{extract_preimage, Contract};
use crate::replay::{check_inputs, ReplayError, UtxoLookup};
use crate::rpc::{Client, RpcError};
use crate::silentpayments::{FeePayment, SilentPaymentAddress};
use crate::swap::{FeeProof, FeeState, LockView, SpendView};

#[derive(Debug)]
pub enum NodeError {
    Rpc(RpcError),
    Replay(ReplayError<RpcError>),
    Unexpected(String),
}

impl From<RpcError> for NodeError {
    fn from(e: RpcError) -> NodeError {
        NodeError::Rpc(e)
    }
}

/// Signs a funding transaction. The engine builds the unsigned PSBT and runs the replay guard; the
/// signer turns it into a signed PSBT. This is the seam that keeps funding keys off the engine
/// server: in production the signer is an external cold device, so the engine holds no spending key
/// for the user's balance. `WalletSigner` (the node wallet) is the hot default for regtest and tests.
pub trait FundingSigner: Send + Sync {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError>;

    /// Sign a funding PSBT that carries a placeholder fee output at `fee_vout`, replacing that
    /// output's script with the fresh silent payment output for `recipient` (design 0010). Returns
    /// the signed PSBT and the [`FeePayment`] (the output, the ECDH share and the BIP374 proof). The
    /// signer needs the input keys, which is why this is its job. The default is to refuse: a signer
    /// that is not BIP352-aware cannot add the fee, and the daemon refuses to enable fees against it.
    fn sign_with_silent_fee(
        &self,
        _unsigned_psbt: &str,
        _recipient: &SilentPaymentAddress,
        _fee_vout: u32,
    ) -> Result<(String, FeePayment), NodeError> {
        Err(NodeError::Unexpected(
            "signer is not BIP352-aware; cannot add a silent payment fee".into(),
        ))
    }
}

/// Signs with a bitcoind wallet that holds the keys. Hot: only for test and regtest use, never the
/// cold production path.
pub struct WalletSigner {
    wallet: Client,
}

impl FundingSigner for WalletSigner {
    fn sign(&self, unsigned_psbt: &str) -> Result<String, NodeError> {
        let signed = self
            .wallet
            .call("walletprocesspsbt", json!([unsigned_psbt]))?;
        if signed["complete"] != true {
            return Err(NodeError::Unexpected(
                "signer did not fully sign the funding psbt".into(),
            ));
        }
        signed["psbt"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| NodeError::Unexpected("no psbt in sign result".into()))
    }
}

pub struct ChainNode {
    pub rpc: Client,
    wallet: Client,
    watch: Client,
    network: Network,
    signer: Box<dyn FundingSigner>,
}

fn parse<T: bitcoin::consensus::Decodable>(hex: &Value) -> Result<T, NodeError> {
    let hex = hex
        .as_str()
        .ok_or_else(|| NodeError::Unexpected(format!("not hex: {hex}")))?;
    deserialize_hex(hex).map_err(|e| NodeError::Unexpected(e.to_string()))
}

impl ChainNode {
    /// Opens (or creates) `<name>` for funds and `<name>-watch` for contracts on this node.
    pub fn open(rpc: Client, name: &str) -> Result<ChainNode, NodeError> {
        let network = match rpc.call("getblockchaininfo", json!([]))?["chain"].as_str() {
            Some("main") => Network::Bitcoin,
            Some("testnet4") => Network::Testnet4,
            Some("signet") => Network::Signet,
            Some("regtest") => Network::Regtest,
            other => return Err(NodeError::Unexpected(format!("chain {other:?}"))),
        };
        let watch_name = format!("{name}-watch");
        let loaded = rpc.call("listwallets", json!([]))?;
        for (wallet, watch_only) in [(name, false), (watch_name.as_str(), true)] {
            if loaded
                .as_array()
                .is_some_and(|l| l.iter().any(|w| w == wallet))
            {
                continue;
            }
            if rpc.call("loadwallet", json!([wallet])).is_err() {
                rpc.call("createwallet", json!([wallet, watch_only, watch_only]))?;
            }
        }
        let wallet = rpc.wallet(name);
        let signer = Box::new(WalletSigner {
            wallet: wallet.clone(),
        });
        Ok(ChainNode {
            wallet,
            watch: rpc.wallet(&watch_name),
            signer,
            rpc,
            network,
        })
    }

    /// Replaces the signer, e.g. an external cold signer in production so no funding key is on the
    /// engine host. The funding wallet is then watch-only.
    pub fn with_signer(mut self, signer: Box<dyn FundingSigner>) -> ChainNode {
        self.signer = signer;
        self
    }

    pub fn height(&self) -> Result<u32, NodeError> {
        Ok(self
            .rpc
            .call("getblockcount", json!([]))?
            .as_u64()
            .unwrap_or_default() as u32)
    }

    /// A transaction the watch wallet knows (it pays a watched contract), by txid: used to read a
    /// counterparty lock's inputs and outputs when checking its fee (design 0010).
    pub fn get_tx(&self, txid: Txid) -> Result<Transaction, NodeError> {
        let got = self
            .watch
            .call("gettransaction", json!([txid.to_string(), true]))?;
        parse(&got["hex"])
    }

    pub fn new_destination(&self) -> Result<ScriptBuf, NodeError> {
        let address = self.wallet.call("getnewaddress", json!([]))?;
        let info = self.wallet.call("getaddressinfo", json!([address]))?;
        ScriptBuf::from_hex(info["scriptPubKey"].as_str().unwrap_or_default())
            .map_err(|e| NodeError::Unexpected(e.to_string()))
    }

    fn address(&self, contract: &Contract) -> Address {
        Address::from_script(&contract.script_pubkey(), self.network).expect("P2WSH has an address")
    }

    pub fn watch_contract(&self, contract: &Contract) -> Result<(), NodeError> {
        let desc = format!("addr({})", self.address(contract));
        let info = self.rpc.call("getdescriptorinfo", json!([desc]))?;
        let desc = format!("{desc}#{}", info["checksum"].as_str().unwrap_or_default());
        let result = self.watch.call(
            "importdescriptors",
            json!([[{"desc": desc, "timestamp": "now"}]]),
        )?;
        match result[0]["success"].as_bool() {
            Some(true) => Ok(()),
            _ => Err(NodeError::Unexpected(format!(
                "importdescriptors: {result}"
            ))),
        }
    }

    /// The lock of `amount` in `contract`, as the node sees it now. `ours` are our own claim and
    /// refund destinations, to tell our spend from the counterparty's.
    pub fn lock_view(
        &self,
        contract: &Contract,
        amount: Amount,
        ours: &[ScriptBuf],
    ) -> Result<Option<LockView>, NodeError> {
        let address = self.address(contract).to_string();
        let history = self
            .watch
            .call("listtransactions", json!(["*", 1000, 0, true]))?;
        let entries = history.as_array().cloned().unwrap_or_default();
        let live = |e: &Value| e["confirmations"].as_i64().unwrap_or(-1) >= 0;
        let receives: Vec<&Value> = entries
            .iter()
            .filter(|e| e["category"] == "receive" && e["address"] == address.as_str() && live(e))
            .collect();
        let exact = receives.iter().find(|e| {
            Amount::from_btc(e["amount"].as_f64().unwrap_or_default()).ok() == Some(amount)
        });
        let Some(entry) = exact.or(receives.first()) else {
            return Ok(None);
        };
        let outpoint = OutPoint {
            txid: entry["txid"]
                .as_str()
                .unwrap_or_default()
                .parse()
                .map_err(|_| NodeError::Unexpected("txid".into()))?,
            vout: entry["vout"].as_u64().unwrap_or_default() as u32,
        };
        let height = self.height()?;
        let confirmations = entry["confirmations"].as_u64().unwrap_or_default() as u32;
        let confirmed_height = (confirmations > 0).then(|| height + 1 - confirmations);

        let mut spend = None;
        let mut seen = HashSet::new();
        for e in entries
            .iter()
            .filter(|e| e["category"] == "send" && live(e))
        {
            let txid: Txid = match e["txid"].as_str().and_then(|t| t.parse().ok()) {
                Some(t) => t,
                None => continue,
            };
            if !seen.insert(txid) {
                continue;
            }
            let tx: Transaction = parse(
                &self
                    .watch
                    .call("gettransaction", json!([txid.to_string(), true]))?["hex"],
            )?;
            if tx.input.iter().any(|i| i.previous_output == outpoint) {
                spend = Some(SpendView {
                    preimage: extract_preimage(&tx, contract),
                    depth: e["confirmations"].as_u64().unwrap_or_default() as u32,
                    ours: tx.output.iter().any(|o| ours.contains(&o.script_pubkey)),
                });
                break;
            }
        }
        let value = Amount::from_btc(entry["amount"].as_f64().unwrap_or_default())
            .map_err(|e| NodeError::Unexpected(e.to_string()))?;
        Ok(Some(LockView {
            outpoint,
            value,
            amount_ok: exact.is_some(),
            confirmed_height,
            spend,
            // The node does not know a swap's fee terms; the engine sets the counterparty lock's
            // fee state after verifying it (design 0010). Our own lock stays NotRequired.
            fee: FeeState::NotRequired,
        }))
    }

    /// Funds and signs a lock of `amount` in `contract` from the funding wallet, from inputs with at
    /// least `minconf` confirmations, refusing inputs that are still spendable on `other_chain`.
    /// Nothing is broadcast.
    pub fn fund(
        &self,
        contract: &Contract,
        amount: Amount,
        fee_rate_sat_vb: u64,
        minconf: u32,
        other_chain: &impl UtxoLookup<Error = RpcError>,
        fee: Option<(Amount, &SilentPaymentAddress)>,
    ) -> Result<(Transaction, Option<FeeProof>), NodeError> {
        let mut outputs = vec![json!({ self.address(contract).to_string(): amount.to_btc() })];
        // When a fee is due, add a placeholder P2TR output the signer rewrites into the fresh silent
        // payment output. P2TR so its size, and so the miner fee, matches the final transaction.
        let placeholder_spk = match fee {
            Some((fee_amount, _)) => {
                let addr = self.wallet.call("getnewaddress", json!(["", "bech32m"]))?;
                let addr = addr
                    .as_str()
                    .ok_or_else(|| NodeError::Unexpected("no placeholder address".into()))?;
                outputs.push(json!({ addr: fee_amount.to_btc() }));
                let info = self.wallet.call("getaddressinfo", json!([addr]))?;
                Some(info["scriptPubKey"].as_str().unwrap_or_default().to_owned())
            }
            None => None,
        };
        let options =
            json!({ "fee_rate": fee_rate_sat_vb, "replaceable": true, "minconf": minconf });
        let funded = self.wallet.call(
            "walletcreatefundedpsbt",
            json!([[], json!(outputs), 0, options]),
        )?;
        let psbt = funded["psbt"]
            .as_str()
            .ok_or_else(|| NodeError::Unexpected("no psbt".into()))?;
        let decoded = self.rpc.call("decodepsbt", json!([psbt]))?;
        check_inputs(&inputs_of(&decoded["tx"])?, other_chain).map_err(NodeError::Replay)?;

        // Delegate signing: the engine never holds the funding keys (cold in production).
        let (signed_psbt, fee_proof) = match (fee, placeholder_spk) {
            (Some((_, recipient)), Some(spk)) => {
                // Funding may insert a change output, so find the placeholder by its script.
                let fee_vout = find_vout(&decoded["tx"], &spk).ok_or_else(|| {
                    NodeError::Unexpected("placeholder fee output not in the funded psbt".into())
                })?;
                let (signed, pay) = self
                    .signer
                    .sign_with_silent_fee(psbt, recipient, fee_vout)?;
                let share = PublicKey::from_slice(&pay.share)
                    .map_err(|_| NodeError::Unexpected("bad fee share".into()))?;
                let prevouts = self.input_prevouts(&decoded["tx"])?;
                (
                    signed,
                    Some(FeeProof {
                        share,
                        proof: pay.proof.to_vec(),
                        prevouts,
                    }),
                )
            }
            _ => (self.signer.sign(psbt)?, None),
        };
        let finalized = self.rpc.call("finalizepsbt", json!([signed_psbt]))?;
        if finalized["complete"] != true {
            return Err(NodeError::Unexpected(
                "funding psbt did not finalize".into(),
            ));
        }
        let tx: Transaction = parse(&finalized["hex"])?;
        contract
            .find_lock_output(&tx, amount)
            .map_err(|e| NodeError::Unexpected(format!("funded lock: {e:?}")))?;
        Ok((tx, fee_proof))
    }

    /// The prevout transactions of a decoded PSBT's inputs, fetched from this node, so a counterparty
    /// can authenticate the input public keys the fee proof is built over.
    fn input_prevouts(&self, tx: &Value) -> Result<Vec<Transaction>, NodeError> {
        let mut out = Vec::new();
        for vin in tx["vin"].as_array().into_iter().flatten() {
            let txid = vin["txid"]
                .as_str()
                .ok_or_else(|| NodeError::Unexpected("input without a txid".into()))?;
            let raw = self.rpc.call("getrawtransaction", json!([txid]))?;
            out.push(parse(&raw)?);
        }
        Ok(out)
    }

    /// Broadcasts `tx`; a transaction the node already has counts as success.
    pub fn broadcast(&self, tx: &Transaction) -> Result<(), NodeError> {
        match self
            .rpc
            .call("sendrawtransaction", json!([serialize_hex(tx)]))
        {
            Ok(_) => Ok(()),
            Err(RpcError::Rpc { code: -27, .. }) => Ok(()),
            Err(RpcError::Rpc { message, .. }) if message.contains("already") => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// The vout of the output of `decodepsbt`'s transaction whose scriptPubKey is `spk_hex`, if any.
fn find_vout(tx: &Value, spk_hex: &str) -> Option<u32> {
    tx["vout"].as_array()?.iter().find_map(|o| {
        (o["scriptPubKey"]["hex"].as_str() == Some(spk_hex))
            .then(|| o["n"].as_u64().unwrap_or(0) as u32)
    })
}

/// The inputs of `decodepsbt`'s transaction, as a transaction the replay guard can read.
fn inputs_of(tx: &Value) -> Result<Transaction, NodeError> {
    use bitcoin::transaction::Version;
    use bitcoin::{absolute, Sequence, TxIn, Witness};
    let bad = || NodeError::Unexpected(format!("decodepsbt tx: {tx}"));
    let input = tx["vin"]
        .as_array()
        .ok_or_else(bad)?
        .iter()
        .map(|i| {
            Ok(TxIn {
                previous_output: OutPoint {
                    txid: i["txid"]
                        .as_str()
                        .and_then(|t| t.parse().ok())
                        .ok_or_else(bad)?,
                    vout: i["vout"].as_u64().ok_or_else(bad)? as u32,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
        })
        .collect::<Result<_, NodeError>>()?;
    Ok(Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output: vec![],
    })
}

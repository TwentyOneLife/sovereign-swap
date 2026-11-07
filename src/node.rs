//! One chain as the engine sees it: the user's own node, a funding wallet and a watch-only wallet.
//!
//! The watch-only wallet holds the swap contracts' addresses, so the node itself tracks locks,
//! spends, confirmations and reorgs for us.

use std::collections::HashSet;
use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{Keypair, PublicKey, Secp256k1, SecretKey};
use bitcoin::{Address, Amount, Network, OutPoint, Psbt, ScriptBuf, Transaction, Txid};
use serde_json::{json, Value};

use crate::htlc::{extract_preimage, Contract};
use crate::replay::{check_inputs, ReplayError, UtxoLookup};
use crate::rpc::{Client, RpcError};
use crate::silentpayments::{pay_fee, FeePayment, InputKey, SilentPaymentAddress};
use crate::swap::{FeeProof, FeeState, LockView, SpendView};

#[derive(Debug)]
pub enum NodeError {
    Rpc(RpcError),
    Replay(ReplayError<RpcError>),
    Signer(SignerError),
    Unexpected(String),
}

/// Why a remote (cold) funding signer did not return a usable signed PSBT (design 0012). Kept
/// distinct from a node `Rpc` error so the daemon can tell "the signer is unreachable, do not fund"
/// from "the signer refused this PSBT", and so neither is ever confused with a hot fallback.
#[derive(Debug)]
pub enum SignerError {
    /// The signer endpoint could not be reached. There is no hot fallback: funding simply refuses.
    Unreachable(String),
    /// The signer did not answer within the timeout.
    Timeout,
    /// The signer answered with a typed refusal (a policy ceiling, an allow-list, a rate limit, ...).
    Refused { code: i64, message: String },
    /// The signer answered, but the reply was not a usable signed PSBT for the same transaction.
    Malformed(String),
}

impl From<RpcError> for NodeError {
    fn from(e: RpcError) -> NodeError {
        NodeError::Rpc(e)
    }
}

/// Where a voluntary fee output pays (design 0013). A silent payment address gives a fresh, unlinkable
/// output that the counterparty authenticates with a DLEQ proof; a normal address is paid directly and
/// verified against the agreed address on chain, with no proof and no BIP352-aware signer required.
pub enum FeeDest {
    SilentPayment(SilentPaymentAddress),
    Normal(Address),
}

impl FeeDest {
    /// Parse a configured fee address, requiring it to be for `network`. An `sp`/`tsp`/`sprt` address
    /// is a silent payment; anything else that is a valid address for the network is normal. Both
    /// chains share Bitcoin's network parameters, so the wrong-chain guard is the per-chain field, not
    /// this network check (design 0013).
    pub fn parse(s: &str, network: Network) -> Result<FeeDest, NodeError> {
        if let Ok(sp) = SilentPaymentAddress::parse(s) {
            if sp.network != network {
                return Err(NodeError::Unexpected(
                    "fee address is for the wrong network".into(),
                ));
            }
            return Ok(FeeDest::SilentPayment(sp));
        }
        let addr = Address::from_str(s)
            .map_err(|e| NodeError::Unexpected(format!("fee address: {e}")))?
            .require_network(network)
            .map_err(|_| NodeError::Unexpected("fee address is for the wrong network".into()))?;
        Ok(FeeDest::Normal(addr))
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

    /// Hot (regtest) BIP352 signing: derive each input's key from the wallet's own descriptors,
    /// compute the silent payment fee output, share and proof, place the output in the PSBT and
    /// sign (design 0010). The production path is an external BIP352-aware cold signer, not this.
    fn sign_with_silent_fee(
        &self,
        unsigned_psbt: &str,
        recipient: &SilentPaymentAddress,
        fee_vout: u32,
    ) -> Result<(String, FeePayment), NodeError> {
        let secp = Secp256k1::new();
        let master = self.master_key()?;
        let decoded = self.wallet.call("decodepsbt", json!([unsigned_psbt]))?;
        let vin = decoded["tx"]["vin"]
            .as_array()
            .ok_or_else(|| NodeError::Unexpected("psbt has no inputs".into()))?;
        let psin = decoded["inputs"].as_array();

        let mut inputs = Vec::new();
        let mut all_outpoints = Vec::new();
        for (i, v) in vin.iter().enumerate() {
            let outpoint = OutPoint {
                txid: v["txid"]
                    .as_str()
                    .and_then(|t| t.parse().ok())
                    .ok_or_else(|| NodeError::Unexpected("input txid".into()))?,
                vout: v["vout"].as_u64().unwrap_or_default() as u32,
            };
            all_outpoints.push(outpoint);
            // The prevout's scriptPubKey is under witness_utxo (segwit) or non_witness_utxo (legacy).
            let pin = psin.and_then(|p| p.get(i)).unwrap_or(&Value::Null);
            let spk = if pin["witness_utxo"].is_object() {
                &pin["witness_utxo"]["scriptPubKey"]
            } else {
                &pin["non_witness_utxo"]["vout"][outpoint.vout as usize]["scriptPubKey"]
            };
            let addr = spk["address"]
                .as_str()
                .ok_or_else(|| NodeError::Unexpected("input is not ours to sign".into()))?;
            let taproot = spk["type"].as_str() == Some("witness_v1_taproot");
            let info = self.wallet.call("getaddressinfo", json!([addr]))?;
            let hdkeypath = info["hdkeypath"]
                .as_str()
                .ok_or_else(|| NodeError::Unexpected("no hdkeypath for input".into()))?;
            let key = derive_input_key(&secp, &master, hdkeypath, taproot)?;
            inputs.push(InputKey { key, taproot });
        }

        let pay = pay_fee(&secp, &inputs, &all_outpoints, recipient, &os_random())
            .map_err(|e| NodeError::Unexpected(format!("fee derivation: {e:?}")))?;
        let signed = self.place_fee_output_and_sign(unsigned_psbt, fee_vout, &pay.output)?;
        Ok((signed, pay))
    }
}

impl WalletSigner {
    /// The wallet's master extended private key, taken from any of its private descriptors (they all
    /// descend from the one wallet seed, so each input's full hdkeypath derives from it). This is the
    /// hot regtest signer; production holds no such key here.
    fn master_key(&self) -> Result<Xpriv, NodeError> {
        let listed = self.wallet.call("listdescriptors", json!([true]))?;
        for d in listed["descriptors"].as_array().into_iter().flatten() {
            let desc = d["desc"].as_str().unwrap_or("");
            // The key runs from `tprv`/`xprv` up to the first path element (`/`).
            if let Some(start) = desc.find("tprv").or_else(|| desc.find("xprv")) {
                let s: String = desc[start..].chars().take_while(|c| *c != '/').collect();
                if let Ok(xprv) = Xpriv::from_str(&s) {
                    return Ok(xprv);
                }
            }
        }
        Err(NodeError::Unexpected(
            "wallet exposes no private key to sign a silent payment fee".into(),
        ))
    }

    /// Replace the placeholder output at `fee_vout` with the silent payment output, then sign. The
    /// value and P2TR size are unchanged, so the funded miner fee still holds; the stale wallet
    /// metadata for the rewritten output is cleared so signing is unaffected.
    fn place_fee_output_and_sign(
        &self,
        unsigned_psbt: &str,
        fee_vout: u32,
        spk: &ScriptBuf,
    ) -> Result<String, NodeError> {
        let mut psbt = Psbt::from_str(unsigned_psbt)
            .map_err(|e| NodeError::Unexpected(format!("psbt: {e}")))?;
        let vout = fee_vout as usize;
        if vout >= psbt.unsigned_tx.output.len() {
            return Err(NodeError::Unexpected("fee vout out of range".into()));
        }
        psbt.unsigned_tx.output[vout].script_pubkey = spk.clone();
        if let Some(o) = psbt.outputs.get_mut(vout) {
            o.bip32_derivation.clear();
            o.tap_key_origins.clear();
            o.tap_internal_key = None;
        }
        let signed = self
            .wallet
            .call("walletprocesspsbt", json!([psbt.to_string()]))?;
        if signed["complete"] != true {
            return Err(NodeError::Unexpected(
                "signer did not fully sign the fee psbt".into(),
            ));
        }
        signed["psbt"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| NodeError::Unexpected("no psbt in sign result".into()))
    }
}

/// Derive an input's signing key from the wallet master and the input's full `m/...` hdkeypath,
/// applying the taproot key-path tweak for a taproot input so the key matches the output key. Works
/// for every BIP352-eligible input type (P2PKH, P2WPKH, P2SH-P2WPKH, P2TR), since the kind is encoded
/// in the path and only taproot needs the tweak.
fn derive_input_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    master: &Xpriv,
    hdkeypath: &str,
    taproot: bool,
) -> Result<SecretKey, NodeError> {
    let path = DerivationPath::from_str(hdkeypath.trim_start_matches("m/"))
        .map_err(|_| NodeError::Unexpected("bad hdkeypath".into()))?;
    let derived = master
        .derive_priv(secp, &path)
        .map_err(|_| NodeError::Unexpected("derive".into()))?
        .private_key;
    if taproot {
        let kp = Keypair::from_secret_key(secp, &derived);
        Ok(kp.tap_tweak(secp, None).to_keypair().secret_key())
    } else {
        Ok(derived)
    }
}

fn os_random() -> [u8; 32] {
    let mut b = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut b);
    }
    b
}

/// The chain data and broadcast surface the engine needs from a node, with no wallet in it: the
/// network, the tip height, a transaction by txid, a watch-only registration for a contract, the
/// live view of a lock, and transaction broadcast. `ChainNode` is the bitcoind implementation; a
/// future Electrum backend (Fulcrum for BTC, Shulcrum for xBTC) is another, which is what removes
/// the user's full-node requirement (design 0014). Funding and signing are deliberately absent:
/// they stay on `ChainNode` until they move to the user's own wallet in a later stage.
pub trait ChainBackend {
    /// The network this backend serves.
    fn network(&self) -> Network;

    /// The current tip height.
    fn height(&self) -> Result<u32, NodeError>;

    /// A transaction this backend knows, by txid: used to read a counterparty lock's inputs and
    /// outputs when checking its fee (design 0010).
    fn get_tx(&self, txid: Txid) -> Result<Transaction, NodeError>;

    /// Registers `contract`'s address so the backend tracks its lock, spends and confirmations.
    fn watch_contract(&self, contract: &Contract) -> Result<(), NodeError>;

    /// The lock of `amount` in `contract`, as the backend sees it now. `ours` are our own claim and
    /// refund destinations, to tell our spend from the counterparty's.
    fn lock_view(
        &self,
        contract: &Contract,
        amount: Amount,
        ours: &[ScriptBuf],
    ) -> Result<Option<LockView>, NodeError>;

    /// Broadcasts `tx`; a transaction the backend already has counts as success.
    fn broadcast(&self, tx: &Transaction) -> Result<(), NodeError>;
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

/// The network this node serves, from `getblockchaininfo`. Shared by `open` and `open_cold`.
fn chain_network(rpc: &Client) -> Result<Network, NodeError> {
    match rpc.call("getblockchaininfo", json!([]))?["chain"].as_str() {
        Some("main") => Ok(Network::Bitcoin),
        Some("testnet4") => Ok(Network::Testnet4),
        Some("signet") => Ok(Network::Signet),
        Some("regtest") => Ok(Network::Regtest),
        other => Err(NodeError::Unexpected(format!("chain {other:?}"))),
    }
}

/// Imports one account descriptor into the watch-only funding wallet as an active descriptor (design
/// 0012), idempotently. The checksum comes from `getdescriptorinfo`'s canonical `descriptor` field,
/// so a descriptor supplied with or without a `#checksum` is normalised and never double-appended.
/// `internal` marks the change branch. When the wallet is not freshly created, the import is skipped
/// if the descriptor is already present, so a restart does not re-import (which Core can reject once
/// the keypool has advanced the stored range).
fn ensure_account_descriptor(
    rpc: &Client,
    wallet: &Client,
    descriptor: &str,
    internal: bool,
    created: bool,
) -> Result<(), NodeError> {
    let info = rpc.call("getdescriptorinfo", json!([descriptor]))?;
    let canonical = info["descriptor"]
        .as_str()
        .ok_or_else(|| NodeError::Unexpected("getdescriptorinfo returned no descriptor".into()))?;
    if !created {
        let listed = wallet.call("listdescriptors", json!([]))?;
        let present = listed["descriptors"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|d| d["desc"].as_str() == Some(canonical));
        if present {
            return Ok(());
        }
    }
    let result = wallet.call(
        "importdescriptors",
        json!([[{
            "desc": canonical,
            "timestamp": "now",
            "active": true,
            "internal": internal,
            "range": 1000,
        }]]),
    )?;
    match result[0]["success"].as_bool() {
        Some(true) => Ok(()),
        _ => Err(NodeError::Unexpected(format!(
            "importdescriptors ({}): {result}",
            if internal { "change" } else { "receive" }
        ))),
    }
}

impl ChainNode {
    /// Opens (or creates) `<name>` for funds and `<name>-watch` for contracts on this node. Hot: the
    /// funding wallet holds its keys and signs with `WalletSigner`. The cold path is `open_cold`.
    pub fn open(rpc: Client, name: &str) -> Result<ChainNode, NodeError> {
        let network = chain_network(&rpc)?;
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

    /// Opens the chain for cold funding (design 0012). `<name>` is created watch-only
    /// (`private_keys_enabled=false`) and the account descriptors (receive external + change
    /// internal) are imported, so the engine builds funded PSBTs with no private key; `<name>-watch`
    /// tracks contracts exactly as in `open`. The external `signer` is injected here, so a hot
    /// `WalletSigner` is never constructed on this path and there is no hot fallback.
    ///
    /// Loud safety refusal: if `<name>` holds private keys (a hot wallet reused under a cold config),
    /// this returns an error rather than ever signing the user's balance on the engine host.
    ///
    /// Import uses `timestamp: "now"`, so only funds received after the import are tracked. An
    /// operator migrating a pre-funded xpub needs a rescan (a later-stage concern, design 0012); for
    /// stage 1 the funding account is expected to be funded after provisioning.
    pub fn open_cold(
        rpc: Client,
        name: &str,
        descriptor_receive: &str,
        descriptor_change: &str,
        signer: Box<dyn FundingSigner>,
    ) -> Result<ChainNode, NodeError> {
        let network = chain_network(&rpc)?;
        let watch_name = format!("{name}-watch");
        let loaded = rpc.call("listwallets", json!([]))?;
        let is_loaded = |w: &str| loaded.as_array().is_some_and(|l| l.iter().any(|v| v == w));
        // Both wallets are watch-only: the funding wallet tracks the user's balance from the account
        // descriptors, the watch wallet tracks the swap contracts. Remember whether the funding
        // wallet was created now, so a restart does not re-import into an existing one.
        let mut funding_created = false;
        for wallet in [name, watch_name.as_str()] {
            if is_loaded(wallet) || rpc.call("loadwallet", json!([wallet])).is_ok() {
                continue;
            }
            // disable_private_keys=true, blank=true, passphrase="", avoid_reuse=false,
            // descriptors=true: a blank descriptor wallet that holds no key.
            rpc.call("createwallet", json!([wallet, true, true, "", false, true]))?;
            if wallet == name {
                funding_created = true;
            }
        }
        let wallet = rpc.wallet(name);
        // Safety (design 0012): the funding wallet must hold no private key, whether just created,
        // loaded, or already present. Keys present means a hot wallet was reused under a cold config;
        // refuse rather than ever sign the user's balance on the engine host.
        let info = wallet.call("getwalletinfo", json!([]))?;
        if info["private_keys_enabled"].as_bool() != Some(false) {
            return Err(NodeError::Unexpected(format!(
                "cold funding wallet {name} has private keys enabled; it must be watch-only. \
                 Refusing to fund from a key on the engine host (recreate it from the account \
                 descriptors)."
            )));
        }
        // Import the receive (external) and change (internal) account descriptors so
        // walletcreatefundedpsbt can select coins and build a change-handling PSBT. Only on a fresh
        // wallet, or when a descriptor is absent: re-importing an existing one on every restart can
        // be rejected once the keypool has advanced the stored range (design 0012).
        ensure_account_descriptor(&rpc, &wallet, descriptor_receive, false, funding_created)?;
        ensure_account_descriptor(&rpc, &wallet, descriptor_change, true, funding_created)?;
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

    pub fn new_destination(&self) -> Result<ScriptBuf, NodeError> {
        let address = self.wallet.call("getnewaddress", json!([]))?;
        let info = self.wallet.call("getaddressinfo", json!([address]))?;
        ScriptBuf::from_hex(info["scriptPubKey"].as_str().unwrap_or_default())
            .map_err(|e| NodeError::Unexpected(e.to_string()))
    }

    fn address(&self, contract: &Contract) -> Address {
        Address::from_script(&contract.script_pubkey(), self.network).expect("P2WSH has an address")
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
        fee: Option<(Amount, &FeeDest)>,
    ) -> Result<(Transaction, Option<FeeProof>), NodeError> {
        let mut outputs = vec![json!({ self.address(contract).to_string(): amount.to_btc() })];
        // A silent-payment fee needs a placeholder P2TR output the signer rewrites into the fresh
        // output (P2TR so its size, and the miner fee, match the final transaction). A normal-address
        // fee is paid directly as its own output, with nothing to rewrite (design 0013).
        let placeholder_spk = match fee {
            Some((fee_amount, FeeDest::SilentPayment(_))) => {
                let addr = self.wallet.call("getnewaddress", json!(["", "bech32m"]))?;
                let addr = addr
                    .as_str()
                    .ok_or_else(|| NodeError::Unexpected("no placeholder address".into()))?;
                outputs.push(json!({ addr: fee_amount.to_btc() }));
                let info = self.wallet.call("getaddressinfo", json!([addr]))?;
                Some(info["scriptPubKey"].as_str().unwrap_or_default().to_owned())
            }
            Some((fee_amount, FeeDest::Normal(addr))) => {
                outputs.push(json!({ addr.to_string(): fee_amount.to_btc() }));
                None
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

        // Delegate signing: the engine never holds the funding keys (cold in production). A silent
        // payment fee is signed through the BIP352 path and yields a proof; a normal-address fee (or
        // no fee) is a plain signature with no proof.
        let (signed_psbt, fee_proof) = match (fee, placeholder_spk) {
            (Some((_, FeeDest::SilentPayment(recipient))), Some(spk)) => {
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
}

/// bitcoind is the first `ChainBackend`: chain data from the node's RPC, locks tracked by the
/// watch-only wallet (`watch_contract`, `lock_view`), and broadcast over `sendrawtransaction`.
impl ChainBackend for ChainNode {
    fn network(&self) -> Network {
        self.network
    }

    fn height(&self) -> Result<u32, NodeError> {
        Ok(self
            .rpc
            .call("getblockcount", json!([]))?
            .as_u64()
            .unwrap_or_default() as u32)
    }

    /// The watch wallet knows this transaction because it pays a watched contract.
    fn get_tx(&self, txid: Txid) -> Result<Transaction, NodeError> {
        let got = self
            .watch
            .call("gettransaction", json!([txid.to_string(), true]))?;
        parse(&got["hex"])
    }

    fn watch_contract(&self, contract: &Contract) -> Result<(), NodeError> {
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

    fn lock_view(
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

    fn broadcast(&self, tx: &Transaction) -> Result<(), NodeError> {
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

#[cfg(test)]
mod fee_dest_tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::WPubkeyHash;

    fn sp(network: Network) -> SilentPaymentAddress {
        let secp = Secp256k1::new();
        SilentPaymentAddress {
            scan: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x11; 32]).unwrap()),
            spend: PublicKey::from_secret_key(&secp, &SecretKey::from_slice(&[0x22; 32]).unwrap()),
            network,
        }
    }

    #[test]
    fn classifies_silent_payment_and_normal() {
        let sp_addr = sp(Network::Regtest).encode();
        assert!(matches!(
            FeeDest::parse(&sp_addr, Network::Regtest),
            Ok(FeeDest::SilentPayment(_))
        ));
        let spk = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x11; 20]));
        let normal = Address::from_script(&spk, Network::Regtest)
            .unwrap()
            .to_string();
        assert!(matches!(
            FeeDest::parse(&normal, Network::Regtest),
            Ok(FeeDest::Normal(_))
        ));
    }

    #[test]
    fn rejects_wrong_network_and_garbage() {
        let mainnet_sp = sp(Network::Bitcoin).encode();
        assert!(FeeDest::parse(&mainnet_sp, Network::Regtest).is_err());
        assert!(FeeDest::parse("not-an-address", Network::Regtest).is_err());
    }
}

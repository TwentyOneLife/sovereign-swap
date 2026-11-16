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
    /// The funding signer is the user, who signs out of band (E2, design 0017): this carries the
    /// unsigned funding PSBT (already past the replay guard in `fund()`) so the engine parks the swap
    /// awaiting the user's signature instead of funding it now. Not a failure, a checkpoint.
    AwaitingSignature {
        psbt: String,
    },
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

    /// Whether this signer can build a silent-payment (BIP352) fee output. The engine checks this
    /// before committing to an offer whose fee for the chain it funds is a silent payment, so it never
    /// takes on a swap it structurally cannot fund (design 0018). A silent-payment output is derived
    /// from the spent inputs' private keys, which an interactive signer (the engine holds no input
    /// keys) and a non-BIP352-aware cold signer do not have for this purpose, so the default is false;
    /// only a BIP352-aware signer overrides it to true.
    fn supports_silent_fee(&self) -> bool {
        false
    }

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

    fn supports_silent_fee(&self) -> bool {
        // The hot node wallet holds the input keys, so it can derive a BIP352 fee output.
        true
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

    /// A fee-rate estimate in sat/vB to confirm within `conf_target` blocks, or `None` when the
    /// backend cannot estimate (a fresh regtest, or the low-activity xBTC chain, returns nothing).
    /// Used to fee the deadline-bound claim/refund spends (F6); the caller applies a conservative
    /// fallback when this is `None`, so a chain with no estimate keeps a safe, near-today fee.
    fn estimate_fee_sat_vb(&self, _conf_target: u16) -> Option<u64> {
        None
    }
}

pub struct ChainNode {
    pub rpc: Client,
    wallet: Client,
    watch: Client,
    network: Network,
    signer: Box<dyn FundingSigner>,
    /// Output-only funding (design 0032): no funding wallet. `wallet` is then a placeholder (the watch
    /// wallet) never used to select coins; `fund` builds an inputless PSBT and the user's own wallet
    /// adds inputs/change/signs. `new_destination` must never be called (config requires a payout
    /// address). False for hot, cold, and descriptor-backed interactive funding.
    output_only: bool,
    /// The bitcoind wallet name this chain funds from, after Hot/Cold name resolution (#301). Hot
    /// keeps a keyed wallet here, cold/descriptor-backed a watch-only one; for output-only funding
    /// there is no funding wallet and this holds the contract watch-wallet name as a placeholder.
    funding_wallet: String,
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

/// Whether a node's `getmininginfo` describes the proof-of-work the configured `chain` expects, or an
/// error message if not. The two chains share Bitcoin's network parameters and address format, so the
/// `getblockchaininfo` `chain` field cannot tell them apart; the BLAKE2b (xBTC) node is distinguished by
/// reporting a `difficulty_blake2b` field, which a SHA256d node does not. A mismatch means the BTC and
/// xBTC node endpoints are almost certainly swapped in the configuration.
fn pow_mismatch(mining_info: &Value, chain: &str) -> Option<String> {
    let is_blake2b = mining_info.get("difficulty_blake2b").is_some();
    let want_blake2b = chain == "xbtc";
    (is_blake2b != want_blake2b).then(|| {
        format!(
            "the node configured as the {chain} chain reports {} proof-of-work; \
             the BTC and xBTC node endpoints look swapped",
            if is_blake2b { "BLAKE2b" } else { "SHA256d" }
        )
    })
}

/// Fail fast if a node is assigned to the wrong chain (there is no network-level guard, so a swapped
/// configuration would otherwise route a swap leg onto the wrong chain). Checked once per chain at
/// startup via `getmininginfo`.
pub fn check_chain_pow(rpc: &Client, chain: &str) -> Result<(), NodeError> {
    let info = rpc.call("getmininginfo", json!([]))?;
    match pow_mismatch(&info, chain) {
        Some(msg) => Err(NodeError::Unexpected(msg)),
        None => Ok(()),
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
    birthday: Option<i64>,
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
    // #294: import from the configured funding birthday (a unix timestamp; 0 = genesis) so a freshly
    // (re)configured descriptor rescans and sees coins received before the import. `None` keeps the
    // historical "now" behaviour (no rescan), for which the operator funds the wallet after configuring.
    // A birthday below a pruned node's prune height makes bitcoind reject the import; surface that
    // plainly rather than as a bare RPC error.
    let timestamp = match birthday {
        Some(t) => json!(t),
        None => json!("now"),
    };
    let result = wallet.call(
        "importdescriptors",
        json!([[{
            "desc": canonical,
            "timestamp": timestamp,
            "active": true,
            "internal": internal,
            "range": 1000,
        }]]),
    )?;
    match result[0]["success"].as_bool() {
        Some(true) => Ok(()),
        _ => {
            let err = result[0]["error"]["message"].as_str().unwrap_or("");
            let hint = if err.contains("prune") || err.contains("pruned") {
                " (the funding birthday is below this pruned node's prune height; raise the birthday \
                 or use an unpruned node)"
            } else {
                ""
            };
            Err(NodeError::Unexpected(format!(
                "importdescriptors ({}){hint}: {result}",
                if internal { "change" } else { "receive" }
            )))
        }
    }
}

/// The key-mode of an existing bitcoind wallet by name (#301). `Ok(None)` = no wallet of this name
/// exists on the node; `Ok(Some(true))` = it exists and holds private keys (a hot funding wallet);
/// `Ok(Some(false))` = it exists and is watch-only (a cold / descriptor-backed funding wallet). A
/// wallet on disk but not loaded is loaded so its mode can be read; a wallet that exists but fails
/// to load is an error, never silently reported as absent.
fn funding_wallet_mode(rpc: &Client, name: &str) -> Result<Option<bool>, NodeError> {
    let loaded = rpc.call("listwallets", json!([]))?;
    let is_loaded = |l: &Value| l.as_array().is_some_and(|a| a.iter().any(|w| w == name));
    if !is_loaded(&loaded) {
        let dir = rpc.call("listwalletdir", json!([]))?;
        let exists = dir["wallets"]
            .as_array()
            .is_some_and(|ws| ws.iter().any(|w| w["name"].as_str() == Some(name)));
        if !exists {
            return Ok(None);
        }
        // On disk but not loaded: load it to read the mode. A concurrent load (the engine already
        // opened it) can race us to "already loaded"; tolerate that and read the mode anyway.
        if rpc.call("loadwallet", json!([name])).is_err()
            && !is_loaded(&rpc.call("listwallets", json!([]))?)
        {
            return Err(NodeError::Unexpected(format!(
                "funding wallet {name} exists on disk but could not be loaded"
            )));
        }
    }
    let info = rpc.wallet(name).call("getwalletinfo", json!([]))?;
    Ok(Some(info["private_keys_enabled"].as_bool() == Some(true)))
}

/// Resolves the funding-wallet name for the wanted key mode, sidestepping a left-over wallet of the
/// other mode so a Hot<->Cold reconfiguration never collides on one bitcoind wallet name (#301). The
/// daemon has no RPC to rename or delete a wallet, so rather than fail on a mismatched left-over it
/// uses a dedicated name for the wanted mode:
///
/// - base absent: base (created fresh in the wanted mode)
/// - base already in wanted mode: base (reused; a live watch-only install keeps its wallet)
/// - base in the OTHER mode: `<base>-hot` (want keyed) or `<base>-cold` (want watch-only)
///
/// The rule is deterministic given what is on disk, so the engine-open paths and the split service
/// resolve to the same wallet name with no shared state. `want_keyed` is true for hot funding (a
/// signing wallet), false for cold / descriptor-backed (a watch-only wallet).
pub fn resolve_funding_wallet_name(
    rpc: &Client,
    base: &str,
    want_keyed: bool,
) -> Result<String, NodeError> {
    Ok(match funding_wallet_mode(rpc, base)? {
        None => base.to_owned(),
        Some(keyed) if keyed == want_keyed => base.to_owned(),
        Some(_) => format!("{base}-{}", if want_keyed { "hot" } else { "cold" }),
    })
}

impl ChainNode {
    /// Opens `<funding_name>` for funds and `<base>-watch` for contracts on this node, with a
    /// `WalletSigner` over the funding wallet. The contract watch wallet is ALWAYS keyed off `base`
    /// (not `funding_name`), so a Hot/Cold funding-wallet rename (#301) never orphans the in-flight
    /// swaps' contract addresses. `require_keyed` makes a watch-only funding wallet a loud startup
    /// error (the hot path, where a watch-only wallet could not sign); false leaves the wallet as it
    /// is, since `open` + `with_signer` legitimately runs a watch-only funding wallet off an external
    /// signer (design 0012).
    fn open_with_funding(
        rpc: Client,
        base: &str,
        funding_name: &str,
        require_keyed: bool,
    ) -> Result<ChainNode, NodeError> {
        let network = chain_network(&rpc)?;
        let watch_name = format!("{base}-watch");
        let loaded = rpc.call("listwallets", json!([]))?;
        for (wallet, watch_only) in [(funding_name, false), (watch_name.as_str(), true)] {
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
        let wallet = rpc.wallet(funding_name);
        if require_keyed {
            // The hot funding wallet must hold its keys, or `WalletSigner` cannot sign the lock; fail
            // loudly at startup rather than later, at swap time.
            let info = wallet.call("getwalletinfo", json!([]))?;
            if info["private_keys_enabled"].as_bool() != Some(true) {
                return Err(NodeError::Unexpected(format!(
                    "hot funding wallet {funding_name} is watch-only; it must hold its keys to sign \
                     the funding lock (use cold or descriptor-backed interactive funding instead)."
                )));
            }
        }
        let signer = Box::new(WalletSigner {
            wallet: wallet.clone(),
        });
        Ok(ChainNode {
            wallet,
            watch: rpc.wallet(&watch_name),
            signer,
            rpc,
            network,
            output_only: false,
            funding_wallet: funding_name.to_owned(),
        })
    }

    /// Opens (or creates) `<name>` for funds and `<name>-watch` for contracts on this node, with a
    /// `WalletSigner`. Mode-agnostic: with a keyed `<name>` it is the hot path; wrapped in
    /// `with_signer` over a watch-only `<name>` it is the cold/external-signer path (design 0012). The
    /// daemon's hot funding uses `open_hot`, which adds the #301 name resolution and the keyed guard.
    pub fn open(rpc: Client, name: &str) -> Result<ChainNode, NodeError> {
        Self::open_with_funding(rpc, name, name, false)
    }

    /// The daemon's hot funding path: funds from a KEYED wallet, signing with `WalletSigner`. If the
    /// base name is a watch-only left-over (a chain flipped from cold/descriptor-backed back to hot),
    /// do not silently wrap it in a signer that cannot sign (which would fail only later, at swap
    /// time): fund from a dedicated keyed `<base>-hot` instead, and guard that it is keyed (#301). The
    /// contract watch wallet stays `<base>-watch`, so in-flight swaps are never orphaned.
    pub fn open_hot(rpc: Client, name: &str) -> Result<ChainNode, NodeError> {
        let funding_name = resolve_funding_wallet_name(&rpc, name, true)?;
        if funding_name != name {
            eprintln!(
                "funding: base wallet {name} is watch-only (a cold/descriptor-backed left-over); \
                 funding hot from {funding_name} instead (#301)."
            );
        }
        Self::open_with_funding(rpc, name, &funding_name, true)
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
        Self::open_cold_from(
            rpc,
            name,
            descriptor_receive,
            descriptor_change,
            signer,
            None,
        )
    }

    /// As `open_cold`, but importing the account descriptors from `birthday` (a unix timestamp, 0 =
    /// genesis) so a freshly (re)configured descriptor rescans and sees coins received before the
    /// import (#294). `None` keeps the no-rescan "now" import. The rescan happens here, at wallet open
    /// (daemon startup), not on a running engine, so a long historical rescan never blocks live ticks.
    pub fn open_cold_from(
        rpc: Client,
        name: &str,
        descriptor_receive: &str,
        descriptor_change: &str,
        signer: Box<dyn FundingSigner>,
        birthday: Option<i64>,
    ) -> Result<ChainNode, NodeError> {
        let network = chain_network(&rpc)?;
        // Cold / descriptor-backed funds from a WATCH-ONLY wallet. If the base name is a keyed
        // left-over (a chain flipped from hot), do not refuse to start: fund from a dedicated
        // watch-only `<base>-cold` and leave the keyed left-over untouched for the operator to sweep
        // (#301). The daemon has no RPC to rename or delete the left-over wallet.
        let funding_name = resolve_funding_wallet_name(&rpc, name, false)?;
        let watch_name = format!("{name}-watch");
        let loaded = rpc.call("listwallets", json!([]))?;
        let is_loaded = |w: &str| loaded.as_array().is_some_and(|l| l.iter().any(|v| v == w));
        // Both wallets are watch-only: the funding wallet tracks the user's balance from the account
        // descriptors, the watch wallet tracks the swap contracts. Remember whether the funding
        // wallet was created now, so a restart does not re-import into an existing one.
        let mut funding_created = false;
        for wallet in [funding_name.as_str(), watch_name.as_str()] {
            if is_loaded(wallet) || rpc.call("loadwallet", json!([wallet])).is_ok() {
                continue;
            }
            // disable_private_keys=true, blank=true, passphrase="", avoid_reuse=false,
            // descriptors=true: a blank descriptor wallet that holds no key.
            rpc.call("createwallet", json!([wallet, true, true, "", false, true]))?;
            if wallet == funding_name {
                funding_created = true;
            }
        }
        let wallet = rpc.wallet(&funding_name);
        // Safety (design 0012): the funding wallet must hold no private key, whether just created,
        // loaded, or already present. Keys present under the resolved name means an operator created
        // this exact wallet keyed by hand; refuse rather than ever sign the user's balance on the
        // engine host. (A keyed BASE left-over is sidestepped above, not signed from.)
        let info = wallet.call("getwalletinfo", json!([]))?;
        if info["private_keys_enabled"].as_bool() != Some(false) {
            return Err(NodeError::Unexpected(format!(
                "cold funding wallet {funding_name} has private keys enabled; it must be watch-only. \
                 Refusing to fund from a key on the engine host (recreate it from the account \
                 descriptors)."
            )));
        }
        if funding_name != name {
            // We sidestepped a keyed base left-over. Tell the operator it is still there with its
            // balance, so coins are never silently stranded (the daemon cannot sweep or remove it).
            let left_btc = rpc
                .wallet(name)
                .call("getbalances", json!([]))
                .ok()
                .and_then(|b| b["mine"]["trusted"].as_f64())
                .unwrap_or(0.0);
            eprintln!(
                "funding: base wallet {name} holds private keys (a hot left-over); funding cold from \
                 {funding_name} instead. The hot wallet {name} is untouched with {left_btc} still in \
                 it; sweep it if you want those coins under this cold config (#301)."
            );
        }
        // Import the receive (external) and change (internal) account descriptors so
        // walletcreatefundedpsbt can select coins and build a change-handling PSBT. Only on a fresh
        // wallet, or when a descriptor is absent: re-importing an existing one on every restart can
        // be rejected once the keypool has advanced the stored range (design 0012).
        ensure_account_descriptor(
            &rpc,
            &wallet,
            descriptor_receive,
            false,
            funding_created,
            birthday,
        )?;
        ensure_account_descriptor(
            &rpc,
            &wallet,
            descriptor_change,
            true,
            funding_created,
            birthday,
        )?;
        Ok(ChainNode {
            wallet,
            watch: rpc.wallet(&watch_name),
            signer,
            rpc,
            network,
            output_only: false,
            funding_wallet: funding_name,
        })
    }

    /// Opens the chain for output-only (interactive, no descriptors) funding (design 0032): only the
    /// `<name>-watch` wallet is created/loaded, to track contracts. There is NO funding wallet, so the
    /// daemon never selects the user's coins; `fund` builds an inputless PSBT the user's own wallet
    /// funds and signs. The `wallet` field is set to the watch wallet as a harmless placeholder that
    /// `output_only` keeps off every coin-selection path, so no code reads a missing wallet.
    pub fn open_watch_only(
        rpc: Client,
        name: &str,
        signer: Box<dyn FundingSigner>,
    ) -> Result<ChainNode, NodeError> {
        let network = chain_network(&rpc)?;
        let watch_name = format!("{name}-watch");
        let loaded = rpc.call("listwallets", json!([]))?;
        let is_loaded = |w: &str| loaded.as_array().is_some_and(|l| l.iter().any(|v| v == w));
        if !is_loaded(&watch_name) && rpc.call("loadwallet", json!([&watch_name])).is_err() {
            // disable_private_keys=true, blank=true: a watch-only wallet that holds no key.
            rpc.call("createwallet", json!([&watch_name, true, true]))?;
        }
        let watch = rpc.wallet(&watch_name);
        Ok(ChainNode {
            wallet: watch.clone(),
            watch,
            signer,
            rpc,
            network,
            output_only: true,
            funding_wallet: watch_name,
        })
    }

    /// The bitcoind wallet name this chain funds from, after Hot/Cold name resolution (#301): keyed
    /// for hot, watch-only for cold / descriptor-backed. For output-only funding there is no funding
    /// wallet, so this returns the contract watch-wallet name as a placeholder; callers that need a
    /// real funding wallet (e.g. the split co-sign) must first check `is_output_only`.
    pub fn funding_wallet_name(&self) -> &str {
        &self.funding_wallet
    }

    /// Whether this node funds output-only (design 0032): no funding wallet, the user supplies the
    /// whole lock. The engine marks a parked swap so its terminal watch (0019) keys off the contract
    /// address, not a pre-known txid (output-only changes the txid when the user adds inputs).
    pub fn is_output_only(&self) -> bool {
        self.output_only
    }

    /// The funding wallet's spendable (confirmed) balance in sats, for the funding-readiness display
    /// (#295). `None` when there is no funding wallet to read (output-only funding, design 0032), so
    /// the UI shows "fund from your own wallet" rather than a meaningless zero. Hot and descriptor-
    /// backed/cold modes all keep a `self.wallet` whose confirmed balance is what can fund a lock; a
    /// zero here on a descriptor-backed wallet is exactly the "configured but unsynced / unfunded"
    /// state the operator needs to see (it may need a rescan, #294, or a deposit).
    pub fn funding_balance_sat(&self) -> Result<Option<u64>, NodeError> {
        if self.output_only {
            return Ok(None);
        }
        let balances = self.wallet.call("getbalances", json!([]))?;
        let trusted_btc = balances["mine"]["trusted"].as_f64().unwrap_or(0.0);
        let sats = Amount::from_btc(trusted_btc)
            .map_err(|e| NodeError::Unexpected(format!("funding balance parse: {e}")))?
            .to_sat();
        Ok(Some(sats))
    }

    /// Replaces the signer, e.g. an external cold signer in production so no funding key is on the
    /// engine host. The funding wallet is then watch-only.
    pub fn with_signer(mut self, signer: Box<dyn FundingSigner>) -> ChainNode {
        self.signer = signer;
        self
    }

    /// Whether this chain's funding signer can build a silent-payment (BIP352) fee output (design
    /// 0018). The engine consults it before committing to an offer whose fee for this chain is a
    /// silent payment.
    pub fn supports_silent_fee(&self) -> bool {
        self.signer.supports_silent_fee()
    }

    pub fn new_destination(&self) -> Result<ScriptBuf, NodeError> {
        let address = self.wallet.call("getnewaddress", json!([]))?;
        let info = self.wallet.call("getaddressinfo", json!([address]))?;
        ScriptBuf::from_hex(info["scriptPubKey"].as_str().unwrap_or_default())
            .map_err(|e| NodeError::Unexpected(e.to_string()))
    }

    /// The scriptPubKey of an operator-configured payout address (finding F5), network-checked for
    /// this node's chain so a wrong-network or malformed address is caught before a claim/refund pays
    /// into it. A silent payment (`sp1...`) address is rejected: a claim/refund spend pays a plain
    /// scriptPubKey, so the payout must be a normal address.
    pub fn script_for(&self, addr: &str) -> Result<ScriptBuf, NodeError> {
        let parsed = Address::from_str(addr)
            .map_err(|e| NodeError::Unexpected(format!("payout address: {e}")))?
            .require_network(self.network)
            .map_err(|_| NodeError::Unexpected("payout address is for the wrong network".into()))?;
        Ok(parsed.script_pubkey())
    }

    pub fn address(&self, contract: &Contract) -> Address {
        Address::from_script(&contract.script_pubkey(), self.network).expect("P2WSH has an address")
    }

    /// SPV proof bundle for one confirmed output (#247): the raw transaction, a Merkle (txout) proof
    /// binding that txid into its block, and the block's serialized header, so a client that does not
    /// trust this daemon (a light client, or a front treating the engine as untrusted) can verify a
    /// lock exists on-chain with the agreed amount and script before committing anything irreversible.
    /// The header is whatever the chain serves: 80 bytes on BTC (SHA256), and the extended form on BTC
    /// (Blake2b), whose proof-of-work is BLAKE2b, so the client checks the right header and PoW per
    /// chain. The block hash is resolved from the height and passed to `getrawtransaction`/
    /// `gettxoutproof`, so neither needs a transaction index. A pruned node that no longer holds the
    /// block returns an RPC error, which the caller surfaces rather than fabricating a proof.
    pub fn spv_proof(&self, outpoint: OutPoint, height: u32) -> Result<Value, NodeError> {
        let txid = outpoint.txid.to_string();
        let str_field = |v: Value, what: &str| -> Result<String, NodeError> {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| NodeError::Unexpected(format!("{what} returned no string")))
        };
        let block_hash = str_field(
            self.rpc.call("getblockhash", json!([height]))?,
            "getblockhash",
        )?;
        // verbose=false -> raw hex; passing the block hash means txindex is not required.
        let raw_tx = str_field(
            self.rpc
                .call("getrawtransaction", json!([&txid, false, &block_hash]))?,
            "getrawtransaction",
        )?;
        let txout_proof = str_field(
            self.rpc
                .call("gettxoutproof", json!([[&txid], &block_hash]))?,
            "gettxoutproof",
        )?;
        // verbose=false -> the 80-byte header as hex.
        let block_header = str_field(
            self.rpc
                .call("getblockheader", json!([&block_hash, false]))?,
            "getblockheader",
        )?;
        Ok(json!({
            "txid": txid,
            "vout": outpoint.vout,
            "height": height,
            "block_hash": block_hash,
            "raw_tx": raw_tx,
            "txout_proof": txout_proof,
            "block_header": block_header,
        }))
    }

    /// Sample this chain's runtime health (#308) from its own block timestamps plus wall-clock now: the
    /// tip's time and median-time-past, and the MTP `window` blocks back, fed to `assess_chain_health`.
    /// Used to refuse locking a taker leg into a stalled or far-slower-than-target chain, whose lock
    /// would outlast the counterparty's reserved timelock budget. Block timestamps come from
    /// `getblockheader` (always present, unlike `getblockchaininfo.time` on older nodes).
    pub fn chain_health(
        &self,
        target_secs: u32,
        window: u32,
    ) -> Result<crate::swap::ChainHealth, NodeError> {
        let info = self.rpc.call("getblockchaininfo", json!([]))?;
        let height = info["blocks"]
            .as_u64()
            .ok_or_else(|| NodeError::Unexpected("getblockchaininfo: no blocks".into()))?
            as u32;
        let best = info["bestblockhash"]
            .as_str()
            .ok_or_else(|| NodeError::Unexpected("getblockchaininfo: no bestblockhash".into()))?;
        let tip = self.rpc.call("getblockheader", json!([best]))?;
        let tip_time = tip["time"]
            .as_i64()
            .ok_or_else(|| NodeError::Unexpected("tip header: no time".into()))?;
        let tip_mtp = tip["mediantime"]
            .as_i64()
            .ok_or_else(|| NodeError::Unexpected("tip header: no mediantime".into()))?;
        let back = height.saturating_sub(window);
        let back_hash = self.rpc.call("getblockhash", json!([back]))?;
        let back_hash = back_hash
            .as_str()
            .ok_or_else(|| NodeError::Unexpected("getblockhash: not a string".into()))?;
        let back_hdr = self.rpc.call("getblockheader", json!([back_hash]))?;
        let mtp_back = back_hdr["mediantime"]
            .as_i64()
            .ok_or_else(|| NodeError::Unexpected("back header: no mediantime".into()))?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        Ok(crate::swap::assess_chain_health(
            now,
            tip_time,
            tip_mtp,
            mtp_back,
            height.saturating_sub(back),
            target_secs,
        ))
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
        // Output-only funding (design 0032): build an inputless PSBT with just the HTLC output (and a
        // normal-address fee output), then hand it to the interactive signer, which parks it for the
        // user. The user's own wallet adds the inputs and change and signs. There is no coin selection
        // and no input-replay check here: the daemon never sees the inputs at this point. The replay
        // guard instead runs at submit time over the signed PSBT's inputs (`finalize_submitted_lock`,
        // #313), which is the only point the daemon sees what the user funded from. A silent-payment fee derives
        // its output from the spending inputs' keys (BIP352), which only the user's wallet holds, so it
        // cannot be built output-only (design 0018); a normal fee address is a plain output and works.
        if self.output_only {
            if matches!(fee, Some((_, FeeDest::SilentPayment(_)))) {
                return Err(NodeError::Unexpected(
                    "a silent-payment fee cannot be built with output-only funding; use a normal fee address"
                        .into(),
                ));
            }
            let mut outputs = vec![json!({ self.address(contract).to_string(): amount.to_btc() })];
            if let Some((fee_amount, FeeDest::Normal(addr))) = fee {
                outputs.push(json!({ addr.to_string(): fee_amount.to_btc() }));
            }
            let created = self
                .rpc
                .call("createpsbt", json!([[], json!(outputs), 0, true]))?;
            let psbt = created
                .as_str()
                .ok_or_else(|| NodeError::Unexpected("createpsbt returned no psbt".into()))?;
            // InteractiveSigner returns `AwaitingSignature`, which the `?` propagates so the engine
            // parks the swap. A signer that instead returns Ok here is not the interactive signer and
            // must not be used for output-only (it would yield an inputless, unbroadcastable tx).
            self.signer.sign(psbt)?;
            return Err(NodeError::Unexpected(
                "output-only funding requires the interactive signer".into(),
            ));
        }
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
        // #269: a non-zero rate is a fixed sat/vB; `0` means omit `fee_rate` so the node estimates
        // (Core falls back to its own fee estimation / `conf_target`), which is safer on a busy chain
        // than a too-low fixed rate that could strand the lock.
        let mut options = json!({ "replaceable": true, "minconf": minconf });
        if fee_rate_sat_vb > 0 {
            options["fee_rate"] = json!(fee_rate_sat_vb);
        }
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

    /// Resume a lock parked for the user's signature (E2, design 0017): the submitted PSBT must carry
    /// the same unsigned transaction as the one handed out (the user may sign, not rewrite it), then
    /// it is finalized and the lock transaction extracted, with the lock output re-checked and the
    /// inputs run through the cross-chain replay guard (#313). Does not broadcast; the caller does.
    pub fn finalize_submitted_lock(
        &self,
        pending_psbt: &str,
        signed_psbt: &str,
        contract: &Contract,
        amount: Amount,
        other_chain: &impl UtxoLookup<Error = RpcError>,
    ) -> Result<Transaction, NodeError> {
        let unsigned_txid = |p: &str| {
            Psbt::from_str(p)
                .map(|psbt| psbt.unsigned_tx.compute_txid())
                .map_err(|e| NodeError::Unexpected(format!("psbt: {e}")))
        };
        // Descriptor-backed interactive funding hands out a fully-funded PSBT the user may only sign,
        // so the unsigned tx (hence the txid) must be unchanged. Output-only funding (design 0032)
        // hands out an inputless PSBT the user funds themselves, so the inputs - and the txid - legitimately
        // change; we do not pin the txid there and instead rely on `find_lock_output` below to confirm
        // the committed HTLC output (script + amount) is present in what the user built.
        if !self.output_only && unsigned_txid(pending_psbt)? != unsigned_txid(signed_psbt)? {
            return Err(NodeError::Unexpected(
                "the submitted PSBT is a different transaction than the one to sign".into(),
            ));
        }
        let finalized = self.rpc.call("finalizepsbt", json!([signed_psbt]))?;
        if finalized["complete"] != true {
            return Err(NodeError::Unexpected(
                "the submitted funding PSBT is not fully signed".into(),
            ));
        }
        let tx: Transaction = parse(&finalized["hex"])?;
        // #313: the cross-chain replay guard, run over the inputs the user actually signed, before the
        // caller broadcasts. Descriptor-backed funding already passed this guard inside `fund()` and
        // pins the txid above, so re-running it here is a cheap backstop. Output-only funding (design
        // 0032) builds the inputs in the user's OWN wallet, which the daemon never saw at `fund()`
        // time, so this submit-time check is the ONLY replay guard on that path. Fail closed: a
        // spendable-on-the-other-chain input, or a lookup the other node cannot answer, refuses rather
        // than broadcasts a lock that could be replayed (a loss path, #74).
        match check_inputs(&tx, other_chain) {
            Ok(()) => {}
            Err(ReplayError::SpendableOnOtherChain(outpoint)) => {
                return Err(NodeError::Unexpected(format!(
                    "funding input {outpoint} is still spendable on the other chain, so this lock \
                     could be replayed there (a loss path). Do NOT broadcast this signed transaction \
                     from your own wallet. Split the coin first (Split tab) and fund the lock from a \
                     post-split output."
                )));
            }
            Err(ReplayError::Lookup(e)) => {
                return Err(NodeError::Unexpected(format!(
                    "cannot verify the funding inputs are replay-safe against the other chain ({e:?}); \
                     not broadcasting. Check the other node is reachable and resubmit."
                )));
            }
        }
        contract
            .find_lock_output(&tx, amount)
            .map_err(|e| NodeError::Unexpected(format!("funded lock: {e:?}")))?;
        Ok(tx)
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

/// Every entry in a watch wallet's transaction history, paged so nothing is missed (#108). A single
/// `listtransactions "*" 1000` capped the view at the newest 1000 entries, so on a busy market-making
/// node a live swap's lock, or the counterparty spend that carries the revealed secret, could age out
/// of the window and the engine would stop seeing it, a missed claim and a lost leg. This walks the
/// whole history in pages until a short page (the end), bounded so a pathological wallet cannot spin
/// forever. On a small wallet the first page is already the last, so it costs exactly one call.
fn all_watch_transactions(watch: &Client) -> Result<Vec<Value>, NodeError> {
    const PAGE: usize = 1000;
    const MAX_ENTRIES: usize = 100_000; // ~50k swaps; a safety bound, not an expected limit
    let mut all = Vec::new();
    let mut skip = 0usize;
    loop {
        let batch = watch.call("listtransactions", json!(["*", PAGE, skip, true]))?;
        let page = batch.as_array().cloned().unwrap_or_default();
        let n = page.len();
        all.extend(page);
        if n < PAGE || all.len() >= MAX_ENTRIES {
            break;
        }
        skip += PAGE;
    }
    Ok(all)
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
        let entries = all_watch_transactions(&self.watch)?;
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

    fn estimate_fee_sat_vb(&self, conf_target: u16) -> Option<u64> {
        // Conservative mode: estimatesmartfee errs toward overpaying, which is right for a spend that
        // races a timelock (F6). `feerate` is BTC/kvB; convert to sat/vB. On a chain that cannot
        // estimate (fresh regtest, quiet xBTC) the result has no `feerate` and we return None.
        let v = self
            .rpc
            .call("estimatesmartfee", json!([conf_target, "CONSERVATIVE"]))
            .ok()?;
        let btc_per_kvb = v.get("feerate")?.as_f64()?;
        let sat_vb = (btc_per_kvb * 100_000.0).round() as u64;
        (sat_vb > 0).then_some(sat_vb)
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

    #[test]
    fn pow_mismatch_catches_a_swapped_chain_assignment() {
        let blake2b = json!({ "difficulty_blake2b": 1.0, "difficulty": 2.0 });
        let sha256d = json!({ "difficulty": 2.0 });
        // A node assigned to the chain whose PoW it actually serves is accepted.
        assert!(pow_mismatch(&blake2b, "xbtc").is_none());
        assert!(pow_mismatch(&sha256d, "btc").is_none());
        // A swapped assignment is rejected, and the message names the chain it was configured as.
        assert!(pow_mismatch(&blake2b, "btc").unwrap().contains("btc"));
        assert!(pow_mismatch(&sha256d, "xbtc").unwrap().contains("xbtc"));
    }
}

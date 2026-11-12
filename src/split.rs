//! Coin-split / replay-protection service (design: `_internal/designs/xbt-btc-replay-split-*`).
//!
//! Bitcoin and Bitcoin Blake2b share byte-identical history up to mainnet block 961,631 and first differ
//! at 961,632 (the BIP-110 split; BLAKE2b PoW follows at 961,640), so a coin that existed before the
//! split exists on BOTH chains under the same key and is **replayable**:
//! a spend on one chain can be copied to the other. To separate the twins the coin must be moved once on
//! the Blake2b chain in a transaction that cannot exist on the SHA256 chain, by spending it **together
//! with** a "Blake2b-Coin" (a coin mined after the fork, which exists on Blake2b only). This module:
//!   - **classifies** a UTXO as a SHA-Coin (pre-fork, replayable, needs splitting) or a Blake2b-Coin
//!     (post-fork, chain-specific) - P1;
//!   - **builds** the separating transaction - P2 (see `split::psbt`).
//!
//! Safety invariant (from the proven runbook): a separating transaction MUST have at least one
//! Blake2b-Coin input, or it is replayable. The builder enforces that; the classifier is how we check.

use std::collections::{HashMap, HashSet};

use std::path::Path;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Address, Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence,
    TapSighashType, Transaction, TxIn, TxOut, Txid, Witness,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::rpc::{Client, RpcError};
use crate::store::write_atomic;

/// Mainnet fork height: the FIRST block that differs between the SHA256 and Blake2b chains, so a
/// coinbase at or above it on the Blake2b chain is a Blake2b-only coin. This is the BIP-110 split at
/// **961,632**, NOT the BLAKE2b-PoW activation at 961,640: the chains already mine different blocks from
/// 961,632 (both still SHA256-difficulty until 961,640). Using 961,640 would misclassify a coin mined at
/// 961,632-639 on the Blake2b chain as a replayable SHA-Coin. Verified live 2026-11-12 (btc-core vs
/// btc-blake `getblockhash`): 961,631 identical on both, 961,632 diverges. Regtest passes its own
/// activation height (`-testactivationheight=blake2b@N`) explicitly.
pub const MAINNET_FORK_HEIGHT: u32 = 961_632;

/// Default bound on the number of ancestry lookups one classification may do, so a pathological input
/// cannot make it trace the whole chain. Real coins are a few hops from a coinbase or from the fork.
pub const DEFAULT_MAX_LOOKUPS: u32 = 200;

/// What a UTXO is, with respect to the fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoinKind {
    /// Pre-fork: exists on both chains under the same key, **replayable**. This is what needs splitting.
    ShaCoin,
    /// Post-fork, Blake2b-only: already chain-specific. The ingredient used to split a SHA-Coin.
    Blake2bCoin,
}

impl CoinKind {
    /// A SHA-Coin is replayable across both chains and so needs a separating move.
    pub fn needs_split(self) -> bool {
        self == CoinKind::ShaCoin
    }
}

#[derive(Debug)]
pub enum SplitError {
    Rpc(RpcError),
    /// A transaction the node returned did not parse as expected.
    Malformed(String),
    /// The ancestry trace exceeded its lookup budget; the coin's kind could not be decided cheaply.
    TooDeep,
}

impl std::fmt::Display for SplitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SplitError::Rpc(e) => write!(f, "node RPC error: {e:?}"),
            SplitError::Malformed(m) => write!(f, "malformed: {m}"),
            SplitError::TooDeep => write!(f, "ancestry trace exceeded its lookup budget"),
        }
    }
}

impl std::error::Error for SplitError {}

/// The facts the classifier needs about one transaction: whether it is a coinbase, the block height it
/// confirmed at (`None` if still unconfirmed), and its inputs' funding outpoints. A trait so the
/// classifier is unit-testable without a live node.
#[derive(Debug, Clone)]
pub struct TxInfo {
    pub is_coinbase: bool,
    pub height: Option<u32>,
    pub inputs: Vec<(String, u32)>,
}

pub trait TxSource {
    fn tx(&self, txid: &str) -> Result<TxInfo, SplitError>;
}

/// Classify the UTXO funded by `txid` on the Blake2b chain. A coin is a **Blake2b-Coin** iff its funding
/// ancestry includes a post-fork coinbase; otherwise it is a **SHA-Coin**. A transaction confirmed
/// before the fork short-circuits to SHA-Coin (it can have no post-fork ancestry), which keeps the trace
/// shallow for the common case. `fork_height` is the activation height (mainnet `MAINNET_FORK_HEIGHT`,
/// or the regtest value). The kind is a property of the funding transaction, so the UTXO's vout does not
/// affect it.
pub fn classify<S: TxSource>(
    src: &S,
    fork_height: u32,
    txid: &str,
    max_lookups: u32,
) -> Result<CoinKind, SplitError> {
    let mut budget = max_lookups;
    classify_tx(src, fork_height, txid, &mut budget)
}

fn classify_tx<S: TxSource>(
    src: &S,
    fork: u32,
    txid: &str,
    budget: &mut u32,
) -> Result<CoinKind, SplitError> {
    if *budget == 0 {
        return Err(SplitError::TooDeep);
    }
    *budget -= 1;
    let info = src.tx(txid)?;
    // A transaction confirmed before the fork cannot have post-fork ancestry.
    if info.height.is_some_and(|h| h < fork) {
        return Ok(CoinKind::ShaCoin);
    }
    if info.is_coinbase {
        // A coinbase at/after the fork mints a Blake2b-only coin; a pre-fork coinbase was handled above.
        return Ok(match info.height {
            Some(h) if h >= fork => CoinKind::Blake2bCoin,
            _ => CoinKind::ShaCoin,
        });
    }
    // Non-coinbase at/after the fork (or unconfirmed): Blake2b-Coin iff ANY input is a Blake2b-Coin.
    for (in_txid, _vout) in &info.inputs {
        if classify_tx(src, fork, in_txid, budget)? == CoinKind::Blake2bCoin {
            return Ok(CoinKind::Blake2bCoin);
        }
    }
    Ok(CoinKind::ShaCoin)
}

/// A [`TxSource`] backed by a bitcoind JSON-RPC client (the Blake2b node), using `getrawtransaction`
/// with verbosity (needs `txindex=1`, which our btc-blake node has). `tip` is the current block height,
/// used to turn confirmations into an absolute height.
pub struct NodeTxSource<'a> {
    rpc: &'a Client,
    tip: u32,
}

impl<'a> NodeTxSource<'a> {
    /// Build a source, reading the tip height once up front.
    pub fn new(rpc: &'a Client) -> Result<NodeTxSource<'a>, SplitError> {
        let tip = rpc
            .call("getblockcount", json!([]))
            .map_err(SplitError::Rpc)?
            .as_u64()
            .ok_or_else(|| SplitError::Malformed("getblockcount".to_owned()))?
            as u32;
        Ok(NodeTxSource { rpc, tip })
    }
}

impl TxSource for NodeTxSource<'_> {
    fn tx(&self, txid: &str) -> Result<TxInfo, SplitError> {
        let v = self
            .rpc
            .call("getrawtransaction", json!([txid, true]))
            .map_err(SplitError::Rpc)?;
        let vin = v["vin"]
            .as_array()
            .ok_or_else(|| SplitError::Malformed(format!("{txid}: no vin")))?;
        // A coinbase transaction's single input carries a "coinbase" field instead of a prevout.
        let is_coinbase = vin.first().is_some_and(|i| i.get("coinbase").is_some());
        // Absolute height from confirmations against the tip (None while unconfirmed).
        let height = v["confirmations"]
            .as_u64()
            .filter(|&c| c > 0)
            .map(|c| self.tip + 1 - c as u32);
        let inputs = if is_coinbase {
            Vec::new()
        } else {
            vin.iter()
                .filter_map(|i| {
                    let t = i["txid"].as_str()?.to_owned();
                    let n = i["vout"].as_u64()? as u32;
                    Some((t, n))
                })
                .collect()
        };
        Ok(TxInfo {
            is_coinbase,
            height,
            inputs,
        })
    }
}

// ---- P2: the separating transaction -------------------------------------------------------------

/// Basis points of the separated value taken as the project fee (0.5%).
pub const FEE_BPS: u64 = 50;

/// A UTXO offered as an input to a separating transaction, with its classified kind and value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitInput {
    pub txid: String,
    pub vout: u32,
    pub kind: CoinKind,
    pub value_sat: u64,
}

/// A validated separating plan: the chosen inputs are safe to build into one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    /// Total input value across all inputs.
    pub total_sat: u64,
    /// Value in SHA-Coins being separated; the project fee is charged on this.
    pub sha_value_sat: u64,
    /// The project fee at [`FEE_BPS`] of `sha_value_sat`.
    pub fee_sat: u64,
}

/// The project fee on a separated amount: `bps` basis points of `sha_value_sat`, rounded up so a tiny
/// amount still pays at least one sat.
pub fn project_fee_sat(sha_value_sat: u64, bps: u64) -> u64 {
    if sha_value_sat == 0 || bps == 0 {
        0
    } else {
        sha_value_sat.saturating_mul(bps).div_ceil(10_000).max(1)
    }
}

/// Validate a proposed input set for a **separating** transaction and compute its plan. Two invariants,
/// proven in the runbook, are safety-critical: (1) at least one input is a **Blake2b-Coin**, or the
/// transaction is valid on the SHA256 chain too and is **replayable** (the whole point is a
/// non-replayable move); and (2) at least one input is a **SHA-Coin**, or there is nothing to separate.
/// Each input's kind comes from `classify`. Returns the plan (totals + fee).
pub fn validate_split_inputs(inputs: &[SplitInput]) -> Result<SplitPlan, SplitError> {
    if inputs.is_empty() {
        return Err(SplitError::Malformed("no inputs".to_owned()));
    }
    let has_blake2b = inputs.iter().any(|i| i.kind == CoinKind::Blake2bCoin);
    if !has_blake2b {
        return Err(SplitError::Malformed(
            "a separating transaction must include at least one Blake2b-Coin, or it is replayable"
                .to_owned(),
        ));
    }
    let sha_value_sat: u64 = inputs
        .iter()
        .filter(|i| i.kind == CoinKind::ShaCoin)
        .map(|i| i.value_sat)
        .sum();
    if sha_value_sat == 0 {
        return Err(SplitError::Malformed(
            "no SHA-Coin among the inputs: nothing to separate".to_owned(),
        ));
    }
    let total_sat: u64 = inputs.iter().map(|i| i.value_sat).sum();
    Ok(SplitPlan {
        total_sat,
        sha_value_sat,
        fee_sat: project_fee_sat(sha_value_sat, FEE_BPS),
    })
}

/// An input prepared for the PSBT: its classified kind + value, its prevout scriptPubKey, and the full
/// previous transaction. The builder sets `witness_utxo` (segwit/taproot) and `non_witness_utxo` (BIP174
/// requires it for non-witness inputs, and many hardware signers want it for segwit v0), so an out-of-
/// band signer can sign from the PSBT alone. The kind is DERIVED from the chain by [`prepare_input`],
/// never supplied by the caller, so a mislabelled coin cannot slip a replayable input into a build.
#[derive(Debug, Clone)]
pub struct PreparedInput {
    pub input: SplitInput,
    pub script_pubkey: ScriptBuf,
    pub prev_tx: Transaction,
}

/// Prepare an input of the move from the Blake2b node: fetch its full funding transaction, read the
/// prevout's value + scriptPubKey from it, and CLASSIFY its kind on-chain (never trusting a caller tag).
/// `fork_height` is the classifier boundary (mainnet [`MAINNET_FORK_HEIGHT`], or the regtest value).
/// Needs `txindex` on the node (`getrawtransaction` of an arbitrary funding tx).
pub fn prepare_input(
    rpc: &Client,
    fork_height: u32,
    txid: &str,
    vout: u32,
) -> Result<PreparedInput, SplitError> {
    let hex = rpc
        .call("getrawtransaction", json!([txid, false]))
        .map_err(SplitError::Rpc)?;
    let hex = hex
        .as_str()
        .ok_or_else(|| SplitError::Malformed(format!("{txid}: no raw tx")))?;
    let prev_tx: Transaction = deserialize_hex(hex)
        .map_err(|e| SplitError::Malformed(format!("{txid}: prev tx decode: {e}")))?;
    let out = prev_tx
        .output
        .get(vout as usize)
        .ok_or_else(|| SplitError::Malformed(format!("{txid}:{vout} out of range")))?;
    let value_sat = out.value.to_sat();
    let script_pubkey = out.script_pubkey.clone();
    let src = NodeTxSource::new(rpc)?;
    let kind = classify(&src, fork_height, txid, DEFAULT_MAX_LOOKUPS)?;
    Ok(PreparedInput {
        input: SplitInput {
            txid: txid.to_owned(),
            vout,
            kind,
            value_sat,
        },
        script_pubkey,
        prev_tx,
    })
}

/// Directly verify a coin is a valid marker: it must NOT exist on the SHA256 chain, so a transaction
/// spending it can never be replayed there. This is the same -5 existence test [`verify_separation`]
/// uses (so it needs a synced txindex on the SHA256 node) and is independent of the fork-height constant.
/// Call it before lending a coin as the marker.
pub fn verify_marker(btc_rpc: &Client, marker_txid: &str) -> Result<(), SplitError> {
    require_txindex(btc_rpc)?;
    if exists_on_node(btc_rpc, marker_txid)? {
        return Err(SplitError::Malformed(format!(
            "{marker_txid} exists on the SHA256 chain; not a Blake2b-only marker, it would not make the \
             move non-replayable"
        )));
    }
    Ok(())
}

/// The SECURITY gate of `/split/submit`: validate a user-signed PSBT before we co-sign our marker. All
/// three must hold or we refuse. (a) The submitted transaction is byte-for-byte the one we built
/// (`expected_unsigned_tx_hex`), so the user cannot have changed an output after we picked the marker and
/// fee. (b) Every input EXCEPT our `marker` is signed with an ALL-family sighash (0x01 or the fork's
/// 0x21, both parse to `All`), NEVER ANYONECANPAY/NONE/SINGLE - an ANYONECANPAY input could be lifted
/// into a SHA256-funded transaction and replayed. (c) Our marker input is left unsigned (we add the only
/// signature on it). It parses the PSBT read-only; the caller co-signs and broadcasts the ORIGINAL
/// base64, so a 0x21 sighash byte is never rewritten (which would invalidate the user's signature).
pub fn validate_user_signed(
    expected_unsigned_tx_hex: &str,
    submitted_psbt_b64: &str,
    marker: OutPoint,
) -> Result<(), SplitError> {
    use std::str::FromStr;
    let psbt = Psbt::from_str(submitted_psbt_b64)
        .map_err(|e| SplitError::Malformed(format!("psbt: {e}")))?;
    if serialize_hex(&psbt.unsigned_tx) != expected_unsigned_tx_hex {
        return Err(SplitError::Malformed(
            "submitted transaction does not match the one we built".to_owned(),
        ));
    }
    for (i, txin) in psbt.unsigned_tx.input.iter().enumerate() {
        let input = &psbt.inputs[i];
        if txin.previous_output == marker {
            if !input.partial_sigs.is_empty() || input.tap_key_sig.is_some() {
                return Err(SplitError::Malformed(
                    "the marker input must be left unsigned for us to co-sign".to_owned(),
                ));
            }
            continue;
        }
        let all_family = if !input.partial_sigs.is_empty() {
            input
                .partial_sigs
                .values()
                .all(|s| s.sighash_type == EcdsaSighashType::All)
        } else if let Some(s) = input.tap_key_sig.as_ref() {
            matches!(
                s.sighash_type,
                TapSighashType::Default | TapSighashType::All
            )
        } else {
            return Err(SplitError::Malformed(format!(
                "user input {i} is not signed"
            )));
        };
        if !all_family {
            return Err(SplitError::Malformed(format!(
                "user input {i} is not signed with SIGHASH_ALL (ANYONECANPAY/NONE/SINGLE would be replayable)"
            )));
        }
    }
    Ok(())
}

/// Build the UNSIGNED separating PSBT for the lent-marker move. Constructed directly (NOT via a funding
/// wallet), so it can mix inputs from two owners - the user's SHA-Coin(s) and our lent Blake2b-Coin
/// marker - which `walletcreatefundedpsbt` on one wallet cannot. Every input carries `witness_utxo`.
/// Three outputs, in order: (a) the user's separated value to `dest`, the SHA value minus the project
/// fee and the network fee; (b) the project fee (0.5% of the SHA value, charged in XBT on the Blake2b
/// side) to `fee_addr`, ours; (c) the marker FULLY recovered to `marker_change`, ours - the marker is
/// lent, never given away.
/// The user pays the network fee out of their own output. The invariant (>=1 Blake2b-Coin, >=1 SHA-Coin)
/// is re-checked, so a bad call cannot produce a replayable transaction. The user signs their input
/// first; we co-sign only the marker last (daemon `/split/submit`). Returns the base64 PSBT.
pub fn build_split_psbt(
    inputs: &[PreparedInput],
    dest: &Address,
    fee_addr: &Address,
    marker_change: &Address,
    network_fee_sat: u64,
) -> Result<String, SplitError> {
    let plan = validate_split_inputs(&inputs.iter().map(|i| i.input.clone()).collect::<Vec<_>>())?;
    let marker_sum: u64 = inputs
        .iter()
        .filter(|i| i.input.kind == CoinKind::Blake2bCoin)
        .map(|i| i.input.value_sat)
        .sum();
    let dest_value = plan
        .sha_value_sat
        .checked_sub(plan.fee_sat)
        .and_then(|v| v.checked_sub(network_fee_sat))
        .ok_or_else(|| {
            SplitError::Malformed(
                "the project fee and network fee exceed the separated value".to_owned(),
            )
        })?;
    let input = inputs
        .iter()
        .map(|i| {
            let txid =
                i.input.txid.parse::<Txid>().map_err(|e| {
                    SplitError::Malformed(format!("bad txid {}: {e}", i.input.txid))
                })?;
            Ok(TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: i.input.vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
        })
        .collect::<Result<Vec<_>, SplitError>>()?;
    let tx = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input,
        output: vec![
            TxOut {
                value: Amount::from_sat(dest_value),
                script_pubkey: dest.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(plan.fee_sat),
                script_pubkey: fee_addr.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(marker_sum),
                script_pubkey: marker_change.script_pubkey(),
            },
        ],
    };
    let mut psbt =
        Psbt::from_unsigned_tx(tx).map_err(|e| SplitError::Malformed(format!("psbt: {e}")))?;
    for (slot, inp) in psbt.inputs.iter_mut().zip(inputs) {
        let txout = TxOut {
            value: Amount::from_sat(inp.input.value_sat),
            script_pubkey: inp.script_pubkey.clone(),
        };
        // Taproot: witness_utxo only. Segwit v0: both. Legacy (P2PKH/P2SH): non_witness_utxo (BIP174
        // requires it for non-witness inputs; stock/hardware signers reject a PSBT that lacks it).
        if inp.script_pubkey.is_p2tr() {
            slot.witness_utxo = Some(txout);
        } else {
            slot.non_witness_utxo = Some(inp.prev_tx.clone());
            if inp.script_pubkey.is_witness_program() {
                slot.witness_utxo = Some(txout);
            }
        }
    }
    Ok(psbt.to_string())
}

// ---- P5c: verify a separation --------------------------------------------------------------------

/// Confirmations a separating transaction must have on the Blake2b chain before it is trusted. The
/// low-hashrate Blake2b chain has frequent short reorgs, so the runbook waits this many (not 1 or 2).
pub const MIN_SEPARATION_CONFIRMATIONS: u32 = 12;

/// Refuse to verify unless the SHA256 node has a fully synced `txindex`. This is safety-critical:
/// `getrawtransaction` returns the "not found" code (-5) for ANY confirmed transaction that is not in
/// the mempool when txindex is off, so without this guard a replayable SHA-Coin's own funding
/// transaction would be read as **absent** and the move declared `separated` - telling the operator the
/// SHA256 side is safe to spend when it is not. `getindexinfo "txindex"` returns `{}` when no index is
/// configured, or `{"txindex":{"synced":bool,...}}`.
pub fn require_txindex(rpc: &Client) -> Result<(), SplitError> {
    let info = rpc
        .call("getindexinfo", json!(["txindex"]))
        .map_err(SplitError::Rpc)?;
    if info["txindex"]["synced"].as_bool().unwrap_or(false) {
        Ok(())
    } else {
        Err(SplitError::Malformed(
            "the SHA256 node has no synced txindex; it cannot tell an absent input from an unindexed \
             one (getrawtransaction returns -5 for both), so a separation cannot be verified safely"
                .to_owned(),
        ))
    }
}

/// Does `funding_txid` exist on the given node? Only a genuine "not found" (RPC code -5) counts as
/// absent; any other RPC error is surfaced, never silently read as absence (a false "absent" on the
/// SHA256 node would wrongly declare a move non-replayable). Call [`require_txindex`] on the node first,
/// or a confirmed-but-unindexed transaction will look absent. Shared by the daemon handler and the
/// regtest test so there is one existence check, not two.
pub fn exists_on_node(rpc: &Client, funding_txid: &str) -> Result<bool, SplitError> {
    match rpc.call("getrawtransaction", json!([funding_txid, false])) {
        Ok(_) => Ok(true),
        Err(RpcError::Rpc { code: -5, .. }) => Ok(false),
        Err(e) => Err(SplitError::Rpc(e)),
    }
}

/// The result of verifying a separating transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Separation {
    /// At least one input does not exist on the SHA256 chain, so the transaction can never be replayed
    /// there - the coin is separated.
    pub separated: bool,
    /// The input (funding txid) that exists only on the Blake2b chain, if any.
    pub sha256_only_input: Option<String>,
    /// Confirmations on the Blake2b chain.
    pub confirmations: u32,
    /// Whether it is confirmed deep enough to be safe from a reorg.
    pub deep_enough: bool,
}

impl Separation {
    /// Fully done: separated AND confirmed deep enough. This is the gate before an operator declares a
    /// coin split and before it is safe to spend the SHA256 side.
    pub fn is_final(&self) -> bool {
        self.separated && self.deep_enough
    }
}

/// Verify that a Blake2b separating transaction has actually separated the coin. It is separated iff at
/// least one of its `inputs` does **not** exist on the SHA256 chain (so the whole transaction is invalid
/// there and can never be replayed). `exists_on_sha256(funding_txid)` checks whether an input's funding
/// transaction exists on the SHA256 node; the first input that does not is the proof. `confirmations` is
/// the transaction's depth on the Blake2b chain. Pure (the chain lookups are passed in) so it is
/// unit-testable without a node.
pub fn verify_separation<F, E>(
    inputs: &[(String, u32)],
    confirmations: u32,
    mut exists_on_sha256: F,
) -> Result<Separation, E>
where
    F: FnMut(&str) -> Result<bool, E>,
{
    let mut sha256_only_input = None;
    for (funding_txid, _vout) in inputs {
        if !exists_on_sha256(funding_txid)? {
            sha256_only_input = Some(funding_txid.clone());
            break;
        }
    }
    Ok(Separation {
        separated: sha256_only_input.is_some(),
        sha256_only_input,
        confirmations,
        deep_enough: confirmations >= MIN_SEPARATION_CONFIRMATIONS,
    })
}

// ---- P3: survey a wallet (what needs splitting, what can split it) -------------------------------

/// One wallet UTXO to be surveyed.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
}

/// The result of surveying a wallet: the SHA-Coins that still need separating, and the Blake2b-Coins
/// available to separate them with (the "ingredients", e.g. our mining rewards). A SHA-Coin can be
/// separated when at least one ingredient exists.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Survey {
    pub to_split: Vec<SplitInput>,
    pub ingredients: Vec<SplitInput>,
}

impl Survey {
    /// Whether every SHA-Coin found can be separated with the ingredients on hand (one per move, but an
    /// ingredient's change is itself an ingredient, so one is enough to start).
    pub fn can_split(&self) -> bool {
        self.to_split.is_empty() || !self.ingredients.is_empty()
    }
}

/// Classify every wallet UTXO and partition it into SHA-Coins (replayable, need separating) and
/// Blake2b-Coins (chain-specific, usable as the separating ingredient). This is what the service shows a
/// user: "these coins need splitting; here is what can split them." Each classification is bounded by
/// `max_lookups`.
pub fn survey_wallet<S: TxSource>(
    src: &S,
    fork_height: u32,
    utxos: &[WalletUtxo],
    max_lookups: u32,
) -> Result<Survey, SplitError> {
    let mut survey = Survey::default();
    for u in utxos {
        let kind = classify(src, fork_height, &u.txid, max_lookups)?;
        let input = SplitInput {
            txid: u.txid.clone(),
            vout: u.vout,
            kind,
            value_sat: u.value_sat,
        };
        match kind {
            CoinKind::ShaCoin => survey.to_split.push(input),
            CoinKind::Blake2bCoin => survey.ingredients.push(input),
        }
    }
    Ok(survey)
}

// ---- P3: the lent-marker pool (reservation + privacy) -------------------------------------------

/// How long a reserved marker is held for a job before it auto-releases (the user never broadcast), so
/// an abandoned job cannot hold or drain the pool. An hour is ample for signing a PSBT out of band.
pub const MARKER_RESERVATION_SECS: u64 = 3600;

/// A Blake2b-Coin we lend as the separating marker. It is RECOVERED as change by the builder (never
/// given away), so a marker is a modest UTXO from our own mining.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Marker {
    pub txid: String,
    pub vout: u32,
    pub value_sat: u64,
}

/// The coin offered as a marker is the change of a previous split; using it would chain users'
/// transactions together through our change (a privacy leak), so the pool refuses it.
#[derive(Debug, PartialEq, Eq)]
pub struct TaintedChange;

/// A pool of lent Blake2b-Coin markers. Pure in-memory state (the daemon persists it) enforcing the two
/// rules the marker scheme needs:
/// (1) a marker is reserved to at most ONE job at a time and a reservation EXPIRES after
/// [`MARKER_RESERVATION_SECS`], so a user who never broadcasts cannot hold or drain the pool; and
/// (2) the change a split returns to us is NEVER reused as a future marker - otherwise every user's
/// split would spend the previous one's change, chaining all users into one common-input cluster.
/// Markers come only from our mining; their recovered change is tainted and sequestered.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MarkerPool {
    available: Vec<Marker>,
    reserved: HashMap<String, (Marker, u64)>, // job_id -> (marker, reserved_at unix)
    tainted: HashSet<String>, // txids of our own split change, never usable as markers
}

impl MarkerPool {
    /// Add a marker from our mining. Refused if the coin is the change of a previous split. Returns
    /// whether it was newly added (idempotent for a coin already held or reserved).
    pub fn add_marker(&mut self, m: Marker) -> Result<bool, TaintedChange> {
        if self.tainted.contains(&m.txid) {
            return Err(TaintedChange);
        }
        let held = |v: &Marker| v.txid == m.txid && v.vout == m.vout;
        if self.available.iter().any(held) || self.reserved.values().any(|(r, _)| held(r)) {
            return Ok(false);
        }
        self.available.push(m);
        Ok(true)
    }

    /// Reserve a marker for `job_id` (idempotent: the same job keeps its marker). `None` if the pool is
    /// empty. Call [`MarkerPool::expire`] first to reclaim stale reservations.
    pub fn reserve(&mut self, job_id: &str, now: u64) -> Option<Marker> {
        if let Some((m, _)) = self.reserved.get(job_id) {
            return Some(m.clone());
        }
        let m = self.available.pop()?;
        self.reserved.insert(job_id.to_owned(), (m.clone(), now));
        Some(m)
    }

    /// The marker currently reserved for `job_id`, if any (so `/split/submit` can learn which input is
    /// ours without trusting the caller).
    pub fn reserved_marker(&self, job_id: &str) -> Option<Marker> {
        self.reserved.get(job_id).map(|(m, _)| m.clone())
    }

    /// Release reservations older than `timeout` back to the pool; returns the freed job ids (so a
    /// caller tracking per-job state can drop them too).
    pub fn expire(&mut self, now: u64, timeout: u64) -> Vec<String> {
        let stale: Vec<String> = self
            .reserved
            .iter()
            .filter(|(_, (_, at))| now.saturating_sub(*at) > timeout)
            .map(|(j, _)| j.clone())
            .collect();
        for j in &stale {
            if let Some((m, _)) = self.reserved.remove(j) {
                self.available.push(m);
            }
        }
        stale
    }

    /// Explicitly release a job's reservation (aborted before broadcast); the marker returns to the pool.
    pub fn release(&mut self, job_id: &str) {
        if let Some((m, _)) = self.reserved.remove(job_id) {
            self.available.push(m);
        }
    }

    /// The job broadcast its split: the marker is spent on-chain, so drop the reservation WITHOUT
    /// returning it to the pool, and taint the split's change `change_txid` so the recovered coin can
    /// never become a future marker (privacy). Returns the consumed marker.
    pub fn consume(&mut self, job_id: &str, change_txid: String) -> Option<Marker> {
        let (m, _) = self.reserved.remove(job_id)?;
        self.tainted.insert(change_txid);
        Some(m)
    }

    pub fn available_count(&self) -> usize {
        self.available.len()
    }
    pub fn reserved_count(&self) -> usize {
        self.reserved.len()
    }
}

/// The persisted split-service state: the lent-marker [`MarkerPool`] plus the pending jobs (the exact
/// unsigned transaction we built per job, so `/split/submit` can require the submitted PSBT to be the
/// very transaction we built and reserved a marker for). Persisted to `split.json` in the data dir, so a
/// reserved marker or a pending job survives a daemon restart (else a restart could double-lend a marker).
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SplitState {
    pub pool: MarkerPool,
    /// job_id -> the exact unsigned transaction we built (hex), matched byte-for-byte at submit.
    jobs: HashMap<String, String>,
}

impl SplitState {
    /// Load from `path`, or a fresh empty state if it is absent or unreadable.
    pub fn load(path: &Path) -> SplitState {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Persist atomically (same `write_atomic` the engine uses).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        write_atomic(
            path,
            &serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?,
        )
    }

    /// Record the exact unsigned tx built for `job_id` (its marker is already reserved in the pool).
    pub fn set_job(&mut self, job_id: &str, unsigned_tx_hex: String) {
        self.jobs.insert(job_id.to_owned(), unsigned_tx_hex);
    }

    /// The exact unsigned tx we built for `job_id`, to match a submitted PSBT against.
    pub fn job(&self, job_id: &str) -> Option<&str> {
        self.jobs.get(job_id).map(String::as_str)
    }

    /// Release every job whose marker reservation has expired (user never submitted): the marker returns
    /// to the pool and the stale job is dropped. Call before reserving.
    pub fn expire(&mut self, now: u64, timeout: u64) {
        for job_id in self.pool.expire(now, timeout) {
            self.jobs.remove(&job_id);
        }
    }

    /// The job's marker was spent on-chain: drop the job and taint its change (via the pool) so the
    /// recovered coin never becomes a future marker. Returns the consumed marker.
    pub fn finish_job(&mut self, job_id: &str, change_txid: String) -> Option<Marker> {
        self.jobs.remove(job_id);
        self.pool.consume(job_id, change_txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock chain: txid -> TxInfo, for unit-testing the classifier without a node.
    struct Mock(HashMap<&'static str, TxInfo>);
    impl TxSource for Mock {
        fn tx(&self, txid: &str) -> Result<TxInfo, SplitError> {
            self.0
                .get(txid)
                .cloned()
                .ok_or_else(|| SplitError::Malformed(format!("unknown {txid}")))
        }
    }
    fn cb(height: u32) -> TxInfo {
        TxInfo {
            is_coinbase: true,
            height: Some(height),
            inputs: vec![],
        }
    }
    fn tx(height: u32, inputs: &[(&'static str, u32)]) -> TxInfo {
        TxInfo {
            is_coinbase: false,
            height: Some(height),
            inputs: inputs.iter().map(|(t, n)| ((*t).to_owned(), *n)).collect(),
        }
    }

    const FORK: u32 = 100;

    #[test]
    fn a_prefork_coinbase_is_a_sha_coin() {
        let m = Mock(HashMap::from([("cbpre", cb(50))]));
        assert_eq!(classify(&m, FORK, "cbpre", 50).unwrap(), CoinKind::ShaCoin);
    }

    #[test]
    fn a_postfork_coinbase_is_a_blake2b_coin() {
        let m = Mock(HashMap::from([("cbpost", cb(120))]));
        assert_eq!(
            classify(&m, FORK, "cbpost", 50).unwrap(),
            CoinKind::Blake2bCoin
        );
    }

    #[test]
    fn a_prefork_funded_coin_is_a_sha_coin_without_tracing_past_the_fork() {
        // A tx confirmed before the fork short-circuits: its ancestry is never consulted.
        let m = Mock(HashMap::from([("pre", tx(60, &[("whatever", 0)]))]));
        // Budget of 1 proves no ancestry lookup happens for a pre-fork tx.
        assert_eq!(classify(&m, FORK, "pre", 1).unwrap(), CoinKind::ShaCoin);
    }

    #[test]
    fn a_coin_spending_a_blake2b_coin_is_a_blake2b_coin() {
        // post-fork tx whose input traces to a post-fork coinbase.
        let m = Mock(HashMap::from([
            ("spend", tx(130, &[("cbpost", 0), ("other", 1)])),
            ("cbpost", cb(125)),
            ("other", cb(80)), // a pre-fork coinbase input
        ]));
        assert_eq!(
            classify(&m, FORK, "spend", 50).unwrap(),
            CoinKind::Blake2bCoin
        );
    }

    #[test]
    fn a_postfork_tx_spending_only_prefork_coins_is_a_sha_coin() {
        // Replayable in practice (this is exactly what the split must avoid creating), but by
        // classification it is a SHA-Coin: no post-fork ancestry.
        let m = Mock(HashMap::from([
            ("spend", tx(130, &[("p1", 0), ("p2", 0)])),
            ("p1", tx(40, &[("x", 0)])), // pre-fork, short-circuits
            ("p2", cb(30)),              // pre-fork coinbase
        ]));
        assert_eq!(classify(&m, FORK, "spend", 50).unwrap(), CoinKind::ShaCoin);
    }

    #[test]
    fn the_lookup_budget_bounds_the_trace() {
        // A chain of post-fork non-coinbase txs longer than the budget returns TooDeep rather than
        // tracing forever.
        let mut h = HashMap::new();
        h.insert("t0", tx(130, &[("t1", 0)]));
        h.insert("t1", tx(129, &[("t2", 0)]));
        h.insert("t2", tx(128, &[("t3", 0)]));
        let m = Mock(h);
        assert!(matches!(
            classify(&m, FORK, "t0", 2),
            Err(SplitError::TooDeep)
        ));
    }

    // ---- P2: separating-transaction invariants ----

    fn si(kind: CoinKind, value_sat: u64) -> SplitInput {
        SplitInput {
            txid: "t".to_owned(),
            vout: 0,
            kind,
            value_sat,
        }
    }

    #[test]
    fn project_fee_is_half_a_percent_rounded_up_and_at_least_one() {
        assert_eq!(project_fee_sat(1_000_000, FEE_BPS), 5_000); // 0.5% of 1,000,000
        assert_eq!(project_fee_sat(10_001, FEE_BPS), 51); // 50.005 -> ceil 51
        assert_eq!(project_fee_sat(1, FEE_BPS), 1); // tiny amount still pays 1
        assert_eq!(project_fee_sat(0, FEE_BPS), 0);
        assert_eq!(project_fee_sat(1_000_000, 0), 0);
    }

    #[test]
    fn a_split_without_a_blake2b_coin_is_refused_as_replayable() {
        let inputs = [si(CoinKind::ShaCoin, 1_000_000), si(CoinKind::ShaCoin, 500)];
        let err = validate_split_inputs(&inputs).unwrap_err();
        assert!(matches!(err, SplitError::Malformed(m) if m.contains("replayable")));
    }

    #[test]
    fn a_split_without_a_sha_coin_has_nothing_to_separate() {
        let inputs = [si(CoinKind::Blake2bCoin, 10_000)];
        let err = validate_split_inputs(&inputs).unwrap_err();
        assert!(matches!(err, SplitError::Malformed(m) if m.contains("nothing to separate")));
    }

    #[test]
    fn empty_inputs_are_refused() {
        assert!(matches!(
            validate_split_inputs(&[]),
            Err(SplitError::Malformed(_))
        ));
    }

    #[test]
    fn a_valid_split_charges_the_fee_on_the_sha_value_only() {
        // One SHA-Coin (separated) + one Blake2b-Coin (the ingredient).
        let inputs = [
            si(CoinKind::ShaCoin, 1_010_115),
            si(CoinKind::Blake2bCoin, 10_238),
        ];
        let plan = validate_split_inputs(&inputs).unwrap();
        assert_eq!(plan.total_sat, 1_020_353);
        assert_eq!(plan.sha_value_sat, 1_010_115); // fee is on the separated value, not the ingredient
        assert_eq!(plan.fee_sat, project_fee_sat(1_010_115, FEE_BPS)); // 0.5%
    }

    // ---- P2: the unsigned builder (pure, no node) ----

    fn spk(n: u8) -> ScriptBuf {
        use bitcoin::hashes::Hash as _;
        ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([n; 20]))
    }
    fn addr(n: u8) -> Address {
        Address::from_script(&spk(n), bitcoin::Network::Regtest).unwrap()
    }
    fn prev_tx_for(spk: &ScriptBuf, value_sat: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(value_sat),
                script_pubkey: spk.clone(),
            }],
        }
    }
    fn prepared_spk(
        txid_byte: u8,
        spk: ScriptBuf,
        kind: CoinKind,
        value_sat: u64,
    ) -> PreparedInput {
        PreparedInput {
            input: SplitInput {
                txid: format!("{txid_byte:064x}"),
                vout: 0,
                kind,
                value_sat,
            },
            prev_tx: prev_tx_for(&spk, value_sat),
            script_pubkey: spk,
        }
    }
    fn prepared(n: u8, kind: CoinKind, value_sat: u64) -> PreparedInput {
        prepared_spk(n, spk(n), kind, value_sat)
    }

    #[test]
    fn build_lays_out_dest_fee_and_recovered_marker() {
        use std::str::FromStr;
        let inputs = [
            prepared(1, CoinKind::ShaCoin, 1_000_000),
            prepared(2, CoinKind::Blake2bCoin, 10_000),
        ];
        let net_fee = 500;
        let b64 = build_split_psbt(&inputs, &addr(3), &addr(4), &addr(5), net_fee).unwrap();
        let psbt = Psbt::from_str(&b64).unwrap();
        // Every input carries witness_utxo (so an out-of-band signer can sign).
        assert_eq!(psbt.inputs.len(), 2);
        assert_eq!(
            psbt.inputs[0].witness_utxo.as_ref().unwrap().value,
            Amount::from_sat(1_000_000)
        );
        assert_eq!(
            psbt.inputs[1].witness_utxo.as_ref().unwrap().value,
            Amount::from_sat(10_000)
        );
        // dest = sha - fee - network_fee; fee to us; marker recovered IN FULL.
        let fee = project_fee_sat(1_000_000, FEE_BPS);
        let out = &psbt.unsigned_tx.output;
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].value, Amount::from_sat(1_000_000 - fee - net_fee));
        assert_eq!(out[0].script_pubkey, spk(3));
        assert_eq!(out[1].value, Amount::from_sat(fee));
        assert_eq!(out[1].script_pubkey, spk(4));
        assert_eq!(out[2].value, Amount::from_sat(10_000));
        assert_eq!(out[2].script_pubkey, spk(5));
        // Segwit v0 inputs also carry non_witness_utxo (BIP174 / hardware-signer compatibility).
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[1].non_witness_utxo.is_some());
        // Unsigned: no witness or script_sig on any input.
        assert!(psbt
            .unsigned_tx
            .input
            .iter()
            .all(|i| i.witness.is_empty() && i.script_sig.is_empty()));
    }

    #[test]
    fn build_sets_utxo_fields_per_input_type() {
        use bitcoin::hashes::Hash as _;
        use std::str::FromStr;
        let p2pkh = ScriptBuf::new_p2pkh(&bitcoin::PubkeyHash::from_byte_array([9u8; 20]));
        let p2tr = {
            let mut v = vec![0x51u8, 0x20];
            v.extend_from_slice(&[0xabu8; 32]);
            ScriptBuf::from(v)
        };
        assert!(p2tr.is_p2tr() && !p2pkh.is_witness_program());
        let inputs = [
            prepared_spk(0x14, p2pkh, CoinKind::ShaCoin, 1_000_000), // legacy user coin
            prepared_spk(0x20, p2tr, CoinKind::Blake2bCoin, 10_000), // taproot marker
        ];
        let b64 = build_split_psbt(&inputs, &addr(3), &addr(4), &addr(5), 500).unwrap();
        let psbt = Psbt::from_str(&b64).unwrap();
        // Legacy input: non_witness_utxo only.
        assert!(psbt.inputs[0].non_witness_utxo.is_some());
        assert!(psbt.inputs[0].witness_utxo.is_none());
        // Taproot input: witness_utxo only.
        assert!(psbt.inputs[1].witness_utxo.is_some());
        assert!(psbt.inputs[1].non_witness_utxo.is_none());
    }

    #[test]
    fn build_refuses_without_a_marker() {
        let inputs = [prepared(1, CoinKind::ShaCoin, 1_000_000)];
        assert!(build_split_psbt(&inputs, &addr(3), &addr(4), &addr(5), 500).is_err());
    }

    #[test]
    fn build_refuses_when_fees_exceed_the_separated_value() {
        let inputs = [
            prepared(1, CoinKind::ShaCoin, 1_000),
            prepared(2, CoinKind::Blake2bCoin, 10_000),
        ];
        assert!(build_split_psbt(&inputs, &addr(3), &addr(4), &addr(5), 10_000).is_err());
    }

    // ---- P5: submit validation ----

    fn dummy_ecdsa(sighash: EcdsaSighashType) -> (bitcoin::PublicKey, bitcoin::ecdsa::Signature) {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[0x11u8; 32]).unwrap();
        let pk = bitcoin::PublicKey::new(sk.public_key(&secp));
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&[0x22u8; 64]).unwrap();
        (
            pk,
            bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: sighash,
            },
        )
    }

    /// (expected unsigned-tx hex, the unsigned PSBT, the marker outpoint) for a user+marker build.
    fn unsigned_job() -> (String, Psbt, OutPoint) {
        let inputs = [
            prepared(1, CoinKind::ShaCoin, 1_000_000), // user input (prev txid 00..01)
            prepared(2, CoinKind::Blake2bCoin, 10_000), // marker (prev txid 00..02)
        ];
        let b64 = build_split_psbt(&inputs, &addr(3), &addr(4), &addr(5), 500).unwrap();
        let psbt: Psbt = b64.parse().unwrap();
        let expected = serialize_hex(&psbt.unsigned_tx);
        let marker = psbt.unsigned_tx.input[1].previous_output;
        (expected, psbt, marker)
    }

    #[test]
    fn submit_refuses_an_unsigned_user_input() {
        let (expected, psbt, marker) = unsigned_job();
        assert!(validate_user_signed(&expected, &psbt.to_string(), marker).is_err());
    }

    #[test]
    fn submit_accepts_a_sighash_all_user_signature() {
        let (expected, mut psbt, marker) = unsigned_job();
        let (pk, sig) = dummy_ecdsa(EcdsaSighashType::All);
        psbt.inputs[0].partial_sigs.insert(pk, sig);
        validate_user_signed(&expected, &psbt.to_string(), marker).unwrap();
    }

    #[test]
    fn submit_refuses_a_non_all_sighash() {
        for bad in [
            EcdsaSighashType::None,
            EcdsaSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay,
        ] {
            let (expected, mut psbt, marker) = unsigned_job();
            let (pk, sig) = dummy_ecdsa(bad);
            psbt.inputs[0].partial_sigs.insert(pk, sig);
            assert!(
                validate_user_signed(&expected, &psbt.to_string(), marker).is_err(),
                "sighash {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn submit_refuses_a_tampered_transaction() {
        let (_expected, mut psbt, marker) = unsigned_job();
        let (pk, sig) = dummy_ecdsa(EcdsaSighashType::All);
        psbt.inputs[0].partial_sigs.insert(pk, sig);
        // A build to a DIFFERENT destination has a different unsigned tx, so its hex must not match.
        let other = build_split_psbt(
            &[
                prepared(1, CoinKind::ShaCoin, 1_000_000),
                prepared(2, CoinKind::Blake2bCoin, 10_000),
            ],
            &addr(6),
            &addr(4),
            &addr(5),
            500,
        )
        .unwrap();
        let other_hex = serialize_hex(&other.parse::<Psbt>().unwrap().unsigned_tx);
        assert!(validate_user_signed(&other_hex, &psbt.to_string(), marker).is_err());
    }

    #[test]
    fn submit_refuses_a_pre_signed_marker() {
        let (expected, mut psbt, marker) = unsigned_job();
        let (pk, sig) = dummy_ecdsa(EcdsaSighashType::All);
        psbt.inputs[0].partial_sigs.insert(pk, sig); // user signed (ok)
        let (pk2, sig2) = dummy_ecdsa(EcdsaSighashType::All);
        psbt.inputs[1].partial_sigs.insert(pk2, sig2); // marker pre-signed (NOT ok)
        assert!(validate_user_signed(&expected, &psbt.to_string(), marker).is_err());
    }

    // ---- P3: wallet survey ----

    #[test]
    fn survey_partitions_sha_coins_from_ingredients_and_reports_splittability() {
        // Wallet: a pre-fork SHA-Coin, a post-fork Blake2b-Coin (ingredient), and another SHA-Coin.
        let m = Mock(HashMap::from([
            ("sha1", cb(50)),              // pre-fork coinbase -> SHA-Coin
            ("ing", cb(130)),              // post-fork coinbase -> Blake2b-Coin
            ("sha2", tx(40, &[("x", 0)])), // pre-fork -> SHA-Coin
        ]));
        let utxos = [
            WalletUtxo {
                txid: "sha1".to_owned(),
                vout: 0,
                value_sat: 1_000_000,
            },
            WalletUtxo {
                txid: "ing".to_owned(),
                vout: 0,
                value_sat: 50_000,
            },
            WalletUtxo {
                txid: "sha2".to_owned(),
                vout: 1,
                value_sat: 500_000,
            },
        ];
        let s = survey_wallet(&m, FORK, &utxos, 50).unwrap();
        assert_eq!(s.to_split.len(), 2);
        assert_eq!(s.ingredients.len(), 1);
        assert!(s.can_split());
    }

    #[test]
    fn survey_reports_not_splittable_without_an_ingredient() {
        let m = Mock(HashMap::from([("sha1", cb(50))]));
        let utxos = [WalletUtxo {
            txid: "sha1".to_owned(),
            vout: 0,
            value_sat: 1_000_000,
        }];
        let s = survey_wallet(&m, FORK, &utxos, 50).unwrap();
        assert_eq!(s.to_split.len(), 1);
        assert!(s.ingredients.is_empty());
        assert!(!s.can_split()); // has a SHA-Coin but no Blake2b-Coin to separate it with
    }

    // ---- P5c: verify_separation ----

    #[test]
    fn separation_holds_when_an_input_is_absent_on_sha256() {
        // Two inputs: the SHA-Coin (exists on SHA256) and the Blake2b-Coin (does NOT).
        let inputs = [("shacoin".to_owned(), 0), ("blake2bcoin".to_owned(), 3)];
        let sep = verify_separation::<_, ()>(&inputs, 14, |t| Ok(t != "blake2bcoin")).unwrap();
        assert!(sep.separated);
        assert_eq!(sep.sha256_only_input.as_deref(), Some("blake2bcoin"));
        assert!(sep.deep_enough); // 14 >= 12
        assert!(sep.is_final());
    }

    #[test]
    fn separation_fails_when_every_input_exists_on_sha256() {
        // A would-be "split" with no Blake2b-Coin: all inputs exist on SHA256 -> replayable.
        let inputs = [("a".to_owned(), 0), ("b".to_owned(), 1)];
        let sep = verify_separation::<_, ()>(&inputs, 20, |_| Ok(true)).unwrap();
        assert!(!sep.separated);
        assert!(sep.sha256_only_input.is_none());
        assert!(!sep.is_final());
    }

    #[test]
    fn separation_is_not_final_until_confirmed_deep_enough() {
        let inputs = [("blake2bcoin".to_owned(), 0)];
        let sep = verify_separation::<_, ()>(&inputs, 3, |_| Ok(false)).unwrap();
        assert!(sep.separated); // the input is Blake2b-only
        assert!(!sep.deep_enough); // only 3 confirmations, needs 12
        assert!(!sep.is_final()); // separated but not yet safe from a reorg
    }

    // ---- P3: the lent-marker pool ----

    fn marker(n: u8) -> Marker {
        Marker {
            txid: format!("{n:064x}"),
            vout: 0,
            value_sat: 10_000,
        }
    }

    #[test]
    fn a_marker_is_reserved_to_one_job_and_the_same_job_is_idempotent() {
        let mut pool = MarkerPool::default();
        pool.add_marker(marker(1)).unwrap();
        pool.add_marker(marker(2)).unwrap();
        let a = pool.reserve("job-a", 100).unwrap();
        let a_again = pool.reserve("job-a", 200).unwrap();
        assert_eq!(a, a_again, "same job keeps its marker");
        let b = pool.reserve("job-b", 100).unwrap();
        assert_ne!(a, b, "a different job gets a different marker");
        assert_eq!(pool.available_count(), 0);
        assert_eq!(pool.reserved_count(), 2);
    }

    #[test]
    fn reserve_is_none_when_the_pool_is_empty() {
        let mut pool = MarkerPool::default();
        assert!(pool.reserve("job", 0).is_none());
    }

    #[test]
    fn a_stale_reservation_expires_back_to_the_pool() {
        let mut pool = MarkerPool::default();
        pool.add_marker(marker(1)).unwrap();
        pool.reserve("abandoned", 1_000);
        assert_eq!(pool.available_count(), 0);
        // Not yet stale.
        assert!(pool
            .expire(1_000 + MARKER_RESERVATION_SECS, MARKER_RESERVATION_SECS)
            .is_empty());
        // Past the timeout: freed (the job id comes back).
        assert_eq!(
            pool.expire(1_001 + MARKER_RESERVATION_SECS, MARKER_RESERVATION_SECS),
            vec!["abandoned".to_owned()]
        );
        assert_eq!(pool.available_count(), 1);
        assert!(pool.reserve("fresh", 0).is_some());
    }

    #[test]
    fn a_split_change_is_never_reusable_as_a_marker() {
        let mut pool = MarkerPool::default();
        pool.add_marker(marker(1)).unwrap();
        pool.reserve("job", 0).unwrap();
        // The job broadcast; its change (say the tx 00..0f) is now tainted.
        let change = format!("{:064x}", 0x0f);
        pool.consume("job", change.clone()).unwrap();
        assert_eq!(pool.reserved_count(), 0);
        assert_eq!(
            pool.available_count(),
            0,
            "a consumed marker does not return"
        );
        // Trying to feed that change back as a marker is refused.
        let recycled = Marker {
            txid: change,
            vout: 1,
            value_sat: 9_500,
        };
        assert_eq!(pool.add_marker(recycled), Err(TaintedChange));
    }

    #[test]
    fn an_aborted_job_releases_its_marker() {
        let mut pool = MarkerPool::default();
        pool.add_marker(marker(1)).unwrap();
        pool.reserve("job", 0).unwrap();
        pool.release("job");
        assert_eq!(pool.available_count(), 1);
        assert_eq!(pool.reserved_count(), 0);
    }

    #[test]
    fn split_state_round_trips_through_disk() {
        let mut st = SplitState::default();
        st.pool.add_marker(marker(1)).unwrap();
        st.pool.add_marker(marker(2)).unwrap();
        let m = st.pool.reserve("job-a", 1_000).unwrap();
        st.set_job("job-a", "deadbeef".to_owned());
        let path =
            std::env::temp_dir().join(format!("split-state-test-{}.json", std::process::id()));
        st.save(&path).unwrap();
        let mut loaded = SplitState::load(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(loaded.job("job-a"), Some("deadbeef"));
        assert_eq!(loaded.pool.reserved_count(), 1);
        assert_eq!(loaded.pool.available_count(), 1);
        // the reserved marker survived the round trip
        assert_eq!(loaded.pool.reserve("job-a", 2_000).unwrap(), m);
    }

    #[test]
    fn split_state_expiry_drops_the_job_and_frees_the_marker() {
        let mut st = SplitState::default();
        st.pool.add_marker(marker(1)).unwrap();
        st.pool.reserve("stale", 1_000).unwrap();
        st.set_job("stale", "aa".to_owned());
        st.expire(1_001 + MARKER_RESERVATION_SECS, MARKER_RESERVATION_SECS);
        assert_eq!(st.job("stale"), None, "stale job dropped");
        assert_eq!(st.pool.available_count(), 1, "marker back in the pool");
    }

    #[test]
    fn finishing_a_job_drops_it_and_taints_the_change() {
        let mut st = SplitState::default();
        st.pool.add_marker(marker(1)).unwrap();
        st.pool.reserve("job", 0).unwrap();
        st.set_job("job", "bb".to_owned());
        let change = format!("{:064x}", 0xfe);
        st.finish_job("job", change.clone()).unwrap();
        assert_eq!(st.job("job"), None);
        assert_eq!(
            st.pool.available_count(),
            0,
            "consumed marker does not return"
        );
        let recycled = Marker {
            txid: change,
            vout: 0,
            value_sat: 9_000,
        };
        assert_eq!(st.pool.add_marker(recycled), Err(TaintedChange));
    }
}

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

use bitcoin::transaction::Version;
use bitcoin::{
    absolute, Address, Amount, OutPoint, Psbt, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
    Witness,
};
use serde_json::json;

use crate::rpc::{Client, RpcError};

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

/// An input paired with its prevout scriptPubKey, so the PSBT can carry `witness_utxo` for it (segwit
/// and taproot signers commit to every input's amount and scriptPubKey). Built by [`prepare_input`].
#[derive(Debug, Clone)]
pub struct PreparedInput {
    pub input: SplitInput,
    pub script_pubkey: ScriptBuf,
}

/// Fetch an input's prevout (value + scriptPubKey) from the node and pair it with its classified kind,
/// so [`build_split_psbt`] can set `witness_utxo` without a funding wallet. Uses `gettxout`, so the
/// input must be unspent (it is, at build time). The value comes from the chain, not the caller.
pub fn prepare_input(
    rpc: &Client,
    txid: &str,
    vout: u32,
    kind: CoinKind,
) -> Result<PreparedInput, SplitError> {
    let v = rpc
        .call("gettxout", json!([txid, vout]))
        .map_err(SplitError::Rpc)?;
    if v.is_null() {
        return Err(SplitError::Malformed(format!(
            "{txid}:{vout} not found or already spent"
        )));
    }
    let value_sat = v["value"]
        .as_f64()
        .map(|b| (b * 1e8).round() as u64)
        .ok_or_else(|| SplitError::Malformed(format!("{txid}:{vout}: no value")))?;
    let hex = v["scriptPubKey"]["hex"]
        .as_str()
        .ok_or_else(|| SplitError::Malformed(format!("{txid}:{vout}: no scriptPubKey")))?;
    let script_pubkey = ScriptBuf::from_hex(hex)
        .map_err(|e| SplitError::Malformed(format!("scriptPubKey: {e}")))?;
    Ok(PreparedInput {
        input: SplitInput {
            txid: txid.to_owned(),
            vout,
            kind,
            value_sat,
        },
        script_pubkey,
    })
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
        slot.witness_utxo = Some(TxOut {
            value: Amount::from_sat(inp.input.value_sat),
            script_pubkey: inp.script_pubkey.clone(),
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
    fn prepared(n: u8, kind: CoinKind, value_sat: u64) -> PreparedInput {
        PreparedInput {
            input: SplitInput {
                txid: format!("{n:064x}"),
                vout: 0,
                kind,
                value_sat,
            },
            script_pubkey: spk(n),
        }
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
        // Unsigned: no witness or script_sig on any input.
        assert!(psbt
            .unsigned_tx
            .input
            .iter()
            .all(|i| i.witness.is_empty() && i.script_sig.is_empty()));
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
}

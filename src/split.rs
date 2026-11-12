//! Coin-split / replay-protection service (design: `_internal/designs/xbt-btc-replay-split-*`).
//!
//! Bitcoin and Bitcoin Blake2b share byte-identical history before the fork (mainnet block 961,640),
//! so a coin that existed before the fork exists on BOTH chains under the same key and is **replayable**:
//! a spend on one chain can be copied to the other. To separate the twins the coin must be moved once on
//! the Blake2b chain in a transaction that cannot exist on the SHA256 chain, by spending it **together
//! with** a "Blake2b-Coin" (a coin mined after the fork, which exists on Blake2b only). This module:
//!   - **classifies** a UTXO as a SHA-Coin (pre-fork, replayable, needs splitting) or a Blake2b-Coin
//!     (post-fork, chain-specific) - P1;
//!   - **builds** the separating transaction - P2 (see `split::psbt`).
//!
//! Safety invariant (from the proven runbook): a separating transaction MUST have at least one
//! Blake2b-Coin input, or it is replayable. The builder enforces that; the classifier is how we check.

use serde_json::json;

use crate::rpc::{Client, RpcError};

/// Mainnet fork height: Bitcoin split into the SHA256 and Blake2b chains at this block (2026-08-30). A
/// coinbase at or above this height, seen on the Blake2b chain, is a Blake2b-only coin. Regtest uses a
/// low activation height (`-testactivationheight=blake2b@N`), passed in explicitly.
pub const MAINNET_FORK_HEIGHT: u32 = 961_640;

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
}

//! Drives every swap: reads both chains, lets `Swap::decide` choose, stores the result, acts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};

use crate::fee::{self, FeeRates};
use crate::htlc::{Contract, Spend};
use crate::keys::{Keys, Use};
use crate::node::{ChainBackend, ChainNode, FeeDest, NodeError};
use crate::policy::{Policy, PolicyError};
use crate::silentpayments;
use crate::store::write_atomic;
use crate::swap::{
    Action, BidError, Chain, ChainView, FeeProof, FeeState, Message, Offer, Phase, Role, Swap,
};
use crate::transport::Transport;

/// Maker-chain blocks a taker waits, beyond the required depth, for the maker's lock before giving up.
const LOCK_WAIT_BLOCKS: u32 = 10;

/// Blocks to target when fee-estimating a claim or refund: short, because these spends race a
/// timelock and must confirm promptly (F6).
const SPEND_CONF_TARGET: u16 = 3;
/// Conservative claim/refund fee rate (sat/vB) used when the node cannot estimate (a fresh regtest or
/// the quiet xBTC chain returns nothing). Sized to today's effective flat fee (2000 sat / 142 vB claim
/// = 14.1 sat/vB), rounded up, so a chain with no estimator keeps a safe, near-unchanged fee.
const FALLBACK_SPEND_RATE_SAT_VB: u64 = 15;

/// Unix seconds now, for a swap's local creation timestamp (web UI time column). A clock before the
/// epoch falls back to 0 rather than panicking.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short hex prefix of a 16-byte id, for log lines (F4): enough to correlate, not the whole id.
fn short_id(id: &[u8; 16]) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The fee output a leg owes, or `None` when none is due. A leg below the minimum trade owes no fee
/// (design 0013 / `fee.rs`), so `BelowMinimum` maps to `None`, NOT an error (#107): the payer funds
/// with no fee output and the counterparty verifies as not-required, so a leg in `[min_swap,
/// min_trade)` with a fee address completes instead of stranding the first locker's coin. Pure, so the
/// both-paths-agree contract is unit-tested directly.
fn fee_amount_or_none(
    rates: FeeRates,
    role: Role,
    locked: Amount,
    min_trade: u64,
) -> Option<Amount> {
    // The only error fee_amount_min returns is BelowMinimum, which here means "no fee output", so
    // `.ok()` is exactly the right mapping.
    fee::fee_amount_min(rates, role, locked, min_trade).ok()
}

/// How long a discovered offer stays in the local market without being re-seen before it ages out
/// (#88/#70/#65). Matches the relay's event retention (7 days), so an offer the relay would still
/// serve is never dropped first, but a dead or withdrawn offer whose maker is gone - including a
/// pre-M1 legacy offer with no `Withdraw` - cannot linger in discovery forever.
const SEEN_OFFER_TTL_SECS: u64 = 7 * 24 * 3600;

/// Drop discovered offers not re-seen within `SEEN_OFFER_TTL_SECS` (and their timestamps). Any offer
/// with no timestamp yet - a legacy entry loaded from state written before `seen_at` existed - is
/// stamped with `now` so it ages from load rather than lingering forever. Pure, so it is unit-tested
/// directly. Returns whether anything changed (so the caller can persist).
fn prune_seen(
    seen_offers: &mut Vec<crate::swap::Offer>,
    seen_at: &mut Vec<([u8; 16], u64)>,
    now: u64,
) -> bool {
    let before = (seen_offers.len(), seen_at.len());
    let known: std::collections::HashSet<[u8; 16]> = seen_at.iter().map(|(id, _)| *id).collect();
    for o in seen_offers.iter() {
        if !known.contains(&o.id) {
            seen_at.push((o.id, now));
        }
    }
    let fresh: std::collections::HashSet<[u8; 16]> = seen_at
        .iter()
        .filter(|(_, t)| now.saturating_sub(*t) < SEEN_OFFER_TTL_SECS)
        .map(|(id, _)| *id)
        .collect();
    seen_offers.retain(|o| fresh.contains(&o.id));
    seen_at.retain(|(id, _)| fresh.contains(id));
    (seen_offers.len(), seen_at.len()) != before
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Lower bound (floor) on a claim/refund transaction fee, in sats. The actual fee is the greater
    /// of this and the live fee-rate estimate applied to the transaction's real vsize (F6); the floor
    /// is min-relay-safe so a spend still confirms when the mempool is empty.
    pub min_spend_fee: Amount,
    /// Fee rate (sat/vB) for the funding (lock) transaction, passed to walletcreatefundedpsbt. The
    /// claim/refund spends do NOT use this; they fee from the live estimate (see `min_spend_fee`).
    pub fee_rate_sat_vb: u64,
    pub policy: Policy,
    /// Optional operator-owned payout address per chain, where this node's claimed proceeds and its
    /// own refunds on that chain are sent instead of a fresh address from the node's hot wallet
    /// (finding F5, design 0014). `None` keeps today's behaviour (the node wallet). The
    /// network-checked parse happens at `start()` via the chain's node, mirroring the fee address, so
    /// a wrong-network or malformed address fails the swap start loudly rather than paying into the
    /// void. Kept per chain because the two chains share Bitcoin's address format.
    pub btc_payout: Option<String>,
    pub xbtc_payout: Option<String>,
}

/// What a swap needs besides its state: where our coins go, and our lock once signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub swap: Swap,
    pub claim_to: ScriptBuf,
    pub refund_to: ScriptBuf,
    /// Our signed lock, stored before its first broadcast so a restart sends the same one again.
    pub funding: Option<Transaction>,
    /// E2 (design 0017): the unsigned funding PSBT parked while the user signs it in their own wallet,
    /// set when funding returned `AwaitingSignature` and cleared when `submit_signed_lock` broadcasts
    /// the signed tx. A swap is either awaiting a signature or already funded, never both. Absent in
    /// older records, hence `serde(default)`.
    #[serde(default)]
    pub pending_lock_psbt: Option<String>,
    /// The voluntary fee output's share and proof, stored with the lock so a restart resends the
    /// same proof to the counterparty (design 0010). `None` when no fee is due. Absent in older
    /// records, hence `serde(default)`.
    #[serde(default)]
    pub fee: Option<FeeProof>,
    /// The counterparty's fee proof, received over the swap channel, used to verify their lock's
    /// fee output (design 0010). Absent until it arrives, hence `serde(default)`.
    #[serde(default)]
    pub received_fee: Option<FeeProof>,
    /// The fee (sats) chosen for this swap's claim or refund spend, stored so every rebroadcast
    /// rebuilds the identical transaction (F6). Set on the first spend from the live rate; a later
    /// tick may raise it, never lower it, so any replacement only bumps the fee and stays within RBF
    /// rules. Absent in older records, hence `serde(default)`.
    #[serde(default)]
    pub spend_fee_sat: Option<u64>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    next_index: u32,
    own_offers: Vec<Offer>,
    seen_offers: Vec<Offer>,
    /// When each discovered offer was last seen (unix secs), by offer id, so a stale or withdrawn
    /// offer ages out of discovery (#88/#70/#65). Absent in older state files, hence `serde(default)`;
    /// a legacy `seen_offers` entry without a timestamp is stamped at load. Carries the market-table
    /// time column too.
    #[serde(default)]
    seen_at: Vec<([u8; 16], u64)>,
    /// Bids we sent and wait to see accepted: swap id to (offer, maker part, key index).
    bids: Vec<([u8; 16], Offer, Amount, u32)>,
    /// Ids of offers a maker has withdrawn. Kept so a relay that replays the original offer event
    /// after the withdrawal does not re-add it to `seen_offers`. Absent in older state files, hence
    /// `serde(default)`.
    #[serde(default)]
    withdrawn: Vec<[u8; 16]>,
}

#[derive(Debug)]
pub enum EngineError {
    Bid(BidError),
    Policy(PolicyError),
    Node(NodeError),
    Io(std::io::Error),
    NoSuchSwap,
    /// Abort was asked for a swap that has already funded its lock; it can only time out to a refund.
    AlreadyFunded,
    /// Withdraw was asked for an offer id that is not among our own offers: either never ours or
    /// already withdrawn/filled. `own_offers` holds only our own offers, so a peer's offer can never
    /// be withdrawn here. Report it instead of returning a misleading success (#78).
    NotYourOffer,
    /// A signed funding PSBT was submitted for a swap that can no longer safely broadcast its lock:
    /// it has abandoned (e.g. the counterparty's lock window ran out while we waited for the user's
    /// signature) or already settled. Broadcasting now would strand the funds in an HTLC the engine
    /// no longer drives to a refund, so the late submission is refused rather than honoured.
    NoLongerFundable,
}

impl From<NodeError> for EngineError {
    fn from(e: NodeError) -> EngineError {
        EngineError::Node(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> EngineError {
        EngineError::Io(e)
    }
}

pub struct Engine<T: Transport> {
    dir: PathBuf,
    keys: Keys,
    nodes: HashMap<Chain, ChainNode>,
    /// Optional per-chain read/broadcast backend override (E1, design 0016): when set for a chain,
    /// `backend()` reads chain data and broadcasts through it (an Electrum server) instead of the
    /// funding node's RPC. Funding and signing still use the `ChainNode` in `nodes`. Empty by
    /// default, so without configuration the engine behaves exactly as before.
    read: HashMap<Chain, Box<dyn ChainBackend + Send + Sync>>,
    transport: T,
    config: Config,
    /// Smallest swap leg either side will bid or accept, in sats. Defaults to
    /// [`crate::swap::MIN_SWAP_AMOUNT`] and is lowered only by a deployment that wants to offer a
    /// small real-rate leg. Threaded into the bid validation ([`Offer::taker_part_min`]); a safety
    /// floor on the setting (see `daemon::types::MIN_SWAP_FLOOR_SAT`) keeps the leg spendable after
    /// the spend fee.
    min_swap_sat: u64,
    /// Smallest trade the voluntary-fee path acts on, in sats. Defaults to [`crate::fee::MIN_TRADE_SAT`]
    /// and is lowered only by a deployment that wants the fee to apply to a small (real-rate dust)
    /// leg. Threaded into both fee paths (funding and verify) so a funder and its counterparty agree.
    /// The fee floor ([`crate::fee::FLOOR_SAT`]) is deliberately not configurable: it guards dust.
    min_trade_sat: u64,
    /// Beta safety cap on the real-value (BTC) leg, in sats (#103). Defaults to no cap (`u64::MAX`);
    /// the daemon sets it from the operator's configured `max_swap_sat`. Enforced locally at bid time
    /// (and at offer creation in the daemon), never in counterparty verification.
    max_swap_sat: u64,
    state: State,
    records: Vec<Record>,
    /// Tests only: drop this many broadcasts instead of sending them.
    pub drop_broadcasts: u32,
    /// Tests only: lock this amount instead of the agreed one, as a cheating counterparty would.
    pub lock_amount_override: Option<Amount>,
}

impl<T: Transport> Engine<T> {
    /// Opens the engine stored in `dir`, or starts a new one there.
    pub fn open(
        dir: &Path,
        btc: ChainNode,
        xbtc: ChainNode,
        transport: T,
        config: Config,
    ) -> Result<Self, EngineError> {
        std::fs::create_dir_all(dir.join("swaps"))?;
        let state: State = match std::fs::read(dir.join("engine.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        let mut records = Vec::new();
        for entry in std::fs::read_dir(dir.join("swaps"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                records.push(
                    serde_json::from_slice(&std::fs::read(&path)?)
                        .map_err(std::io::Error::other)?,
                );
            }
        }
        let mut engine = Engine {
            dir: dir.to_owned(),
            keys: Keys::open(dir)?,
            nodes: HashMap::from([(Chain::Btc, btc), (Chain::Xbtc, xbtc)]),
            read: HashMap::new(),
            transport,
            config,
            min_swap_sat: crate::swap::MIN_SWAP_AMOUNT.to_sat(),
            min_trade_sat: crate::fee::MIN_TRADE_SAT,
            max_swap_sat: u64::MAX,
            state,
            records,
            drop_broadcasts: 0,
            lock_amount_override: None,
        };
        engine.reconcile_offers()?;
        engine.prune_stale_offers()?;
        Ok(engine)
    }

    /// On load, drop any own offer a record already covers. A started swap means the offer was taken,
    /// and an atomic offer is then fully consumed, so keeping it would let it be taken again or
    /// re-announced on reconnect from a wallet that might still hold funds.
    fn reconcile_offers(&mut self) -> Result<(), EngineError> {
        let taken: std::collections::HashSet<[u8; 16]> =
            self.records.iter().map(|r| r.swap.offer.id).collect();
        let dropped: Vec<[u8; 16]> = self
            .state
            .own_offers
            .iter()
            .filter(|o| taken.contains(&o.id))
            .map(|o| o.id)
            .collect();
        if dropped.is_empty() {
            return Ok(());
        }
        self.state.own_offers.retain(|o| !taken.contains(&o.id));
        self.save_state()?;
        // Tell peers to drop these too, so a filled offer does not linger in their discovery (#70).
        // The send queues on the transport and goes out once the relay connection is up.
        for offer_id in dropped {
            self.transport.send(&Message::Withdraw { offer_id });
        }
        Ok(())
    }

    /// Overrides the minimum swap leg bids are checked against, replacing the
    /// [`crate::swap::MIN_SWAP_AMOUNT`] default. Call it right after [`Engine::open`], before the
    /// first tick; the daemon sets it from the operator's configured `min_swap_sat`.
    pub fn set_min_swap_sat(&mut self, min_swap_sat: u64) {
        self.min_swap_sat = min_swap_sat;
    }

    /// Sets the beta cap on the BTC leg (#103), replacing the no-cap default. The daemon calls this
    /// right after [`Engine::open`] from the operator's configured `max_swap_sat`.
    pub fn set_max_swap_sat(&mut self, max_swap_sat: u64) {
        self.max_swap_sat = max_swap_sat;
    }

    /// Overrides the minimum trade the fee path acts on, replacing the [`crate::fee::MIN_TRADE_SAT`]
    /// default. Call it right after [`Engine::open`], before the first tick; the daemon sets it from
    /// the operator's configured `min_trade_sat`.
    pub fn set_min_trade_sat(&mut self, min_trade_sat: u64) {
        self.min_trade_sat = min_trade_sat;
    }

    pub fn swaps(&self) -> impl Iterator<Item = &Swap> {
        self.records.iter().map(|r| &r.swap)
    }

    /// A record-derived ledger for operator reporting (#67): one entry per swap, plus totals, built
    /// from local records only (no chain query). The voluntary fee a leg paid is recomputed from the
    /// offer terms exactly as the engine placed it on our lock, so it matches what was spent. Txids
    /// beyond our own lock are on the live per-swap view (`GET /swaps/{id}`). Fees *received* at the
    /// project addresses are deliberately not here: that needs an operator-side watch-only wallet, not
    /// the package (see #67's layer note).
    pub fn history(&self) -> serde_json::Value {
        let chain = |c: Chain| match c {
            Chain::Btc => "btc",
            Chain::Xbtc => "xbtc",
        };
        let mut entries = Vec::with_capacity(self.records.len());
        let (mut done, mut refunded, mut abandoned, mut active) = (0u64, 0u64, 0u64, 0u64);
        let (mut btc_vol, mut xbtc_vol) = (0u64, 0u64);
        let (mut fee_paid_total, mut fee_count) = (0u64, 0u64);
        for r in &self.records {
            let s = &r.swap;
            let own_chain = match s.role {
                Role::Maker => s.offer.maker_chain,
                Role::Taker => s.offer.maker_chain.other(),
            };
            let own_locked = match s.role {
                Role::Maker => s.maker_part,
                Role::Taker => s.taker_part,
            };
            // What we paid the project on our own lock, only if we locked and the offer set a fee
            // address for our chain. Recomputed from the terms with the same function that placed it.
            let fee_paid = if r.funding.is_some() {
                s.offer
                    .fee
                    .as_ref()
                    .filter(|t| t.address(own_chain).is_some())
                    .and_then(|t| {
                        fee::fee_amount_min(
                            FeeRates {
                                maker_bps: t.maker_bps,
                                taker_bps: t.taker_bps,
                            },
                            s.role,
                            own_locked,
                            self.min_trade_sat,
                        )
                        .ok()
                    })
                    .map(|a| a.to_sat())
            } else {
                None
            };
            if let Some(f) = fee_paid {
                fee_paid_total += f;
                fee_count += 1;
            }
            match s.phase {
                Phase::Done => done += 1,
                Phase::Refunded => refunded += 1,
                Phase::Abandoned => abandoned += 1,
                _ => active += 1,
            }
            for (c, amt) in [
                (s.offer.maker_chain, s.maker_part),
                (s.offer.maker_chain.other(), s.taker_part),
            ] {
                match c {
                    Chain::Btc => btc_vol += amt.to_sat(),
                    Chain::Xbtc => xbtc_vol += amt.to_sat(),
                }
            }
            let id: String = s.id.iter().map(|b| format!("{b:02x}")).collect();
            entries.push(serde_json::json!({
                "id": id,
                "role": match s.role { Role::Maker => "maker", Role::Taker => "taker" },
                "phase": format!("{:?}", s.phase).to_lowercase(),
                "maker_chain": chain(s.offer.maker_chain),
                "taker_chain": chain(s.offer.maker_chain.other()),
                "maker_amount_sat": s.maker_part.to_sat(),
                "taker_amount_sat": s.taker_part.to_sat(),
                "rate": s.taker_part.to_sat() as f64 / s.maker_part.to_sat().max(1) as f64,
                "our_lock_txid": r.funding.as_ref().map(|t| t.compute_txid().to_string()),
                "voluntary_fee_paid_sat": fee_paid,
                "started_at": s.started_at,
                "secret_revealed": s.learned_secret.is_some(),
                "active": !matches!(s.phase, Phase::Done | Phase::Refunded | Phase::Abandoned),
            }));
        }
        serde_json::json!({
            "swaps": entries,
            "totals": {
                "count": self.records.len(),
                "done": done,
                "refunded": refunded,
                "abandoned": abandoned,
                "active": active,
                "volume_sat": { "btc": btc_vol, "xbtc": xbtc_vol },
                "voluntary_fee_paid": { "swaps": fee_count, "total_sat": fee_paid_total },
            }
        })
    }

    pub fn seen_offers(&self) -> &[Offer] {
        &self.state.seen_offers
    }

    /// Discovered offers paired with when each was last seen (unix secs), for the market view (#88).
    pub fn seen_offers_with_time(&self) -> Vec<(Offer, Option<u64>)> {
        self.state
            .seen_offers
            .iter()
            .map(|o| {
                let t = self
                    .state
                    .seen_at
                    .iter()
                    .find(|(id, _)| *id == o.id)
                    .map(|(_, t)| *t);
                (o.clone(), t)
            })
            .collect()
    }

    /// Age stale or withdrawn offers out of discovery (#88/#70/#65); persists if anything changed.
    fn prune_stale_offers(&mut self) -> Result<(), EngineError> {
        if prune_seen(
            &mut self.state.seen_offers,
            &mut self.state.seen_at,
            now_unix(),
        ) {
            self.save_state()?;
        }
        Ok(())
    }

    /// Our own live offers (those not yet taken). A filled offer is pruned, so this never advertises
    /// a spent offer.
    pub fn own_offers(&self) -> &[Offer] {
        &self.state.own_offers
    }

    /// Takes one of our offers off the market: drops it locally so `/offers` stops serving it and it
    /// cannot be taken, and broadcasts a `Withdraw` so peers drop it from their seen offers. A no-op
    /// if we do not hold the offer.
    pub fn withdraw(&mut self, offer_id: [u8; 16]) -> Result<(), EngineError> {
        let before = self.state.own_offers.len();
        self.state.own_offers.retain(|o| o.id != offer_id);
        if self.state.own_offers.len() == before {
            // Nothing was removed: the id is not one of our own offers (never ours, or already
            // withdrawn/filled). Report it rather than reporting a no-op as success (#78).
            return Err(EngineError::NotYourOffer);
        }
        self.save_state()?;
        self.transport.send(&Message::Withdraw { offer_id });
        Ok(())
    }

    /// Operator teardown of a swap that has not locked yet: mark it `Abandoned` so the engine stops
    /// trying to fund it. Refused once our lock is funded: a locked swap can only reach a timelock
    /// refund, never a forced abandon that would strand the coin. Idempotent on an already-terminal
    /// swap.
    pub fn abort(&mut self, swap_id: [u8; 16]) -> Result<(), EngineError> {
        let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) else {
            return Err(EngineError::NoSuchSwap);
        };
        if self.records[i].funding.is_some() {
            return Err(EngineError::AlreadyFunded);
        }
        if matches!(
            self.records[i].swap.phase,
            Phase::Done | Phase::Refunded | Phase::Abandoned
        ) {
            return Ok(());
        }
        self.records[i].swap.phase = Phase::Abandoned;
        self.save(&self.records[i])?;
        Ok(())
    }

    /// Resume a swap parked awaiting the user's funding signature (E2, design 0017): validate the
    /// submitted signed PSBT against the parked unsigned one (it must be the same transaction),
    /// finalize and broadcast it, record the lock, and clear the pending state. The swap proceeds on
    /// the next tick exactly as if the node had signed.
    pub fn submit_signed_lock(
        &mut self,
        swap_id: [u8; 16],
        signed_psbt: &str,
    ) -> Result<(), EngineError> {
        let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) else {
            return Err(EngineError::NoSuchSwap);
        };
        let Some(pending) = self.records[i].pending_lock_psbt.clone() else {
            return Err(EngineError::Node(NodeError::Unexpected(
                "swap is not awaiting a funding signature".into(),
            )));
        };
        // Broadcast the lock only if funding is still the right move, re-decided against a fresh chain
        // view by the same path `tick` uses. A parked swap can stop being fundable between ticks: its
        // phase is still `Locking` but the counterparty's lock window has already run out, so a phase
        // check alone would let a late signature through and commit the user's coin to an HTLC the
        // engine no longer drives to a refund (the #74 lose-both-legs case, and the same class as the
        // maker-`Locking` loaded gun). When funding is no longer decided, clear the pending PSBT so the
        // UI stops asking for a signature on a dead swap, and refuse. The user must also not broadcast
        // the signed PSBT from their own wallet; the engine refusing cannot stop that.
        let view = self.view(&self.records[i])?;
        let secret = (self.records[i].swap.role == Role::Maker)
            .then(|| self.keys.secret(self.records[i].swap.key_index));
        let still_funding = self.records[i]
            .swap
            .decide(&view, secret)
            .iter()
            .any(|a| matches!(a, Action::Fund));
        if !still_funding {
            self.records[i].pending_lock_psbt = None;
            self.save(&self.records[i])?;
            return Err(EngineError::NoLongerFundable);
        }
        let own_chain = match self.records[i].swap.role {
            Role::Maker => self.records[i].swap.offer.maker_chain,
            Role::Taker => self.records[i].swap.offer.maker_chain.other(),
        };
        let (contract, amount) = match self.records[i].swap.role {
            Role::Maker => (
                self.records[i].swap.maker_contract.clone(),
                self.records[i].swap.maker_part,
            ),
            Role::Taker => (
                self.records[i].swap.taker_contract.clone(),
                self.records[i].swap.taker_part,
            ),
        };
        let tx = self.nodes[&own_chain].finalize_submitted_lock(
            &pending,
            signed_psbt,
            &contract,
            amount,
        )?;
        self.backend(own_chain).broadcast(&tx)?;
        self.records[i].funding = Some(tx);
        self.records[i].pending_lock_psbt = None;
        self.save(&self.records[i])?;
        Ok(())
    }

    /// The unsigned funding PSBT a swap is parked on, for the user to sign (E2, design 0017); `None`
    /// when the swap is not awaiting a funding signature.
    pub fn pending_lock_psbt(&self, id: [u8; 16]) -> Option<String> {
        self.records
            .iter()
            .find(|r| r.swap.id == id)?
            .pending_lock_psbt
            .clone()
    }

    pub fn node(&self, chain: Chain) -> &ChainNode {
        &self.nodes[&chain]
    }

    /// The chain's read/broadcast backend: a configured Electrum override (E1) if present, else the
    /// funding node. Funding and signing still need the concrete [`ChainNode`] (via `self.nodes`), so
    /// those call sites keep it; the data and broadcast ones go through the trait (design 0014/0016).
    fn backend(&self, chain: Chain) -> &dyn ChainBackend {
        if let Some(b) = self.read.get(&chain) {
            b.as_ref()
        } else {
            &self.nodes[&chain]
        }
    }

    /// Point `chain`'s chain-data reads and broadcasts at an Electrum server instead of the funding
    /// node's RPC (E1, design 0016). Funding and signing still use the node. Call right after
    /// [`Engine::open`]; the daemon sets it from the operator's configured Electrum endpoint.
    pub fn set_read_backend(&mut self, chain: Chain, backend: Box<dyn ChainBackend + Send + Sync>) {
        self.read.insert(chain, backend);
    }

    fn save_state(&self) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        Ok(write_atomic(&self.dir.join("engine.json"), &bytes)?)
    }

    fn save(&self, record: &Record) -> Result<(), EngineError> {
        let name = format!(
            "{}.json",
            bitcoin::hex::DisplayHex::to_lower_hex_string(&record.swap.id[..])
        );
        let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
        Ok(write_atomic(&self.dir.join("swaps").join(name), &bytes)?)
    }

    fn take_index(&mut self) -> u32 {
        self.state.next_index += 1;
        self.state.next_index - 1
    }

    pub fn publish(&mut self, offer: Offer) -> Result<(), EngineError> {
        self.config
            .policy
            .depths(&offer, offer.maker_amount, offer.taker_amount)
            .map_err(EngineError::Policy)?;
        self.state.own_offers.push(offer.clone());
        self.save_state()?;
        self.transport.send(&Message::Offer(offer));
        Ok(())
    }

    /// Bids for `maker_part` of a seen offer.
    pub fn bid(
        &mut self,
        offer: &Offer,
        maker_part: Amount,
        swap_id: [u8; 16],
    ) -> Result<(), EngineError> {
        if self.state.own_offers.iter().any(|o| o.id == offer.id) {
            return Err(EngineError::Bid(BidError::OwnOffer));
        }
        let taker_part = offer
            .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
            .map_err(EngineError::Bid)?;
        // #103 beta cap: refuse to take a swap whose real-value (BTC) leg exceeds the local cap. The
        // BTC leg is `maker_part` when the maker sells BTC, else what we (the taker) pay in BTC.
        let btc_leg = if offer.maker_chain == Chain::Btc {
            maker_part
        } else {
            taker_part
        };
        if btc_leg.to_sat() > self.max_swap_sat {
            return Err(EngineError::Bid(BidError::AboveMax));
        }
        // F3 local band: refuse to take if our own voluntary fee would be a disproportionate fraction
        // of our leg. Local only (never the counterparty's fee verification), so an old and a new peer
        // never disagree over the offer.
        if let Some(terms) = &offer.fee {
            let taker_chain = offer.maker_chain.other();
            if terms.address(taker_chain).is_some() {
                let rates = FeeRates {
                    maker_bps: terms.maker_bps,
                    taker_bps: terms.taker_bps,
                };
                if let Ok(fee) =
                    fee::fee_amount_min(rates, Role::Taker, taker_part, self.min_trade_sat)
                {
                    if fee::fee_exceeds_band(fee, taker_part) {
                        return Err(EngineError::Bid(BidError::FeeTooHigh));
                    }
                }
            }
        }
        self.config
            .policy
            .depths(offer, maker_part, taker_part)
            .map_err(EngineError::Policy)?;
        let index = self.take_index();
        self.state
            .bids
            .push((swap_id, offer.clone(), maker_part, index));
        self.save_state()?;
        self.transport.send(&Message::Bid {
            offer_id: offer.id,
            swap_id,
            maker_part,
            taker_claim_pkh: self.keys.pkh(index, Use::Claim),
            taker_refund_pkh: self.keys.pkh(index, Use::Refund),
        });
        Ok(())
    }

    fn handle(&mut self, message: Message) -> Result<(), EngineError> {
        match message {
            Message::Offer(offer) => {
                // A replay of an offer the maker has since withdrawn must not reappear.
                if self.state.withdrawn.contains(&offer.id) {
                    return Ok(());
                }
                // Refresh the seen-at on every sighting, so a live, re-announced offer stays fresh
                // and a dead one ages out at its TTL (#88/#70).
                let now = now_unix();
                match self
                    .state
                    .seen_at
                    .iter_mut()
                    .find(|(id, _)| *id == offer.id)
                {
                    Some(e) => e.1 = now,
                    None => self.state.seen_at.push((offer.id, now)),
                }
                if !self.state.seen_offers.contains(&offer) {
                    self.state.seen_offers.push(offer);
                }
                self.save_state()?;
            }
            Message::Withdraw { offer_id } => {
                let before = self.state.seen_offers.len();
                self.state.seen_offers.retain(|o| o.id != offer_id);
                self.state.seen_at.retain(|(id, _)| *id != offer_id);
                let newly = !self.state.withdrawn.contains(&offer_id);
                if newly {
                    self.state.withdrawn.push(offer_id);
                }
                if newly || self.state.seen_offers.len() != before {
                    self.save_state()?;
                }
            }
            Message::Bid {
                offer_id,
                swap_id,
                maker_part,
                taker_claim_pkh,
                taker_refund_pkh,
            } => {
                let Some(offer) = self
                    .state
                    .own_offers
                    .iter()
                    .find(|o| o.id == offer_id)
                    .cloned()
                else {
                    eprintln!(
                        "bid dropped: no own offer {} (withdrawn or never ours)",
                        short_id(&offer_id)
                    );
                    return Ok(());
                };
                if self.records.iter().any(|r| r.swap.id == swap_id) {
                    return Ok(());
                }
                // A bid the maker cannot honour was silently dropped, so an operator could not tell a
                // below-minimum (or above-offer) bid from a lost message (F4). Log the reason.
                let taker_part = match offer
                    .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
                {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!(
                            "bid dropped for offer {}: amount {} sat rejected ({e:?}); min_swap_sat {}",
                            short_id(&offer_id),
                            maker_part.to_sat(),
                            self.min_swap_sat
                        );
                        return Ok(());
                    }
                };
                let depths = match self.config.policy.depths(&offer, maker_part, taker_part) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!(
                            "bid dropped for offer {}: policy rejected ({e:?})",
                            short_id(&offer_id)
                        );
                        return Ok(());
                    }
                };
                let index = self.take_index();
                let secret_hash =
                    bitcoin::hashes::sha256::Hash::hash(&self.keys.secret(index)).to_byte_array();
                let swap = Swap {
                    id: swap_id,
                    role: Role::Maker,
                    key_index: index,
                    maker_part,
                    taker_part,
                    maker_contract: Contract {
                        secret_hash,
                        claim_pkh: taker_claim_pkh,
                        refund_pkh: self.keys.pkh(index, Use::Refund),
                        lock_blocks: offer.maker_lock_blocks,
                    },
                    taker_contract: Contract {
                        secret_hash,
                        claim_pkh: self.keys.pkh(index, Use::Claim),
                        refund_pkh: taker_refund_pkh,
                        lock_blocks: offer.taker_lock_blocks,
                    },
                    depths,
                    // The same reference the taker computes, so the maker gives up (in
                    // `decide_maker`) strictly before the taker abandons, and never funds a lock
                    // against a swap the taker has already walked away from.
                    lock_deadline: self.backend(offer.maker_chain).height()?
                        + depths.maker_lock
                        + LOCK_WAIT_BLOCKS,
                    learned_secret: None,
                    phase: Phase::Locking,
                    started_at: Some(now_unix()),
                    offer,
                };
                self.start(swap)?;
                // The offer is atomic, so this bid consumes it: drop it so it cannot be taken again,
                // and tell peers to drop it from discovery too.
                self.state.own_offers.retain(|o| o.id != offer_id);
                self.save_state()?;
                self.transport.send(&Message::Withdraw { offer_id });
                let swap = &self.records.last().expect("just started").swap;
                self.transport.send(&Message::Accept {
                    swap_id,
                    secret_hash,
                    maker_claim_pkh: swap.taker_contract.claim_pkh,
                    maker_refund_pkh: swap.maker_contract.refund_pkh,
                });
            }
            Message::Accept {
                swap_id,
                secret_hash,
                maker_claim_pkh,
                maker_refund_pkh,
            } => {
                let Some(pos) = self.state.bids.iter().position(|b| b.0 == swap_id) else {
                    return Ok(());
                };
                let (_, offer, maker_part, index) = self.state.bids[pos].clone();
                let taker_part = offer
                    .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
                    .map_err(EngineError::Bid)?;
                let depths = self
                    .config
                    .policy
                    .depths(&offer, maker_part, taker_part)
                    .map_err(EngineError::Policy)?;
                let swap = Swap {
                    id: swap_id,
                    role: Role::Taker,
                    key_index: index,
                    maker_part,
                    taker_part,
                    maker_contract: Contract {
                        secret_hash,
                        claim_pkh: self.keys.pkh(index, Use::Claim),
                        refund_pkh: maker_refund_pkh,
                        lock_blocks: offer.maker_lock_blocks,
                    },
                    taker_contract: Contract {
                        secret_hash,
                        claim_pkh: maker_claim_pkh,
                        refund_pkh: self.keys.pkh(index, Use::Refund),
                        lock_blocks: offer.taker_lock_blocks,
                    },
                    depths,
                    lock_deadline: self.backend(offer.maker_chain).height()?
                        + depths.maker_lock
                        + LOCK_WAIT_BLOCKS,
                    learned_secret: None,
                    phase: Phase::Waiting,
                    started_at: Some(now_unix()),
                    offer,
                };
                self.state.bids.remove(pos);
                self.start(swap)?;
            }
            Message::FeeProof { swap_id, proof } => {
                // Store the counterparty's fee proof so `view` can verify their lock's fee output
                // (design 0010). Keep the first one; a resend of a different proof is ignored.
                if let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) {
                    if self.records[i].received_fee.is_none() {
                        self.records[i].received_fee = Some(proof);
                        self.save(&self.records[i])?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Watches both contracts, picks destinations, stores the swap, then keeps the bookkeeping.
    /// Where our coin lands on `chain`: the operator's configured payout address if set (F5), else a
    /// fresh address from the node's own wallet (today's default). A configured address is
    /// network-checked by the node, so a misconfigured one fails the swap start rather than paying
    /// into the void.
    fn destination(&self, chain: Chain) -> Result<ScriptBuf, EngineError> {
        let configured = match chain {
            Chain::Btc => self.config.btc_payout.as_deref(),
            Chain::Xbtc => self.config.xbtc_payout.as_deref(),
        };
        match configured {
            Some(addr) => Ok(self.nodes[&chain].script_for(addr)?),
            None => Ok(self.nodes[&chain].new_destination()?),
        }
    }

    fn start(&mut self, swap: Swap) -> Result<(), EngineError> {
        let maker_chain = swap.offer.maker_chain;
        let (claim_chain, refund_chain) = match swap.role {
            Role::Maker => (maker_chain.other(), maker_chain),
            Role::Taker => (maker_chain, maker_chain.other()),
        };
        self.backend(maker_chain)
            .watch_contract(&swap.maker_contract)?;
        self.backend(maker_chain.other())
            .watch_contract(&swap.taker_contract)?;
        let record = Record {
            claim_to: self.destination(claim_chain)?,
            refund_to: self.destination(refund_chain)?,
            funding: None,
            pending_lock_psbt: None,
            fee: None,
            received_fee: None,
            spend_fee_sat: None,
            swap,
        };
        let id: String = record.swap.id.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "swap {id} ({:?}) started: maker {}, taker {}, phase {:?}",
            record.swap.role, record.swap.maker_part, record.swap.taker_part, record.swap.phase
        );
        self.save(&record)?;
        self.records.push(record);
        self.save_state()
    }

    /// The live on-chain view of swap `id` (both locks' txids, confirmations and heights), or `None`
    /// if there is no such swap. Queries the nodes, so a caller asks for it on demand, not every tick.
    pub fn chain_view(&self, id: [u8; 16]) -> Option<Result<ChainView, EngineError>> {
        self.records
            .iter()
            .find(|r| r.swap.id == id)
            .map(|r| self.view(r))
    }

    fn view(&self, record: &Record) -> Result<ChainView, EngineError> {
        let swap = &record.swap;
        let (a, b) = (
            self.backend(swap.offer.maker_chain),
            self.backend(swap.offer.maker_chain.other()),
        );
        let ours = [record.claim_to.clone(), record.refund_to.clone()];
        let mut maker_lock = a.lock_view(&swap.maker_contract, swap.maker_part, &ours)?;
        let mut taker_lock = b.lock_view(&swap.taker_contract, swap.taker_part, &ours)?;
        // Set the counterparty lock's voluntary-fee state (design 0010). The maker's counterparty is
        // the taker (taker_lock, on the other chain) and the reverse for the taker; our own lock's
        // fee is never checked.
        match swap.role {
            Role::Maker => {
                if let Some(lock) = taker_lock.as_mut() {
                    lock.fee = self.fee_state(record, lock.outpoint.txid, b);
                }
            }
            Role::Taker => {
                if let Some(lock) = maker_lock.as_mut() {
                    lock.fee = self.fee_state(record, lock.outpoint.txid, a);
                }
            }
        }
        Ok(ChainView {
            maker_chain_height: a.height()?,
            taker_chain_height: b.height()?,
            maker_lock,
            taker_lock,
            own_funded: record.funding.is_some(),
        })
    }

    /// The fee state of the counterparty's lock `lock_txid` on `cp_chain` (design 0010, 0013): no fee
    /// set for the counterparty's chain is `NotRequired`; the lock not readable (or, for a silent
    /// payment fee, no proof yet) is `Pending`; a fee output of at least the required amount, paying
    /// the agreed address (directly for a normal address, or by the DLEQ proof for a silent payment),
    /// is `Verified`; anything else is `Failed`.
    fn fee_state(&self, record: &Record, lock_txid: Txid, cp_chain: &dyn ChainBackend) -> FeeState {
        let swap = &record.swap;
        let Some(terms) = &swap.offer.fee else {
            return FeeState::NotRequired;
        };
        // The counterparty pays its fee on the chain it locks (design 0013). If the offer sets no fee
        // address for that chain, the counterparty owes no fee output and there is nothing to check.
        let cp_chain_id = match swap.role {
            Role::Maker => swap.offer.maker_chain.other(),
            Role::Taker => swap.offer.maker_chain,
        };
        let Some(fee_address) = terms.address(cp_chain_id) else {
            return FeeState::NotRequired;
        };
        let dest = match FeeDest::parse(fee_address, cp_chain.network()) {
            Ok(dest) => dest,
            Err(_) => return FeeState::Failed, // a malformed or wrong-network fee address
        };
        let cp_role = swap.role.other();
        let cp_locked = match cp_role {
            Role::Maker => swap.maker_part,
            Role::Taker => swap.taker_part,
        };
        let rates = FeeRates {
            maker_bps: terms.maker_bps,
            taker_bps: terms.taker_bps,
        };
        // A counterparty leg below the minimum trade owes no fee output, so there is nothing to verify
        // (design 0013 / fee.rs). This matches the payer's fund path, which also emits no fee output
        // for such a leg (#107); treating it as Failed broke the swap end to end.
        let Some(required) = fee_amount_or_none(rates, cp_role, cp_locked, self.min_trade_sat)
        else {
            return FeeState::NotRequired;
        };
        let Ok(lock_tx) = cp_chain.get_tx(lock_txid) else {
            return FeeState::Pending; // not on chain yet, or not readable: wait
        };
        match dest {
            // A normal address is verified directly: the lock must carry an output paying it at least
            // the required amount. No proof is involved (design 0013).
            FeeDest::Normal(addr) => {
                let spk = addr.script_pubkey();
                if lock_tx
                    .output
                    .iter()
                    .any(|o| o.script_pubkey == spk && o.value >= required)
                {
                    FeeState::Verified
                } else {
                    FeeState::Failed
                }
            }
            // A silent payment output is unlinkable, so the payer reveals a DLEQ share and proof the
            // counterparty authenticates against the lock's inputs (design 0010).
            FeeDest::SilentPayment(recipient) => {
                let Some(proof) = &record.received_fee else {
                    return FeeState::Pending;
                };
                let Ok(proof_bytes) = <[u8; 64]>::try_from(proof.proof.as_slice()) else {
                    return FeeState::Failed;
                };
                // Authenticate each input's public key from the proof's prevout transactions.
                let mut pubkeys = Vec::new();
                let mut outpoints = Vec::new();
                for input in &lock_tx.input {
                    outpoints.push(input.previous_output);
                    let Some(prevout) = proof
                        .prevouts
                        .iter()
                        .find(|t| t.compute_txid() == input.previous_output.txid)
                    else {
                        return FeeState::Failed;
                    };
                    let Some(txout) = prevout.output.get(input.previous_output.vout as usize)
                    else {
                        return FeeState::Failed;
                    };
                    if let Some(pk) = silentpayments::input_pubkey(
                        &txout.script_pubkey,
                        &input.script_sig,
                        &input.witness,
                    ) {
                        pubkeys.push(pk);
                    }
                }
                let share = proof.share.serialize();
                if silentpayments::verify_fee(
                    self.keys.secp(),
                    &pubkeys,
                    &outpoints,
                    &recipient,
                    &share,
                    &proof_bytes,
                    &lock_tx.output,
                    required,
                ) {
                    FeeState::Verified
                } else {
                    FeeState::Failed
                }
            }
        }
    }

    /// One round: messages in, then every unfinished swap decided, stored and acted on. Errors of a
    /// single swap are returned and do not stop the others.
    pub fn tick(&mut self) -> Vec<([u8; 16], EngineError)> {
        let mut errors = Vec::new();
        for message in self.transport.receive() {
            if let Err(e) = self.handle(message) {
                errors.push(([0; 16], e));
            }
        }
        if let Err(e) = self.prune_stale_offers() {
            errors.push(([0; 16], e));
        }
        for i in 0..self.records.len() {
            if matches!(
                self.records[i].swap.phase,
                Phase::Done | Phase::Refunded | Phase::Abandoned
            ) {
                continue;
            }
            let before = self.records[i].swap.phase;
            if let Err(e) = self.advance(i) {
                errors.push((self.records[i].swap.id, e));
            }
            // Log every phase transition so an operator can follow a swap in `package logs`, not only
            // in the web UI: the engine store and the API remain the record of truth, this is the
            // monitoring trail. No secrets are logged, only the swap id, role, and phase.
            let after = self.records[i].swap.phase;
            if after != before {
                let swap = &self.records[i].swap;
                let id: String = swap.id.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("swap {id} ({:?}): {before:?} -> {after:?}", swap.role);
            }
        }
        errors
    }

    fn advance(&mut self, i: usize) -> Result<(), EngineError> {
        let view = self.view(&self.records[i])?;
        // Re-send our fee proof each tick while the swap is live (design 0010); the relay may drop
        // it, and the counterparty needs it to verify our lock. Receiving it twice is harmless.
        if let Some(proof) = self.records[i].fee.clone() {
            self.transport.send(&Message::FeeProof {
                swap_id: self.records[i].swap.id,
                proof,
            });
        }
        let secret = (self.records[i].swap.role == Role::Maker)
            .then(|| self.keys.secret(self.records[i].swap.key_index));
        let actions = self.records[i].swap.decide(&view, secret);
        // A swap parked on an unsigned funding PSBT that has now reached a terminal phase (it abandoned
        // while waiting for the user's signature) must drop the pending PSBT, so the UI stops asking
        // the user to sign a dead swap and submit_signed_lock's refusal is consistent with the store.
        if self.records[i].pending_lock_psbt.is_some()
            && matches!(
                self.records[i].swap.phase,
                Phase::Abandoned | Phase::Done | Phase::Refunded
            )
        {
            self.records[i].pending_lock_psbt = None;
        }
        self.save(&self.records[i])?;
        for action in actions {
            self.act(i, action)?;
        }
        Ok(())
    }

    /// Fee a claim or refund by the chain's live estimate (or the conservative fallback when it cannot
    /// estimate), never below the configured floor and never below any fee already chosen for this
    /// spend, so a rebuild only ever replaces upward and stays within RBF rules (F6).
    fn rate_spend(
        &self,
        chain: Chain,
        prior: Option<u64>,
        build: impl Fn(Amount) -> Result<Transaction, crate::htlc::SpendError>,
    ) -> Result<(Transaction, Amount), crate::htlc::SpendError> {
        let rate = self
            .backend(chain)
            .estimate_fee_sat_vb(SPEND_CONF_TARGET)
            .unwrap_or(FALLBACK_SPEND_RATE_SAT_VB);
        crate::htlc::spend_at_rate(
            build,
            rate,
            self.config.min_spend_fee,
            prior.map(Amount::from_sat),
        )
    }

    fn act(&mut self, i: usize, action: Action) -> Result<(), EngineError> {
        let record = self.records[i].clone();
        let swap = &record.swap;
        let (own_chain, own_contract, own_amount, other_contract, other_amount) = match swap.role {
            Role::Maker => (
                swap.offer.maker_chain,
                &swap.maker_contract,
                swap.maker_part,
                &swap.taker_contract,
                swap.taker_part,
            ),
            Role::Taker => (
                swap.offer.maker_chain.other(),
                &swap.taker_contract,
                swap.taker_part,
                &swap.maker_contract,
                swap.maker_part,
            ),
        };
        let (chain, tx, spend_fee) = match action {
            Action::Fund => match record.funding {
                Some(tx) => (own_chain, tx, None),
                None => {
                    // E2 (0017): parked awaiting the user's funding signature? Do nothing until they
                    // submit it via submit_signed_lock. Never rebuild a parked lock: a fresh
                    // walletcreatefundedpsbt could pick different inputs and strand the signature.
                    if record.pending_lock_psbt.is_some() {
                        return Ok(());
                    }
                    let other = &self.nodes[&own_chain.other()].rpc;
                    let lock_amount = self.lock_amount_override.unwrap_or(own_amount);
                    // The voluntary fee (design 0010, 0013): terms come from the offer, the address
                    // for the chain we lock, the amount from our role and what we lock. If the offer
                    // sets no fee address for our chain, we lock without a fee output. A leg below the
                    // minimum trade owes no fee (design 0013 / fee.rs semantics), so BelowMinimum means
                    // "no fee output" here too, not a failure: treating it as a failure stranded the
                    // first locker's coin for any leg in [min_swap, min_trade) with a fee address (#107).
                    // The counterparty's fee verification reaches the same conclusion (NotRequired).
                    let fee = match swap
                        .offer
                        .fee
                        .as_ref()
                        .and_then(|terms| terms.address(own_chain).map(|a| (terms, a)))
                    {
                        None => None,
                        Some((terms, fee_address)) => {
                            let dest =
                                FeeDest::parse(fee_address, self.nodes[&own_chain].network())?;
                            let rates = FeeRates {
                                maker_bps: terms.maker_bps,
                                taker_bps: terms.taker_bps,
                            };
                            fee_amount_or_none(rates, swap.role, lock_amount, self.min_trade_sat)
                                .map(|amount| (amount, dest))
                        }
                    };
                    match self.nodes[&own_chain].fund(
                        own_contract,
                        lock_amount,
                        self.config.fee_rate_sat_vb,
                        self.config.policy.funding_minconf(own_chain),
                        other,
                        fee.as_ref().map(|(a, dest)| (*a, dest)),
                    ) {
                        Ok((tx, fee_proof)) => {
                            self.records[i].funding = Some(tx.clone());
                            self.records[i].fee = fee_proof;
                            self.save(&self.records[i])?;
                            (own_chain, tx, None)
                        }
                        // E2 (0017): the user signs out of band. Park the unsigned PSBT (it has
                        // already passed the replay guard) and wait for submit_signed_lock; do not
                        // broadcast anything now.
                        Err(NodeError::AwaitingSignature { psbt }) => {
                            self.records[i].pending_lock_psbt = Some(psbt);
                            self.save(&self.records[i])?;
                            return Ok(());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            },
            Action::Claim { lock, preimage } => {
                let spend_chain = own_chain.other();
                let key = self.keys.key(swap.key_index, Use::Claim);
                let secp = self.keys.secp();
                let build = |fee| {
                    let spend = Spend {
                        outpoint: lock,
                        value: other_amount,
                        destination: record.claim_to.clone(),
                        fee,
                    };
                    other_contract.claim(secp, &spend, &key, &preimage)
                };
                let (tx, fee) = self
                    .rate_spend(spend_chain, record.spend_fee_sat, build)
                    .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?;
                (spend_chain, tx, Some(fee.to_sat()))
            }
            Action::Refund { lock, value } => {
                let key = self.keys.key(swap.key_index, Use::Refund);
                let secp = self.keys.secp();
                let build = |fee| {
                    let spend = Spend {
                        outpoint: lock,
                        value,
                        destination: record.refund_to.clone(),
                        fee,
                    };
                    own_contract.refund(secp, &spend, &key)
                };
                let (tx, fee) = self
                    .rate_spend(own_chain, record.spend_fee_sat, build)
                    .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?;
                (own_chain, tx, Some(fee.to_sat()))
            }
        };
        if self.drop_broadcasts > 0 {
            self.drop_broadcasts -= 1;
            return Ok(());
        }
        self.backend(chain).broadcast(&tx)?;
        // Persist the chosen claim/refund fee only AFTER the broadcast is accepted (F6), so the stored
        // fee never diverges from the transaction actually in the mempool: a rejected bump leaves the
        // prior fee in place, and the next tick rebuilds the identical, already-accepted transaction.
        if let Some(fee) = spend_fee {
            if self.records[i].spend_fee_sat != Some(fee) {
                self.records[i].spend_fee_sat = Some(fee);
                self.save(&self.records[i])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{fee_amount_or_none, State};
    use crate::fee::FeeRates;
    use crate::swap::Role;
    use bitcoin::Amount;

    #[test]
    fn a_leg_below_the_minimum_trade_owes_no_fee_output_107() {
        let rates = FeeRates {
            maker_bps: 20,
            taker_bps: 30,
        };
        let min_trade = 100_000;
        // Below the minimum trade: no fee output, on either role. Before #107 this returned an error
        // that the fund path turned into a hard failure, stranding the first locker's coin.
        assert_eq!(
            fee_amount_or_none(rates, Role::Maker, Amount::from_sat(50_000), min_trade),
            None
        );
        assert_eq!(
            fee_amount_or_none(rates, Role::Taker, Amount::from_sat(99_999), min_trade),
            None
        );
        // At or above the minimum trade: a fee is owed (floored), so an output is required.
        assert!(
            fee_amount_or_none(rates, Role::Maker, Amount::from_sat(100_000), min_trade).is_some()
        );
        assert!(
            fee_amount_or_none(rates, Role::Taker, Amount::from_sat(1_000_000), min_trade)
                .is_some()
        );
    }

    #[test]
    fn a_pre_m1_engine_state_still_loads() {
        // An engine.json written before the withdrawn set existed must still deserialize, with the
        // new field defaulting to empty (serde(default)).
        let old = r#"{"next_index":3,"own_offers":[],"seen_offers":[],"bids":[]}"#;
        let state: State = serde_json::from_str(old).unwrap();
        assert_eq!(state.next_index, 3);
        assert!(state.withdrawn.is_empty());
        assert!(
            state.seen_at.is_empty(),
            "seen_at defaults empty on an old state"
        );
    }

    #[test]
    fn prune_seen_ages_out_stale_and_stamps_legacy() {
        use super::{prune_seen, SEEN_OFFER_TTL_SECS};
        use crate::swap::{Chain, Offer};
        use bitcoin::Amount;
        let offer = |n: u8| Offer {
            id: [n; 16],
            maker_chain: Chain::Xbtc,
            maker_amount: Amount::from_sat(1000),
            taker_amount: Amount::from_sat(1000),
            min_maker_amount: Amount::ZERO,
            maker_lock_blocks: 40,
            taker_lock_blocks: 20,
            maker_lock_depth: 2,
            taker_lock_depth: 2,
            margin_blocks: 3,
            fee: None,
        };
        let now = 1_000_000u64;
        let mut seen_offers = vec![offer(1), offer(2), offer(3)];
        let mut seen_at = vec![
            ([1u8; 16], now), // fresh
            ([2u8; 16], now - SEEN_OFFER_TTL_SECS - 1), // stale, must drop
                              // offer(3): no entry = legacy, stamped at now
        ];
        assert!(
            prune_seen(&mut seen_offers, &mut seen_at, now),
            "stale dropped = a change"
        );
        let ids: Vec<[u8; 16]> = seen_offers.iter().map(|o| o.id).collect();
        assert!(ids.contains(&[1u8; 16]) && !ids.contains(&[2u8; 16]) && ids.contains(&[3u8; 16]));
        // The legacy offer now carries a timestamp: a second prune at the same time is a no-op.
        assert!(!prune_seen(&mut seen_offers, &mut seen_at, now));
        // Everything ages out once past the TTL.
        assert!(prune_seen(
            &mut seen_offers,
            &mut seen_at,
            now + SEEN_OFFER_TTL_SECS + 1
        ));
        assert!(seen_offers.is_empty() && seen_at.is_empty());
    }
}

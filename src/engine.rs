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

#[derive(Clone, Debug)]
pub struct Config {
    /// Fee of each claim and refund transaction.
    pub spend_fee: Amount,
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
    /// The voluntary fee output's share and proof, stored with the lock so a restart resends the
    /// same proof to the counterparty (design 0010). `None` when no fee is due. Absent in older
    /// records, hence `serde(default)`.
    #[serde(default)]
    pub fee: Option<FeeProof>,
    /// The counterparty's fee proof, received over the swap channel, used to verify their lock's
    /// fee output (design 0010). Absent until it arrives, hence `serde(default)`.
    #[serde(default)]
    pub received_fee: Option<FeeProof>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    next_index: u32,
    own_offers: Vec<Offer>,
    seen_offers: Vec<Offer>,
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
            transport,
            config,
            min_swap_sat: crate::swap::MIN_SWAP_AMOUNT.to_sat(),
            min_trade_sat: crate::fee::MIN_TRADE_SAT,
            state,
            records,
            drop_broadcasts: 0,
            lock_amount_override: None,
        };
        engine.reconcile_offers()?;
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

    pub fn node(&self, chain: Chain) -> &ChainNode {
        &self.nodes[&chain]
    }

    /// The chain's node as the read/broadcast backend the engine depends on. Funding and signing
    /// still need the concrete [`ChainNode`] (via `self.nodes`), so those call sites keep it; the
    /// data and broadcast ones go through the trait (design 0014).
    fn backend(&self, chain: Chain) -> &dyn ChainBackend {
        &self.nodes[&chain]
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
                if !self.state.seen_offers.contains(&offer) {
                    self.state.seen_offers.push(offer);
                    self.save_state()?;
                }
            }
            Message::Withdraw { offer_id } => {
                let before = self.state.seen_offers.len();
                self.state.seen_offers.retain(|o| o.id != offer_id);
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
                    return Ok(());
                };
                if self.records.iter().any(|r| r.swap.id == swap_id) {
                    return Ok(());
                }
                let Ok(taker_part) =
                    offer.taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
                else {
                    return Ok(());
                };
                let Ok(depths) = self.config.policy.depths(&offer, maker_part, taker_part) else {
                    return Ok(());
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
            fee: None,
            received_fee: None,
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
        let Ok(required) = fee::fee_amount_min(rates, cp_role, cp_locked, self.min_trade_sat)
        else {
            return FeeState::Failed;
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
        self.save(&self.records[i])?;
        for action in actions {
            self.act(i, action)?;
        }
        Ok(())
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
        let (chain, tx) = match action {
            Action::Fund => match record.funding {
                Some(tx) => (own_chain, tx),
                None => {
                    let other = &self.nodes[&own_chain.other()].rpc;
                    let lock_amount = self.lock_amount_override.unwrap_or(own_amount);
                    // The voluntary fee (design 0010, 0013): terms come from the offer, the address
                    // for the chain we lock, the amount from our role and what we lock. If the offer
                    // sets no fee address for our chain, we lock without a fee output. If it sets one
                    // we cannot honour (a bad address, or a trade below the minimum), funding fails
                    // loudly: we never lock without the fee the counterparty will look for.
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
                            let amount = fee::fee_amount_min(
                                rates,
                                swap.role,
                                lock_amount,
                                self.min_trade_sat,
                            )
                            .map_err(|e| NodeError::Unexpected(format!("fee amount: {e:?}")))?;
                            Some((amount, dest))
                        }
                    };
                    let (tx, fee_proof) = self.nodes[&own_chain].fund(
                        own_contract,
                        lock_amount,
                        self.config.fee_rate_sat_vb,
                        self.config.policy.funding_minconf(own_chain),
                        other,
                        fee.as_ref().map(|(a, dest)| (*a, dest)),
                    )?;
                    self.records[i].funding = Some(tx.clone());
                    self.records[i].fee = fee_proof;
                    self.save(&self.records[i])?;
                    (own_chain, tx)
                }
            },
            Action::Claim { lock, preimage } => {
                let spend = Spend {
                    outpoint: lock,
                    value: other_amount,
                    destination: record.claim_to.clone(),
                    fee: self.config.spend_fee,
                };
                let key = self.keys.key(swap.key_index, Use::Claim);
                let tx = other_contract
                    .claim(self.keys.secp(), &spend, &key, &preimage)
                    .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?;
                (own_chain.other(), tx)
            }
            Action::Refund { lock, value } => {
                let spend = Spend {
                    outpoint: lock,
                    value,
                    destination: record.refund_to.clone(),
                    fee: self.config.spend_fee,
                };
                let key = self.keys.key(swap.key_index, Use::Refund);
                let tx = own_contract
                    .refund(self.keys.secp(), &spend, &key)
                    .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?;
                (own_chain, tx)
            }
        };
        if self.drop_broadcasts > 0 {
            self.drop_broadcasts -= 1;
            return Ok(());
        }
        Ok(self.backend(chain).broadcast(&tx)?)
    }
}

#[cfg(test)]
mod tests {
    use super::State;

    #[test]
    fn a_pre_m1_engine_state_still_loads() {
        // An engine.json written before the withdrawn set existed must still deserialize, with the
        // new field defaulting to empty (serde(default)).
        let old = r#"{"next_index":3,"own_offers":[],"seen_offers":[],"bids":[]}"#;
        let state: State = serde_json::from_str(old).unwrap();
        assert_eq!(state.next_index, 3);
        assert!(state.withdrawn.is_empty());
    }
}

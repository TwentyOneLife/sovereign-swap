//! Drives every swap: reads both chains, lets `Swap::decide` choose, stores the result, acts.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, ScriptBuf, Transaction};
use serde::{Deserialize, Serialize};

use crate::htlc::{Contract, Spend};
use crate::keys::{Keys, Use};
use crate::node::{ChainNode, NodeError};
use crate::policy::{Policy, PolicyError};
use crate::store::write_atomic;
use crate::swap::{Action, BidError, Chain, ChainView, Message, Offer, Phase, Role, Swap};
use crate::transport::Transport;

/// Maker-chain blocks a taker waits, beyond the required depth, for the maker's lock before giving up.
const LOCK_WAIT_BLOCKS: u32 = 10;

#[derive(Clone, Debug)]
pub struct Config {
    /// Fee of each claim and refund transaction.
    pub spend_fee: Amount,
    pub fee_rate_sat_vb: u64,
    pub policy: Policy,
}

/// What a swap needs besides its state: where our coins go, and our lock once signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub swap: Swap,
    pub claim_to: ScriptBuf,
    pub refund_to: ScriptBuf,
    /// Our signed lock, stored before its first broadcast so a restart sends the same one again.
    pub funding: Option<Transaction>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    next_index: u32,
    own_offers: Vec<Offer>,
    seen_offers: Vec<Offer>,
    /// Bids we sent and wait to see accepted: swap id to (offer, maker part, key index).
    bids: Vec<([u8; 16], Offer, Amount, u32)>,
}

#[derive(Debug)]
pub enum EngineError {
    Bid(BidError),
    Policy(PolicyError),
    Node(NodeError),
    Io(std::io::Error),
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
        let state = match std::fs::read(dir.join("engine.json")) {
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
        Ok(Engine {
            dir: dir.to_owned(),
            keys: Keys::open(dir)?,
            nodes: HashMap::from([(Chain::Btc, btc), (Chain::Xbtc, xbtc)]),
            transport,
            config,
            state,
            records,
            drop_broadcasts: 0,
            lock_amount_override: None,
        })
    }

    pub fn swaps(&self) -> impl Iterator<Item = &Swap> {
        self.records.iter().map(|r| &r.swap)
    }

    pub fn seen_offers(&self) -> &[Offer] {
        &self.state.seen_offers
    }

    pub fn node(&self, chain: Chain) -> &ChainNode {
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
        let taker_part = offer.taker_part(maker_part).map_err(EngineError::Bid)?;
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
                if !self.state.seen_offers.contains(&offer) {
                    self.state.seen_offers.push(offer);
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
                let Ok(taker_part) = offer.taker_part(maker_part) else {
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
                    lock_deadline: 0,
                    learned_secret: None,
                    phase: Phase::Locking,
                    offer,
                };
                self.start(swap)?;
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
                let taker_part = offer.taker_part(maker_part).map_err(EngineError::Bid)?;
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
                    lock_deadline: self.nodes[&offer.maker_chain].height()?
                        + depths.maker_lock
                        + LOCK_WAIT_BLOCKS,
                    learned_secret: None,
                    phase: Phase::Waiting,
                    offer,
                };
                self.state.bids.remove(pos);
                self.start(swap)?;
            }
        }
        Ok(())
    }

    /// Watches both contracts, picks destinations, stores the swap, then keeps the bookkeeping.
    fn start(&mut self, swap: Swap) -> Result<(), EngineError> {
        let maker_chain = swap.offer.maker_chain;
        let (claim_chain, refund_chain) = match swap.role {
            Role::Maker => (maker_chain.other(), maker_chain),
            Role::Taker => (maker_chain, maker_chain.other()),
        };
        self.nodes[&maker_chain].watch_contract(&swap.maker_contract)?;
        self.nodes[&maker_chain.other()].watch_contract(&swap.taker_contract)?;
        let record = Record {
            claim_to: self.nodes[&claim_chain].new_destination()?,
            refund_to: self.nodes[&refund_chain].new_destination()?,
            funding: None,
            swap,
        };
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
            &self.nodes[&swap.offer.maker_chain],
            &self.nodes[&swap.offer.maker_chain.other()],
        );
        let ours = [record.claim_to.clone(), record.refund_to.clone()];
        Ok(ChainView {
            maker_chain_height: a.height()?,
            taker_chain_height: b.height()?,
            maker_lock: a.lock_view(&swap.maker_contract, swap.maker_part, &ours)?,
            taker_lock: b.lock_view(&swap.taker_contract, swap.taker_part, &ours)?,
        })
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
            if let Err(e) = self.advance(i) {
                errors.push((self.records[i].swap.id, e));
            }
        }
        errors
    }

    fn advance(&mut self, i: usize) -> Result<(), EngineError> {
        let view = self.view(&self.records[i])?;
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
                    let tx = self.nodes[&own_chain].fund(
                        own_contract,
                        self.lock_amount_override.unwrap_or(own_amount),
                        self.config.fee_rate_sat_vb,
                        self.config.policy.funding_minconf(own_chain),
                        other,
                    )?;
                    self.records[i].funding = Some(tx.clone());
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
        Ok(self.nodes[&chain].broadcast(&tx)?)
    }
}

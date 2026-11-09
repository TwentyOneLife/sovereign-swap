//! Protocol messages and the per-swap state machine, see `docs/design/0002-swap-engine.md`.
//!
//! `Swap::decide` is a pure function of the swap's stored state and a fresh view of both chains. It
//! is level-triggered: given the same chains it returns the same actions, so a restart, a dropped
//! broadcast or a reorg is handled by deciding again, not by remembering what happened.

use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint, PubkeyHash, Transaction};
use serde::{Deserialize, Serialize};

use crate::htlc::{Contract, PREIMAGE_LEN};
use crate::policy::Depths;

/// The payer's voluntary fee output as a counterparty needs to check it (design 0010): the ECDH
/// share `a*B_scan`, the BIP374 proof that it matches the lock's input-key sum, and the prevout
/// transactions of the lock's inputs, so the counterparty can authenticate the input public keys
/// without a transaction index. Persisted with the lock and sent to the counterparty in a
/// `Message::FeeProof`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeProof {
    pub share: PublicKey,
    pub proof: Vec<u8>,
    pub prevouts: Vec<Transaction>,
}

/// Where the counterparty's lock stands on the voluntary fee (design 0010). The gate in `decide`
/// reads this on the counterparty's lock: `Failed` abandons before we commit, `Pending` waits, and
/// `Verified` or `NotRequired` lets us proceed. It is never read on our own lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeState {
    /// The offer sets no fee, or the lock is our own: nothing to check.
    NotRequired,
    /// A fee is due but the proof or the lock is not yet verifiable.
    Pending,
    /// The fee output is present and its proof checks out.
    Verified,
    /// The fee output is missing, short, or its proof failed.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Chain {
    Btc,
    Xbtc,
}

impl Chain {
    pub fn other(self) -> Chain {
        match self {
            Chain::Btc => Chain::Xbtc,
            Chain::Xbtc => Chain::Btc,
        }
    }

    /// Protocol target seconds per block, for normalizing timelock block-counts across the two
    /// chains (#74). BTC targets 10 min; the BLAKE2b/xBTC chain (BIP-110 RDTS) targets ~13 min.
    /// ASSUMPTION: 780 is from the design docs, not read from consensus params. A chain running far
    /// from target (e.g. a stalled low-hashrate xBTC tip) breaks timelock safety regardless; that is
    /// an operational gate, not something this static figure can model.
    pub const fn target_block_secs(self) -> u32 {
        match self {
            Chain::Btc => 600,
            Chain::Xbtc => 780,
        }
    }
}

/// Express `count` blocks measured on chain `from` as a number of blocks on chain `to`, by
/// wall-clock, so a timelock requirement denominated on one chain can be compared against a budget
/// denominated on the other (#74). Rounds up, and is clamped so it can only ever *tighten* a
/// requirement, never loosen one: scaling a slow-chain (xBTC) count down to fast BTC blocks would
/// otherwise shave the only cushion the low-hashrate xBTC chain has against block-time variance.
/// Identity when the chains match. The result is therefore always >= `count`.
pub(crate) fn blocks_as(count: u32, from: Chain, to: Chain) -> u32 {
    if from == to {
        return count;
    }
    let scaled = (u64::from(count) * u64::from(from.target_block_secs()))
        .div_ceil(u64::from(to.target_block_secs()));
    u32::try_from(scaled).unwrap_or(u32::MAX).max(count)
}

/// The default smallest swap leg: below this a swap output is not worth making, and it keeps both
/// sides clear of dust. The runtime value is configurable (daemon setting `min_swap_sat`, threaded
/// into the engine) and defaults to this; the pure state machine takes it as an input, never a global.
/// A deployment may lower it (down to a safety floor; see `daemon::types::MIN_SWAP_FLOOR_SAT`) to
/// offer a small real-rate leg. The claim and refund each subtract the spend fee from the leg, so the
/// floor keeps the remainder clear of Bitcoin's dust limit.
pub const MIN_SWAP_AMOUNT: Amount = Amount::from_sat(10_000);

/// The voluntary fee terms an offer carries (design 0010, 0013). Both sides pay and verify against
/// these, so the terms are never taken from one side's local settings; `None` on an offer means no
/// fee. The address is per chain: each side pays to the address for the chain it locks. The two
/// chains share Bitcoin's address format, so the fields are kept separate by construction to stop a
/// BTC and an xBTC address being confused (design 0013). `deny_unknown_fields` makes an offer of the
/// old single-address shape fail to parse rather than silently drop the fee.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeeTerms {
    pub maker_bps: u16,
    pub taker_bps: u16,
    /// Fee address for the side locking BTC; `None` means no fee on that chain. A silent payment
    /// (`sp1...`) or a normal address.
    #[serde(default)]
    pub btc_address: Option<String>,
    /// Fee address for the side locking xBTC; `None` means no fee on that chain.
    #[serde(default)]
    pub xbtc_address: Option<String>,
}

impl FeeTerms {
    /// The fee address the side locking `chain` pays to, if the offer sets one for that chain.
    pub fn address(&self, chain: Chain) -> Option<&str> {
        match chain {
            Chain::Btc => self.btc_address.as_deref(),
            Chain::Xbtc => self.xbtc_address.as_deref(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offer {
    pub id: [u8; 16],
    /// The maker locks here; the taker receives here.
    pub maker_chain: Chain,
    pub maker_amount: Amount,
    /// What the maker wants for all of `maker_amount`, on the other chain.
    pub taker_amount: Amount,
    pub min_maker_amount: Amount,
    pub maker_lock_blocks: u16,
    pub taker_lock_blocks: u16,
    /// Depth the maker asks the taker to wait for on its lock; each engine may require more.
    pub maker_lock_depth: u32,
    /// Depth the maker will wait for on the taker's lock before revealing the secret.
    pub taker_lock_depth: u32,
    /// Blocks kept in reserve before any deadline.
    pub margin_blocks: u32,
    /// Voluntary fee terms (design 0010); `None` means a fee-less offer. `serde(default)` so offers
    /// from before the fee existed still deserialize.
    #[serde(default)]
    pub fee: Option<FeeTerms>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum BidError {
    BelowMinimum,
    AboveOffer,
    OwnOffer,
    /// The taker's own voluntary fee would exceed the per-trade sanity band (F3). Local refusal.
    FeeTooHigh,
    /// The swap's real-value (BTC) leg exceeds the local beta cap (#103). Local refusal, never part
    /// of counterparty verification.
    AboveMax,
}

impl Offer {
    /// What the taker pays for `maker_part`, rounded down: both engines compute the same number.
    /// Uses the default [`MIN_SWAP_AMOUNT`]; see [`Offer::taker_part_min`] for the configurable form.
    pub fn taker_part(&self, maker_part: Amount) -> Result<Amount, BidError> {
        self.taker_part_min(maker_part, MIN_SWAP_AMOUNT)
    }

    /// As [`Offer::taker_part`], but with the smallest swap leg `min_swap` passed in rather than read
    /// from the [`MIN_SWAP_AMOUNT`] default, so a deployment can lower the bound through config. The
    /// state machine stays pure: the limit is an input, never a global read.
    pub fn taker_part_min(&self, maker_part: Amount, min_swap: Amount) -> Result<Amount, BidError> {
        if maker_part > self.maker_amount {
            return Err(BidError::AboveOffer);
        }
        if maker_part < self.min_maker_amount || maker_part < min_swap {
            return Err(BidError::BelowMinimum);
        }
        let part = u128::from(self.taker_amount.to_sat()) * u128::from(maker_part.to_sat())
            / u128::from(self.maker_amount.to_sat());
        let part = Amount::from_sat(part as u64);
        if part < min_swap {
            return Err(BidError::BelowMinimum);
        }
        Ok(part)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Offer(Offer),
    Bid {
        offer_id: [u8; 16],
        swap_id: [u8; 16],
        maker_part: Amount,
        taker_claim_pkh: PubkeyHash,
        taker_refund_pkh: PubkeyHash,
    },
    Accept {
        swap_id: [u8; 16],
        secret_hash: [u8; 32],
        maker_claim_pkh: PubkeyHash,
        maker_refund_pkh: PubkeyHash,
    },
    /// Sent after a side funds its lock with a voluntary fee (design 0010): the share and proof the
    /// counterparty needs to verify the fee output, re-sent each tick until it is seen on chain.
    FeeProof {
        swap_id: [u8; 16],
        proof: FeeProof,
    },
    /// Broadcast when a maker takes an offer off the market (filled or cancelled): receivers drop it
    /// from their seen offers so it is no longer discoverable. Additive, so a peer that predates this
    /// variant simply ignores the event and keeps the offer until the maker stops honoring it.
    Withdraw {
        offer_id: [u8; 16],
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Maker,
    Taker,
}

impl Role {
    pub fn other(self) -> Role {
        match self {
            Role::Maker => Role::Taker,
            Role::Taker => Role::Maker,
        }
    }
}

/// Which of the two locks: the maker's (on the maker chain) or the taker's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Side {
    Maker,
    Taker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    /// Taker only: waiting for the maker's lock before deciding to lock.
    Waiting,
    /// Our lock is decided and funded, not yet seen on chain.
    Locking,
    /// Our lock is on chain.
    Locked,
    Claiming,
    Refunding,
    Done,
    Refunded,
    /// Nothing of ours was locked; nothing to recover.
    Abandoned,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Swap {
    pub id: [u8; 16],
    pub role: Role,
    pub offer: Offer,
    pub key_index: u32,
    pub maker_part: Amount,
    pub taker_part: Amount,
    /// On the maker chain: the taker claims it, the maker refunds it.
    pub maker_contract: Contract,
    /// On the taker chain: the maker claims it, the taker refunds it.
    pub taker_contract: Contract,
    pub depths: Depths,
    /// Taker only: the swap is abandoned if the maker's lock is not confirmed by this maker-chain height.
    pub lock_deadline: u32,
    /// Taker only: the secret, kept once seen, since a reorg can take its transaction away again.
    pub learned_secret: Option<[u8; PREIMAGE_LEN]>,
    pub phase: Phase,
    /// Unix seconds when this swap was created locally, for the web UI's time column (newest-first,
    /// sortable). `serde(default)` so a record written before the field existed still loads (as None).
    #[serde(default)]
    pub started_at: Option<u64>,
}

/// What one lock looks like on its chain right now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LockView {
    pub outpoint: OutPoint,
    /// What the output actually holds; a refund must sign for this, not for the agreed amount.
    pub value: Amount,
    /// False when the contract received a different amount than agreed.
    pub amount_ok: bool,
    /// None while unconfirmed.
    pub confirmed_height: Option<u32>,
    pub spend: Option<SpendView>,
    /// The voluntary fee state of this lock (design 0010). Only meaningful on the counterparty's
    /// lock, where the gate in `decide` reads it; our own lock is always `NotRequired`.
    pub fee: FeeState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendView {
    /// Set when the spend was a claim: the secret, read from its witness.
    pub preimage: Option<[u8; PREIMAGE_LEN]>,
    /// 0 while in the mempool.
    pub depth: u32,
    /// The spend pays us (our claim or our refund), not the counterparty.
    pub ours: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainView {
    pub maker_chain_height: u32,
    pub taker_chain_height: u32,
    pub maker_lock: Option<LockView>,
    pub taker_lock: Option<LockView>,
    /// Whether our lock transaction has been funded (signed and stored) yet. Lets the maker tell a
    /// swap it has already committed coin to from one it has not funded, so only the latter can be
    /// abandoned at its deadline.
    pub own_funded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Fund our own lock.
    Fund,
    Claim {
        lock: OutPoint,
        preimage: [u8; PREIMAGE_LEN],
    },
    Refund {
        lock: OutPoint,
        value: Amount,
    },
}

impl Swap {
    pub fn own_side(&self) -> Side {
        match self.role {
            Role::Maker => Side::Maker,
            Role::Taker => Side::Taker,
        }
    }

    fn lock_blocks(&self, side: Side) -> u32 {
        u32::from(match side {
            Side::Maker => self.offer.maker_lock_blocks,
            Side::Taker => self.offer.taker_lock_blocks,
        })
    }

    /// Blocks left on `side`'s lock before its refund opens, or None while unconfirmed.
    fn remaining(&self, side: Side, lock: &LockView, height: u32) -> Option<i64> {
        let confirmed = lock.confirmed_height?;
        Some(i64::from(confirmed) + i64::from(self.lock_blocks(side)) - 1 - i64::from(height))
    }

    fn depth(lock: &LockView, height: u32) -> u32 {
        lock.confirmed_height.map_or(0, |h| height + 1 - h)
    }

    /// The secret (maker only) is passed in so it never has to be stored in the swap file.
    pub fn decide(&mut self, view: &ChainView, secret: Option<[u8; PREIMAGE_LEN]>) -> Vec<Action> {
        // A settled swap is never reconsidered, so no later chain state can resurrect it.
        if matches!(self.phase, Phase::Done | Phase::Refunded | Phase::Abandoned) {
            return vec![];
        }
        match self.role {
            Role::Maker => self.decide_maker(view, secret.expect("maker always has the secret")),
            Role::Taker => self.decide_taker(view),
        }
    }

    fn decide_maker(&mut self, view: &ChainView, secret: [u8; PREIMAGE_LEN]) -> Vec<Action> {
        let (ha, hb) = (view.maker_chain_height, view.taker_chain_height);
        let Some(own) = &view.maker_lock else {
            return match self.phase {
                // Confirmed once, then gone (a reorg): rebroadcast the same transaction.
                Phase::Locked => vec![Action::Fund],
                Phase::Locking => {
                    if view.own_funded {
                        // Funded, awaiting its first confirmation: the driver rebroadcasts it.
                        return vec![Action::Fund];
                    }
                    // Not funded yet. Give up before the taker's deadline once a fresh lock could no
                    // longer reach funding depth in time, so we never fund a lock against a swap the
                    // taker has already abandoned.
                    let cutoff = self.lock_deadline.saturating_sub(self.depths.maker_lock);
                    if ha > cutoff {
                        self.phase = Phase::Abandoned;
                        vec![]
                    } else {
                        vec![Action::Fund]
                    }
                }
                _ => vec![],
            };
        };
        if self.phase == Phase::Locking {
            self.phase = Phase::Locked;
        }
        if let Some(spend) = own.spend.as_ref().filter(|s| s.ours) {
            self.phase = final_or(
                spend,
                self.depths.maker_final,
                Phase::Refunded,
                Phase::Refunding,
            );
            return vec![];
        }
        if let Some(theirs) = &view.taker_lock {
            if let Some(spend) = theirs.spend.as_ref().filter(|s| s.ours) {
                self.phase = final_or(spend, self.depths.taker_final, Phase::Done, Phase::Claiming);
                return vec![];
            }
            let deep = Self::depth(theirs, hb) >= self.depths.taker_lock;
            // Room for our claim to become final before the taker's refund opens.
            let needed = i64::from(self.offer.margin_blocks) + i64::from(self.depths.taker_final);
            let time_left = self
                .remaining(Side::Taker, theirs, hb)
                .is_some_and(|r| r > needed);
            // Once the secret has been broadcast it is public: keep claiming whatever the clock says.
            // The taker's lock must carry its voluntary fee before we reveal the secret (design
            // 0010). This is only one term of the pre-claim test: once we are Claiming the secret is
            // public and we keep claiming whatever the fee state, or the taker could take both legs.
            let fee_ok = matches!(theirs.fee, FeeState::Verified | FeeState::NotRequired);
            let go =
                self.phase == Phase::Claiming || (theirs.amount_ok && fee_ok && deep && time_left);
            if theirs.spend.is_none() && own.spend.is_none() && go {
                self.phase = Phase::Claiming;
                return vec![Action::Claim {
                    lock: theirs.outpoint,
                    preimage: secret,
                }];
            }
        }
        let refund_open = self.remaining(Side::Maker, own, ha).is_some_and(|r| r <= 0);
        if own.spend.is_none() && refund_open && self.phase != Phase::Claiming {
            self.phase = Phase::Refunding;
            return vec![Action::Refund {
                lock: own.outpoint,
                value: own.value,
            }];
        }
        vec![]
    }

    fn decide_taker(&mut self, view: &ChainView) -> Vec<Action> {
        let (ha, hb) = (view.maker_chain_height, view.taker_chain_height);
        if let Some(spend) = view
            .maker_lock
            .as_ref()
            .and_then(|l| l.spend.as_ref())
            .filter(|s| s.ours)
        {
            self.phase = final_or(spend, self.depths.maker_final, Phase::Done, Phase::Claiming);
            return vec![];
        }
        let seen = view
            .taker_lock
            .as_ref()
            .and_then(|l| l.spend.as_ref())
            .and_then(|s| s.preimage);
        if seen.is_some() {
            self.learned_secret = seen;
        }
        if let (Some(preimage), Some(theirs)) = (self.learned_secret, &view.maker_lock) {
            if theirs.spend.is_none() {
                self.phase = Phase::Claiming;
                return vec![Action::Claim {
                    lock: theirs.outpoint,
                    preimage,
                }];
            }
        }

        let Some(own) = &view.taker_lock else {
            match self.phase {
                // Confirmed once then reorged away: we committed coin, so rebroadcast the same tx.
                Phase::Locked => return vec![Action::Fund],
                // Funded and awaiting its first confirmation: rebroadcast.
                Phase::Locking if view.own_funded => return vec![Action::Fund],
                // Not committed yet (Waiting, or Locking where funding has not succeeded): fall through
                // to the lock gate below so a stalled taker re-checks the window and gives up instead
                // of funding late against a stale safety check (#72).
                Phase::Waiting | Phase::Locking => {}
                _ => return vec![],
            }
            let Some(theirs) = &view.maker_lock else {
                if ha > self.lock_deadline {
                    self.phase = Phase::Abandoned;
                }
                return vec![];
            };
            let deep = Self::depth(theirs, ha) >= self.depths.maker_lock;
            // Enough of the maker's lock must remain for our lock to confirm and run out, and for a
            // claim to become final, or a maker whose lock confirmed late could take both.
            // The taker's own lock (`taker_lock` confirmations and `taker_lock_blocks` duration) runs
            // on the taker chain, but `remaining(Side::Maker)` below is a maker-chain budget. Convert
            // those two taker-chain terms to maker-chain blocks before summing, or a BTC maker (whose
            // ~10-min blocks undercount the taker's ~13-min xBTC blocks) would let the taker lock too
            // late and lose both legs (#74). `maker_final` is already maker-chain; `margin_blocks` is
            // the native buffer on the deciding (maker) chain.
            let m = self.offer.maker_chain;
            let t = m.other();
            let needed = i64::from(blocks_as(self.depths.taker_lock, t, m))
                + i64::from(blocks_as(u32::from(self.offer.taker_lock_blocks), t, m))
                + i64::from(self.offer.margin_blocks)
                + i64::from(self.depths.maker_final);
            let time_left = self
                .remaining(Side::Maker, theirs, ha)
                .is_some_and(|r| r > needed);
            // The maker's lock must carry its voluntary fee before we lock (design 0010). A failed
            // fee abandons, like a wrong amount. A pending fee (proof not yet arrived) is not a
            // failure: we simply wait, bounded by the existing lock deadline, and never abandon a
            // sound swap just because the proof is a little late.
            let fee_ok = matches!(theirs.fee, FeeState::Verified | FeeState::NotRequired);
            if !theirs.amount_ok || theirs.spend.is_some() || theirs.fee == FeeState::Failed {
                self.phase = Phase::Abandoned;
            } else if deep && time_left && fee_ok {
                self.phase = Phase::Locking;
                return vec![Action::Fund];
            } else if ha > self.lock_deadline || (deep && !time_left) {
                self.phase = Phase::Abandoned;
            }
            return vec![];
        };

        if let Some(spend) = own.spend.as_ref().filter(|s| s.ours) {
            self.phase = final_or(
                spend,
                self.depths.taker_final,
                Phase::Refunded,
                Phase::Refunding,
            );
            return vec![];
        }
        if own.spend.is_none() && self.remaining(Side::Taker, own, hb).is_some_and(|r| r <= 0) {
            self.phase = Phase::Refunding;
            return vec![Action::Refund {
                lock: own.outpoint,
                value: own.value,
            }];
        }
        self.phase = Phase::Locked;
        vec![]
    }
}

fn final_or(spend: &SpendView, final_depth: u32, done: Phase, pending: Phase) -> Phase {
    if spend.depth >= final_depth {
        done
    } else {
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    fn offer() -> Offer {
        Offer {
            id: [1; 16],
            maker_chain: Chain::Xbtc,
            maker_amount: Amount::from_sat(1_000_000),
            taker_amount: Amount::from_sat(300_000),
            min_maker_amount: Amount::from_sat(100_000),
            maker_lock_blocks: 40,
            taker_lock_blocks: 20,
            maker_lock_depth: 2,
            taker_lock_depth: 2,
            margin_blocks: 3,
            fee: None,
        }
    }

    #[test]
    fn a_swap_from_before_started_at_still_deserializes() {
        // A record written before the timestamp field existed must still load, with started_at None.
        let mut v = serde_json::to_value(swap(Role::Taker)).unwrap();
        v.as_object_mut().unwrap().remove("started_at");
        let back: Swap = serde_json::from_value(v).unwrap();
        assert_eq!(back.started_at, None);
    }

    #[test]
    fn an_offer_from_before_the_fee_still_deserializes() {
        // A pre-fee offer has no `fee` field; serde(default) fills it with None.
        let mut v = serde_json::to_value(offer()).unwrap();
        v.as_object_mut().unwrap().remove("fee");
        let back: Offer = serde_json::from_value(v).unwrap();
        assert!(back.fee.is_none());
    }

    fn contract(byte: u8) -> Contract {
        Contract {
            secret_hash: [byte; 32],
            claim_pkh: PubkeyHash::from_byte_array([byte; 20]),
            refund_pkh: PubkeyHash::from_byte_array([byte + 1; 20]),
            lock_blocks: 1,
        }
    }

    fn swap(role: Role) -> Swap {
        Swap {
            id: [2; 16],
            role,
            offer: offer(),
            key_index: 0,
            maker_part: Amount::from_sat(1_000_000),
            taker_part: Amount::from_sat(300_000),
            maker_contract: contract(3),
            taker_contract: contract(5),
            depths: Depths {
                maker_lock: 2,
                taker_lock: 2,
                maker_final: 3,
                taker_final: 3,
            },
            lock_deadline: 110,
            learned_secret: None,
            phase: match role {
                Role::Maker => Phase::Locking,
                Role::Taker => Phase::Waiting,
            },
            started_at: None,
        }
    }

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([n; 32]),
            vout: 0,
        }
    }

    fn lock(n: u8, confirmed_height: Option<u32>) -> LockView {
        LockView {
            outpoint: outpoint(n),
            value: Amount::from_sat(1_000_000),
            amount_ok: true,
            confirmed_height,
            spend: None,
            fee: FeeState::NotRequired,
        }
    }

    fn view(
        ha: u32,
        hb: u32,
        maker_lock: Option<LockView>,
        taker_lock: Option<LockView>,
    ) -> ChainView {
        ChainView {
            maker_chain_height: ha,
            taker_chain_height: hb,
            maker_lock,
            taker_lock,
            own_funded: false,
        }
    }

    const SECRET: Option<[u8; 32]> = Some([9; 32]);

    #[test]
    fn taker_part_rounds_down_and_refuses_small_or_large_bids() {
        let o = offer();
        assert_eq!(
            o.taker_part(Amount::from_sat(333_333)),
            Ok(Amount::from_sat(99_999))
        );
        assert_eq!(
            o.taker_part(Amount::from_sat(99_999)),
            Err(BidError::BelowMinimum)
        );
        assert_eq!(
            o.taker_part(Amount::from_sat(1_000_001)),
            Err(BidError::AboveOffer)
        );
        let tiny = Offer {
            taker_amount: Amount::from_sat(20_000),
            min_maker_amount: Amount::ZERO,
            ..o
        };
        assert_eq!(
            tiny.taker_part(Amount::from_sat(400_000)),
            Err(BidError::BelowMinimum)
        );
    }

    #[test]
    fn a_lowered_min_swap_accepts_a_small_leg() {
        // A 1:1 offer whose legs sit below the 10_000 sat default minimum.
        let small = Offer {
            maker_amount: Amount::from_sat(4_000),
            taker_amount: Amount::from_sat(4_000),
            min_maker_amount: Amount::ZERO,
            ..offer()
        };
        // At the default minimum a 4_000-sat bid is refused.
        assert_eq!(
            small.taker_part(Amount::from_sat(4_000)),
            Err(BidError::BelowMinimum)
        );
        // Lower the configured minimum and the same 4_000-sat bid is accepted on both the bid and
        // the computed counter leg.
        assert_eq!(
            small.taker_part_min(Amount::from_sat(4_000), Amount::from_sat(3_000)),
            Ok(Amount::from_sat(4_000))
        );
    }

    #[test]
    fn maker_funds_once_then_waits() {
        let mut s = swap(Role::Maker);
        assert_eq!(
            s.decide(&view(100, 100, None, None), SECRET),
            vec![Action::Fund]
        );
        assert_eq!(
            s.decide(&view(100, 100, Some(lock(1, None)), None), SECRET),
            vec![]
        );
        assert_eq!(s.phase, Phase::Locked);
        // A reorg takes the lock away: the same funding transaction goes out again.
        assert_eq!(
            s.decide(&view(101, 101, None, None), SECRET),
            vec![Action::Fund]
        );
    }

    #[test]
    fn blocks_as_normalizes_by_wall_clock_and_never_loosens() {
        // Same chain is identity.
        assert_eq!(blocks_as(20, Chain::Btc, Chain::Btc), 20);
        assert_eq!(blocks_as(20, Chain::Xbtc, Chain::Xbtc), 20);
        // A slow-chain (xBTC ~13m) requirement expressed in fast BTC blocks grows: ceil(20*780/600)=26.
        assert_eq!(blocks_as(20, Chain::Xbtc, Chain::Btc), 26);
        // A fast-chain (BTC) requirement expressed in slow xBTC blocks is ceil(20*600/780)=16, but the
        // clamp keeps it at 20 so the low-hashrate chain keeps its variance cushion.
        assert_eq!(blocks_as(20, Chain::Btc, Chain::Xbtc), 20);
        // The clamp guarantees the result never drops below the raw count, in any direction, for any
        // count: this is what makes the normalized `depths`/`needed` at least as strict as before.
        for &c in &[0u32, 1, 2, 5, 20, 100, 288, 10_000, u32::MAX] {
            for pair in [
                (Chain::Btc, Chain::Xbtc),
                (Chain::Xbtc, Chain::Btc),
                (Chain::Btc, Chain::Btc),
            ] {
                assert!(blocks_as(c, pair.0, pair.1) >= c, "{c} {pair:?} loosened");
            }
        }
    }

    #[test]
    fn taker_refuses_to_lock_too_late_in_the_btc_maker_direction() {
        // #74: a BTC-maker offer (maker locks BTC ~10m blocks, taker locks xBTC ~13m blocks). The
        // taker's own leg (taker_lock_blocks = 20 xBTC blocks) burns more wall-clock than its bare
        // count, so the maker-chain room the taker must see on the maker's lock is larger than the
        // un-normalized sum:
        //   un-normalized needed = taker_lock(2) + taker_lock_blocks(20) + margin(3) + maker_final(3) = 28
        //   normalized    needed = blocks_as(2)=3 + blocks_as(20)=26 + margin(3) + maker_final(3)     = 35
        // With 30 maker-chain blocks of room the old math (30 > 28) would have locked; the normalized
        // math (30 > 35 is false) must refuse, or the maker could claim the taker's late lock and
        // still refund its own leg - the "take both legs" loss.
        let mut late = swap(Role::Taker);
        late.offer.maker_chain = Chain::Btc; // taker chain is now xBTC
                                             // maker lock confirmed at height 1; offer.maker_lock_blocks = 40, so at ha=10 the room is
                                             // 1 + 40 - 1 - 10 = 30 maker-chain blocks, and depth 10 >= maker_lock 2 (deep).
        assert_eq!(
            late.decide(&view(10, 10, Some(lock(7, Some(1))), None), None),
            vec![]
        );
        assert_eq!(
            late.phase,
            Phase::Abandoned,
            "must not lock with only 30 blocks of room"
        );

        // Same BTC-maker offer with comfortable room (ha=2 -> room 38 > 35, depth 2 >= 2) still locks.
        let mut ample = swap(Role::Taker);
        ample.offer.maker_chain = Chain::Btc;
        assert_eq!(
            ample.decide(&view(2, 2, Some(lock(7, Some(1))), None), None),
            vec![Action::Fund]
        );
        assert_eq!(ample.phase, Phase::Locking);
    }

    #[test]
    fn maker_abandons_if_it_cannot_fund_by_the_deadline() {
        let mut s = swap(Role::Maker);
        // Cutoff is lock_deadline 110 minus the maker_lock depth 2, so 108: at it, still try.
        assert_eq!(
            s.decide(&view(108, 108, None, None), SECRET),
            vec![Action::Fund]
        );
        assert_eq!(s.phase, Phase::Locking);
        // One block past the cutoff with nothing funded: give up, having locked nothing.
        assert_eq!(s.decide(&view(109, 109, None, None), SECRET), vec![]);
        assert_eq!(s.phase, Phase::Abandoned);
    }

    #[test]
    fn maker_past_the_deadline_never_abandons_a_funded_lock() {
        let mut s = swap(Role::Maker);
        // Funded but not yet on chain, long past the cutoff: rebroadcast, never abandon.
        let funded = ChainView {
            own_funded: true,
            ..view(200, 200, None, None)
        };
        assert_eq!(s.decide(&funded, SECRET), vec![Action::Fund]);
        assert_eq!(s.phase, Phase::Locking);
    }

    #[test]
    fn maker_claims_only_a_deep_correct_lock_with_time_left() {
        let mut s = swap(Role::Maker);
        let own = Some(lock(1, Some(100)));
        assert_eq!(
            s.decide(
                &view(105, 105, own.clone(), Some(lock(2, Some(105)))),
                SECRET
            ),
            vec![]
        );
        let wrong = LockView {
            amount_ok: false,
            ..lock(2, Some(100))
        };
        assert_eq!(
            s.decide(&view(105, 105, own.clone(), Some(wrong)), SECRET),
            vec![]
        );
        // Confirmed at 100 for 20 blocks: refund valid from 120; margin 3 plus final depth 3.
        assert_eq!(
            s.decide(
                &view(105, 113, own.clone(), Some(lock(2, Some(100)))),
                SECRET
            ),
            vec![]
        );
        assert_eq!(
            s.decide(&view(105, 112, own, Some(lock(2, Some(100)))), SECRET),
            vec![Action::Claim {
                lock: outpoint(2),
                preimage: [9; 32]
            }]
        );
        assert_eq!(s.phase, Phase::Claiming);
    }

    #[test]
    fn maker_keeps_claiming_once_the_secret_is_out() {
        let mut s = swap(Role::Maker);
        let own = Some(lock(1, Some(100)));
        let mut theirs = lock(2, Some(100));
        theirs.spend = Some(SpendView {
            preimage: Some([9; 32]),
            depth: 0,
            ours: true,
        });
        assert_eq!(
            s.decide(&view(105, 105, own.clone(), Some(theirs.clone())), SECRET),
            vec![]
        );
        assert_eq!(s.phase, Phase::Claiming);
        // The claim was dropped and the margin has passed meanwhile: claim again anyway.
        let claim = vec![Action::Claim {
            lock: outpoint(2),
            preimage: [9; 32],
        }];
        assert_eq!(
            s.decide(
                &view(105, 118, own.clone(), Some(lock(2, Some(100)))),
                SECRET
            ),
            claim
        );
        theirs.spend.as_mut().unwrap().depth = 3;
        assert_eq!(s.decide(&view(105, 118, own, Some(theirs)), SECRET), vec![]);
        assert_eq!(s.phase, Phase::Done);
    }

    #[test]
    fn maker_refunds_when_the_taker_never_locks() {
        let mut s = swap(Role::Maker);
        let own = Some(lock(1, Some(100)));
        // Confirmed at 100 with 40 blocks: valid in block 140, so broadcast from height 139.
        assert_eq!(s.decide(&view(138, 138, own.clone(), None), SECRET), vec![]);
        assert_eq!(
            s.decide(&view(139, 139, own, None), SECRET),
            vec![Action::Refund {
                lock: outpoint(1),
                value: Amount::from_sat(1_000_000)
            }]
        );
        assert_eq!(s.phase, Phase::Refunding);
    }

    #[test]
    fn taker_locks_only_on_a_deep_lock_with_enough_time_left() {
        let mut s = swap(Role::Taker);
        assert_eq!(
            s.decide(&view(100, 100, Some(lock(1, Some(100))), None), None),
            vec![]
        );
        assert_eq!(
            s.decide(&view(101, 101, Some(lock(1, Some(100))), None), None),
            vec![Action::Fund]
        );
    }

    #[test]
    fn taker_refuses_a_late_maker_lock() {
        let mut s = swap(Role::Taker);
        // Maker lock confirmed at 100 for 40 blocks: 25 needed (2 + 20 + 3); at 115 only 24 remain.
        assert_eq!(
            s.decide(&view(115, 115, Some(lock(1, Some(100))), None), None),
            vec![]
        );
        assert_eq!(s.phase, Phase::Abandoned);
    }

    #[test]
    fn taker_refuses_a_wrong_amount_and_gives_up_after_the_deadline() {
        let mut s = swap(Role::Taker);
        let wrong = LockView {
            amount_ok: false,
            ..lock(1, Some(100))
        };
        assert_eq!(s.decide(&view(101, 101, Some(wrong), None), None), vec![]);
        assert_eq!(s.phase, Phase::Abandoned);
        let mut s = swap(Role::Taker);
        assert_eq!(s.decide(&view(111, 111, None, None), None), vec![]);
        assert_eq!(s.phase, Phase::Abandoned);
    }

    // --- voluntary fee gate (design 0010) ---

    #[test]
    fn taker_waits_for_a_pending_fee_then_locks_when_it_verifies() {
        let mut s = swap(Role::Taker);
        let maker = |fee| LockView {
            fee,
            ..lock(1, Some(100))
        };
        // The maker's lock is deep with time to spare, but its fee proof has not arrived yet: the
        // taker neither locks nor abandons, it simply waits.
        assert_eq!(
            s.decide(&view(101, 101, Some(maker(FeeState::Pending)), None), None),
            vec![]
        );
        assert_eq!(s.phase, Phase::Waiting);
        // The proof arrives and verifies: now the taker locks.
        assert_eq!(
            s.decide(&view(101, 101, Some(maker(FeeState::Verified)), None), None),
            vec![Action::Fund]
        );
        assert_eq!(s.phase, Phase::Locking);
    }

    #[test]
    fn taker_abandons_a_fee_that_never_arrives_by_the_deadline() {
        let mut s = swap(Role::Taker);
        let maker = LockView {
            fee: FeeState::Pending,
            ..lock(1, Some(100))
        };
        // The deadline is 110; past it with the fee still pending, the taker gives up (and never
        // locked, so there is nothing to recover).
        assert_eq!(s.decide(&view(111, 111, Some(maker), None), None), vec![]);
        assert_eq!(s.phase, Phase::Abandoned);
    }

    #[test]
    fn taker_abandons_a_failed_maker_fee_at_once() {
        let mut s = swap(Role::Taker);
        let maker = LockView {
            fee: FeeState::Failed,
            ..lock(1, Some(100))
        };
        // A fee that is present but wrong (failed verification) is like a wrong amount: abandon.
        assert_eq!(s.decide(&view(101, 101, Some(maker), None), None), vec![]);
        assert_eq!(s.phase, Phase::Abandoned);
    }

    #[test]
    fn maker_gates_its_claim_on_the_takers_fee_but_not_once_claiming() {
        let own = Some(lock(1, Some(100)));
        let taker = |fee| LockView {
            fee,
            ..lock(2, Some(100))
        };
        // A deep, correct taker lock with time left, but its fee failed: the maker does not reveal
        // the secret (it will refund instead).
        let mut s = swap(Role::Maker);
        assert_eq!(
            s.decide(
                &view(105, 112, own.clone(), Some(taker(FeeState::Failed))),
                SECRET
            ),
            vec![]
        );
        assert_ne!(s.phase, Phase::Claiming);
        // With the fee verified, the same view claims.
        let mut s = swap(Role::Maker);
        assert_eq!(
            s.decide(
                &view(105, 112, own.clone(), Some(taker(FeeState::Verified))),
                SECRET
            ),
            vec![Action::Claim {
                lock: outpoint(2),
                preimage: [9; 32]
            }]
        );
        assert_eq!(s.phase, Phase::Claiming);
        // Once claiming, the secret is public: the maker keeps claiming even if the fee now looks
        // failed, or the taker could take both legs.
        assert_eq!(
            s.decide(&view(105, 112, own, Some(taker(FeeState::Failed))), SECRET),
            vec![Action::Claim {
                lock: outpoint(2),
                preimage: [9; 32]
            }]
        );
        assert_eq!(s.phase, Phase::Claiming);
    }

    #[test]
    fn taker_claims_as_soon_as_the_secret_appears() {
        let mut s = swap(Role::Taker);
        let mut own = lock(2, Some(102));
        own.spend = Some(SpendView {
            preimage: Some([9; 32]),
            depth: 0,
            ours: false,
        });
        assert_eq!(
            s.decide(&view(104, 104, Some(lock(1, Some(100))), Some(own)), None),
            vec![Action::Claim {
                lock: outpoint(1),
                preimage: [9; 32]
            }]
        );
    }

    #[test]
    fn taker_refunds_when_the_maker_never_claims() {
        let mut s = swap(Role::Taker);
        let own = Some(lock(2, Some(102)));
        assert_eq!(
            s.decide(&view(120, 120, Some(lock(1, Some(100))), own.clone()), None),
            vec![]
        );
        assert_eq!(
            s.decide(&view(121, 121, Some(lock(1, Some(100))), own), None),
            vec![Action::Refund {
                lock: outpoint(2),
                value: Amount::from_sat(1_000_000)
            }]
        );
    }

    #[test]
    fn a_reorged_claim_is_claimed_again_with_the_kept_secret() {
        let mut s = swap(Role::Taker);
        let mut own = lock(2, Some(102));
        own.spend = Some(SpendView {
            preimage: Some([9; 32]),
            depth: 1,
            ours: false,
        });
        let claim = vec![Action::Claim {
            lock: outpoint(1),
            preimage: [9; 32],
        }];
        assert_eq!(
            s.decide(&view(106, 106, Some(lock(1, Some(100))), Some(own)), None),
            claim
        );
        // The reorg removed both claims: the secret is no longer on chain, the swap still has it.
        assert_eq!(
            s.decide(
                &view(106, 106, Some(lock(1, Some(100))), Some(lock(2, Some(102)))),
                None
            ),
            claim
        );
    }

    #[test]
    fn taker_does_not_abandon_a_lock_it_has_funded() {
        let mut s = swap(Role::Taker);
        assert_eq!(
            s.decide(&view(101, 101, Some(lock(1, Some(100))), None), None),
            vec![Action::Fund]
        );
        assert_eq!(s.phase, Phase::Locking);
        // Funded now (own_funded), lock not yet on chain. Too late for a fresh decision, but the lock
        // is already out: keep rebroadcasting it, never abandon.
        let funded_late = ChainView {
            own_funded: true,
            ..view(130, 130, Some(lock(1, Some(100))), None)
        };
        assert_eq!(s.decide(&funded_late, None), vec![Action::Fund]);
        assert_eq!(s.phase, Phase::Locking);
    }

    #[test]
    fn taker_abandons_if_its_lock_never_funds_in_time() {
        let mut s = swap(Role::Taker);
        // Decides to fund (Waiting -> Locking) while the window is open.
        assert_eq!(
            s.decide(&view(101, 101, Some(lock(1, Some(100))), None), None),
            vec![Action::Fund]
        );
        assert_eq!(s.phase, Phase::Locking);
        // Funding never succeeded (own_funded stays false) and the window has now closed: give up
        // rather than fund late against a safety check made at height 101 (#72).
        assert_eq!(
            s.decide(&view(130, 130, Some(lock(1, Some(100))), None), None),
            vec![]
        );
        assert_eq!(s.phase, Phase::Abandoned);
    }

    #[test]
    fn a_claim_on_xbtc_is_watched_until_the_xbtc_final_depth() {
        let mut s = swap(Role::Taker);
        s.depths.maker_final = 6;
        let mut theirs = lock(1, Some(100));
        theirs.spend = Some(SpendView {
            preimage: Some([9; 32]),
            depth: 5,
            ours: true,
        });
        s.decide(
            &view(106, 106, Some(theirs.clone()), Some(lock(2, Some(102)))),
            None,
        );
        assert_eq!(s.phase, Phase::Claiming);
        theirs.spend.as_mut().unwrap().depth = 6;
        s.decide(
            &view(107, 107, Some(theirs), Some(lock(2, Some(102)))),
            None,
        );
        assert_eq!(s.phase, Phase::Done);
    }

    #[test]
    fn the_taker_waits_for_its_own_depth_not_the_offers() {
        let mut s = swap(Role::Taker);
        s.offer.maker_lock_depth = 0;
        s.depths.maker_lock = 6;
        assert_eq!(
            s.decide(&view(102, 102, Some(lock(1, Some(100))), None), None),
            vec![]
        );
        assert_eq!(
            s.decide(&view(105, 105, Some(lock(1, Some(100))), None), None),
            vec![Action::Fund]
        );
    }
}

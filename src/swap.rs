//! Protocol messages and the per-swap state machine, see `docs/design/0002-swap-engine.md`.
//!
//! `Swap::decide` is a pure function of the swap's stored state and a fresh view of both chains. It
//! is level-triggered: given the same chains it returns the same actions, so a restart, a dropped
//! broadcast or a reorg is handled by deciding again, not by remembering what happened.

use bitcoin::{Amount, OutPoint, PubkeyHash};
use serde::{Deserialize, Serialize};

use crate::htlc::{Contract, PREIMAGE_LEN};
use crate::policy::Depths;

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
}

/// Below this a swap output is not worth making; also keeps both sides clear of dust.
pub const MIN_SWAP_AMOUNT: Amount = Amount::from_sat(10_000);

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
}

#[derive(Debug, PartialEq, Eq)]
pub enum BidError {
    BelowMinimum,
    AboveOffer,
    OwnOffer,
}

impl Offer {
    /// What the taker pays for `maker_part`, rounded down: both engines compute the same number.
    pub fn taker_part(&self, maker_part: Amount) -> Result<Amount, BidError> {
        if maker_part > self.maker_amount {
            return Err(BidError::AboveOffer);
        }
        if maker_part < self.min_maker_amount || maker_part < MIN_SWAP_AMOUNT {
            return Err(BidError::BelowMinimum);
        }
        let part = u128::from(self.taker_amount.to_sat()) * u128::from(maker_part.to_sat())
            / u128::from(self.maker_amount.to_sat());
        let part = Amount::from_sat(part as u64);
        if part < MIN_SWAP_AMOUNT {
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Maker,
    Taker,
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
            // Funded but not (or no longer) on chain: the driver rebroadcasts the same transaction.
            return match self.phase {
                Phase::Locking | Phase::Locked => vec![Action::Fund],
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
            let go = self.phase == Phase::Claiming || (theirs.amount_ok && deep && time_left);
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
                Phase::Locking | Phase::Locked => return vec![Action::Fund],
                Phase::Waiting => {}
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
            let needed = i64::from(self.depths.taker_lock)
                + i64::from(self.offer.taker_lock_blocks)
                + i64::from(self.offer.margin_blocks)
                + i64::from(self.depths.maker_final);
            let time_left = self
                .remaining(Side::Maker, theirs, ha)
                .is_some_and(|r| r > needed);
            if !theirs.amount_ok || theirs.spend.is_some() {
                self.phase = Phase::Abandoned;
            } else if deep && time_left {
                self.phase = Phase::Locking;
                return vec![Action::Fund];
            } else if deep || ha > self.lock_deadline {
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
        }
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
        // Too late now for a fresh decision, but the lock is already out: keep it going.
        assert_eq!(
            s.decide(&view(130, 130, Some(lock(1, Some(100))), None), None),
            vec![Action::Fund]
        );
        assert_eq!(s.phase, Phase::Locking);
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

//! This engine's own confirmation rules. An offer can ask for more, never for less: the maker writes
//! the offer, so depths that protect the taker cannot be left to the maker.

use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use crate::swap::{blocks_as, Chain, Offer};

/// Confirmations a swap waits for, fixed when the swap starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Depths {
    /// On the maker's lock, before the taker locks.
    pub maker_lock: u32,
    /// On the taker's lock, before the maker reveals the secret.
    pub taker_lock: u32,
    /// A spend on the maker chain counts as final at this depth; until then it is watched.
    pub maker_final: u32,
    /// The same on the taker chain.
    pub taker_final: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    AmountAboveLimit,
    /// The timelocks leave no room for the confirmations this policy requires.
    TimelocksTooShort,
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// (largest BTC-side amount, depth), ascending; larger swaps are refused.
    pub btc: Vec<(Amount, u32)>,
    pub xbtc: Vec<(Amount, u32)>,
    /// Confirmations our own lock inputs need before we spend them.
    pub funding_minconf_btc: u32,
    pub funding_minconf_xbtc: u32,
}

impl Policy {
    /// Provisional table until the xBTC reorg-cost study: xBTC has a small fraction of BTC's hashrate.
    pub fn standard() -> Policy {
        Policy {
            btc: vec![
                (Amount::from_sat(1_000_000), 1),
                (Amount::from_sat(10_000_000), 2),
                (Amount::ONE_BTC, 3),
            ],
            xbtc: vec![
                (Amount::from_sat(1_000_000), 6),
                (Amount::from_sat(10_000_000), 12),
                (Amount::ONE_BTC, 36),
            ],
            funding_minconf_btc: 1,
            funding_minconf_xbtc: 6,
        }
    }

    pub fn depth(&self, chain: Chain, btc_side: Amount) -> Option<u32> {
        let table = match chain {
            Chain::Btc => &self.btc,
            Chain::Xbtc => &self.xbtc,
        };
        table
            .iter()
            .find(|(limit, _)| btc_side <= *limit)
            .map(|(_, depth)| *depth)
    }

    pub fn funding_minconf(&self, chain: Chain) -> u32 {
        match chain {
            Chain::Btc => self.funding_minconf_btc,
            Chain::Xbtc => self.funding_minconf_xbtc,
        }
    }

    /// The depths for a swap of `maker_part` against `taker_part` under `offer`.
    pub fn depths(
        &self,
        offer: &Offer,
        maker_part: Amount,
        taker_part: Amount,
    ) -> Result<Depths, PolicyError> {
        let btc_side = match offer.maker_chain {
            Chain::Btc => maker_part,
            Chain::Xbtc => taker_part,
        };
        let need = |chain| {
            self.depth(chain, btc_side)
                .ok_or(PolicyError::AmountAboveLimit)
        };
        let (maker_final, taker_final) =
            (need(offer.maker_chain)?, need(offer.maker_chain.other())?);
        let depths = Depths {
            maker_lock: offer.maker_lock_depth.max(maker_final),
            taker_lock: offer.taker_lock_depth.max(taker_final),
            maker_final,
            taker_final,
        };
        // The taker locks after `maker_lock` confirmations and needs, on the maker's clock, room for
        // its own lock to confirm and run out plus a final claim; the maker needs room on the
        // taker's clock to reveal and see its claim final.
        let margin = offer.margin_blocks;
        // `maker_room` bounds `maker_lock_blocks`, a maker-chain count, so the two taker-chain terms
        // (`taker_lock` confirmations and the taker's `taker_lock_blocks` duration) must be converted
        // to maker-chain blocks by wall-clock first, per term, before summing (#74). Without this a
        // BTC maker's ~10-min blocks undercount the taker's ~13-min xBTC blocks and the room is too
        // short. `maker_lock`, `maker_final` and `margin` are already maker-chain.
        let (m, t) = (offer.maker_chain, offer.maker_chain.other());
        let maker_room = depths.maker_lock
            + blocks_as(depths.taker_lock, t, m)
            + blocks_as(u32::from(offer.taker_lock_blocks), t, m)
            + margin
            + maker_final;
        let taker_room = depths.taker_lock + margin + taker_final;
        if u32::from(offer.maker_lock_blocks) <= maker_room
            || u32::from(offer.taker_lock_blocks) <= taker_room
        {
            return Err(PolicyError::TimelocksTooShort);
        }
        Ok(depths)
    }

    /// The smallest `(maker_lock_blocks, taker_lock_blocks)` that satisfy `depths` for an offer of
    /// these parameters, plus a small headroom. A client sizes an offer's timelocks to the amount
    /// with this, rather than a fixed default that is too short once the amount needs deeper
    /// confirmations. `None` if the amount is above the policy's table (there is no valid lock then).
    pub fn min_lock_blocks(
        &self,
        maker_chain: Chain,
        maker_part: Amount,
        taker_part: Amount,
        maker_lock_depth: u32,
        taker_lock_depth: u32,
        margin: u32,
    ) -> Option<(u16, u16)> {
        let btc_side = match maker_chain {
            Chain::Btc => maker_part,
            Chain::Xbtc => taker_part,
        };
        let maker_final = self.depth(maker_chain, btc_side)?;
        let taker_final = self.depth(maker_chain.other(), btc_side)?;
        let maker_lock = maker_lock_depth.max(maker_final);
        let taker_lock = taker_lock_depth.max(taker_final);
        // Mirror `depths`: each lock must exceed its room, so take room + headroom. The maker's room
        // includes the taker's lock blocks, so size the taker first.
        let headroom = 2;
        let taker_lock_blocks = taker_lock + margin + taker_final + headroom;
        // Mirror `depths` exactly: convert the two taker-chain terms to maker-chain blocks per term
        // (never the sum) so the sizing a client computes here satisfies the normalized `depths`
        // check above (#74). `t` is the taker chain.
        let t = maker_chain.other();
        let maker_lock_blocks = maker_lock
            + blocks_as(taker_lock, t, maker_chain)
            + blocks_as(taker_lock_blocks, t, maker_chain)
            + margin
            + maker_final
            + headroom;
        Some((
            u16::try_from(maker_lock_blocks).ok()?,
            u16::try_from(taker_lock_blocks).ok()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(maker_lock_blocks: u16, taker_lock_blocks: u16) -> Offer {
        Offer {
            id: [1; 16],
            maker_chain: Chain::Xbtc,
            maker_amount: Amount::from_sat(300_000_000),
            taker_amount: Amount::from_sat(90_000_000),
            min_maker_amount: Amount::ZERO,
            maker_lock_blocks,
            taker_lock_blocks,
            maker_lock_depth: 0,
            taker_lock_depth: 0,
            margin_blocks: 6,
            fee: None,
            valid_until: None,
        }
    }

    #[test]
    fn standard_depths_grow_with_the_btc_side_and_stop_at_one_btc() {
        let p = Policy::standard();
        assert_eq!(p.depth(Chain::Xbtc, Amount::from_sat(1_000_000)), Some(6));
        assert_eq!(p.depth(Chain::Xbtc, Amount::from_sat(1_000_001)), Some(12));
        assert_eq!(p.depth(Chain::Xbtc, Amount::ONE_BTC), Some(36));
        assert_eq!(p.depth(Chain::Btc, Amount::from_sat(50_000_000)), Some(3));
        assert_eq!(p.depth(Chain::Btc, Amount::from_sat(100_000_001)), None);
    }

    #[test]
    fn an_offer_cannot_lower_the_depths_that_protect_us() {
        // The offer asks for 0 confirmations; 0.9 BTC against xBTC gets 36 xBTC and 3 BTC.
        let d = Policy::standard().depths(
            &offer(288, 144),
            Amount::from_sat(300_000_000),
            Amount::from_sat(90_000_000),
        );
        assert_eq!(
            d,
            Ok(Depths {
                maker_lock: 36,
                taker_lock: 3,
                maker_final: 36,
                taker_final: 3
            })
        );
    }

    #[test]
    fn an_offer_may_ask_for_more() {
        let mut o = offer(288, 144);
        o.taker_lock_depth = 10;
        let d = Policy::standard()
            .depths(
                &o,
                Amount::from_sat(300_000_000),
                Amount::from_sat(90_000_000),
            )
            .unwrap();
        assert_eq!(d.taker_lock, 10);
    }

    #[test]
    fn swaps_above_the_limit_and_too_short_timelocks_are_refused() {
        let p = Policy::standard();
        let big = Amount::from_sat(100_000_001);
        assert_eq!(
            p.depths(&offer(288, 144), Amount::from_sat(300_000_001), big),
            Err(PolicyError::AmountAboveLimit)
        );
        // 36 + 3 + 144 + 6 + 36 = 225 blocks of room needed on the maker's lock.
        let small = (Amount::from_sat(300_000_000), Amount::from_sat(90_000_000));
        assert_eq!(
            p.depths(&offer(225, 144), small.0, small.1),
            Err(PolicyError::TimelocksTooShort)
        );
        assert!(p.depths(&offer(226, 144), small.0, small.1).is_ok());
        // 3 + 6 + 3 = 12 blocks of room on the taker's lock.
        assert_eq!(
            p.depths(&offer(288, 12), small.0, small.1),
            Err(PolicyError::TimelocksTooShort)
        );
    }

    #[test]
    fn min_lock_blocks_pass_the_depths_check_for_any_amount() {
        let policy = Policy::standard();
        // Across the policy table (small to the cap), the sized locks must satisfy `depths`.
        for sat in [500_000u64, 50_000_000, 100_000_000] {
            let o = {
                let mut o = offer(0, 0);
                o.maker_amount = Amount::from_sat(sat);
                o.taker_amount = Amount::from_sat((sat as f64 * 0.997) as u64);
                o
            };
            let (m, t) = policy
                .min_lock_blocks(
                    o.maker_chain,
                    o.maker_amount,
                    o.taker_amount,
                    1,
                    1,
                    o.margin_blocks,
                )
                .expect("within the table");
            let sized = Offer {
                maker_lock_blocks: m,
                taker_lock_blocks: t,
                ..o.clone()
            };
            policy
                .depths(&sized, sized.maker_amount, sized.taker_amount)
                .expect("sized timelocks satisfy depths");
        }
    }

    #[test]
    fn btc_maker_timelocks_are_normalized_to_wall_clock() {
        // #74: a BTC-maker offer (maker locks BTC ~10m, taker locks xBTC ~13m). The two taker-chain
        // terms in the maker's room must be scaled up to maker-chain blocks, so the required
        // maker_lock_blocks is larger than the un-normalized sum.
        let p = Policy::standard();
        let amt = Amount::from_sat(500_000); // BTC side; depth(Btc)=1, depth(Xbtc)=6
        let base = Offer {
            maker_chain: Chain::Btc,
            maker_amount: amt,
            taker_amount: amt,
            margin_blocks: 6,
            ..offer(0, 0)
        };
        // The sizing helper satisfies `depths` in this direction too (per-term conversion matches).
        let (m, t) = p
            .min_lock_blocks(Chain::Btc, amt, amt, 1, 1, 6)
            .expect("within the table");
        // Normalized: maker 1 + ceil(6*780/600)=8 + ceil(20*780/600)=26 + margin 6 + final 1 + head 2
        // = 44; the un-normalized formula would have been 36. Taker leg (all xBTC) is unchanged at 20.
        assert_eq!((m, t), (44, 20));
        let sized = Offer {
            maker_lock_blocks: m,
            taker_lock_blocks: t,
            ..base.clone()
        };
        p.depths(&sized, amt, amt)
            .expect("normalized sizing satisfies depths");
        // An offer sized at the OLD (un-normalized) maker minimum of 36 is now rejected as too short:
        // exactly the non-conservative gap #74 closed.
        let old_min = Offer {
            maker_lock_blocks: 36,
            taker_lock_blocks: 20,
            ..base
        };
        assert_eq!(
            p.depths(&old_min, amt, amt),
            Err(PolicyError::TimelocksTooShort)
        );
    }
}

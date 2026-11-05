//! This engine's own confirmation rules. An offer can ask for more, never for less: the maker writes
//! the offer, so depths that protect the taker cannot be left to the maker.

use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use crate::swap::{Chain, Offer};

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
        let maker_room = depths.maker_lock
            + depths.taker_lock
            + u32::from(offer.taker_lock_blocks)
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
}

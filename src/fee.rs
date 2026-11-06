//! The voluntary fee amount (design 0010, spec 7.5): a static rate per side, a floor, and a minimum
//! trade. This is only the amount; the output itself (a silent payment output, see
//! [`crate::silentpayments`]) and its placement on the funding transaction are the engine's job, and
//! happen only when the fee is switched on. The fee is an EXTRA output funded by the payer, never
//! carved out of the amount being swapped.

use bitcoin::Amount;

use crate::swap::Role;

/// The smallest fee output we will create, well above any dust limit so a fee is always spendable.
pub const FLOOR_SAT: u64 = 1_000;

/// The smallest trade the fee path will act on (0.001 BTC, spec 7.5). Below this the proportional
/// fee is meaningless against the floor, so the fee is simply not applied.
pub const MIN_TRADE_SAT: u64 = 100_000;

/// The static per-side rates, in basis points (hundredths of a percent). Defaults 20 / 30 (spec 7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeeRates {
    pub maker_bps: u16,
    pub taker_bps: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FeeError {
    /// The trade is below the minimum the fee path acts on.
    BelowMinimum,
}

impl FeeRates {
    fn bps(&self, role: Role) -> u64 {
        match role {
            Role::Maker => self.maker_bps,
            Role::Taker => self.taker_bps,
        }
        .into()
    }
}

/// The fee for locking `locked` as `role`: the greater of the floor and `locked * rate`, or an error
/// if `locked` is below the minimum trade. A u128 intermediate keeps the product exact for any sat
/// amount up to the supply cap.
pub fn fee_amount(rates: FeeRates, role: Role, locked: Amount) -> Result<Amount, FeeError> {
    if locked.to_sat() < MIN_TRADE_SAT {
        return Err(FeeError::BelowMinimum);
    }
    let proportional = (u128::from(locked.to_sat()) * u128::from(rates.bps(role)) / 10_000) as u64;
    Ok(Amount::from_sat(proportional.max(FLOOR_SAT)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RATES: FeeRates = FeeRates {
        maker_bps: 20,
        taker_bps: 30,
    };

    #[test]
    fn proportional_above_the_floor() {
        // 1 BTC maker at 0.20 % = 200_000 sat; taker at 0.30 % = 300_000 sat.
        assert_eq!(
            fee_amount(RATES, Role::Maker, Amount::ONE_BTC),
            Ok(Amount::from_sat(200_000))
        );
        assert_eq!(
            fee_amount(RATES, Role::Taker, Amount::ONE_BTC),
            Ok(Amount::from_sat(300_000))
        );
    }

    #[test]
    fn small_trades_hit_the_floor() {
        // 0.001 BTC maker at 0.20 % = 200 sat, below the 1_000 sat floor.
        assert_eq!(
            fee_amount(RATES, Role::Maker, Amount::from_sat(MIN_TRADE_SAT)),
            Ok(Amount::from_sat(FLOOR_SAT))
        );
    }

    #[test]
    fn below_the_minimum_is_refused() {
        assert_eq!(
            fee_amount(RATES, Role::Maker, Amount::from_sat(MIN_TRADE_SAT - 1)),
            Err(FeeError::BelowMinimum)
        );
    }

    #[test]
    fn a_zero_rate_still_pays_the_floor() {
        let free = FeeRates {
            maker_bps: 0,
            taker_bps: 0,
        };
        assert_eq!(
            fee_amount(free, Role::Maker, Amount::ONE_BTC),
            Ok(Amount::from_sat(FLOOR_SAT))
        );
    }
}

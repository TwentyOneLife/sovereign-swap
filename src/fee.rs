//! The voluntary fee amount (design 0010, spec 7.5): a static rate per side, a floor, and a minimum
//! trade. This is only the amount; the output itself (a silent payment output, see
//! [`crate::silentpayments`]) and its placement on the funding transaction are the engine's job, and
//! happen only when the fee is switched on. The fee is an EXTRA output funded by the payer, never
//! carved out of the amount being swapped.

use bitcoin::Amount;

use crate::swap::Role;

/// The smallest fee output we will create, well above any dust limit so a fee is always spendable.
pub const FLOOR_SAT: u64 = 1_000;

/// The default smallest trade the fee path will act on (0.001 BTC, spec 7.5). Below this the
/// proportional fee is meaningless against the floor, so the fee is simply not applied. The runtime
/// value is configurable (daemon setting `min_trade_sat`, threaded into the engine) and defaults to
/// this. The floor above is deliberately NOT configurable: it guards Bitcoin's dust limit.
pub const MIN_TRADE_SAT: u64 = 100_000;

/// The per-trade fee-vs-leg sanity band (F3, design 0010): the voluntary fee must not exceed this
/// fraction of the leg it rides. Enforced ONLY locally - a maker at publish and a taker before it
/// takes - never in counterparty fee verification, so an old and a new peer never disagree over an
/// offer. Belt-and-braces: under today's constants it cannot fire, because the swap minimum
/// (`MIN_SWAP_FLOOR_SAT`, 3000) keeps the 1000-sat fee floor to at most ~33% of the smallest leg. It
/// guards only against a later change to the floor, the bps cap, or the swap minimum.
pub const MAX_FEE_FRACTION_BPS: u64 = 5_000; // 50%

/// True when `fee` is more than [`MAX_FEE_FRACTION_BPS`] of `locked` (the F3 band). u128 intermediates
/// keep the comparison exact for any sat amount.
pub fn fee_exceeds_band(fee: Amount, locked: Amount) -> bool {
    u128::from(fee.to_sat()) * 10_000
        > u128::from(locked.to_sat()) * u128::from(MAX_FEE_FRACTION_BPS)
}

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
/// if `locked` is below the minimum trade. Uses the default [`MIN_TRADE_SAT`]; see [`fee_amount_min`]
/// for the configurable form.
pub fn fee_amount(rates: FeeRates, role: Role, locked: Amount) -> Result<Amount, FeeError> {
    fee_amount_min(rates, role, locked, MIN_TRADE_SAT)
}

/// As [`fee_amount`], but with the minimum trade `min_trade_sat` passed in rather than read from the
/// [`MIN_TRADE_SAT`] default, so a deployment can lower it through config. The floor ([`FLOOR_SAT`])
/// is never configurable: it guards Bitcoin's dust limit. A u128 intermediate keeps the product exact
/// for any sat amount up to the supply cap.
pub fn fee_amount_min(
    rates: FeeRates,
    role: Role,
    locked: Amount,
    min_trade_sat: u64,
) -> Result<Amount, FeeError> {
    if locked.to_sat() < min_trade_sat {
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
    fn fee_vs_leg_band() {
        // The worst case under today's constants: the 1000-sat floor on the smallest 3000-sat leg is
        // 33%, inside the 50% band.
        assert!(!fee_exceeds_band(
            Amount::from_sat(1_000),
            Amount::from_sat(3_000)
        ));
        // Just under 50% passes, just over fails (leg under 2000 so the floor could exceed the band
        // only if the swap minimum were lowered below it - which it is not).
        assert!(!fee_exceeds_band(
            Amount::from_sat(1_000),
            Amount::from_sat(2_001)
        ));
        assert!(fee_exceeds_band(
            Amount::from_sat(1_000),
            Amount::from_sat(1_999)
        ));
        // Equal fee and leg is well over the band.
        assert!(fee_exceeds_band(
            Amount::from_sat(500),
            Amount::from_sat(500)
        ));
    }

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
    fn a_lowered_min_trade_applies_the_fee_to_a_small_trade() {
        // A 200-sat trade is below the default minimum, so no fee is due.
        assert_eq!(
            fee_amount(RATES, Role::Maker, Amount::from_sat(200)),
            Err(FeeError::BelowMinimum)
        );
        // Lower the configured minimum to 50 and the fee applies, hitting the floor on so small a trade.
        assert_eq!(
            fee_amount_min(RATES, Role::Maker, Amount::from_sat(200), 50),
            Ok(Amount::from_sat(FLOOR_SAT))
        );
        // The floor is independent of the minimum: a trade just under the lowered minimum is refused.
        assert_eq!(
            fee_amount_min(RATES, Role::Maker, Amount::from_sat(49), 50),
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

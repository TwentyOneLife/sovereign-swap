//! Market-anchored offer pricing (design 0025). The nonkyc `BTCB2_BTC` reference is the default and
//! the anchor for an offer's price. A human maker moves off it by a whole-percent margin
//! (`margin_pct`, 1% steps); how far off-market an offer may sit is an operator setting
//! (`price_band_pct`), not a compiled-in constant. Automation never invents a rate: with no explicit
//! in-band price it gets the market rate, and a raw off-market `counter_amount_sat` is rejected rather
//! than taken verbatim (that is the hole this closes). All checks are local (publish + pre-take), like
//! the F3 fee band, so there is no wire-format change.

use crate::daemon::Chain;

/// The market price in *counter coin per unit of the sold coin*, derived from the nonkyc reference
/// `rate` (BTC per xBTC). Selling BTC, the price is xBTC per BTC = `1/rate`; selling xBTC, it is `rate`.
/// `None` for a non-finite or non-positive rate (a garbage ticker is "no reference", never a zero).
pub(crate) fn market_price(sell_chain: Chain, rate: f64) -> Option<f64> {
    if !rate.is_finite() || rate <= 0.0 {
        return None;
    }
    Some(match sell_chain {
        Chain::Btc => 1.0 / rate,
        Chain::Xbtc => rate,
    })
}

/// The effective price after a whole-percent maker margin. Positive earns the maker more (asks more of
/// the counter coin than the market); negative undercuts the market to fill faster.
pub(crate) fn effective_price(market: f64, margin_pct: i32) -> f64 {
    market * (1.0 + margin_pct as f64 / 100.0)
}

/// Whether `price` sits within `band_pct` percent of `market`, either side. A tiny epsilon absorbs the
/// float round-trip so an exactly-at-the-band price is not spuriously rejected.
pub(crate) fn in_band(price: f64, market: f64, band_pct: u32) -> bool {
    if !price.is_finite() || !market.is_finite() || market <= 0.0 || price <= 0.0 {
        return false;
    }
    (price / market - 1.0).abs() <= band_pct as f64 / 100.0 + 1e-9
}

/// The counter amount in sats for `amount_sat` at `price`, rounded UP so integer rounding favours the
/// maker (the taker pays at most one extra sat), never down into the maker's loss.
pub(crate) fn counter_from(amount_sat: u64, price: f64) -> u64 {
    (amount_sat as f64 * price).ceil() as u64
}

/// The allowed price range `[lo, hi]` at `band_pct` around `market`, for an error message.
pub(crate) fn band_range(market: f64, band_pct: u32) -> (f64, f64) {
    let f = band_pct as f64 / 100.0;
    (market * (1.0 - f), market * (1.0 + f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn market_price_is_direction_aware() {
        // nonkyc rate ~0.00339 BTC per xBTC.
        let rate = 0.00339094;
        // Selling BTC: price is xBTC per BTC, ~295.
        let p = market_price(Chain::Btc, rate).unwrap();
        assert!((p - 1.0 / rate).abs() < 1e-9);
        assert!((294.0..296.0).contains(&p));
        // Selling xBTC: price is BTC per xBTC = rate.
        assert!((market_price(Chain::Xbtc, rate).unwrap() - rate).abs() < 1e-12);
    }

    #[test]
    fn garbage_rate_is_no_reference() {
        assert!(market_price(Chain::Btc, 0.0).is_none());
        assert!(market_price(Chain::Btc, -1.0).is_none());
        assert!(market_price(Chain::Btc, f64::NAN).is_none());
        assert!(market_price(Chain::Btc, f64::INFINITY).is_none());
    }

    #[test]
    fn margin_moves_in_whole_percent() {
        let m = 295.0;
        assert!((effective_price(m, 0) - 295.0).abs() < 1e-9);
        assert!((effective_price(m, 1) - 297.95).abs() < 1e-9); // +1%
        assert!((effective_price(m, -2) - 289.1).abs() < 1e-9); // -2%
    }

    #[test]
    fn band_rejects_off_market_and_accepts_within() {
        let market = 295.0;
        let band = 10; // 10%
        assert!(in_band(295.0, market, band)); // exactly market
        assert!(in_band(324.0, market, band)); // +9.8%
        assert!(in_band(266.0, market, band)); // -9.8%
        assert!(!in_band(1.0, market, band)); // the 1:1 hole: ~0.3% of market -> rejected
        assert!(!in_band(330.0, market, band)); // +11.9% -> rejected
        assert!(in_band(324.5, market, band)); // +10% exactly, epsilon-safe
    }

    #[test]
    fn the_one_to_one_hole_is_closed() {
        // A 5000:5000 sell-BTC offer implies price 1.0; the market is ~295. It is far out of any sane
        // band, so it is rejected. This is the exact offer that slipped through before.
        let market = market_price(Chain::Btc, 0.00339094).unwrap();
        assert!(!in_band(1.0, market, 10));
        assert!(!in_band(1.0, market, 50));
    }

    #[test]
    fn counter_rounds_up_for_the_maker() {
        // 5000 sat BTC at ~294.96 xBTC per BTC -> 1_474_800 xBTC, ceil.
        assert_eq!(counter_from(5000, 294.96), 1_474_800);
        assert_eq!(counter_from(3, 0.5), 2); // 1.5 -> ceil 2, maker-favourable
    }
}

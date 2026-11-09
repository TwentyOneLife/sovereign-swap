//! Optional price proxy (#106): the relay fetches the nonkyc BTCB2/BTC ticker over the CLEAR internet
//! on a timer and caches it, so connected clients can read the rate from the relay's NIP-11 document
//! over Tor instead of each client fetching a centralized exchange directly (nonkyc blocks many Tor
//! exits, so a direct per-client fetch is flaky).
//!
//! Privacy, a hard requirement of this feature:
//! - The fetch reveals only THIS relay's own IP to the exchange, never a client's: clients read the
//!   cached value from the relay over Tor and never touch the exchange.
//! - The cached value is public market data. Nothing about who requested it is stored or logged.
//! - This module logs ONLY when reachability flips (reachable <-> unreachable), never per request,
//!   never a header, never an address. `curl` runs without `-v` so no connection detail is emitted.
//!
//! Off by default: the relay runs the proxy only when the operator enables it (`RELAY_PRICE_PROXY`).

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const URL: &str = "https://api.nonkyc.io/api/v2/ticker/BTCB2_BTC";
pub const SOURCE: &str = "nonkyc BTCB2/BTC";
const REFRESH: Duration = Duration::from_secs(60);
/// A cached price older than this is not served. A relay whose fetch has been failing must not keep
/// presenting an old number as live: that would silently defeat the sanity check the client uses it
/// for. The relay enforces this at serve time and the client enforces it again on its side.
pub const MAX_AGE_SECS: u64 = 300;

/// The cached reference price. `rate` is BTC per xBTC (the last trade); `bid`/`ask` may be NaN when
/// the ticker omits them. `as_of` is the unix second the value was fetched, used for the staleness cut.
#[derive(Clone, Copy)]
pub struct CachedPrice {
    pub rate: f64,
    pub bid: f64,
    pub ask: f64,
    pub as_of: u64,
}

pub type PriceCache = Arc<Mutex<Option<CachedPrice>>>;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Starts the fetch loop in a background thread. Updates `cache` on each success and leaves the last
/// value in place on a failure (the serve-time age check drops it once it is stale). Logs only when
/// reachability changes, so a flapping exit or a down endpoint does not spam the journal.
pub fn spawn(cache: PriceCache) {
    std::thread::spawn(move || {
        let mut last_ok: Option<bool> = None;
        loop {
            let ok = match fetch() {
                Some((rate, bid, ask)) => {
                    *cache.lock().unwrap() = Some(CachedPrice {
                        rate,
                        bid,
                        ask,
                        as_of: now_secs(),
                    });
                    true
                }
                None => false,
            };
            if last_ok != Some(ok) {
                eprintln!(
                    "price proxy: nonkyc {}",
                    if ok {
                        "reachable"
                    } else {
                        "unreachable (serving the last value until it ages out)"
                    }
                );
                last_ok = Some(ok);
            }
            std::thread::sleep(REFRESH);
        }
    });
}

/// One clearnet fetch of the ticker. No Tor proxy (the whole point is to fetch from a stable IP the
/// exchange does not block), no `-v`, no header dump: only the body is read.
fn fetch() -> Option<(f64, f64, f64)> {
    let out = Command::new("curl")
        .args(["-sS", "--fail", "--max-time", "8", URL])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8(out.stdout).ok()?;
    parse(&body)
}

/// Parses `(rate, bid, ask)` from the nonkyc ticker JSON (a flat object of string fields). Mirrors
/// the client-side parser; kept here so the relay does not depend on the daemon's internals.
pub fn parse(json: &str) -> Option<(f64, f64, f64)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let num = |k: &str| v[k].as_str().and_then(|s| s.parse::<f64>().ok());
    Some((
        num("last_price")?,
        num("bid").unwrap_or(f64::NAN),
        num("ask").unwrap_or(f64::NAN),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_nonkyc_ticker() {
        let sample = r#"{"ticker_id":"BTCB2_BTC","last_price":"0.00385254","bid":"0.00384102","ask":"0.00386028"}"#;
        let (rate, bid, ask) = parse(sample).unwrap();
        assert!((rate - 0.00385254).abs() < 1e-12);
        assert!((bid - 0.00384102).abs() < 1e-12);
        assert!((ask - 0.00386028).abs() < 1e-12);
        assert!(parse("not json").is_none());
        // last_price is required; without it there is no rate to serve.
        assert!(parse(r#"{"bid":"1"}"#).is_none());
    }
}

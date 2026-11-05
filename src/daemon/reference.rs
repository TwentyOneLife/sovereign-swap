//! Optional, opt-in external price reference (design 0009): the daemon fetches nonkyc's BTCB2/BTC
//! ticker over Tor as a pricing *hint*, never something the protocol relies on. Off by default.
//!
//! Privacy: the fetch always goes through the Tor SOCKS proxy, so the user's IP never reaches a
//! centralized exchange; it is the daemon that fetches (not the browser), and the route is
//! token-guarded, so a cross-origin page cannot trigger it. The result is a hint beside the
//! order-book hint; the maker still sets the price and the protocol never depends on it.
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

const URL: &str = "https://api.nonkyc.io/api/v2/ticker/BTCB2_BTC";
const SOCKS: &str = "127.0.0.1:9050";
const TTL: Duration = Duration::from_secs(60);

/// BTCB2(xBTC)/BTC prices. `rate` is BTC per xBTC (the last trade).
#[derive(Clone, Copy)]
pub(crate) struct ReferenceRate {
    pub(crate) rate: f64,
    pub(crate) bid: f64,
    pub(crate) ask: f64,
}

#[derive(Default)]
pub(crate) struct Reference {
    cache: Mutex<Option<(ReferenceRate, Instant)>>,
}

impl Reference {
    /// The reference rate, cached for a minute. Fetches over Tor on a miss.
    pub(crate) fn get(&self) -> Result<ReferenceRate, String> {
        if let Some((r, at)) = *self.cache.lock().unwrap() {
            if at.elapsed() < TTL {
                return Ok(r);
            }
        }
        let body = fetch()?;
        let rate = parse_reference_rate(&body).ok_or("could not parse the reference ticker")?;
        *self.cache.lock().unwrap() = Some((rate, Instant::now()));
        Ok(rate)
    }
}

/// Always over Tor: the user's IP must not reach a centralized exchange. Shelling out to curl keeps
/// a TLS stack out of the core dependencies for an opt-in hint; a missing curl or a down Tor just
/// surfaces as an error and the GUI falls back to the order-book hint.
fn fetch() -> Result<String, String> {
    let out = Command::new("curl")
        .args(["-s", "--max-time", "8", "--socks5-hostname", SOCKS, URL])
        .output()
        .map_err(|e| format!("curl not available: {e}"))?;
    if !out.status.success() {
        return Err("reference fetch failed (is Tor running?)".to_owned());
    }
    String::from_utf8(out.stdout).map_err(|_| "non-utf8 response".to_owned())
}

pub(crate) fn parse_reference_rate(json: &str) -> Option<ReferenceRate> {
    let v: Value = serde_json::from_str(json).ok()?;
    let num = |k: &str| v[k].as_str().and_then(|s| s.parse::<f64>().ok());
    Some(ReferenceRate {
        rate: num("last_price")?,
        bid: num("bid").unwrap_or(f64::NAN),
        ask: num("ask").unwrap_or(f64::NAN),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_nonkyc_ticker() {
        let sample = r#"{"ticker_id":"BTCB2_BTC","last_price":"0.00385254","bid":"0.00384102","ask":"0.00386028"}"#;
        let r = parse_reference_rate(sample).unwrap();
        assert!((r.rate - 0.00385254).abs() < 1e-12);
        assert!((r.bid - 0.00384102).abs() < 1e-12);
        assert!(parse_reference_rate("not json").is_none());
    }
}

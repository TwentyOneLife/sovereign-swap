//! Optional, opt-in external price reference (design 0009): the daemon fetches nonkyc's BTCB2/BTC
//! ticker over Tor as a pricing *hint*, never something the protocol relies on. Off by default.
//!
//! Privacy: the fetch always goes through the Tor SOCKS proxy, so the user's IP never reaches a
//! centralized exchange; it is the daemon that fetches (not the browser), and the route is
//! token-guarded, so a cross-origin page cannot trigger it. The result is a hint beside the
//! order-book hint; the maker still sets the price and the protocol never depends on it.
//!
//! The proxy address is NOT hardcoded here: it is the same address the engine dials nodes and the
//! relay through (`SWAP_TOR_SOCKS`, else the `tor_socks` setting), passed in by the caller. A fixed
//! `127.0.0.1:9050` was wrong on StartOS, where Tor lives at an injected bridge address and the
//! fetch silently failed while the rest of the daemon worked.
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::Value;

const URL: &str = "https://api.nonkyc.io/api/v2/ticker/BTCB2_BTC";
/// A good result is a minute fresh; a failure is re-tried sooner so a transient Tor hiccup clears
/// without the header dot staying red for a full minute.
const TTL_OK: Duration = Duration::from_secs(60);
const TTL_ERR: Duration = Duration::from_secs(15);

/// BTCB2(xBTC)/BTC prices. `rate` is BTC per xBTC (the last trade).
#[derive(Clone, Copy)]
pub(crate) struct ReferenceRate {
    pub(crate) rate: f64,
    pub(crate) bid: f64,
    pub(crate) ask: f64,
}

#[derive(Default)]
pub(crate) struct Reference {
    /// The last outcome and when it was taken. Both success and failure are cached (failure for a
    /// shorter window), so the header polling the rate every few seconds never spawns a fresh curl
    /// per request.
    cache: Mutex<Option<(Result<ReferenceRate, String>, Instant)>>,
}

impl Reference {
    /// The reference rate, cached. Fetches over Tor (through `socks`) on a miss or once stale.
    pub(crate) fn get(&self, socks: &str) -> Result<ReferenceRate, String> {
        if let Some((res, at)) = self.cache.lock().unwrap().as_ref() {
            let ttl = if res.is_ok() { TTL_OK } else { TTL_ERR };
            if at.elapsed() < ttl {
                return res.clone();
            }
        }
        let result = fetch(socks).and_then(|body| {
            parse_reference_rate(&body)
                .ok_or_else(|| "could not parse the reference ticker".to_owned())
        });
        *self.cache.lock().unwrap() = Some((result.clone(), Instant::now()));
        result
    }
}

/// Always over Tor: the user's IP must not reach a centralized exchange. Shelling out to curl keeps
/// a TLS stack out of the core dependencies for an opt-in hint; a missing curl or a down Tor just
/// surfaces as an error and the GUI falls back to the order-book hint. `--socks5-hostname` is
/// socks5h (the proxy resolves the host), so no DNS leaks around Tor.
fn fetch(socks: &str) -> Result<String, String> {
    let out = Command::new("curl")
        .args([
            "-sS",
            "--fail",
            "--max-time",
            "8",
            "--socks5-hostname",
            socks,
            URL,
        ])
        .output()
        .map_err(|e| format!("curl not available: {e}"))?;
    if out.status.success() {
        return String::from_utf8(out.stdout).map_err(|_| "non-utf8 response".to_owned());
    }
    let detail = String::from_utf8_lossy(&out.stderr);
    Err(classify_curl_failure(
        out.status.code(),
        socks,
        detail.trim(),
    ))
}

/// Turn a curl exit code into an accurate, actionable reason. The point is to stop reporting every
/// failure as "is Tor running?": a wrong proxy address, a cold-circuit timeout, a missing CA bundle
/// in the container, and an HTTP block of the Tor exit are different problems with different fixes.
/// `--fail` makes an HTTP error (a 403 Tor-exit block is common) exit 22 instead of parsing as a
/// bad ticker.
fn classify_curl_failure(code: Option<i32>, socks: &str, detail: &str) -> String {
    let reason = match code {
        Some(5) | Some(7) | Some(97) => {
            format!("cannot reach the Tor SOCKS proxy at {socks} (is Tor running there?)")
        }
        Some(6) => "the proxy could not resolve the exchange host".to_owned(),
        Some(28) => "timed out over Tor (the circuit may be cold, retry)".to_owned(),
        Some(22) => {
            "the exchange refused the request, an HTTP error (a Tor-exit block?)".to_owned()
        }
        Some(35) | Some(60) | Some(77) => {
            "TLS failed (a CA bundle may be missing in the container)".to_owned()
        }
        Some(c) => format!("curl exit {c}"),
        None => "curl was terminated".to_owned(),
    };
    if detail.is_empty() {
        format!("reference fetch failed: {reason}")
    } else {
        format!("reference fetch failed: {reason} [{detail}]")
    }
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
        // The real shape, confirmed against the live endpoint: a flat object of string fields.
        let sample = r#"{"ticker_id":"BTCB2_BTC","last_price":"0.00385254","bid":"0.00384102","ask":"0.00386028"}"#;
        let r = parse_reference_rate(sample).unwrap();
        assert!((r.rate - 0.00385254).abs() < 1e-12);
        assert!((r.bid - 0.00384102).abs() < 1e-12);
        assert!(parse_reference_rate("not json").is_none());
    }

    #[test]
    fn curl_failures_are_classified() {
        // A proxy-connect failure names the proxy address, not a blanket "is Tor running?".
        let proxy = classify_curl_failure(Some(7), "127.0.0.1:9050", "");
        assert!(proxy.contains("SOCKS proxy at 127.0.0.1:9050"));
        // An HTTP error (e.g. a 403 Tor-exit block) is distinct from a parse failure.
        assert!(classify_curl_failure(Some(22), "127.0.0.1:9050", "").contains("HTTP error"));
        assert!(classify_curl_failure(Some(28), "127.0.0.1:9050", "").contains("timed out"));
        assert!(classify_curl_failure(Some(60), "127.0.0.1:9050", "").contains("TLS"));
        // stderr detail is appended when curl provides it.
        assert!(classify_curl_failure(Some(7), "127.0.0.1:9050", "boom").ends_with("[boom]"));
    }
}

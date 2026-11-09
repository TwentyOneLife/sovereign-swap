//! Optional, opt-in external price reference (design 0009): a pricing *hint*, never something the
//! protocol relies on. Off by default.
//!
//! Source, in order (#106): a **relay's price proxy** first (the relay fetches the exchange
//! clearnet-side and serves the rate in its NIP-11 document, so the client reads it over Tor and the
//! client's IP never reaches the exchange), then a **direct** fetch of the exchange over Tor as a
//! fallback. Both go through the Tor SOCKS proxy; the client never fetches clearnet.
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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

/// Where a reference rate came from: a relay's price proxy, or a direct fetch of the exchange. Both
/// go over Tor; the distinction is shown to the operator and lets the relay path be preferred.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum RateVia {
    Relay,
    Direct,
}

/// A cached outcome (success carries the rate and where it came from) and when it was taken.
type Cached = (Result<(ReferenceRate, RateVia), String>, Instant);

#[derive(Default)]
pub(crate) struct Reference {
    /// The last outcome and when it was taken. Both success and failure are cached (failure for a
    /// shorter window), so the header polling the rate every few seconds never spawns a fresh curl
    /// per request.
    cache: Mutex<Option<Cached>>,
}

impl Reference {
    /// The reference rate, cached. Prefers a relay's price proxy (#106): the relay fetches the
    /// exchange clearnet-side and serves the rate in its NIP-11 document, so the client reads it over
    /// Tor and its IP never reaches the exchange. Falls back to a direct fetch of the exchange over
    /// Tor when no relay offers a fresh price. Never fetches clearnet from the client.
    pub(crate) fn get(
        &self,
        relays: &[String],
        socks: &str,
    ) -> Result<(ReferenceRate, RateVia), String> {
        if let Some((res, at)) = self.cache.lock().unwrap().as_ref() {
            let ttl = if res.is_ok() { TTL_OK } else { TTL_ERR };
            if at.elapsed() < ttl {
                return res.clone();
            }
        }
        // 1) A relay's price proxy, over Tor. First relay with a fresh price wins.
        let mut result = None;
        for relay in relays {
            if let Some(rate) = fetch_relay_price(relay, socks) {
                result = Some(Ok((rate, RateVia::Relay)));
                break;
            }
        }
        // 2) Fall back to a direct fetch of the exchange, still over Tor.
        let result = result.unwrap_or_else(|| {
            fetch(socks)
                .and_then(|body| {
                    parse_reference_rate(&body)
                        .ok_or_else(|| "could not parse the reference ticker".to_owned())
                })
                .map(|r| (r, RateVia::Direct))
        });
        *self.cache.lock().unwrap() = Some((result.clone(), Instant::now()));
        result
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetches a relay's NIP-11 document over Tor and reads `swap_relay.price`, if the relay runs the
/// price proxy and the value is fresh (within [`crate::relay_price::MAX_AGE_SECS`]). Returns `None`
/// on any error, a missing price, or a stale one, so the caller moves on to the next relay or the
/// direct fetch. A `ws(s)://host:port` relay URL maps to `http(s)://host:port`; only this GET is made,
/// never a websocket, and always through the Tor proxy for an onion.
fn fetch_relay_price(relay: &str, socks: &str) -> Option<ReferenceRate> {
    let url = relay
        .trim_end_matches('/')
        .replacen("wss://", "https://", 1)
        .replacen("ws://", "http://", 1);
    let onion = url.contains(".onion");
    let mut cmd = Command::new("curl");
    cmd.args(["-sS", "--fail", "--max-time", "8"]);
    if onion {
        cmd.args(["--socks5-hostname", socks]);
    }
    cmd.args(["-H", "Accept: application/nostr+json", &url]);
    let out = cmd.output().ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8(out.stdout).ok()?;
    parse_relay_price(&body, now_unix())
}

/// Reads `swap_relay.price` from a relay's NIP-11 document, rejecting a value staler than
/// [`crate::relay_price::MAX_AGE_SECS`] (a relay whose own fetch has been failing must not have its
/// old number trusted as live). Pure (`now` is passed in) so it is unit-testable without a relay.
fn parse_relay_price(body: &str, now: u64) -> Option<ReferenceRate> {
    let v: Value = serde_json::from_str(body).ok()?;
    let price = &v["swap_relay"]["price"];
    let as_of = price["as_of"].as_u64()?;
    if now.saturating_sub(as_of) >= crate::relay_price::MAX_AGE_SECS {
        return None;
    }
    Some(ReferenceRate {
        rate: price["rate"].as_f64()?,
        bid: price["bid"].as_f64().unwrap_or(f64::NAN),
        ask: price["ask"].as_f64().unwrap_or(f64::NAN),
    })
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
    fn relay_price_is_taken_when_fresh_and_rejected_when_stale_or_absent() {
        let now = 1_000_000u64;
        let doc = |as_of: u64| {
            format!(
                r#"{{"swap_relay":{{"price":{{"source":"x","rate":0.00385,"bid":null,"ask":0.00386,"as_of":{as_of}}}}}}}"#
            )
        };
        // Fresh: parsed, with the rate; a null bid comes through as NaN.
        let r = parse_relay_price(&doc(now), now).unwrap();
        assert!((r.rate - 0.00385).abs() < 1e-12);
        assert!(r.bid.is_nan());
        assert!((r.ask - 0.00386).abs() < 1e-12);
        // Stale (older than the max age): rejected, so a dead relay fetch is not trusted.
        assert!(parse_relay_price(&doc(now - crate::relay_price::MAX_AGE_SECS - 1), now).is_none());
        // No price field (proxy off) or no as_of: rejected.
        assert!(parse_relay_price(r#"{"swap_relay":{}}"#, now).is_none());
        assert!(parse_relay_price("not json", now).is_none());
    }

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

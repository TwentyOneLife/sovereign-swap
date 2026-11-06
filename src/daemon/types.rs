//! The daemon's data types: the user-facing settings, the offer forms, and amount parsing.
use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use crate::swap::{Chain as SwapChain, Offer as SwapOffer};

use super::engine::{engine_config, MAKER_LOCK_BLOCKS, TAKER_LOCK_BLOCKS};
use super::wire::random16;

/// Below this an amount is dust; an offer under it is refused.
pub(crate) const DUST_SAT: u64 = 10_000;

/// A sane band for a swap price, so a fat-fingered or hostile rate is caught before it is published.
pub(crate) const MIN_PRICE: f64 = 0.5;

pub(crate) const MAX_PRICE: f64 = 2.0;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Signer {
    /// Spending keys stay offline; the daemon proposes, an external signer approves. The norm.
    Cold,
    /// The node wallet signs. Regtest and testing only.
    Hot,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Btc,
    Xbtc,
}

/// The user-facing settings, saved in the data dir and reloaded on start. Separate from the engine's
/// internal `Config`/`Policy`: this is what a person edits, not the safety-critical invariants the
/// engine enforces regardless.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Settings {
    pub btc_node: String,
    pub xbtc_node: String,
    pub relays: Vec<String>,
    pub signer: Signer,
    pub btc_conf: u32,
    pub xbtc_conf: u32,
    pub margin_blocks: u16,
    /// Node RPC credentials. Local to the daemon (data dir, mode 600); not a key to funds (the
    /// funding wallet is watch-only, 0008). Absent in older config, hence `serde(default)`.
    #[serde(default)]
    pub btc_rpc_user: String,
    #[serde(default)]
    pub btc_rpc_pass: String,
    #[serde(default)]
    pub xbtc_rpc_user: String,
    #[serde(default)]
    pub xbtc_rpc_pass: String,
    /// Opt-in external price reference (nonkyc BTCB2/BTC, fetched over Tor). A hint only; off by default.
    #[serde(default)]
    pub price_reference: bool,
    /// Voluntary fee, off by default (design 0010). Off keeps the engine on today's lock path with no
    /// fee output and no BIP352 code. Stays off until a legal opinion.
    #[serde(default)]
    pub fee_enabled: bool,
    /// The operator's published silent payment address (BIP352). Each swap pays a fresh, unlinkable
    /// output derived from it. Required when `fee_enabled`; ignored otherwise.
    #[serde(default)]
    pub fee_sp_address: String,
    /// Maker fee, basis points (default 20 = 0.20 %). See design 0010 / spec 7.5.
    #[serde(default = "default_fee_maker_bps")]
    pub fee_maker_bps: u16,
    /// Taker fee, basis points (default 30 = 0.30 %).
    #[serde(default = "default_fee_taker_bps")]
    pub fee_taker_bps: u16,
}

/// The largest fee a setting may ask for: a guard against a fat-finger, not a policy (spec 7.5 sets
/// the real defaults far below this). One percent is already well above any sane swap fee.
pub(crate) const MAX_FEE_BPS: u16 = 100;

fn default_fee_maker_bps() -> u16 {
    20
}
fn default_fee_taker_bps() -> u16 {
    30
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            btc_node: "127.0.0.1:8332".to_owned(),
            xbtc_node: "127.0.0.1:8442".to_owned(),
            relays: Vec::new(),
            signer: Signer::Cold,
            btc_conf: 1,
            xbtc_conf: 2,
            margin_blocks: 2,
            btc_rpc_user: String::new(),
            btc_rpc_pass: String::new(),
            xbtc_rpc_user: String::new(),
            xbtc_rpc_pass: String::new(),
            price_reference: false,
            fee_enabled: false,
            fee_sp_address: String::new(),
            fee_maker_bps: default_fee_maker_bps(),
            fee_taker_bps: default_fee_taker_bps(),
        }
    }
}

impl Settings {
    /// Authoritative validation (design 0009 layer 2). Returns one message per bad field; empty means
    /// valid. The engine enforces the safety-critical invariants regardless, but we refuse nonsense
    /// here so it never reaches the engine and so the GUI can show the reasons.
    pub fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        for (name, addr) in [("btc_node", &self.btc_node), ("xbtc_node", &self.xbtc_node)] {
            if !valid_host_port(addr) {
                e.push(format!("{name}: expected host:port"));
            }
        }
        for relay in &self.relays {
            if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
                e.push(format!("relay {relay}: must be a ws:// or wss:// URL"));
            }
        }
        if self.btc_conf < 1 || self.btc_conf > 100 {
            e.push("btc_conf: 1..=100".to_owned());
        }
        if self.xbtc_conf < 1 || self.xbtc_conf > 100 {
            e.push("xbtc_conf: 1..=100".to_owned());
        }
        if self.margin_blocks < 1 || self.margin_blocks > 1000 {
            e.push("margin_blocks: 1..=1000".to_owned());
        }
        if self.fee_maker_bps > MAX_FEE_BPS {
            e.push(format!("fee_maker_bps: 0..={MAX_FEE_BPS}"));
        }
        if self.fee_taker_bps > MAX_FEE_BPS {
            e.push(format!("fee_taker_bps: 0..={MAX_FEE_BPS}"));
        }
        // Only when the fee is switched on does the address matter. The signer's BIP352 capability is
        // checked where the live signer is known (the engine wiring), not in this pure validation; a
        // non-BIP352 signer refuses to enable fees there with a clear message (design 0010).
        if self.fee_enabled && !looks_like_sp_address(&self.fee_sp_address) {
            e.push(
                "fee_sp_address: a silent payment address is required when the fee is enabled"
                    .to_owned(),
            );
        }
        e
    }
}

/// A lightweight shape check for a silent payment address (BIP352): the bech32m `sp1`/`tsp1` prefix
/// and a plausible length. This is a settings guard only; the authoritative parse happens in the
/// BIP352 layer that derives the output (design 0010 step 3), which rejects anything malformed or on
/// the wrong network before a single sat is committed.
fn looks_like_sp_address(a: &str) -> bool {
    let a = a.trim();
    (a.starts_with("sp1") || a.starts_with("tsp1")) && a.len() >= 110 && a.len() <= 1023
}

/// What a `POST /offers` body must contain. Validated before an offer is created.
#[derive(Deserialize)]
pub(crate) struct NewOffer {
    pub(crate) sell_chain: Chain,
    pub(crate) amount_sat: u64,
    pub(crate) price: f64,
    pub(crate) min_amount_sat: u64,
}

impl NewOffer {
    pub(crate) fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        if self.amount_sat < DUST_SAT {
            e.push(format!("amount_sat: below dust ({DUST_SAT})"));
        }
        if self.amount_sat > 21_000_000 * 100_000_000 {
            e.push("amount_sat: above the supply cap".to_owned());
        }
        if !(self.price.is_finite() && (MIN_PRICE..=MAX_PRICE).contains(&self.price)) {
            e.push(format!("price: expected {MIN_PRICE}..={MAX_PRICE}"));
        }
        if self.min_amount_sat < DUST_SAT || self.min_amount_sat > self.amount_sat {
            e.push("min_amount_sat: between dust and amount_sat".to_owned());
        }
        e
    }

    /// Maps a validated API offer onto the engine's `Offer`. The timelocks and depths are defaults;
    /// the engine clamps them to policy regardless (design 0002), so the form cannot lower safety.
    pub(crate) fn into_swap_offer(self, s: &Settings) -> SwapOffer {
        let maker_chain = match self.sell_chain {
            Chain::Btc => SwapChain::Btc,
            Chain::Xbtc => SwapChain::Xbtc,
        };
        let taker_amount = Amount::from_sat((self.amount_sat as f64 * self.price).round() as u64);
        let maker_amount = Amount::from_sat(self.amount_sat);
        let margin = s.margin_blocks as u32;
        // Size the timelocks to the amount from policy, so a larger offer (needing deeper
        // confirmations) is not rejected for too-short locks. Fall back to the fixed defaults if the
        // amount is above the policy table; the engine then returns the precise error.
        let (maker_lock_blocks, taker_lock_blocks) = engine_config(s)
            .policy
            .min_lock_blocks(maker_chain, maker_amount, taker_amount, 1, 1, margin)
            .unwrap_or((MAKER_LOCK_BLOCKS, TAKER_LOCK_BLOCKS));
        SwapOffer {
            id: random16(),
            maker_chain,
            maker_amount,
            taker_amount,
            min_maker_amount: Amount::from_sat(self.min_amount_sat),
            maker_lock_blocks,
            taker_lock_blocks,
            maker_lock_depth: 1,
            taker_lock_depth: 1,
            margin_blocks: margin,
        }
    }
}

/// Parses a BTC amount string into satoshis, accepting either `.` or `,` as the decimal separator
/// (a European `0,5` and an English `0.5` both mean half a coin). This is the canonical normalizer the
/// GUI uses before it calls the sats-only API, so a locale never reaches the protocol. A string with
/// both separators is ambiguous (thousands grouping) and refused rather than guessed; more than eight
/// decimals is sub-satoshi and refused.
pub fn parse_btc_to_sats(input: &str) -> Option<u64> {
    let s = input.trim();
    if s.contains('.') && s.contains(',') {
        return None;
    }
    let norm = s.replace(',', ".");
    let (whole, frac) = match norm.split_once('.') {
        Some((w, f)) => (w, f),
        None => (norm.as_str(), ""),
    };
    if (whole.is_empty() && frac.is_empty()) || frac.len() > 8 {
        return None;
    }
    if !whole.bytes().all(|b| b.is_ascii_digit()) || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let frac: u64 = format!("{frac:0<8}").parse().ok()?;
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

pub(crate) fn valid_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && port.parse::<u16>().map(|p| p > 0).unwrap_or(false)
                && !host.contains('/')
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A plausible-length sp1 string for the shape check (not a real key; the BIP352 layer parses it).
    fn sp_addr() -> String {
        format!("sp1q{}", "q".repeat(110))
    }

    #[test]
    fn fee_defaults_are_off_and_old_config_loads() {
        let s = Settings::default();
        assert!(!s.fee_enabled);
        assert_eq!((s.fee_maker_bps, s.fee_taker_bps), (20, 30));
        assert!(s.validate().is_empty(), "defaults must validate");
        // Config written before the fee fields existed still deserializes (serde defaults).
        let old = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":[],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(!s.fee_enabled && s.fee_maker_bps == 20 && s.fee_taker_bps == 30);
    }

    #[test]
    fn enabling_the_fee_requires_a_silent_payment_address() {
        let mut s = Settings {
            fee_enabled: true,
            ..Default::default()
        };
        assert!(
            s.validate().iter().any(|m| m.contains("fee_sp_address")),
            "enabled fee with no address must be refused"
        );
        s.fee_sp_address = sp_addr();
        assert!(
            s.validate().is_empty(),
            "a well-formed sp address is accepted"
        );
        // Disabled again, the address is irrelevant and a blank one is fine.
        s.fee_enabled = false;
        s.fee_sp_address = String::new();
        assert!(s.validate().is_empty());
    }

    #[test]
    fn a_fat_finger_rate_is_capped() {
        let s = Settings {
            fee_maker_bps: MAX_FEE_BPS + 1,
            ..Default::default()
        };
        assert!(s.validate().iter().any(|m| m.contains("fee_maker_bps")));
    }
}

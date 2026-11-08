//! The daemon's data types: the user-facing settings, the offer forms, and amount parsing.
use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use crate::swap::{Chain as SwapChain, FeeTerms, Offer as SwapOffer};

use super::engine::{engine_config, MAKER_LOCK_BLOCKS, TAKER_LOCK_BLOCKS};
use super::wire::random16;

/// The default smallest swap leg; an offer under it is refused. The runtime value is the configurable
/// `min_swap_sat` setting, which defaults to this.
pub(crate) const DUST_SAT: u64 = 10_000;

/// The hard safety floor a configured `min_swap_sat` may be lowered to. The claim and refund each
/// subtract a spend fee from the leg (now fee-rate-based with a small floor, see the engine config,
/// F6), and the remainder must stay above Bitcoin's dust limit (~330 sat). 3_000 clears any spend fee
/// at a sane rate (at ~14 sat/vB a ~142 vB claim is ~2_000, leaving ~1_000, safely above dust); in an
/// extreme fee spike a leg this small may not be claimable until the rate falls, which is inherent to
/// dust-sized swaps. A setting below this is rejected at config load.
pub(crate) const MIN_SWAP_FLOOR_SAT: u64 = 3_000;

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

/// Per-chain funding mode (design 0012). `Hot`: the node wallet holds the funding keys and signs,
/// the regtest and dust default, unchanged for existing installs. `Cold`: the funding wallet is
/// watch-only and an external signer signs, so no key to the user's balance lives on the engine
/// host. Per chain because BTC and xBTC can run different signers.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum FundingMode {
    #[default]
    Hot,
    Cold,
}

/// A chain's funding configuration (design 0012): the mode, and for cold mode the external signer
/// endpoint (same shape and transport as a node endpoint, design 0011), its RPC auth and optional
/// Root CA, and the account output descriptors (receive external + change internal) for the
/// watch-only funding wallet. The auth and the descriptors are operator secrets: kept in the data
/// dir, never served to the web layer, and redacted from `Debug` (see below) so a settings dump does
/// not leak them. (A malformed descriptor can still surface in a node RPC error in the operator's own
/// daemon log; that path never reaches the web layer.)
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct FundingConfig {
    #[serde(default)]
    pub mode: FundingMode,
    #[serde(default)]
    pub signer_endpoint: String,
    #[serde(default)]
    pub signer_user: String,
    #[serde(default)]
    pub signer_pass: String,
    #[serde(default)]
    pub signer_ca: String,
    #[serde(default)]
    pub descriptor_receive: String,
    #[serde(default)]
    pub descriptor_change: String,
}

impl std::fmt::Debug for FundingConfig {
    /// Redacts the signer password and the account descriptors so they never reach a log line; the
    /// mode, endpoint, user and CA are not secret (an endpoint carries the same exposure as a node).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |s: &str| {
            if s.trim().is_empty() {
                "<empty>"
            } else {
                "<set>"
            }
        };
        f.debug_struct("FundingConfig")
            .field("mode", &self.mode)
            .field("signer_endpoint", &self.signer_endpoint)
            .field("signer_user", &self.signer_user)
            .field("signer_pass", &redact(&self.signer_pass))
            .field("signer_ca", &redact(&self.signer_ca))
            .field("descriptor_receive", &redact(&self.descriptor_receive))
            .field("descriptor_change", &redact(&self.descriptor_change))
            .finish()
    }
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
    /// Smallest swap leg this deployment will offer, bid or accept, in sats. Defaults to `DUST_SAT`
    /// (10_000), so existing configs are unchanged. Lower it only on a deployment that wants to offer
    /// a small real-rate leg (xBTC is far cheaper than BTC, so a realistic swap's BTC side is tiny).
    /// Validated `>= MIN_SWAP_FLOOR_SAT` so the leg stays spendable after the claim/refund spend fee.
    /// Enforced in two places from this one value: the offer form (`NewOffer::validate`) and the
    /// engine's bid validation.
    #[serde(default = "default_min_swap_sat")]
    pub min_swap_sat: u64,
    /// Smallest trade the voluntary-fee path acts on, in sats. Defaults to the production
    /// `MIN_TRADE_SAT` (100_000), so existing configs are unchanged. Lower it only on a test
    /// deployment that wants the fee to apply to a small (real-rate dust) leg, where xBTC being far
    /// cheaper than BTC makes a realistic swap's BTC side tiny. Both counterparties must set the same
    /// value: `FeeTerms` does not carry it, so a mismatch fails safely (the verifier marks the fee
    /// `Failed`, or funding errors loudly, before anything commits) and never loses funds. The fee
    /// floor is not configurable; it guards Bitcoin's dust limit.
    #[serde(default = "default_min_trade_sat")]
    pub min_trade_sat: u64,
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
    /// Voluntary fee (design 0010). On by default for a fresh install, paying the project's per-chain
    /// addresses; an operator can turn it off in the Fee config action. `serde(default)` is `false`, so
    /// an existing config that never had the key stays off (no silent migration); only a truly fresh
    /// `Settings::default()` is on, and it ships with the project addresses so it validates.
    #[serde(default)]
    pub fee_enabled: bool,
    /// The operator's published fee address for the side locking BTC (design 0013). A silent payment
    /// (`sp1...`) address today; each swap pays a fresh, unlinkable output derived from it. Used only
    /// when `fee_enabled`; at least one of the two chain addresses is then required.
    #[serde(default)]
    pub fee_btc_address: String,
    /// The operator's published fee address for the side locking xBTC. Kept separate from the BTC
    /// address because the two chains share Bitcoin's address format (design 0013).
    #[serde(default)]
    pub fee_xbtc_address: String,
    /// Optional operator-owned address where this node's claimed proceeds and its own refunds on the
    /// BTC chain are sent (finding F5, design 0014). Empty (the default) keeps today's behaviour: a
    /// fresh address from the node's own funding wallet, so proceeds sit in the hot wallet. Set it to
    /// move claimed proceeds and refunds to an operator-held (e.g. cold) address off the engine host.
    /// Must be a normal address (not a silent payment); network-checked where the spend is built.
    #[serde(default)]
    pub btc_payout_address: String,
    /// The same for the xBTC chain. Kept separate from the BTC address because the two chains share
    /// Bitcoin's address format.
    #[serde(default)]
    pub xbtc_payout_address: String,
    /// Optional per-chain block-explorer base URL the web UI links txids against, as
    /// `<base>/tx/<txid>` (#67). Empty (default) renders txids as plain text. Defaults in practice to
    /// the operator's own local mempool; accepts a clearnet https URL or a Tor `.onion` URL, the
    /// operator's choice and their privacy trade-off.
    #[serde(default)]
    pub btc_explorer_url: String,
    #[serde(default)]
    pub xbtc_explorer_url: String,
    /// Maker fee, basis points (default 20 = 0.20 %). See design 0010 / spec 7.5.
    #[serde(default = "default_fee_maker_bps")]
    pub fee_maker_bps: u16,
    /// Taker fee, basis points (default 30 = 0.30 %).
    #[serde(default = "default_fee_taker_bps")]
    pub fee_taker_bps: u16,
    /// PEM Root CA to verify an HTTPS node against (the node's StartOS Root CA). Required for an
    /// https:// LAN address; ignored for plain http and accepted-but-unused for an onion, where Tor
    /// authenticates the endpoint (design 0011). Empty by default.
    #[serde(default)]
    pub btc_rpc_ca: String,
    #[serde(default)]
    pub xbtc_rpc_ca: String,
    /// Tor SOCKS5 proxy used to dial an `.onion` node RPC and an `.onion` relay. One setting for both,
    /// replacing the former hardcoded default (design 0011). The StartOS Tor proxy on a node install.
    #[serde(default = "default_tor_socks")]
    pub tor_socks: String,
    /// Per-chain funding mode and cold signer config (design 0012). Absent (the default) is hot on
    /// both chains, so existing installs and regtest are unchanged. The legacy global `signer` field
    /// above is not consulted by the connect wiring; these per-chain values are authoritative.
    #[serde(default)]
    pub btc_funding: FundingConfig,
    #[serde(default)]
    pub xbtc_funding: FundingConfig,
}

/// The largest fee a setting may ask for: a guard against a fat-finger, not a policy (spec 7.5 sets
/// the real defaults far below this). One percent is already well above any sane swap fee.
pub(crate) const MAX_FEE_BPS: u16 = 100;

fn default_min_swap_sat() -> u64 {
    DUST_SAT
}
fn default_min_trade_sat() -> u64 {
    crate::fee::MIN_TRADE_SAT
}
fn default_fee_maker_bps() -> u16 {
    20
}
fn default_fee_taker_bps() -> u16 {
    30
}
fn default_tor_socks() -> String {
    "127.0.0.1:9050".to_owned()
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            btc_node: "http://127.0.0.1:8332".to_owned(),
            xbtc_node: "http://127.0.0.1:8442".to_owned(),
            relays: Vec::new(),
            signer: Signer::Cold,
            btc_conf: 1,
            xbtc_conf: 2,
            margin_blocks: 2,
            min_swap_sat: default_min_swap_sat(),
            min_trade_sat: default_min_trade_sat(),
            btc_rpc_user: String::new(),
            btc_rpc_pass: String::new(),
            xbtc_rpc_user: String::new(),
            xbtc_rpc_pass: String::new(),
            price_reference: false,
            // On by default for a fresh install (design 0010, revised): this reverses the earlier
            // "off until a legal opinion". Shipped WITH the project fee addresses so the default still
            // validates (an enabled fee requires an address). An existing config that lacks the key
            // still deserializes to `false` via serde(default), so no existing install is migrated on.
            fee_enabled: true,
            fee_btc_address: "bc1p37x3ehmhdy6s40fuy0haw9sv9pmyjdqz5wulvm93jry4fy63ttksxja9sh"
                .to_owned(),
            fee_xbtc_address: "bc1pe62v4m0p6njpxn2ej9hx307tm0xlccnxe652vxk9r76g2qync7sqkfly4t"
                .to_owned(),
            btc_payout_address: String::new(),
            xbtc_payout_address: String::new(),
            btc_explorer_url: String::new(),
            xbtc_explorer_url: String::new(),
            fee_maker_bps: default_fee_maker_bps(),
            fee_taker_bps: default_fee_taker_bps(),
            btc_rpc_ca: String::new(),
            xbtc_rpc_ca: String::new(),
            tor_socks: default_tor_socks(),
            btc_funding: FundingConfig::default(),
            xbtc_funding: FundingConfig::default(),
        }
    }
}

impl Settings {
    /// Authoritative validation (design 0009 layer 2). Returns one message per bad field; empty means
    /// valid. The engine enforces the safety-critical invariants regardless, but we refuse nonsense
    /// here so it never reaches the engine and so the GUI can show the reasons.
    pub fn validate(&self) -> Vec<String> {
        let mut e = Vec::new();
        for (name, addr, ca) in [
            ("btc_node", &self.btc_node, &self.btc_rpc_ca),
            ("xbtc_node", &self.xbtc_node, &self.xbtc_rpc_ca),
        ] {
            if let Err(msg) = validate_node(addr, ca, &self.tor_socks) {
                e.push(format!("{name}: {msg}"));
            }
        }
        for relay in &self.relays {
            if !(relay.starts_with("ws://") || relay.starts_with("wss://")) {
                e.push(format!("relay {relay}: must be a ws:// or wss:// URL"));
            }
        }
        for (name, cfg) in [
            ("btc_funding", &self.btc_funding),
            ("xbtc_funding", &self.xbtc_funding),
        ] {
            e.extend(validate_funding(name, cfg, &self.tor_socks));
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
        if self.min_swap_sat < MIN_SWAP_FLOOR_SAT {
            e.push(format!(
                "min_swap_sat: at least {MIN_SWAP_FLOOR_SAT} (claim/refund subtract a spend fee; the remainder must clear dust)"
            ));
        }
        if self.min_trade_sat < 1 {
            e.push("min_trade_sat: at least 1".to_owned());
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
        if self.fee_enabled {
            let addresses = [
                ("fee_btc_address", &self.fee_btc_address),
                ("fee_xbtc_address", &self.fee_xbtc_address),
            ];
            if addresses.iter().all(|(_, a)| a.trim().is_empty()) {
                e.push(
                    "fee: a BTC or xBTC fee address is required when the fee is enabled".to_owned(),
                );
            }
            for (name, a) in addresses {
                if !a.trim().is_empty() && !looks_like_fee_address(a) {
                    e.push(format!(
                        "{name}: must be a silent payment or a normal address"
                    ));
                }
            }
        }
        // Operator payout addresses (finding F5): optional, but if set must be a normal address, since
        // a claim/refund spend pays a plain scriptPubKey. The authoritative, network-checked parse is
        // in the node (`ChainNode::script_for`); this is the settings-time shape guard.
        for (name, a) in [
            ("btc_payout_address", &self.btc_payout_address),
            ("xbtc_payout_address", &self.xbtc_payout_address),
        ] {
            if !a.trim().is_empty() && !looks_like_normal_address(a) {
                e.push(format!(
                    "{name}: must be a normal address (not a silent payment address)"
                ));
            }
        }
        // Explorer base URLs (#67): optional; if set, a clearnet http(s) or a Tor .onion over http(s)
        // base. The UI appends `/tx/<txid>`; a malformed base would just make a dead link.
        for (name, url) in [
            ("btc_explorer_url", &self.btc_explorer_url),
            ("xbtc_explorer_url", &self.xbtc_explorer_url),
        ] {
            let u = url.trim();
            if !u.is_empty() && !(u.starts_with("http://") || u.starts_with("https://")) {
                e.push(format!(
                    "{name}: must be an http:// or https:// URL, or empty"
                ));
            }
        }
        e
    }
}

/// A lightweight shape check for a fee address (design 0013): a silent payment (BIP352) address, or a
/// normal address that parses. This is a settings guard only; the authoritative parse and the
/// per-chain network check happen where the output is built (`FeeDest::parse`), which rejects anything
/// malformed or on the wrong network before a single sat is committed.
fn looks_like_fee_address(a: &str) -> bool {
    let a = a.trim();
    looks_like_sp_address(a)
        || a.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .is_ok()
}

/// A settings-time shape check for an operator payout address (finding F5): it must parse as a normal
/// Bitcoin-format address and must NOT be a silent payment address, because a claim/refund spend pays
/// a plain scriptPubKey. The authoritative per-chain network check is in `ChainNode::script_for`.
fn looks_like_normal_address(a: &str) -> bool {
    let a = a.trim();
    !looks_like_sp_address(a)
        && a.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .is_ok()
}

/// A lightweight shape check for a silent payment address (BIP352): the bech32m `sp1`/`tsp1` prefix
/// and a plausible length.
fn looks_like_sp_address(a: &str) -> bool {
    let a = a.trim();
    (a.starts_with("sp1") || a.starts_with("tsp1") || a.starts_with("sprt1"))
        && a.len() >= 110
        && a.len() <= 1023
}

/// What a `POST /offers` body must contain. Validated before an offer is created.
#[derive(Deserialize)]
pub(crate) struct NewOffer {
    pub(crate) sell_chain: Chain,
    pub(crate) amount_sat: u64,
    /// The relative price (counter amount = `amount_sat * price`). Mutually exclusive with
    /// `counter_amount_sat`: set exactly one. The price path is band-checked (`MIN_PRICE..=MAX_PRICE`)
    /// and rounds through an f64, so it fits parity-ish offers but cannot express a lopsided rate
    /// precisely.
    #[serde(default)]
    pub(crate) price: Option<f64>,
    /// The exact counter amount in sats, given directly rather than as a price. Mutually exclusive
    /// with `price`. Use this for a lopsided real-rate offer (xBTC is far cheaper than BTC, so the
    /// price would fall outside the band and the f64 round-trip would lose precision); the integer
    /// amount removes both problems, so the band check is skipped and the amount is taken verbatim.
    #[serde(default)]
    pub(crate) counter_amount_sat: Option<u64>,
    pub(crate) min_amount_sat: u64,
}

impl NewOffer {
    /// Validates the form against the operator's configured smallest leg `min_swap_sat` (which
    /// defaults to [`DUST_SAT`]). Every "smallest leg" bound, both legs and the per-bid minimum, is
    /// this one value, so lowering the setting lets a small real-rate offer through; the engine's bid
    /// validation enforces the same value on the other side.
    pub(crate) fn validate(&self, min_swap_sat: u64) -> Vec<String> {
        let mut e = Vec::new();
        if self.amount_sat < min_swap_sat {
            e.push(format!(
                "amount_sat: below the minimum leg ({min_swap_sat})"
            ));
        }
        if self.amount_sat > 21_000_000 * 100_000_000 {
            e.push("amount_sat: above the supply cap".to_owned());
        }
        // Exactly one of `price` or `counter_amount_sat`. The band check guards only the float price
        // path; an exact counter amount is a plain minimum-leg-and-cap check, with no band.
        match (self.price, self.counter_amount_sat) {
            (Some(_), Some(_)) => {
                e.push("price and counter_amount_sat: set exactly one, not both".to_owned());
            }
            (None, None) => {
                e.push("price or counter_amount_sat: one is required".to_owned());
            }
            (Some(price), None) => {
                if !(price.is_finite() && (MIN_PRICE..=MAX_PRICE).contains(&price)) {
                    e.push(format!("price: expected {MIN_PRICE}..={MAX_PRICE}"));
                }
            }
            (None, Some(counter)) => {
                if counter < min_swap_sat {
                    e.push(format!(
                        "counter_amount_sat: below the minimum leg ({min_swap_sat})"
                    ));
                }
                if counter > 21_000_000 * 100_000_000 {
                    e.push("counter_amount_sat: above the supply cap".to_owned());
                }
            }
        }
        // Offers are atomic: the whole amount is taken at once. Partial or pro-rata fills are not
        // supported yet (they need offer decrement, re-broadcast, and take-time concurrency), so the
        // minimum must equal the amount. This keeps a filled offer safe to prune outright.
        if self.min_amount_sat != self.amount_sat {
            e.push(
                "min_amount_sat: must equal amount_sat (partial takes are not supported yet)"
                    .to_owned(),
            );
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
        // Validation guarantees exactly one of the two is set. An exact counter amount is taken
        // verbatim; otherwise the relative price rounds through an f64. The `(None, None)` arm is
        // unreachable after `validate`; fall back to a 1:1 amount rather than panic.
        let taker_amount = match (self.counter_amount_sat, self.price) {
            (Some(counter), _) => Amount::from_sat(counter),
            (None, Some(price)) => {
                Amount::from_sat((self.amount_sat as f64 * price).round() as u64)
            }
            (None, None) => Amount::from_sat(self.amount_sat),
        };
        let maker_amount = Amount::from_sat(self.amount_sat);
        let margin = s.margin_blocks as u32;
        // Size the timelocks to the amount from policy, so a larger offer (needing deeper
        // confirmations) is not rejected for too-short locks. Fall back to the fixed defaults if the
        // amount is above the policy table; the engine then returns the precise error.
        let (maker_lock_blocks, taker_lock_blocks) = engine_config(s)
            .policy
            .min_lock_blocks(maker_chain, maker_amount, taker_amount, 1, 1, margin)
            .unwrap_or((MAKER_LOCK_BLOCKS, TAKER_LOCK_BLOCKS));
        // The fee terms travel in the offer (design 0010), filled from the operator's settings when
        // the fee is on; a fee-less offer carries None. The address was shape-checked by
        // Settings::validate; the taker's engine parses it for its network before paying.
        let non_empty = |a: &str| (!a.trim().is_empty()).then(|| a.trim().to_owned());
        let fee = s.fee_enabled.then(|| FeeTerms {
            maker_bps: s.fee_maker_bps,
            taker_bps: s.fee_taker_bps,
            btc_address: non_empty(&s.fee_btc_address),
            xbtc_address: non_empty(&s.fee_xbtc_address),
        });
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
            fee,
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

/// Validates a node address against its CA and the configured Tor proxy, by the design-0011 rules:
/// a bare `host:port` or `http://` is fine; `https://` to a plain host needs a Root CA; any `.onion`
/// (which forces SOCKS) needs a Tor proxy address. Returns the reason a setting is refused.
pub(crate) fn validate_node(addr: &str, ca: &str, tor_socks: &str) -> Result<(), String> {
    let endpoint =
        crate::rpc::parse_endpoint(addr).map_err(|_| "expected host:port or http(s):// URL")?;
    if endpoint.is_onion() && !valid_host_port(tor_socks) {
        return Err("an .onion node needs a valid tor_socks host:port".to_owned());
    }
    if endpoint.is_https() && !endpoint.is_onion() && ca.trim().is_empty() {
        return Err("an https node needs a Root CA (paste the node's StartOS Root CA)".to_owned());
    }
    Ok(())
}

fn valid_host_port(s: &str) -> bool {
    match s.rsplit_once(':') {
        Some((host, port)) => {
            !host.is_empty()
                && port.parse::<u16>().map(|p| p > 0).unwrap_or(false)
                && !host.contains('/')
        }
        None => false,
    }
}

/// Validates a chain's funding config (design 0012). Hot needs nothing. Cold needs a signer endpoint
/// (checked by the same node-endpoint rules, reusing the signer's own CA) and both account
/// descriptors, so the watch-only funding wallet can build a change-handling PSBT. Never echoes a
/// descriptor or a credential: the messages are logged.
fn validate_funding(name: &str, cfg: &FundingConfig, tor_socks: &str) -> Vec<String> {
    let mut e = Vec::new();
    if cfg.mode != FundingMode::Cold {
        return e;
    }
    if cfg.signer_endpoint.trim().is_empty() {
        e.push(format!("{name}: cold mode needs a signer_endpoint"));
    } else if let Err(msg) = validate_node(&cfg.signer_endpoint, &cfg.signer_ca, tor_socks) {
        e.push(format!("{name} signer_endpoint: {msg}"));
    }
    if cfg.descriptor_receive.trim().is_empty() || cfg.descriptor_change.trim().is_empty() {
        e.push(format!(
            "{name}: cold mode needs a receive and a change account descriptor"
        ));
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    // A plausible-length sp1 string for the shape check (not a real key; the BIP352 layer parses it).
    fn sp_addr() -> String {
        format!("sp1q{}", "q".repeat(110))
    }

    fn a_new_offer() -> NewOffer {
        NewOffer {
            sell_chain: Chain::Xbtc,
            amount_sat: 50_000_000,
            price: Some(1.0),
            counter_amount_sat: None,
            min_amount_sat: 50_000_000,
        }
    }

    #[test]
    fn an_offer_carries_fee_terms_only_when_the_fee_is_on() {
        // Fee off: the offer is fee-less.
        let off = Settings {
            fee_enabled: false,
            ..Default::default()
        };
        assert!(a_new_offer().into_swap_offer(&off).fee.is_none());
        // Fee on: the offer carries the operator's rates and the per-chain addresses, from settings.
        let on = Settings {
            fee_enabled: true,
            fee_btc_address: sp_addr(),
            fee_xbtc_address: sp_addr(),
            fee_maker_bps: 20,
            fee_taker_bps: 30,
            ..Default::default()
        };
        let terms = a_new_offer().into_swap_offer(&on).fee.expect("fee terms");
        assert_eq!((terms.maker_bps, terms.taker_bps), (20, 30));
        assert_eq!(terms.btc_address.as_deref(), Some(sp_addr().as_str()));
        assert_eq!(terms.xbtc_address.as_deref(), Some(sp_addr().as_str()));
    }

    #[test]
    fn fee_is_on_by_default_with_project_addresses_but_old_config_stays_off() {
        // A fresh install: fee on, with the project addresses, and it validates.
        let s = Settings::default();
        assert!(s.fee_enabled, "a fresh install has the fee on");
        assert!(
            !s.fee_btc_address.is_empty() && !s.fee_xbtc_address.is_empty(),
            "the on-by-default must ship with the project fee addresses"
        );
        assert_eq!((s.fee_maker_bps, s.fee_taker_bps), (20, 30));
        assert!(
            s.validate().is_empty(),
            "the on-by-default must validate: {:?}",
            s.validate()
        );
        // An existing config that never had the fee key stays OFF (serde default is false), so no
        // install is silently migrated on.
        let old = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":[],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert!(!s.fee_enabled && s.fee_maker_bps == 20 && s.fee_taker_bps == 30);
    }

    #[test]
    fn enabling_the_fee_requires_a_silent_payment_address() {
        // Start from an explicit empty-address state (the default now ships the project addresses).
        let mut s = Settings {
            fee_enabled: true,
            fee_btc_address: String::new(),
            fee_xbtc_address: String::new(),
            ..Default::default()
        };
        assert!(
            s.validate()
                .iter()
                .any(|m| m.contains("fee address is required")),
            "enabled fee with no address must be refused"
        );
        // A fee address on one chain only is enough; the other side simply pays no fee.
        s.fee_btc_address = sp_addr();
        assert!(
            s.validate().is_empty(),
            "a well-formed sp address on one chain is accepted"
        );
        // A malformed address on the other chain is refused even though the first is valid.
        s.fee_xbtc_address = "not-an-sp-address".to_owned();
        assert!(
            s.validate().iter().any(|m| m.contains("fee_xbtc_address")),
            "a malformed per-chain address must be refused"
        );
        // Disabled again, the addresses are irrelevant and blank ones are fine.
        s.fee_enabled = false;
        s.fee_btc_address = String::new();
        s.fee_xbtc_address = String::new();
        assert!(s.validate().is_empty());
    }

    #[test]
    fn operator_payout_addresses_are_optional_and_shape_checked() {
        // Blank (the default) is fine: today's node-wallet behaviour.
        let s = Settings::default();
        assert!(
            s.validate().is_empty(),
            "blank payout addresses must validate"
        );
        // A well-formed normal address is accepted.
        let normal = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let s = Settings {
            btc_payout_address: normal.to_owned(),
            ..Default::default()
        };
        assert!(
            s.validate().is_empty(),
            "a normal payout address must be accepted: {:?}",
            s.validate()
        );
        // A silent payment address is refused: a claim/refund spend pays a plain scriptPubKey.
        let s = Settings {
            xbtc_payout_address: sp_addr(),
            ..Default::default()
        };
        assert!(
            s.validate()
                .iter()
                .any(|m| m.contains("xbtc_payout_address")),
            "a silent payment payout address must be refused"
        );
        // A malformed address is refused.
        let s = Settings {
            btc_payout_address: "not-an-address".to_owned(),
            ..Default::default()
        };
        assert!(s
            .validate()
            .iter()
            .any(|m| m.contains("btc_payout_address")));
    }

    #[test]
    fn engine_config_maps_payout_addresses_to_the_engine_config() {
        use crate::daemon::engine::engine_config;
        let normal = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let s = Settings {
            btc_payout_address: format!("  {normal}  "), // trimmed
            xbtc_payout_address: String::new(),
            ..Default::default()
        };
        let cfg = engine_config(&s);
        assert_eq!(cfg.btc_payout.as_deref(), Some(normal), "set + trimmed");
        assert_eq!(cfg.xbtc_payout, None, "blank maps to None (node wallet)");
    }

    #[test]
    fn explorer_urls_are_optional_and_scheme_checked() {
        // Blank (default) validates.
        assert!(Settings::default().validate().is_empty());
        // A clearnet https base and a Tor .onion over http both validate.
        let s = Settings {
            btc_explorer_url: "https://mempool.lan".to_owned(),
            xbtc_explorer_url: "http://abcd1234.onion".to_owned(),
            ..Default::default()
        };
        assert!(
            s.validate().is_empty(),
            "https and onion-over-http bases must validate: {:?}",
            s.validate()
        );
        // A base without a scheme is refused (it would make a dead link).
        let s = Settings {
            btc_explorer_url: "mempool.lan".to_owned(),
            ..Default::default()
        };
        assert!(s.validate().iter().any(|m| m.contains("btc_explorer_url")));
    }

    #[test]
    fn a_fat_finger_rate_is_capped() {
        let s = Settings {
            fee_maker_bps: MAX_FEE_BPS + 1,
            ..Default::default()
        };
        assert!(s.validate().iter().any(|m| m.contains("fee_maker_bps")));
    }

    #[test]
    fn min_trade_sat_defaults_to_the_production_value_and_validates() {
        // No config: the production default, and nothing changes for existing installs.
        let s = Settings::default();
        assert_eq!(s.min_trade_sat, 100_000);
        assert!(s.validate().is_empty(), "the default must validate");
        // Config written before the field existed still deserializes with the default.
        let old = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":[],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.min_trade_sat, 100_000);
        // A lowered value validates; zero is refused.
        let low = Settings {
            min_trade_sat: 50,
            ..Default::default()
        };
        assert!(low.validate().is_empty(), "a lowered minimum is accepted");
        let zero = Settings {
            min_trade_sat: 0,
            ..Default::default()
        };
        assert!(zero.validate().iter().any(|m| m.contains("min_trade_sat")));
    }

    #[test]
    fn an_exact_counter_amount_skips_the_price_band() {
        // A real-rate offer: xBTC far cheaper than BTC, so the implied price (287) is far outside the
        // [0.5, 2.0] band. Given as an exact counter amount it validates, and the taker amount is
        // taken verbatim with no float round-trip.
        let o = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 1_000_000,
            price: None,
            counter_amount_sat: Some(287_000_000),
            min_amount_sat: 1_000_000,
        };
        assert!(
            o.validate(DUST_SAT).is_empty(),
            "an exact counter amount is not band-checked: {:?}",
            o.validate(DUST_SAT)
        );
        let swap = o.into_swap_offer(&Settings::default());
        assert_eq!(swap.taker_amount, Amount::from_sat(287_000_000));
    }

    #[test]
    fn a_non_atomic_offer_is_refused() {
        // Partial takes are not supported yet, so an offer whose minimum is below its amount is
        // refused; an equal minimum and amount validates.
        let partial = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 2_000_000,
            price: None,
            counter_amount_sat: Some(2_000_000),
            min_amount_sat: 1_000_000,
        };
        assert!(partial
            .validate(DUST_SAT)
            .iter()
            .any(|m| m.contains("min_amount_sat")));
        let atomic = NewOffer {
            min_amount_sat: 2_000_000,
            ..partial
        };
        assert!(atomic.validate(DUST_SAT).is_empty());
    }

    #[test]
    fn price_and_counter_amount_are_mutually_exclusive() {
        // Both set: refused.
        let both = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 1_000_000,
            price: Some(1.0),
            counter_amount_sat: Some(1_000_000),
            min_amount_sat: 1_000_000,
        };
        assert!(both
            .validate(DUST_SAT)
            .iter()
            .any(|m| m.contains("exactly one")));
        // Neither set: refused.
        let neither = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 1_000_000,
            price: None,
            counter_amount_sat: None,
            min_amount_sat: 1_000_000,
        };
        assert!(neither
            .validate(DUST_SAT)
            .iter()
            .any(|m| m.contains("one is required")));
    }

    #[test]
    fn min_swap_sat_defaults_and_has_a_safety_floor() {
        // No config: the default smallest leg, and nothing changes for existing installs.
        let s = Settings::default();
        assert_eq!(s.min_swap_sat, DUST_SAT);
        assert!(s.validate().is_empty(), "the default must validate");
        // Config written before the field existed still deserializes with the default.
        let old = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":[],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.min_swap_sat, DUST_SAT);
        // At the floor it validates; one sat below the floor is rejected.
        let at_floor = Settings {
            min_swap_sat: MIN_SWAP_FLOOR_SAT,
            ..Default::default()
        };
        assert!(at_floor.validate().is_empty(), "the floor is accepted");
        let below = Settings {
            min_swap_sat: MIN_SWAP_FLOOR_SAT - 1,
            ..Default::default()
        };
        assert!(below.validate().iter().any(|m| m.contains("min_swap_sat")));
    }

    #[test]
    fn a_lowered_min_swap_lets_a_small_leg_be_offered() {
        // A 4_000-sat leg: refused at the default minimum, accepted once the setting is lowered. Both
        // the price form and the exact-counter form honour the configured minimum.
        let priced = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 4_000,
            price: Some(1.0),
            counter_amount_sat: None,
            min_amount_sat: 4_000,
        };
        assert!(
            !priced.validate(DUST_SAT).is_empty(),
            "4_000 is below the 10_000 default"
        );
        assert!(
            priced.validate(3_000).is_empty(),
            "4_000 is accepted when the minimum is lowered: {:?}",
            priced.validate(3_000)
        );
        let exact = NewOffer {
            sell_chain: Chain::Btc,
            amount_sat: 4_000,
            price: None,
            counter_amount_sat: Some(4_000),
            min_amount_sat: 4_000,
        };
        assert!(
            exact.validate(3_000).is_empty(),
            "an exact 4_000-sat counter leg is accepted when the minimum is lowered: {:?}",
            exact.validate(3_000)
        );
    }

    #[test]
    fn funding_defaults_hot_and_old_config_loads() {
        // The default is hot on both chains, so nothing changes for existing installs.
        let s = Settings::default();
        assert_eq!(s.btc_funding.mode, FundingMode::Hot);
        assert_eq!(s.xbtc_funding.mode, FundingMode::Hot);
        assert!(s.validate().is_empty(), "hot defaults must validate");
        // Config written before the funding fields existed still deserializes (serde defaults).
        let old = r#"{"btc_node":"127.0.0.1:8332","xbtc_node":"127.0.0.1:8442","relays":[],
            "signer":"cold","btc_conf":1,"xbtc_conf":2,"margin_blocks":2}"#;
        let s: Settings = serde_json::from_str(old).unwrap();
        assert_eq!(s.btc_funding.mode, FundingMode::Hot);
    }

    #[test]
    fn cold_mode_requires_an_endpoint_and_both_descriptors() {
        // Cold with nothing set: endpoint and descriptors both missing.
        let mut s = Settings::default();
        s.btc_funding.mode = FundingMode::Cold;
        let issues = s.validate();
        assert!(issues.iter().any(|m| m.contains("signer_endpoint")));
        assert!(issues.iter().any(|m| m.contains("descriptor")));

        // A plain host:port endpoint and both descriptors: valid.
        s.btc_funding.signer_endpoint = "127.0.0.1:8080".to_owned();
        s.btc_funding.descriptor_receive = "wpkh(tpub.../0/*)".to_owned();
        s.btc_funding.descriptor_change = "wpkh(tpub.../1/*)".to_owned();
        assert!(
            s.validate().is_empty(),
            "a complete cold config must validate: {:?}",
            s.validate()
        );

        // One descriptor missing is still refused.
        s.btc_funding.descriptor_change = String::new();
        assert!(s.validate().iter().any(|m| m.contains("descriptor")));

        // An https LAN signer with no CA is refused by the shared node-endpoint rule.
        s.btc_funding.descriptor_change = "wpkh(tpub.../1/*)".to_owned();
        s.btc_funding.signer_endpoint = "https://192.0.2.7:8080".to_owned();
        assert!(s
            .validate()
            .iter()
            .any(|m| m.contains("signer_endpoint") && m.contains("Root CA")));
    }

    #[test]
    fn funding_debug_redacts_the_secrets() {
        let cfg = FundingConfig {
            mode: FundingMode::Cold,
            signer_endpoint: "node.example:8080".to_owned(),
            signer_user: "operator".to_owned(),
            signer_pass: "hunter2".to_owned(),
            signer_ca: String::new(),
            descriptor_receive: "wpkh(tpub.../0/*)".to_owned(),
            descriptor_change: "wpkh(tpub.../1/*)".to_owned(),
        };
        let shown = format!("{cfg:?}");
        assert!(!shown.contains("hunter2"), "password must not be logged");
        assert!(!shown.contains("tpub"), "descriptors must not be logged");
        // The non-secret fields stay visible for diagnosis.
        assert!(shown.contains("node.example:8080") && shown.contains("operator"));
    }
}

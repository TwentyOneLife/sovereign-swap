//! Drives every swap: reads both chains, lets `Swap::decide` choose, stores the result, acts.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Amount, PubkeyHash, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};

use crate::fee::{self, FeeRates};
use crate::htlc::{Contract, Spend, UnsignedSpend, PREIMAGE_LEN};
use crate::keys::{Keys, Use};
use crate::node::{ChainBackend, ChainNode, FeeDest, NodeError};
use crate::policy::{Policy, PolicyError};
use crate::silentpayments;
use crate::store::write_atomic;
use crate::swap::{
    Action, BidError, Chain, ChainView, FeeProof, FeeState, Message, Offer, Phase, Role, Swap,
};
use crate::transport::Transport;

/// Maker-chain blocks a taker waits, beyond the required depth, for the maker's lock before giving up.
const LOCK_WAIT_BLOCKS: u32 = 10;

/// Blocks to target when fee-estimating a claim or refund: short, because these spends race a
/// timelock and must confirm promptly (F6).
const SPEND_CONF_TARGET: u16 = 3;
/// Conservative claim/refund fee rate (sat/vB) used when the node cannot estimate (a fresh regtest or
/// the quiet xBTC chain returns nothing). Sized to today's effective flat fee (2000 sat / 142 vB claim
/// = 14.1 sat/vB), rounded up, so a chain with no estimator keeps a safe, near-unchanged fee.
const FALLBACK_SPEND_RATE_SAT_VB: u64 = 15;

/// Default period between re-announcements of our own live offers (design 0020 decision 2). A relay's
/// bounded store (design 0020 phase 1) can evict an offer under a flood; nothing re-publishes it today
/// (not even a reconnect, which only re-subscribes), so a peer that subscribes after the eviction never
/// discovers it. Re-announcing on this period makes eviction self-healing. Five minutes bounds how long
/// an evicted offer stays undiscoverable, sends only a few small events per period, and stays far below
/// `SEEN_OFFER_TTL_SECS` so a peer never ages a live offer out between announces.
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);

/// Unix seconds now, for a swap's local creation timestamp (web UI time column). A clock before the
/// epoch falls back to 0 rather than panicking.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A short hex prefix of a 16-byte id, for log lines (F4): enough to correlate, not the whole id.
fn short_id(id: &[u8; 16]) -> String {
    id.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// The stored signed spend to rebroadcast for an action on `lock` (0028): the transaction iff its sole
/// input spends `lock`. `None`, or a mismatch (the stored spend is for a different outpoint, e.g. a dead
/// refund when the current action is now a claim on the other chain), returns `None`, so the caller
/// parks a fresh spend for the user instead of rebroadcasting a stale one. Pure, so it is unit-tested
/// without nodes.
fn reusable_spend(spent: Option<&Transaction>, lock: bitcoin::OutPoint) -> Option<&Transaction> {
    let tx = spent?;
    (tx.input.first().map(|i| i.previous_output) == Some(lock)).then_some(tx)
}

/// The txid of a base64 funding PSBT's unsigned transaction (design 0019). A segwit txid is fixed by
/// the unsigned tx, so this matches the signed lock that lands on chain; stored as the watch marker
/// when a swap parks on a handed-out PSBT.
fn funding_psbt_txid(psbt: &str) -> Result<Txid, EngineError> {
    psbt.parse::<bitcoin::Psbt>()
        .map(|p| p.unsigned_tx.compute_txid())
        .map_err(|e| EngineError::Node(NodeError::Unexpected(format!("parse funding psbt: {e}"))))
}

/// Whether a fee address is a silent payment (`sp1`/`tsp1`/`sprt1`), which needs a BIP352-aware signer
/// to build (design 0018). A normal address parses as `Err` here and is fundable by any signer.
fn is_silent_payment(addr: &str) -> bool {
    silentpayments::SilentPaymentAddress::parse(addr).is_ok()
}

/// The fee output a leg owes, or `None` when none is due. A leg below the minimum trade owes no fee
/// (design 0013 / `fee.rs`), so `BelowMinimum` maps to `None`, NOT an error (#107): the payer funds
/// with no fee output and the counterparty verifies as not-required, so a leg in `[min_swap,
/// min_trade)` with a fee address completes instead of stranding the first locker's coin. Pure, so the
/// both-paths-agree contract is unit-tested directly.
fn fee_amount_or_none(
    rates: FeeRates,
    role: Role,
    locked: Amount,
    min_trade: u64,
) -> Option<Amount> {
    // The only error fee_amount_min returns is BelowMinimum, which here means "no fee output", so
    // `.ok()` is exactly the right mapping.
    fee::fee_amount_min(rates, role, locked, min_trade).ok()
}

/// How long a discovered offer stays in the local market without being re-seen before it ages out
/// (#88/#70/#65). Matches the relay's event retention (7 days), so an offer the relay would still
/// serve is never dropped first, but a dead or withdrawn offer whose maker is gone - including a
/// pre-M1 legacy offer with no `Withdraw` - cannot linger in discovery forever.
const SEEN_OFFER_TTL_SECS: u64 = 7 * 24 * 3600;

/// How many own-chain blocks the engine keeps watching a handed-out, then abandoned, Interactive lock
/// for the user to broadcast before it gives up (design 0019 bound). ~1 week of BTC blocks: long
/// enough for a realistically late broadcast, bounded so a counterparty that bids and walks away cannot
/// leave a marker watched forever. The precise "inputs spent, can never confirm" drop is a later
/// refinement; this horizon is what bounds the walk-away case (where the inputs stay unspent).
const ADOPT_WATCH_CAP_BLOCKS: u32 = 1008;

/// Drop discovered offers not re-seen within `SEEN_OFFER_TTL_SECS` (and their timestamps). Any offer
/// with no timestamp yet - a legacy entry loaded from state written before `seen_at` existed - is
/// stamped with `now` so it ages from load rather than lingering forever. Pure, so it is unit-tested
/// directly. Returns whether anything changed (so the caller can persist).
fn prune_seen(
    seen_offers: &mut Vec<crate::swap::Offer>,
    seen_at: &mut Vec<([u8; 16], u64)>,
    now: u64,
) -> bool {
    let before = (seen_offers.len(), seen_at.len());
    let known: std::collections::HashSet<[u8; 16]> = seen_at.iter().map(|(id, _)| *id).collect();
    for o in seen_offers.iter() {
        if !known.contains(&o.id) {
            seen_at.push((o.id, now));
        }
    }
    let fresh: std::collections::HashSet<[u8; 16]> = seen_at
        .iter()
        .filter(|(_, t)| now.saturating_sub(*t) < SEEN_OFFER_TTL_SECS)
        .map(|(id, _)| *id)
        .collect();
    seen_offers.retain(|o| fresh.contains(&o.id));
    seen_at.retain(|(id, _)| fresh.contains(id));
    (seen_offers.len(), seen_at.len()) != before
}

/// Record that an offer `id` was just seen at `now`: refresh its stamp if known, else add it. The
/// LAST-seen time (not the first) is what `prune_seen` ages against, so a live, re-announced offer
/// stays fresh while a dead one (its maker gone, no more re-announce) ages out at the TTL (#88/#70).
/// Pure, so the sliding-window behaviour is unit-tested directly.
fn touch_seen(seen_at: &mut Vec<([u8; 16], u64)>, id: [u8; 16], now: u64) {
    match seen_at.iter_mut().find(|(i, _)| *i == id) {
        Some(e) => e.1 = now,
        None => seen_at.push((id, now)),
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Lower bound (floor) on a claim/refund transaction fee, in sats. The actual fee is the greater
    /// of this and the live fee-rate estimate applied to the transaction's real vsize (F6); the floor
    /// is min-relay-safe so a spend still confirms when the mempool is empty.
    pub min_spend_fee: Amount,
    /// Fee rate (sat/vB) for the funding (lock) transaction, passed to walletcreatefundedpsbt. The
    /// claim/refund spends do NOT use this; they fee from the live estimate (see `min_spend_fee`).
    pub fee_rate_sat_vb: u64,
    pub policy: Policy,
    /// Optional operator-owned payout address per chain, where this node's claimed proceeds and its
    /// own refunds on that chain are sent instead of a fresh address from the node's hot wallet
    /// (finding F5, design 0014). `None` keeps today's behaviour (the node wallet). The
    /// network-checked parse happens at `start()` via the chain's node, mirroring the fee address, so
    /// a wrong-network or malformed address fails the swap start loudly rather than paying into the
    /// void. Kept per chain because the two chains share Bitcoin's address format.
    pub btc_payout: Option<String>,
    pub xbtc_payout: Option<String>,
    /// User-held claim/refund signing (0027, the 2b non-custodial core). When true, the engine does NOT
    /// sign claim or refund spends with its own keys: it builds the unsigned spend, parks it on the
    /// record (`pending_spend`) for the user to sign, and `submit_signed_spend` finalizes + broadcasts.
    /// Default `false` keeps today's behaviour (the engine signs locally), so the current product and
    /// the self-hosted (2a) client, where the per-swap keys are legitimately the user's own, are
    /// untouched. Gates only the SIGNATURE; the preimage is still engine-side until a later slice.
    pub user_held_spends: bool,
}

/// A per-swap PUBLIC commitment bundle the user's browser pre-provisions for an upcoming `take_index`
/// (0027, the 2b non-custodial core). It holds only public data: the hash of the maker's secret and
/// the user's own claim/refund pubkey hashes, all derived client-side from the user's OWN seed (the
/// same `KeyStore` derivation the engine runs locally in 2a). The engine never holds the secret or the
/// keys; it commits these into the contract at swap-start so the contract pays and is claimable only
/// by the user, and the user signs/reveals at `submit_signed_spend`. One bundle is consumed per swap
/// and never reused (reuse across takes of an offer is a theft vector, see design 0027 section 0).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Commitment {
    pub secret_hash: [u8; 32],
    pub claim_pkh: PubkeyHash,
    pub refund_pkh: PubkeyHash,
}

/// A claim or refund that is built but awaiting the user's signature (0027, user-held spends): which
/// spend it is, the fee it was built at (so `submit_signed_spend` rebuilds the byte-identical
/// transaction), and the sighash the user signs with the claim/refund key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingSpend {
    /// True for a claim, false for a refund.
    pub claim: bool,
    pub fee_sat: u64,
    pub sighash: [u8; 32],
}

/// What a swap needs besides its state: where our coins go, and our lock once signed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub swap: Swap,
    pub claim_to: ScriptBuf,
    pub refund_to: ScriptBuf,
    /// Our signed lock, stored before its first broadcast so a restart sends the same one again.
    pub funding: Option<Transaction>,
    /// E2 (design 0017): the unsigned funding PSBT parked while the user signs it in their own wallet,
    /// set when funding returned `AwaitingSignature` and cleared when `submit_signed_lock` broadcasts
    /// the signed tx. A swap is either awaiting a signature or already funded, never both. Absent in
    /// older records, hence `serde(default)`.
    #[serde(default)]
    pub pending_lock_psbt: Option<String>,
    /// A claim or refund built but awaiting the user's signature (0027, user-held spends). Set when
    /// `Action::Claim`/`Action::Refund` is parked under `Config::user_held_spends`, cleared when
    /// `submit_signed_spend` broadcasts. `serde(default)` so older records load.
    #[serde(default)]
    pub pending_spend: Option<PendingSpend>,
    /// E2 (design 0019): the txid of the funding lock we handed the user to sign, kept as a watch that
    /// outlives `pending_lock_psbt`. The prompt (`pending_lock_psbt`) is cleared the moment the swap
    /// stops awaiting a signature (adopted, settled, or abandoned), so the UI never asks the user to
    /// sign a dead or already-funded swap; this marker is kept past an abandon so the engine still
    /// recognises and refunds the user's lock if they broadcast it late. A segwit txid is fixed by the
    /// unsigned tx, so it matches the signed lock that lands on chain. Absent in older records, hence
    /// `serde(default)`.
    #[serde(default)]
    pub expected_lock_txid: Option<Txid>,
    /// The own-chain height when the swap parked on the handed-out PSBT (design 0019). It bounds the
    /// terminal watch: once the chain is `adopt_watch_cap_blocks` past this, the engine stops watching
    /// a handed-out lock that never appeared, so a counterparty that bids and walks away cannot leave
    /// an unboundedly-watched marker. Cleared with `expected_lock_txid`. Absent in older records.
    #[serde(default)]
    pub watch_from_height: Option<u32>,
    /// The voluntary fee output's share and proof, stored with the lock so a restart resends the
    /// same proof to the counterparty (design 0010). `None` when no fee is due. Absent in older
    /// records, hence `serde(default)`.
    #[serde(default)]
    pub fee: Option<FeeProof>,
    /// The counterparty's fee proof, received over the swap channel, used to verify their lock's
    /// fee output (design 0010). Absent until it arrives, hence `serde(default)`.
    #[serde(default)]
    pub received_fee: Option<FeeProof>,
    /// The fee (sats) chosen for this swap's claim or refund spend, stored so every rebroadcast
    /// rebuilds the identical transaction (F6). Set on the first spend from the live rate; a later
    /// tick may raise it, never lower it, so any replacement only bumps the fee and stays within RBF
    /// rules. Absent in older records, hence `serde(default)`.
    #[serde(default)]
    pub spend_fee_sat: Option<u64>,
    /// Whether this swap is user-held (0027): its claim/refund keys and the maker's secret belong to
    /// the user, not the engine, so the engine parks the claim/refund for the user to sign instead of
    /// signing locally. FIXED when the swap is created (from `Config::user_held_spends` then), NOT
    /// read live, so flipping the config never changes how an in-flight swap settles. Absent in older
    /// records, hence `serde(default)` (false = today's local-signing behaviour).
    #[serde(default)]
    pub user_held: bool,
    /// The user's signed claim or refund, once submitted (0028). Stored so a user-held swap whose spend
    /// left the node's view before confirming (a restart losing the mempool, a reorg, an eviction) is
    /// REBROADCAST instead of re-parking and demanding a second signature, which for a claim would be a
    /// race once the secret is public. Rebroadcast only when it matches the current action's lock (see
    /// `reusable_spend`); cleared on a lock mismatch or a terminal phase. Public data (a broadcast tx),
    /// so it is non-custodial. Only ever set on the user-held path; the local path re-signs each tick.
    /// Absent in older records, hence `serde(default)`.
    #[serde(default)]
    pub spent_tx: Option<Transaction>,
}

#[derive(Default, Serialize, Deserialize)]
struct State {
    next_index: u32,
    own_offers: Vec<Offer>,
    seen_offers: Vec<Offer>,
    /// When each discovered offer was last seen (unix secs), by offer id, so a stale or withdrawn
    /// offer ages out of discovery (#88/#70/#65). Absent in older state files, hence `serde(default)`;
    /// a legacy `seen_offers` entry without a timestamp is stamped at load. Carries the market-table
    /// time column too.
    #[serde(default)]
    seen_at: Vec<([u8; 16], u64)>,
    /// Bids we sent and wait to see accepted: swap id to (offer, maker part, key index).
    bids: Vec<([u8; 16], Offer, Amount, u32)>,
    /// Ids of offers a maker has withdrawn. Kept so a relay that replays the original offer event
    /// after the withdrawal does not re-add it to `seen_offers`. Absent in older state files, hence
    /// `serde(default)`.
    #[serde(default)]
    withdrawn: Vec<[u8; 16]>,
    /// User-held commitment bundles (0027), keyed by the `take_index` the engine will assign. The
    /// browser pre-provisions a window (a Nostr bid arrives while it may be offline), the engine
    /// consumes one at swap-start and removes it, and refuses the bid/take when the index is absent.
    /// Public data only. Absent in older state files, hence `serde(default)`.
    #[serde(default)]
    commitment_pool: BTreeMap<u32, Commitment>,
    /// A user-held taker consumes its bundle at BID time (0027), because the pubkey hashes it puts on
    /// the wire in `Message::Bid` must be exactly the ones it later commits at `Accept`. The bundle is
    /// stashed here by swap id until the Accept arrives, so a later `provision_commitments` for the
    /// same index cannot change what was already advertised. A `Vec` of pairs, not a map, because a
    /// `[u8; 16]` key does not serialize as a JSON object key (same reason `bids` is a `Vec`). Absent
    /// in older state files, hence `serde(default)`.
    #[serde(default)]
    bid_commitments: Vec<([u8; 16], Commitment)>,
}

#[derive(Debug)]
pub enum EngineError {
    Bid(BidError),
    Policy(PolicyError),
    Node(NodeError),
    Io(std::io::Error),
    NoSuchSwap,
    /// Abort was asked for a swap that has already funded its lock; it can only time out to a refund.
    AlreadyFunded,
    /// Withdraw was asked for an offer id that is not among our own offers: either never ours or
    /// already withdrawn/filled. `own_offers` holds only our own offers, so a peer's offer can never
    /// be withdrawn here. Report it instead of returning a misleading success (#78).
    NotYourOffer,
    /// A signed funding PSBT was submitted for a swap that can no longer safely broadcast its lock:
    /// it has abandoned (e.g. the counterparty's lock window ran out while we waited for the user's
    /// signature) or already settled. Broadcasting now would strand the funds in an HTLC the engine
    /// no longer drives to a refund, so the late submission is refused rather than honoured.
    NoLongerFundable,
    /// A signed funding PSBT was submitted while the swap is still live but not yet clear to fund (for
    /// example the counterparty's fee proof has not been verified yet, which a transient backend read
    /// or a restart can briefly leave pending). The swap is NOT dead: the parked PSBT is kept exactly
    /// as it is (rebuilding it with fresh inputs would strand the signature) and the submission is
    /// refused retryably, to try again shortly.
    NotYetFundable,
    /// Refused to publish an offer whose voluntary fee for the chain the maker would lock is a silent
    /// payment (`sp1...`), while the maker's funding signer for that chain cannot build one (interactive
    /// funding, or a non-BIP352-aware cold signer; design 0018). Publishing it would advertise a swap
    /// the maker structurally cannot fund.
    FeeNotFundable,
    /// A user-held swap (0027) reached a point that needs its commitment bundle (for the index it
    /// was created at) but the pool has none: either never provisioned or already consumed. The
    /// engine cannot commit or settle the swap without the user's public claim/refund pubkey hashes.
    NoCommitment,
    /// A signed spend was submitted whose signature does not verify against the parked sighash under
    /// the submitted key (#240). The spend is left PARKED so the signer can retry with a correct
    /// signature; nothing is broadcast or stored.
    BadSignature,
}

impl From<NodeError> for EngineError {
    fn from(e: NodeError) -> EngineError {
        EngineError::Node(e)
    }
}

impl From<std::io::Error> for EngineError {
    fn from(e: std::io::Error) -> EngineError {
        EngineError::Io(e)
    }
}

/// The spend a parked claim/refund rebuilds to, from `Engine::build_spend`: the chain to broadcast on,
/// the unsigned transaction and its BIP143 sighash, the witness script, the input value it spends (not
/// in the segwit tx), and the claim preimage the engine already knows (`None` for a refund or a
/// user-held maker claim). Internal; `submit_signed_spend` finalizes it and `pending_spend_template`
/// exposes the public parts.
struct RebuiltSpend {
    chain: Chain,
    unsigned: UnsignedSpend,
    witness_script: ScriptBuf,
    input_value: Amount,
    preimage: Option<[u8; PREIMAGE_LEN]>,
}

/// The public spend template a parked user-held swap is awaiting (0027), for the browser to recompute
/// the BIP143 sighash itself and sign its OWN digest rather than trusting the engine's `sighash`. Holds
/// no key and no preimage. The browser must still rebuild the witness script from its own verified
/// contract and check the destination against a reference it owns; this only exposes what the engine
/// would spend.
pub struct SpendTemplate {
    pub claim: bool,
    pub unsigned_tx: Transaction,
    pub witness_script: ScriptBuf,
    pub input_value: Amount,
    pub sighash: [u8; 32],
}

/// Tests only: how a cheating counterparty tampers with the voluntary fee output it funds, so the
/// honest party's fee verification (design 0010/0013) can be exercised against a real on-chain lock
/// that carries a wrong or underpaid fee. Mirrors [`Engine::lock_amount_override`].
#[derive(Clone)]
pub enum FeeTamper {
    /// Pay the full required fee amount, but to this (valid) address instead of the agreed one.
    WrongAddress(String),
    /// Pay the agreed address, but only this many sats (below the required amount).
    Underpay(u64),
}

pub struct Engine<T: Transport> {
    dir: PathBuf,
    keys: Keys,
    nodes: HashMap<Chain, ChainNode>,
    /// Optional per-chain read/broadcast backend override (E1, design 0016): when set for a chain,
    /// `backend()` reads chain data and broadcasts through it (an Electrum server) instead of the
    /// funding node's RPC. Funding and signing still use the `ChainNode` in `nodes`. Empty by
    /// default, so without configuration the engine behaves exactly as before.
    read: HashMap<Chain, Box<dyn ChainBackend + Send + Sync>>,
    transport: T,
    config: Config,
    /// Smallest swap leg either side will bid or accept, in sats. Defaults to
    /// [`crate::swap::MIN_SWAP_AMOUNT`] and is lowered only by a deployment that wants to offer a
    /// small real-rate leg. Threaded into the bid validation ([`Offer::taker_part_min`]); a safety
    /// floor on the setting (see `daemon::types::MIN_SWAP_FLOOR_SAT`) keeps the leg spendable after
    /// the spend fee.
    min_swap_sat: u64,
    /// Smallest trade the voluntary-fee path acts on, in sats. Defaults to [`crate::fee::MIN_TRADE_SAT`]
    /// and is lowered only by a deployment that wants the fee to apply to a small (real-rate dust)
    /// leg. Threaded into both fee paths (funding and verify) so a funder and its counterparty agree.
    /// The fee floor ([`crate::fee::FLOOR_SAT`]) is deliberately not configurable: it guards dust.
    min_trade_sat: u64,
    /// Beta safety cap on the real-value (BTC) leg, in sats (#103). Defaults to no cap (`u64::MAX`);
    /// the daemon sets it from the operator's configured `max_swap_sat`. Enforced locally at bid time
    /// (and at offer creation in the daemon), never in counterparty verification.
    max_swap_sat: u64,
    /// Take-side fee policy (design 0018 / security). `0` is off (the default, so the core and tests
    /// are unaffected); the daemon sets it from the operator's config. When set, a taken offer whose
    /// `taker_bps` exceeds this cap is refused, protecting the taker from a malicious maker on the
    /// public relay charging a large "fee". Local refusal, never counterparty verification.
    fee_take_max_bps: u16,
    /// The fee addresses the operator accepts a taken offer to pay (its own configured set, per chain).
    /// Empty means no address restriction. When non-empty, a taken offer whose fee address for the
    /// chain we lock is not in the set is refused, so the taker never pays a "fee" to an attacker's
    /// address. Set by the daemon from `fee_<chain>_address` + the rotating set.
    fee_known_btc: Vec<String>,
    fee_known_xbtc: Vec<String>,
    /// How many own-chain blocks the engine keeps watching a handed-out, abandoned lock for before it
    /// gives up (design 0019 bound). Defaults to [`ADOPT_WATCH_CAP_BLOCKS`]; a test may lower it.
    adopt_watch_cap_blocks: u32,
    state: State,
    records: Vec<Record>,
    /// How often `tick` re-announces our own live offers (design 0020 decision 2). Runtime-only (not
    /// persisted): reset to [`REANNOUNCE_INTERVAL`] at `open`. A test lowers it (to `Duration::ZERO`)
    /// to make every tick re-announce.
    reannounce_interval: Duration,
    /// When we last re-announced (monotonic). Set to `Instant::now()` at `open`, so the first
    /// re-announce is one interval after start, not at boot: the initial `publish` already announced.
    last_reannounce: Instant,
    /// Tests only: drop this many broadcasts instead of sending them.
    pub drop_broadcasts: u32,
    /// Tests only: lock this amount instead of the agreed one, as a cheating counterparty would.
    pub lock_amount_override: Option<Amount>,
    /// Tests only: fund a tampered fee output (wrong address or underpaid), as a fee-cheating
    /// counterparty would, to exercise the honest party's fee verification.
    pub fee_tamper: Option<FeeTamper>,
}

impl<T: Transport> Engine<T> {
    /// Opens the engine stored in `dir`, or starts a new one there.
    pub fn open(
        dir: &Path,
        btc: ChainNode,
        xbtc: ChainNode,
        transport: T,
        config: Config,
    ) -> Result<Self, EngineError> {
        std::fs::create_dir_all(dir.join("swaps"))?;
        let state: State = match std::fs::read(dir.join("engine.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State::default(),
            Err(e) => return Err(e.into()),
        };
        let mut records = Vec::new();
        for entry in std::fs::read_dir(dir.join("swaps"))? {
            let path = entry?.path();
            if path.extension().is_some_and(|e| e == "json") {
                records.push(
                    serde_json::from_slice(&std::fs::read(&path)?)
                        .map_err(std::io::Error::other)?,
                );
            }
        }
        let mut engine = Engine {
            dir: dir.to_owned(),
            keys: Keys::open(dir)?,
            nodes: HashMap::from([(Chain::Btc, btc), (Chain::Xbtc, xbtc)]),
            read: HashMap::new(),
            transport,
            config,
            min_swap_sat: crate::swap::MIN_SWAP_AMOUNT.to_sat(),
            min_trade_sat: crate::fee::MIN_TRADE_SAT,
            max_swap_sat: u64::MAX,
            fee_take_max_bps: 0,
            fee_known_btc: Vec::new(),
            fee_known_xbtc: Vec::new(),
            adopt_watch_cap_blocks: ADOPT_WATCH_CAP_BLOCKS,
            state,
            records,
            reannounce_interval: REANNOUNCE_INTERVAL,
            last_reannounce: Instant::now(),
            drop_broadcasts: 0,
            lock_amount_override: None,
            fee_tamper: None,
        };
        engine.reconcile_offers()?;
        engine.prune_stale_offers()?;
        Ok(engine)
    }

    /// On load, drop any own offer a record already covers. A started swap means the offer was taken,
    /// and an atomic offer is then fully consumed, so keeping it would let it be taken again or
    /// re-announced on reconnect from a wallet that might still hold funds.
    fn reconcile_offers(&mut self) -> Result<(), EngineError> {
        let taken: std::collections::HashSet<[u8; 16]> =
            self.records.iter().map(|r| r.swap.offer.id).collect();
        let dropped: Vec<[u8; 16]> = self
            .state
            .own_offers
            .iter()
            .filter(|o| taken.contains(&o.id))
            .map(|o| o.id)
            .collect();
        if dropped.is_empty() {
            return Ok(());
        }
        self.state.own_offers.retain(|o| !taken.contains(&o.id));
        self.save_state()?;
        // Tell peers to drop these too, so a filled offer does not linger in their discovery (#70).
        // The send queues on the transport and goes out once the relay connection is up.
        for offer_id in dropped {
            self.transport.send(&Message::Withdraw { offer_id });
        }
        Ok(())
    }

    /// Overrides the minimum swap leg bids are checked against, replacing the
    /// [`crate::swap::MIN_SWAP_AMOUNT`] default. Call it right after [`Engine::open`], before the
    /// first tick; the daemon sets it from the operator's configured `min_swap_sat`.
    pub fn set_min_swap_sat(&mut self, min_swap_sat: u64) {
        self.min_swap_sat = min_swap_sat;
    }

    /// Sets the beta cap on the BTC leg (#103), replacing the no-cap default. The daemon calls this
    /// right after [`Engine::open`] from the operator's configured `max_swap_sat`.
    pub fn set_max_swap_sat(&mut self, max_swap_sat: u64) {
        self.max_swap_sat = max_swap_sat;
    }

    /// Sets the take-side fee policy (security): a cap on a taken offer's `taker_bps`, and the fee
    /// addresses the operator accepts for each chain (its own configured set). The daemon calls this
    /// right after [`Engine::open`] from the operator's config, so the taker refuses an offer that
    /// would charge a large fee, or a fee to an address it does not recognise, on the public relay.
    /// `max_bps = 0` and empty sets leave the policy off.
    pub fn set_fee_take_policy(
        &mut self,
        max_bps: u16,
        known_btc: Vec<String>,
        known_xbtc: Vec<String>,
    ) {
        self.fee_take_max_bps = max_bps;
        self.fee_known_btc = known_btc;
        self.fee_known_xbtc = known_xbtc;
    }

    /// Lowers the handed-out-lock watch horizon (design 0019 bound) from its block default, for tests.
    pub fn set_adopt_watch_cap_blocks(&mut self, blocks: u32) {
        self.adopt_watch_cap_blocks = blocks;
    }

    /// Overrides the offer re-announce period (design 0020 decision 2), replacing
    /// [`REANNOUNCE_INTERVAL`]. Call it right after [`Engine::open`]. A test sets it to
    /// `Duration::ZERO` so every `tick` re-announces.
    pub fn set_reannounce_interval(&mut self, interval: Duration) {
        self.reannounce_interval = interval;
    }

    /// Re-announces our own live offers once the period has elapsed, so an offer a relay evicted from
    /// its bounded store (design 0020) is re-published and becomes discoverable again without waiting
    /// for a reconnect (which only re-subscribes, it does not re-publish). Each
    /// [`Transport::send`] builds a fresh event (new id and `created_at`), so a relay's dedupe does not
    /// drop the re-send and a reconnecting peer's `since` watermark does not hide it. Peer handling of
    /// a repeated `Offer` is idempotent (`handle`), so this needs no wire change. `own_offers` already
    /// holds only live offers (a taken or withdrawn one is removed), so a filled offer is never
    /// re-announced.
    fn reannounce_offers(&mut self) {
        if self.last_reannounce.elapsed() < self.reannounce_interval {
            return;
        }
        self.last_reannounce = Instant::now();
        // Maker-set expiry (design 0026, #212): stop re-announcing an expired own offer and drop it, so
        // it is not kept alive by our own re-announce past its deadline.
        let now = now_unix();
        let before = self.state.own_offers.len();
        self.state.own_offers.retain(|o| !o.is_expired(now));
        if self.state.own_offers.len() != before {
            let _ = self.save_state();
        }
        for offer in &self.state.own_offers {
            self.transport.send(&Message::Offer(offer.clone()));
        }
    }

    /// Overrides the minimum trade the fee path acts on, replacing the [`crate::fee::MIN_TRADE_SAT`]
    /// default. Call it right after [`Engine::open`], before the first tick; the daemon sets it from
    /// the operator's configured `min_trade_sat`.
    pub fn set_min_trade_sat(&mut self, min_trade_sat: u64) {
        self.min_trade_sat = min_trade_sat;
    }

    pub fn swaps(&self) -> impl Iterator<Item = &Swap> {
        self.records.iter().map(|r| &r.swap)
    }

    /// A record-derived ledger for operator reporting (#67): one entry per swap, plus totals, built
    /// from local records only (no chain query). The voluntary fee a leg paid is recomputed from the
    /// offer terms exactly as the engine placed it on our lock, so it matches what was spent. Txids
    /// beyond our own lock are on the live per-swap view (`GET /swaps/{id}`). Fees *received* at the
    /// project addresses are deliberately not here: that needs an operator-side watch-only wallet, not
    /// the package (see #67's layer note).
    pub fn history(&self) -> serde_json::Value {
        let chain = |c: Chain| match c {
            Chain::Btc => "btc",
            Chain::Xbtc => "xbtc",
        };
        let mut entries = Vec::with_capacity(self.records.len());
        let (mut done, mut refunded, mut abandoned, mut active) = (0u64, 0u64, 0u64, 0u64);
        let (mut btc_vol, mut xbtc_vol) = (0u64, 0u64);
        let (mut fee_paid_total, mut fee_count) = (0u64, 0u64);
        for r in &self.records {
            let s = &r.swap;
            let own_chain = match s.role {
                Role::Maker => s.offer.maker_chain,
                Role::Taker => s.offer.maker_chain.other(),
            };
            let own_locked = match s.role {
                Role::Maker => s.maker_part,
                Role::Taker => s.taker_part,
            };
            // What we paid the project on our own lock, only if we locked and the offer set a fee
            // address for our chain. Recomputed from the terms with the same function that placed it.
            let fee_paid = if r.funding.is_some() {
                s.offer
                    .fee
                    .as_ref()
                    .filter(|t| t.address(own_chain).is_some())
                    .and_then(|t| {
                        fee::fee_amount_min(
                            FeeRates {
                                maker_bps: t.maker_bps,
                                taker_bps: t.taker_bps,
                            },
                            s.role,
                            own_locked,
                            self.min_trade_sat,
                        )
                        .ok()
                    })
                    .map(|a| a.to_sat())
            } else {
                None
            };
            if let Some(f) = fee_paid {
                fee_paid_total += f;
                fee_count += 1;
            }
            match s.phase {
                Phase::Done => done += 1,
                Phase::Refunded => refunded += 1,
                Phase::Abandoned => abandoned += 1,
                _ => active += 1,
            }
            for (c, amt) in [
                (s.offer.maker_chain, s.maker_part),
                (s.offer.maker_chain.other(), s.taker_part),
            ] {
                match c {
                    Chain::Btc => btc_vol += amt.to_sat(),
                    Chain::Xbtc => xbtc_vol += amt.to_sat(),
                }
            }
            let id: String = s.id.iter().map(|b| format!("{b:02x}")).collect();
            entries.push(serde_json::json!({
                "id": id,
                "role": match s.role { Role::Maker => "maker", Role::Taker => "taker" },
                "phase": format!("{:?}", s.phase).to_lowercase(),
                "maker_chain": chain(s.offer.maker_chain),
                "taker_chain": chain(s.offer.maker_chain.other()),
                "maker_amount_sat": s.maker_part.to_sat(),
                "taker_amount_sat": s.taker_part.to_sat(),
                "rate": s.taker_part.to_sat() as f64 / s.maker_part.to_sat().max(1) as f64,
                "our_lock_txid": r.funding.as_ref().map(|t| t.compute_txid().to_string()),
                "voluntary_fee_paid_sat": fee_paid,
                "started_at": s.started_at,
                "secret_revealed": s.learned_secret.is_some(),
                "active": !matches!(s.phase, Phase::Done | Phase::Refunded | Phase::Abandoned),
            }));
        }
        serde_json::json!({
            "swaps": entries,
            "totals": {
                "count": self.records.len(),
                "done": done,
                "refunded": refunded,
                "abandoned": abandoned,
                "active": active,
                "volume_sat": { "btc": btc_vol, "xbtc": xbtc_vol },
                "voluntary_fee_paid": { "swaps": fee_count, "total_sat": fee_paid_total },
            }
        })
    }

    pub fn seen_offers(&self) -> &[Offer] {
        &self.state.seen_offers
    }

    /// Discovered offers paired with when each was last seen (unix secs), for the market view (#88).
    pub fn seen_offers_with_time(&self) -> Vec<(Offer, Option<u64>)> {
        let now = now_unix();
        self.state
            .seen_offers
            .iter()
            // Maker-set expiry (design 0026, #212): an expired offer is dropped from the market view so
            // it is never shown or taken, independent of the re-announce TTL.
            .filter(|o| !o.is_expired(now))
            .map(|o| {
                let t = self
                    .state
                    .seen_at
                    .iter()
                    .find(|(id, _)| *id == o.id)
                    .map(|(_, t)| *t);
                (o.clone(), t)
            })
            .collect()
    }

    /// Age stale or withdrawn offers out of discovery (#88/#70/#65); persists if anything changed.
    fn prune_stale_offers(&mut self) -> Result<(), EngineError> {
        if prune_seen(
            &mut self.state.seen_offers,
            &mut self.state.seen_at,
            now_unix(),
        ) {
            self.save_state()?;
        }
        Ok(())
    }

    /// Our own live offers (those not yet taken). A filled offer is pruned, so this never advertises
    /// a spent offer.
    pub fn own_offers(&self) -> &[Offer] {
        &self.state.own_offers
    }

    /// Per-relay connection status (design 0029), for the client to show which relays (markets) it is
    /// connected to. Delegates to the transport.
    pub fn relay_status(&self) -> Vec<crate::routing::RelayStatus> {
        self.transport.relay_status()
    }

    /// Takes one of our offers off the market: drops it locally so `/offers` stops serving it and it
    /// cannot be taken, and broadcasts a `Withdraw` so peers drop it from their seen offers. A no-op
    /// if we do not hold the offer.
    pub fn withdraw(&mut self, offer_id: [u8; 16]) -> Result<(), EngineError> {
        let before = self.state.own_offers.len();
        self.state.own_offers.retain(|o| o.id != offer_id);
        if self.state.own_offers.len() == before {
            // Nothing was removed: the id is not one of our own offers (never ours, or already
            // withdrawn/filled). Report it rather than reporting a no-op as success (#78).
            return Err(EngineError::NotYourOffer);
        }
        self.save_state()?;
        self.transport.send(&Message::Withdraw { offer_id });
        Ok(())
    }

    /// Operator teardown of a swap that has not locked yet: mark it `Abandoned` so the engine stops
    /// trying to fund it. Refused once our lock is funded: a locked swap can only reach a timelock
    /// refund, never a forced abandon that would strand the coin. Idempotent on an already-terminal
    /// swap.
    pub fn abort(&mut self, swap_id: [u8; 16]) -> Result<(), EngineError> {
        let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) else {
            return Err(EngineError::NoSuchSwap);
        };
        if self.records[i].funding.is_some() {
            return Err(EngineError::AlreadyFunded);
        }
        if matches!(
            self.records[i].swap.phase,
            Phase::Done | Phase::Refunded | Phase::Abandoned
        ) {
            return Ok(());
        }
        self.records[i].swap.phase = Phase::Abandoned;
        self.save(&self.records[i])?;
        Ok(())
    }

    /// Resume a swap parked awaiting the user's funding signature (E2, design 0017): validate the
    /// submitted signed PSBT against the parked unsigned one (it must be the same transaction),
    /// finalize and broadcast it, record the lock, and clear the pending state. The swap proceeds on
    /// the next tick exactly as if the node had signed.
    pub fn submit_signed_lock(
        &mut self,
        swap_id: [u8; 16],
        signed_psbt: &str,
    ) -> Result<(), EngineError> {
        let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) else {
            return Err(EngineError::NoSuchSwap);
        };
        let Some(pending) = self.records[i].pending_lock_psbt.clone() else {
            return Err(EngineError::Node(NodeError::Unexpected(
                "swap is not awaiting a funding signature".into(),
            )));
        };
        // Broadcast the lock only if funding is still the right move, re-decided against a fresh chain
        // view by the same path `tick` uses. A parked swap can stop being fundable between ticks: its
        // phase is still `Locking` but the counterparty's lock window has already run out, so a phase
        // check alone would let a late signature through and commit the user's coin to an HTLC the
        // engine no longer drives to a refund (the #74 lose-both-legs case, and the same class as the
        // maker-`Locking` loaded gun). When funding is no longer decided, clear the pending PSBT so the
        // UI stops asking for a signature on a dead swap, and refuse. The user must also not broadcast
        // the signed PSBT from their own wallet; the engine refusing cannot stop that.
        let view = self.view(&self.records[i])?;
        // A user-held maker's secret is the USER's, not the engine's (0027): pass `None` so the engine
        // never fills the claim preimage from its own keys; the user reveals it at submit time.
        let secret = (self.records[i].swap.role == Role::Maker && !self.records[i].user_held)
            .then(|| self.keys.secret(self.records[i].swap.key_index));
        let still_funding = self.records[i]
            .swap
            .decide(&view, secret)
            .iter()
            .any(|a| matches!(a, Action::Fund));
        if !still_funding {
            // A non-Fund decision is not the same as a dead swap. Only a terminal re-decision (the swap
            // abandoned while the user was signing, or already settled) means the lock must never
            // broadcast: drop the pending PSBT so the UI stops asking, and refuse for good. Any other
            // non-Fund result is the swap still waiting on a precondition (e.g. the counterparty's fee
            // proof, which a transient backend read or a restart can briefly leave pending), NOT dead:
            // keep the parked PSBT exactly as it is (a rebuild with fresh inputs would strand the
            // signature) and refuse retryably so the user tries again shortly.
            if matches!(
                self.records[i].swap.phase,
                Phase::Abandoned | Phase::Done | Phase::Refunded | Phase::Refunding
            ) {
                self.records[i].pending_lock_psbt = None;
                self.save(&self.records[i])?;
                return Err(EngineError::NoLongerFundable);
            }
            return Err(EngineError::NotYetFundable);
        }
        let own_chain = match self.records[i].swap.role {
            Role::Maker => self.records[i].swap.offer.maker_chain,
            Role::Taker => self.records[i].swap.offer.maker_chain.other(),
        };
        let (contract, amount) = match self.records[i].swap.role {
            Role::Maker => (
                self.records[i].swap.maker_contract.clone(),
                self.records[i].swap.maker_part,
            ),
            Role::Taker => (
                self.records[i].swap.taker_contract.clone(),
                self.records[i].swap.taker_part,
            ),
        };
        let tx = self.nodes[&own_chain].finalize_submitted_lock(
            &pending,
            signed_psbt,
            &contract,
            amount,
        )?;
        self.backend(own_chain).broadcast(&tx)?;
        self.records[i].funding = Some(tx);
        self.records[i].pending_lock_psbt = None;
        self.records[i].expected_lock_txid = None;
        self.save(&self.records[i])?;
        Ok(())
    }

    /// The role -> (contract, value, destination) construction for a decided claim/refund action,
    /// built at `fee`, shared by `submit_signed_spend` (which verifies + finalizes it) and
    /// `pending_spend_template` (which exposes it for the browser). Pure: no `decide`, no chain read,
    /// no state change, and no park handling - the caller owns those, so the hardened terminal and
    /// sighash-mismatch branches in `submit_signed_spend` stay exactly where they are.
    fn build_spend(
        &self,
        i: usize,
        action: &Action,
        fee: Amount,
        user_preimage: Option<[u8; PREIMAGE_LEN]>,
    ) -> Result<RebuiltSpend, EngineError> {
        let swap = &self.records[i].swap;
        let (own_chain, own_contract, other_contract, other_amount) = match swap.role {
            Role::Maker => (
                swap.offer.maker_chain,
                &swap.maker_contract,
                &swap.taker_contract,
                swap.taker_part,
            ),
            Role::Taker => (
                swap.offer.maker_chain.other(),
                &swap.taker_contract,
                &swap.maker_contract,
                swap.maker_part,
            ),
        };
        match action {
            Action::Claim { lock, preimage } => {
                let spend = Spend {
                    outpoint: *lock,
                    value: other_amount,
                    destination: self.records[i].claim_to.clone(),
                    fee,
                };
                Ok(RebuiltSpend {
                    chain: own_chain.other(),
                    unsigned: other_contract
                        .claim_unsigned(&spend)
                        .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?,
                    witness_script: other_contract.script(),
                    input_value: other_amount,
                    preimage: (*preimage).or(user_preimage),
                })
            }
            Action::Refund { lock, value } => {
                let spend = Spend {
                    outpoint: *lock,
                    value: *value,
                    destination: self.records[i].refund_to.clone(),
                    fee,
                };
                Ok(RebuiltSpend {
                    chain: own_chain,
                    unsigned: own_contract
                        .refund_unsigned(&spend)
                        .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?,
                    witness_script: own_contract.script(),
                    input_value: *value,
                    preimage: None,
                })
            }
            _ => unreachable!("caller filters to Claim/Refund"),
        }
    }

    /// Resume a user-held claim/refund (0027): the user signed the parked spend's sighash, so assemble
    /// it with their signature and broadcast. Mirrors `submit_signed_lock`'s guard: it re-decides
    /// against a fresh chain view and only broadcasts if claim/refund is still the move. A terminal
    /// swap drops the park and refuses for good (`NoLongerFundable`); any other non-spend result is a
    /// retryable "not yet" (`NotYetFundable`). The spend is rebuilt at the parked fee, and its sighash
    /// must match what the user signed, so a swap that changed underneath them is refused, not
    /// broadcast with a signature that would not verify.
    pub fn submit_signed_spend(
        &mut self,
        swap_id: [u8; 16],
        sig: bitcoin::secp256k1::ecdsa::Signature,
        pubkey: bitcoin::PublicKey,
        // 0027: the maker's secret, supplied by the user with the claim signature. The user-held maker
        // holds the secret, so `decide` does not fill the preimage; the user reveals it here, and
        // `finalize` checks it against the committed `secret_hash`. `None` for a refund, and for a
        // taker claim (the taker's secret is public on chain, so `decide` already carries it).
        user_preimage: Option<[u8; PREIMAGE_LEN]>,
    ) -> Result<(), EngineError> {
        let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) else {
            return Err(EngineError::NoSuchSwap);
        };
        let Some(pending) = self.records[i].pending_spend.clone() else {
            return Err(EngineError::Node(NodeError::Unexpected(
                "swap is not awaiting a spend signature".into(),
            )));
        };
        let view = self.view(&self.records[i])?;
        // A user-held maker's secret is the USER's, not the engine's (0027): pass `None` so the engine
        // never fills the claim preimage from its own keys; the user reveals it at submit time.
        let secret = (self.records[i].swap.role == Role::Maker && !self.records[i].user_held)
            .then(|| self.keys.secret(self.records[i].swap.key_index));
        let action = self.records[i]
            .swap
            .decide(&view, secret)
            .into_iter()
            .find(|a| matches!(a, Action::Claim { .. } | Action::Refund { .. }));
        let Some(action) = action else {
            if matches!(
                self.records[i].swap.phase,
                Phase::Abandoned | Phase::Done | Phase::Refunded | Phase::Refunding
            ) {
                self.records[i].pending_spend = None;
                self.save(&self.records[i])?;
                return Err(EngineError::NoLongerFundable);
            }
            return Err(EngineError::NotYetFundable);
        };
        let fee = Amount::from_sat(pending.fee_sat);
        // Rebuild the spend at the parked fee. The claim preimage build_spend returns is whichever is
        // present: the one the re-decided action carries (a taker's learned secret, or a local maker's
        // own secret) or, for a user-held maker where `decide` leaves it `None`, the one the user
        // supplied with the signature. `finalize` then checks it against the committed `secret_hash`.
        let RebuiltSpend {
            chain,
            unsigned,
            preimage,
            ..
        } = self.build_spend(i, &action, fee, user_preimage)?;
        if unsigned.sighash != pending.sighash {
            self.records[i].pending_spend = None;
            self.save(&self.records[i])?;
            return Err(EngineError::Node(NodeError::Unexpected(
                "the swap changed while signing; re-request the spend signature".into(),
            )));
        }
        // Verify the submitted signature against the parked sighash under the submitted key before
        // finalizing (#240). `finalize` checks only the pubkey hash and the preimage, not the
        // signature. An honest backend already rejects an invalid-signature spend at broadcast (so the
        // `?` below leaves the spend parked, not poisoned), but verifying locally first gives a precise
        // retryable `BadSignature` instead of an opaque broadcast error, stops settlement relying on
        // the backend to validate the script (an untrusted Electrum server in E1 mode), and rejects a
        // high-S signature here. On failure leave the spend PARKED so the signer can retry: do not
        // clear `pending_spend` or store a `spent_tx`.
        let secp = bitcoin::secp256k1::Secp256k1::verification_only();
        if secp
            .verify_ecdsa(
                &bitcoin::secp256k1::Message::from_digest(unsigned.sighash),
                &sig,
                &pubkey.inner,
            )
            .is_err()
        {
            return Err(EngineError::BadSignature);
        }
        let tx = unsigned
            .finalize(sig, pubkey, preimage)
            .map_err(|e| NodeError::Unexpected(format!("finalize: {e:?}")))?;
        self.backend(chain).broadcast(&tx)?;
        // 0028: keep the user's signed spend so a later tick rebroadcasts it (if its lock still
        // matches) instead of re-parking and demanding a second signature. A swap is either awaiting a
        // signature (`pending_spend`) or already signed (`spent_tx`), never both, exactly like
        // `pending_lock_psbt` vs `funding`.
        self.records[i].pending_spend = None;
        self.records[i].spent_tx = Some(tx);
        self.records[i].spend_fee_sat = Some(pending.fee_sat);
        self.save(&self.records[i])?;
        Ok(())
    }

    /// The unsigned funding PSBT a swap is parked on, for the user to sign (E2, design 0017); `None`
    /// when the swap is not awaiting a funding signature.
    pub fn pending_lock_psbt(&self, id: [u8; 16]) -> Option<String> {
        self.records
            .iter()
            .find(|r| r.swap.id == id)?
            .pending_lock_psbt
            .clone()
    }

    /// The parked claim/refund a user-held swap is awaiting a signature on (0027): whether it is a
    /// claim (vs a refund) and the sighash the user signs with their claim/refund key. `None` when the
    /// swap is not awaiting a spend signature. The user signs this sighash with the key they derived
    /// for `key_index` (and, for a maker claim, reveals their secret), then posts it to
    /// `submit_signed_spend`, which rebuilds the identical spend and checks the sighash before
    /// broadcasting, so a stale or tampered value cannot settle.
    pub fn pending_spend(&self, id: [u8; 16]) -> Option<(bool, [u8; 32])> {
        let p = self
            .records
            .iter()
            .find(|r| r.swap.id == id)?
            .pending_spend
            .as_ref()?;
        Some((p.claim, p.sighash))
    }

    /// The full spend template a parked user-held swap is awaiting (0027), so the browser can recompute
    /// the BIP143 sighash from first principles and sign its own digest. `None` if the swap is not
    /// awaiting a spend signature, is no longer spendable, or has changed underneath the parked sighash.
    /// Rebuilt read-only through the same `build_spend` the signature submission uses, so what it
    /// exposes is exactly what the engine would spend. Decides with `secret = None` (the engine never
    /// needs the user's secret to describe the spend) and carries no preimage.
    ///
    /// The rebuilt-vs-parked sighash check is a FRESHNESS guard, not a security one: a malicious engine
    /// could serve any template with a matching sighash, so the browser must still rebuild the witness
    /// script from its own verified contract and check the destination against a reference it owns.
    pub fn pending_spend_template(&self, id: [u8; 16]) -> Option<SpendTemplate> {
        let i = self.records.iter().position(|r| r.swap.id == id)?;
        let sighash = self.records[i].pending_spend.as_ref()?.sighash;
        let claim = self.records[i].pending_spend.as_ref()?.claim;
        let fee = Amount::from_sat(self.records[i].pending_spend.as_ref()?.fee_sat);
        let view = self.view(&self.records[i]).ok()?;
        // `decide` takes `&mut self` and advances the swap phase; this accessor is read-only, so decide
        // on a CLONE and discard the transition. The action is identical to the one the real swap would
        // yield (same state), so the rebuilt spend matches what `submit_signed_spend` builds.
        let action = self.records[i]
            .swap
            .clone()
            .decide(&view, None)
            .into_iter()
            .find(|a| matches!(a, Action::Claim { .. } | Action::Refund { .. }))?;
        let rebuilt = self.build_spend(i, &action, fee, None).ok()?;
        // Freshness: if the swap changed underneath the parked sighash there is no stable template.
        if rebuilt.unsigned.sighash != sighash {
            return None;
        }
        Some(SpendTemplate {
            claim,
            unsigned_tx: rebuilt.unsigned.tx,
            witness_script: rebuilt.witness_script,
            input_value: rebuilt.input_value,
            sighash,
        })
    }

    pub fn node(&self, chain: Chain) -> &ChainNode {
        &self.nodes[&chain]
    }

    /// The chain's read/broadcast backend: a configured Electrum override (E1) if present, else the
    /// funding node. Funding and signing still need the concrete [`ChainNode`] (via `self.nodes`), so
    /// those call sites keep it; the data and broadcast ones go through the trait (design 0014/0016).
    fn backend(&self, chain: Chain) -> &dyn ChainBackend {
        if let Some(b) = self.read.get(&chain) {
            b.as_ref()
        } else {
            &self.nodes[&chain]
        }
    }

    /// Point `chain`'s chain-data reads and broadcasts at an Electrum server instead of the funding
    /// node's RPC (E1, design 0016). Funding and signing still use the node. Call right after
    /// [`Engine::open`]; the daemon sets it from the operator's configured Electrum endpoint.
    pub fn set_read_backend(&mut self, chain: Chain, backend: Box<dyn ChainBackend + Send + Sync>) {
        self.read.insert(chain, backend);
    }

    fn save_state(&self) -> Result<(), EngineError> {
        let bytes = serde_json::to_vec_pretty(&self.state).map_err(std::io::Error::other)?;
        Ok(write_atomic(&self.dir.join("engine.json"), &bytes)?)
    }

    fn save(&self, record: &Record) -> Result<(), EngineError> {
        let name = format!(
            "{}.json",
            bitcoin::hex::DisplayHex::to_lower_hex_string(&record.swap.id[..])
        );
        let bytes = serde_json::to_vec_pretty(record).map_err(std::io::Error::other)?;
        Ok(write_atomic(&self.dir.join("swaps").join(name), &bytes)?)
    }

    fn take_index(&mut self) -> u32 {
        self.state.next_index += 1;
        self.state.next_index - 1
    }

    /// Pre-provision user-held commitment bundles (0027) for upcoming swap indices. Public data only,
    /// derived client-side from the user's seed; the browser tops the pool up as swaps consume it. An
    /// entry for an index not yet consumed is overwritten (re-provision is idempotent). Persists.
    pub fn provision_commitments(
        &mut self,
        entries: Vec<(u32, Commitment)>,
    ) -> Result<(), EngineError> {
        for (index, c) in entries {
            self.state.commitment_pool.insert(index, c);
        }
        self.save_state()?;
        Ok(())
    }

    /// The next swap index that will be assigned, and the sorted indices the commitment pool already
    /// holds, so a user-held browser knows which indices still need provisioning (it tops up from
    /// `next_index` upward, skipping any already present). Public data only.
    pub fn commitment_status(&self) -> (u32, Vec<u32>) {
        (
            self.state.next_index,
            self.state.commitment_pool.keys().copied().collect(),
        )
    }

    /// True if a user-held commitment bundle is provisioned for `index` (peek, does not consume).
    fn has_commitment(&self, index: u32) -> bool {
        self.state.commitment_pool.contains_key(&index)
    }

    /// Take and REMOVE the user-held commitment for `index` so it is never reused (0027). Errors when
    /// absent, which refuses the swap rather than falling back to an engine-derived commitment.
    fn take_commitment(&mut self, index: u32) -> Result<Commitment, EngineError> {
        self.state
            .commitment_pool
            .remove(&index)
            .ok_or(EngineError::NoCommitment)
    }

    pub fn publish(&mut self, offer: Offer) -> Result<(), EngineError> {
        self.config
            .policy
            .depths(&offer, offer.maker_amount, offer.taker_amount)
            .map_err(EngineError::Policy)?;
        // 0018: the maker locks `maker_chain` and pays any fee there. If that fee address is a silent
        // payment but this chain's funding signer cannot build one (interactive, or a non-BIP352 cold
        // signer), the maker could never fund the offer, so refuse to advertise it.
        if let Some(terms) = &offer.fee {
            if let Some(addr) = terms.address(offer.maker_chain) {
                if is_silent_payment(addr) && !self.nodes[&offer.maker_chain].supports_silent_fee()
                {
                    return Err(EngineError::FeeNotFundable);
                }
            }
        }
        self.state.own_offers.push(offer.clone());
        self.save_state()?;
        self.transport.send(&Message::Offer(offer));
        Ok(())
    }

    /// Bids for `maker_part` of a seen offer.
    pub fn bid(
        &mut self,
        offer: &Offer,
        maker_part: Amount,
        swap_id: [u8; 16],
    ) -> Result<(), EngineError> {
        if self.state.own_offers.iter().any(|o| o.id == offer.id) {
            return Err(EngineError::Bid(BidError::OwnOffer));
        }
        // Maker-set expiry (design 0026, #212): never commit to an expired offer. Local refusal.
        if offer.is_expired(now_unix()) {
            return Err(EngineError::Bid(BidError::Expired));
        }
        let taker_part = offer
            .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
            .map_err(EngineError::Bid)?;
        // #103 beta cap: refuse to take a swap whose real-value (BTC) leg exceeds the local cap. The
        // BTC leg is `maker_part` when the maker sells BTC, else what we (the taker) pay in BTC.
        let btc_leg = if offer.maker_chain == Chain::Btc {
            maker_part
        } else {
            taker_part
        };
        if btc_leg.to_sat() > self.max_swap_sat {
            return Err(EngineError::Bid(BidError::AboveMax));
        }
        // F3 local band: refuse to take if our own voluntary fee would be a disproportionate fraction
        // of our leg. Local only (never the counterparty's fee verification), so an old and a new peer
        // never disagree over the offer.
        if let Some(terms) = &offer.fee {
            let taker_chain = offer.maker_chain.other();
            if let Some(addr) = terms.address(taker_chain) {
                // 0018: the taker locks `taker_chain` and pays the fee there. If that fee address is a
                // silent payment our funding signer for that chain cannot build (interactive, or a
                // non-BIP352 cold signer), taking the offer would let us commit while unable to fund the
                // fee, stranding the maker's already-locked coin to a refund. Refuse up front.
                if is_silent_payment(addr) && !self.nodes[&taker_chain].supports_silent_fee() {
                    return Err(EngineError::Bid(BidError::FeeNotFundable));
                }
                let rates = FeeRates {
                    maker_bps: terms.maker_bps,
                    taker_bps: terms.taker_bps,
                };
                if let Ok(fee) =
                    fee::fee_amount_min(rates, Role::Taker, taker_part, self.min_trade_sat)
                {
                    if fee::fee_exceeds_band(fee, taker_part) {
                        return Err(EngineError::Bid(BidError::FeeTooHigh));
                    }
                }
                // Take-side fee policy (security). The offer's fee rate and address are chosen by the
                // maker, who on the public relay may be hostile: cap the taker fee and require the fee
                // address for the chain we lock to be one the operator recognises, so we never pay a
                // large "fee" to an attacker's address. Off by default; the daemon sets it from config.
                if self.fee_take_max_bps > 0 && terms.taker_bps > self.fee_take_max_bps {
                    return Err(EngineError::Bid(BidError::FeeTooHigh));
                }
                let known = match taker_chain {
                    Chain::Btc => &self.fee_known_btc,
                    Chain::Xbtc => &self.fee_known_xbtc,
                };
                if !known.is_empty() && !known.iter().any(|k| k == addr) {
                    return Err(EngineError::Bid(BidError::FeeAddressNotAccepted));
                }
            }
        }
        self.config
            .policy
            .depths(offer, maker_part, taker_part)
            .map_err(EngineError::Policy)?;
        // 0027: a user-held taker needs a provisioned commitment for the index it is about to use.
        // Peek before consuming the index or sending a bid over the wire, so a missing bundle is a
        // clean local refusal rather than a bid the taker cannot honour when the Accept arrives.
        if self.config.user_held_spends && !self.has_commitment(self.state.next_index) {
            return Err(EngineError::Bid(BidError::NoCommitment));
        }
        let index = self.take_index();
        // The pubkey hashes the taker advertises in the bid MUST be the ones it later commits at
        // Accept, or the two sides build contracts at different addresses and never see each other's
        // lock. For a user-held taker, consume its bundle now, send the bundle's pubkey hashes, and
        // stash the bundle by swap id (so a later re-provision of this index cannot change what was
        // advertised). Otherwise the engine's own keys go on the wire and are rebuilt at Accept.
        let (taker_claim_pkh, taker_refund_pkh) = if self.config.user_held_spends {
            let c = self.take_commitment(index)?;
            let pkhs = (c.claim_pkh, c.refund_pkh);
            self.state.bid_commitments.push((swap_id, c));
            pkhs
        } else {
            (
                self.keys.pkh(index, Use::Claim),
                self.keys.pkh(index, Use::Refund),
            )
        };
        self.state
            .bids
            .push((swap_id, offer.clone(), maker_part, index));
        self.save_state()?;
        self.transport.send(&Message::Bid {
            offer_id: offer.id,
            swap_id,
            maker_part,
            taker_claim_pkh,
            taker_refund_pkh,
        });
        Ok(())
    }

    fn handle(&mut self, message: Message) -> Result<(), EngineError> {
        match message {
            Message::Offer(offer) => {
                // A replay of an offer the maker has since withdrawn must not reappear.
                if self.state.withdrawn.contains(&offer.id) {
                    return Ok(());
                }
                // Refresh the seen-at on every sighting, so a live, re-announced offer stays fresh
                // and a dead one ages out at its TTL (#88/#70).
                touch_seen(&mut self.state.seen_at, offer.id, now_unix());
                if !self.state.seen_offers.contains(&offer) {
                    self.state.seen_offers.push(offer);
                }
                self.save_state()?;
            }
            Message::Withdraw { offer_id } => {
                let before = self.state.seen_offers.len();
                self.state.seen_offers.retain(|o| o.id != offer_id);
                self.state.seen_at.retain(|(id, _)| *id != offer_id);
                let newly = !self.state.withdrawn.contains(&offer_id);
                if newly {
                    self.state.withdrawn.push(offer_id);
                }
                if newly || self.state.seen_offers.len() != before {
                    self.save_state()?;
                }
            }
            Message::Bid {
                offer_id,
                swap_id,
                maker_part,
                taker_claim_pkh,
                taker_refund_pkh,
            } => {
                let Some(offer) = self
                    .state
                    .own_offers
                    .iter()
                    .find(|o| o.id == offer_id)
                    .cloned()
                else {
                    eprintln!(
                        "bid dropped: no own offer {} (withdrawn or never ours)",
                        short_id(&offer_id)
                    );
                    return Ok(());
                };
                if self.records.iter().any(|r| r.swap.id == swap_id) {
                    return Ok(());
                }
                // A bid the maker cannot honour was silently dropped, so an operator could not tell a
                // below-minimum (or above-offer) bid from a lost message (F4). Log the reason.
                let taker_part = match offer
                    .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
                {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!(
                            "bid dropped for offer {}: amount {} sat rejected ({e:?}); min_swap_sat {}",
                            short_id(&offer_id),
                            maker_part.to_sat(),
                            self.min_swap_sat
                        );
                        return Ok(());
                    }
                };
                let depths = match self.config.policy.depths(&offer, maker_part, taker_part) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!(
                            "bid dropped for offer {}: policy rejected ({e:?})",
                            short_id(&offer_id)
                        );
                        return Ok(());
                    }
                };
                let index = self.take_index();
                // 0027: a user-held maker commits the hash and pubkey hashes the USER derived from
                // its own seed (the pre-provisioned bundle), not the engine's. Dropping the bid when
                // no bundle is provisioned is the same failure mode as any other bid-drop above.
                let (secret_hash, own_claim_pkh, own_refund_pkh) = if self.config.user_held_spends {
                    match self.take_commitment(index) {
                        Ok(c) => (c.secret_hash, c.claim_pkh, c.refund_pkh),
                        Err(_) => {
                            eprintln!(
                                "bid dropped for offer {}: no user-held commitment for index {index}",
                                short_id(&offer_id)
                            );
                            return Ok(());
                        }
                    }
                } else {
                    (
                        bitcoin::hashes::sha256::Hash::hash(&self.keys.secret(index))
                            .to_byte_array(),
                        self.keys.pkh(index, Use::Claim),
                        self.keys.pkh(index, Use::Refund),
                    )
                };
                let swap = Swap {
                    id: swap_id,
                    role: Role::Maker,
                    key_index: index,
                    maker_part,
                    taker_part,
                    maker_contract: Contract {
                        secret_hash,
                        claim_pkh: taker_claim_pkh,
                        refund_pkh: own_refund_pkh,
                        lock_blocks: offer.maker_lock_blocks,
                    },
                    taker_contract: Contract {
                        secret_hash,
                        claim_pkh: own_claim_pkh,
                        refund_pkh: taker_refund_pkh,
                        lock_blocks: offer.taker_lock_blocks,
                    },
                    depths,
                    // The same reference the taker computes, so the maker gives up (in
                    // `decide_maker`) strictly before the taker abandons, and never funds a lock
                    // against a swap the taker has already walked away from.
                    lock_deadline: self.backend(offer.maker_chain).height()?
                        + depths.maker_lock
                        + LOCK_WAIT_BLOCKS,
                    learned_secret: None,
                    phase: Phase::Locking,
                    started_at: Some(now_unix()),
                    offer,
                };
                self.start(swap)?;
                // The offer is atomic, so this bid consumes it: drop it so it cannot be taken again,
                // and tell peers to drop it from discovery too.
                self.state.own_offers.retain(|o| o.id != offer_id);
                self.save_state()?;
                self.transport.send(&Message::Withdraw { offer_id });
                let swap = &self.records.last().expect("just started").swap;
                self.transport.send(&Message::Accept {
                    swap_id,
                    secret_hash,
                    maker_claim_pkh: swap.taker_contract.claim_pkh,
                    maker_refund_pkh: swap.maker_contract.refund_pkh,
                });
            }
            Message::Accept {
                swap_id,
                secret_hash,
                maker_claim_pkh,
                maker_refund_pkh,
            } => {
                let Some(pos) = self.state.bids.iter().position(|b| b.0 == swap_id) else {
                    return Ok(());
                };
                let (_, offer, maker_part, index) = self.state.bids[pos].clone();
                let taker_part = offer
                    .taker_part_min(maker_part, Amount::from_sat(self.min_swap_sat))
                    .map_err(EngineError::Bid)?;
                let depths = self
                    .config
                    .policy
                    .depths(&offer, maker_part, taker_part)
                    .map_err(EngineError::Policy)?;
                // 0027: a user-held taker commits exactly the pubkey hashes it advertised in the bid,
                // taken from the stash keyed by swap id (consumed from the pool at bid time), so both
                // sides build the same contract. The secret hash is the maker's, off the wire.
                let (own_claim_pkh, own_refund_pkh) = if self.config.user_held_spends {
                    match self
                        .state
                        .bid_commitments
                        .iter()
                        .position(|(id, _)| *id == swap_id)
                    {
                        Some(pos) => {
                            let (_, c) = self.state.bid_commitments.remove(pos);
                            (c.claim_pkh, c.refund_pkh)
                        }
                        None => {
                            eprintln!(
                                "accept dropped for swap {}: no stashed user-held commitment",
                                short_id(&swap_id)
                            );
                            return Ok(());
                        }
                    }
                } else {
                    (
                        self.keys.pkh(index, Use::Claim),
                        self.keys.pkh(index, Use::Refund),
                    )
                };
                let swap = Swap {
                    id: swap_id,
                    role: Role::Taker,
                    key_index: index,
                    maker_part,
                    taker_part,
                    maker_contract: Contract {
                        secret_hash,
                        claim_pkh: own_claim_pkh,
                        refund_pkh: maker_refund_pkh,
                        lock_blocks: offer.maker_lock_blocks,
                    },
                    taker_contract: Contract {
                        secret_hash,
                        claim_pkh: maker_claim_pkh,
                        refund_pkh: own_refund_pkh,
                        lock_blocks: offer.taker_lock_blocks,
                    },
                    depths,
                    lock_deadline: self.backend(offer.maker_chain).height()?
                        + depths.maker_lock
                        + LOCK_WAIT_BLOCKS,
                    learned_secret: None,
                    phase: Phase::Waiting,
                    started_at: Some(now_unix()),
                    offer,
                };
                self.state.bids.remove(pos);
                self.start(swap)?;
            }
            Message::FeeProof { swap_id, proof } => {
                // Store the counterparty's fee proof so `view` can verify their lock's fee output
                // (design 0010). Keep the first one; a resend of a different proof is ignored.
                if let Some(i) = self.records.iter().position(|r| r.swap.id == swap_id) {
                    if self.records[i].received_fee.is_none() {
                        self.records[i].received_fee = Some(proof);
                        self.save(&self.records[i])?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Watches both contracts, picks destinations, stores the swap, then keeps the bookkeeping.
    /// Where our coin lands on `chain`: the operator's configured payout address if set (F5), else a
    /// fresh address from the node's own wallet (today's default). A configured address is
    /// network-checked by the node, so a misconfigured one fails the swap start rather than paying
    /// into the void.
    fn destination(&self, chain: Chain) -> Result<ScriptBuf, EngineError> {
        let configured = match chain {
            Chain::Btc => self.config.btc_payout.as_deref(),
            Chain::Xbtc => self.config.xbtc_payout.as_deref(),
        };
        match configured {
            Some(addr) => Ok(self.nodes[&chain].script_for(addr)?),
            None => Ok(self.nodes[&chain].new_destination()?),
        }
    }

    fn start(&mut self, swap: Swap) -> Result<(), EngineError> {
        let maker_chain = swap.offer.maker_chain;
        let (claim_chain, refund_chain) = match swap.role {
            Role::Maker => (maker_chain.other(), maker_chain),
            Role::Taker => (maker_chain, maker_chain.other()),
        };
        self.backend(maker_chain)
            .watch_contract(&swap.maker_contract)?;
        self.backend(maker_chain.other())
            .watch_contract(&swap.taker_contract)?;
        let record = Record {
            claim_to: self.destination(claim_chain)?,
            refund_to: self.destination(refund_chain)?,
            funding: None,
            pending_lock_psbt: None,
            pending_spend: None,
            expected_lock_txid: None,
            watch_from_height: None,
            fee: None,
            received_fee: None,
            spend_fee_sat: None,
            // 0027: fixed at creation from the config, never read live, so a later gate flip does not
            // change how this swap settles. The commitments were already sourced from the user's
            // bundle (or the engine's keys) above, consistently with this flag.
            user_held: self.config.user_held_spends,
            spent_tx: None,
            swap,
        };
        let id: String = record.swap.id.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!(
            "swap {id} ({:?}) started: maker {}, taker {}, phase {:?}",
            record.swap.role, record.swap.maker_part, record.swap.taker_part, record.swap.phase
        );
        self.save(&record)?;
        self.records.push(record);
        self.save_state()
    }

    /// The live on-chain view of swap `id` (both locks' txids, confirmations and heights), or `None`
    /// if there is no such swap. Queries the nodes, so a caller asks for it on demand, not every tick.
    pub fn chain_view(&self, id: [u8; 16]) -> Option<Result<ChainView, EngineError>> {
        self.records
            .iter()
            .find(|r| r.swap.id == id)
            .map(|r| self.view(r))
    }

    fn view(&self, record: &Record) -> Result<ChainView, EngineError> {
        let swap = &record.swap;
        let (a, b) = (
            self.backend(swap.offer.maker_chain),
            self.backend(swap.offer.maker_chain.other()),
        );
        let ours = [record.claim_to.clone(), record.refund_to.clone()];
        let mut maker_lock = a.lock_view(&swap.maker_contract, swap.maker_part, &ours)?;
        let mut taker_lock = b.lock_view(&swap.taker_contract, swap.taker_part, &ours)?;
        // Set the counterparty lock's voluntary-fee state (design 0010). The maker's counterparty is
        // the taker (taker_lock, on the other chain) and the reverse for the taker; our own lock's
        // fee is never checked.
        match swap.role {
            Role::Maker => {
                if let Some(lock) = taker_lock.as_mut() {
                    lock.fee = self.fee_state(record, lock.outpoint.txid, b);
                }
            }
            Role::Taker => {
                if let Some(lock) = maker_lock.as_mut() {
                    lock.fee = self.fee_state(record, lock.outpoint.txid, a);
                }
            }
        }
        Ok(ChainView {
            maker_chain_height: a.height()?,
            taker_chain_height: b.height()?,
            maker_lock,
            taker_lock,
            own_funded: record.funding.is_some(),
        })
    }

    /// The fee state of the counterparty's lock `lock_txid` on `cp_chain` (design 0010, 0013): no fee
    /// set for the counterparty's chain is `NotRequired`; the lock not readable (or, for a silent
    /// payment fee, no proof yet) is `Pending`; a fee output of at least the required amount, paying
    /// the agreed address (directly for a normal address, or by the DLEQ proof for a silent payment),
    /// is `Verified`; anything else is `Failed`.
    fn fee_state(&self, record: &Record, lock_txid: Txid, cp_chain: &dyn ChainBackend) -> FeeState {
        let swap = &record.swap;
        let Some(terms) = &swap.offer.fee else {
            return FeeState::NotRequired;
        };
        // The counterparty pays its fee on the chain it locks (design 0013). If the offer sets no fee
        // address for that chain, the counterparty owes no fee output and there is nothing to check.
        let cp_chain_id = match swap.role {
            Role::Maker => swap.offer.maker_chain.other(),
            Role::Taker => swap.offer.maker_chain,
        };
        let Some(fee_address) = terms.address(cp_chain_id) else {
            return FeeState::NotRequired;
        };
        let dest = match FeeDest::parse(fee_address, cp_chain.network()) {
            Ok(dest) => dest,
            Err(_) => return FeeState::Failed, // a malformed or wrong-network fee address
        };
        let cp_role = swap.role.other();
        let cp_locked = match cp_role {
            Role::Maker => swap.maker_part,
            Role::Taker => swap.taker_part,
        };
        let rates = FeeRates {
            maker_bps: terms.maker_bps,
            taker_bps: terms.taker_bps,
        };
        // A counterparty leg below the minimum trade owes no fee output, so there is nothing to verify
        // (design 0013 / fee.rs). This matches the payer's fund path, which also emits no fee output
        // for such a leg (#107); treating it as Failed broke the swap end to end.
        let Some(required) = fee_amount_or_none(rates, cp_role, cp_locked, self.min_trade_sat)
        else {
            return FeeState::NotRequired;
        };
        let Ok(lock_tx) = cp_chain.get_tx(lock_txid) else {
            return FeeState::Pending; // not on chain yet, or not readable: wait
        };
        match dest {
            // A normal address is verified directly: the lock must carry an output paying it at least
            // the required amount. No proof is involved (design 0013).
            FeeDest::Normal(addr) => {
                let spk = addr.script_pubkey();
                if lock_tx
                    .output
                    .iter()
                    .any(|o| o.script_pubkey == spk && o.value >= required)
                {
                    FeeState::Verified
                } else {
                    FeeState::Failed
                }
            }
            // A silent payment output is unlinkable, so the payer reveals a DLEQ share and proof the
            // counterparty authenticates against the lock's inputs (design 0010).
            FeeDest::SilentPayment(recipient) => {
                let Some(proof) = &record.received_fee else {
                    return FeeState::Pending;
                };
                let Ok(proof_bytes) = <[u8; 64]>::try_from(proof.proof.as_slice()) else {
                    return FeeState::Failed;
                };
                // Authenticate each input's public key from the proof's prevout transactions.
                let mut pubkeys = Vec::new();
                let mut outpoints = Vec::new();
                for input in &lock_tx.input {
                    outpoints.push(input.previous_output);
                    let Some(prevout) = proof
                        .prevouts
                        .iter()
                        .find(|t| t.compute_txid() == input.previous_output.txid)
                    else {
                        return FeeState::Failed;
                    };
                    let Some(txout) = prevout.output.get(input.previous_output.vout as usize)
                    else {
                        return FeeState::Failed;
                    };
                    if let Some(pk) = silentpayments::input_pubkey(
                        &txout.script_pubkey,
                        &input.script_sig,
                        &input.witness,
                    ) {
                        pubkeys.push(pk);
                    }
                }
                let share = proof.share.serialize();
                if silentpayments::verify_fee(
                    self.keys.secp(),
                    &pubkeys,
                    &outpoints,
                    &recipient,
                    &share,
                    &proof_bytes,
                    &lock_tx.output,
                    required,
                ) {
                    FeeState::Verified
                } else {
                    FeeState::Failed
                }
            }
        }
    }

    /// One round: messages in, then every unfinished swap decided, stored and acted on. Errors of a
    /// single swap are returned and do not stop the others.
    pub fn tick(&mut self) -> Vec<([u8; 16], EngineError)> {
        let mut errors = Vec::new();
        for message in self.transport.receive() {
            if let Err(e) = self.handle(message) {
                errors.push(([0; 16], e));
            }
        }
        if let Err(e) = self.prune_stale_offers() {
            errors.push(([0; 16], e));
        }
        self.reannounce_offers();
        for i in 0..self.records.len() {
            // Terminal swaps are skipped, with one exception (design 0019): a swap that abandoned while
            // a handed-out funding PSBT could still land keeps its `expected_lock_txid` marker and is
            // still advanced, so a lock the user broadcasts late is adopted and refunded.
            if matches!(self.records[i].swap.phase, Phase::Done | Phase::Refunded)
                || (self.records[i].swap.phase == Phase::Abandoned
                    && self.records[i].expected_lock_txid.is_none())
            {
                continue;
            }
            let before = self.records[i].swap.phase;
            if let Err(e) = self.advance(i) {
                errors.push((self.records[i].swap.id, e));
            }
            // Log every phase transition so an operator can follow a swap in `package logs`, not only
            // in the web UI: the engine store and the API remain the record of truth, this is the
            // monitoring trail. No secrets are logged, only the swap id, role, and phase.
            let after = self.records[i].swap.phase;
            if after != before {
                let swap = &self.records[i].swap;
                let id: String = swap.id.iter().map(|b| format!("{b:02x}")).collect();
                eprintln!("swap {id} ({:?}): {before:?} -> {after:?}", swap.role);
            }
        }
        errors
    }

    /// E2 (design 0019): if the lock we handed the user to sign is now on chain (whoever broadcast it),
    /// adopt it. Record the funding transaction so the normal claim/refund and reorg-rebroadcast paths
    /// drive it, and clear both the prompt and the watch marker. Matches on the expected txid, which a
    /// segwit lock preserves from the unsigned PSBT. Returns whether it adopted.
    fn adopt_own_lock(&mut self, i: usize, view: &ChainView) -> Result<bool, EngineError> {
        let Some(marker) = self.records[i].expected_lock_txid else {
            return Ok(false);
        };
        let own_txid = match self.records[i].swap.role {
            Role::Maker => view.maker_lock.as_ref(),
            Role::Taker => view.taker_lock.as_ref(),
        }
        .map(|lock| lock.outpoint.txid);
        if own_txid != Some(marker) {
            return Ok(false);
        }
        let own_chain = match self.records[i].swap.role {
            Role::Maker => self.records[i].swap.offer.maker_chain,
            Role::Taker => self.records[i].swap.offer.maker_chain.other(),
        };
        let tx = self.backend(own_chain).get_tx(marker)?;
        self.records[i].funding = Some(tx);
        self.records[i].pending_lock_psbt = None;
        self.records[i].expected_lock_txid = None;
        self.records[i].watch_from_height = None;
        self.save(&self.records[i])?;
        Ok(true)
    }

    fn advance(&mut self, i: usize) -> Result<(), EngineError> {
        let view = self.view(&self.records[i])?;

        // E2 terminal watch (design 0019): a swap that abandoned while a handed-out PSBT could still
        // land is not skipped by tick() while its marker is set. If the user's lock has now appeared,
        // adopt it and drive it to a self.keys refund (decide refuses to reconsider a terminal swap, so
        // the Refunding transition is made here explicitly); otherwise there is nothing to drive yet,
        // so keep watching. decide's own deadline logic keeps the refund safe.
        if self.records[i].swap.phase == Phase::Abandoned {
            // Adopt ANY lock on our contract refund-only (design 0019). The expected lock OR a
            // look-alike (a different txid, e.g. the user re-funded in their wallet) is still our HTLC,
            // refundable only by self.keys; the swap already abandoned, so decide drives it to a refund.
            // We must not let the watch horizon drop the marker while our contract is funded, or that
            // coin is stranded (the #134 hazard, with a timer).
            let own_lock_txid = match self.records[i].swap.role {
                Role::Maker => view.maker_lock.as_ref(),
                Role::Taker => view.taker_lock.as_ref(),
            }
            .map(|lock| lock.outpoint.txid);
            if let Some(txid) = own_lock_txid {
                let own_chain = match self.records[i].swap.role {
                    Role::Maker => self.records[i].swap.offer.maker_chain,
                    Role::Taker => self.records[i].swap.offer.maker_chain.other(),
                };
                let tx = self.backend(own_chain).get_tx(txid)?;
                self.records[i].funding = Some(tx);
                self.records[i].expected_lock_txid = None;
                self.records[i].watch_from_height = None;
                self.records[i].swap.phase = Phase::Refunding;
                self.save(&self.records[i])?;
                // fall through to decide -> self.keys refund
            } else {
                // Our contract is unfunded. Keep watching, but bounded (design 0019): once the own chain
                // is past the horizon the user never broadcast, so drop the marker and stop watching, so
                // a counterparty that bids and walks away cannot leave a marker watched forever.
                let own_height = match self.records[i].swap.role {
                    Role::Maker => view.maker_chain_height,
                    Role::Taker => view.taker_chain_height,
                };
                if let Some(from) = self.records[i].watch_from_height {
                    if own_height > from.saturating_add(self.adopt_watch_cap_blocks) {
                        self.records[i].expected_lock_txid = None;
                        self.records[i].watch_from_height = None;
                        self.save(&self.records[i])?;
                    }
                }
                return Ok(());
            }
        }

        // Re-send our fee proof each tick while the swap is live (design 0010); the relay may drop
        // it, and the counterparty needs it to verify our lock. Receiving it twice is harmless.
        if let Some(proof) = self.records[i].fee.clone() {
            self.transport.send(&Message::FeeProof {
                swap_id: self.records[i].swap.id,
                proof,
            });
        }

        // E2 adoption while parked (design 0019): the user may have broadcast the lock themselves
        // during the funding window. If it is on chain, adopt it (this clears the prompt) and let
        // decide below run it to Done or a refund on the same view.
        if self.records[i].pending_lock_psbt.is_some() {
            self.adopt_own_lock(i, &view)?;
        }

        // A user-held maker's secret is the USER's, not the engine's (0027): pass `None` so the engine
        // never fills the claim preimage from its own keys; the user reveals it at submit time.
        let secret = (self.records[i].swap.role == Role::Maker && !self.records[i].user_held)
            .then(|| self.keys.secret(self.records[i].swap.key_index));
        let before = self.records[i].swap.phase;
        let actions = self.records[i].swap.decide(&view, secret);

        // E2 split the prompt from the watch (design 0019): when a parked swap abandons at the funding
        // window, clear the prompt so the UI stops asking for a signature and submit_signed_lock's
        // refusal is consistent, but KEEP `expected_lock_txid`. The terminal watch above then keeps
        // looking for the user's lock and refunds it if it lands, which is the #134 hazard.
        if self.records[i].pending_lock_psbt.is_some() {
            if before != Phase::Abandoned && self.records[i].swap.phase == Phase::Abandoned {
                self.records[i].pending_lock_psbt = None;
            } else if matches!(self.records[i].swap.phase, Phase::Done | Phase::Refunded) {
                self.records[i].pending_lock_psbt = None;
                self.records[i].expected_lock_txid = None;
                self.records[i].watch_from_height = None;
            }
        }
        self.save(&self.records[i])?;
        for action in actions {
            self.act(i, action)?;
        }
        // Stamp the watch horizon (design 0019) once a swap has parked (act set `pending_lock_psbt`),
        // from the view height, so the bounded terminal watch counts from a synced height consistent
        // with the give-up comparison (not a possibly-lagging backend read at park time).
        if self.records[i].pending_lock_psbt.is_some()
            && self.records[i].watch_from_height.is_none()
        {
            let own_height = match self.records[i].swap.role {
                Role::Maker => view.maker_chain_height,
                Role::Taker => view.taker_chain_height,
            };
            self.records[i].watch_from_height = Some(own_height);
            self.save(&self.records[i])?;
        }
        Ok(())
    }

    /// Fee a claim or refund by the chain's live estimate (or the conservative fallback when it cannot
    /// estimate), never below the configured floor and never below any fee already chosen for this
    /// spend, so a rebuild only ever replaces upward and stays within RBF rules (F6).
    fn rate_spend(
        &self,
        chain: Chain,
        prior: Option<u64>,
        build: impl Fn(Amount) -> Result<Transaction, crate::htlc::SpendError>,
    ) -> Result<(Transaction, Amount), crate::htlc::SpendError> {
        let rate = self
            .backend(chain)
            .estimate_fee_sat_vb(SPEND_CONF_TARGET)
            .unwrap_or(FALLBACK_SPEND_RATE_SAT_VB);
        crate::htlc::spend_at_rate(
            build,
            rate,
            self.config.min_spend_fee,
            prior.map(Amount::from_sat),
        )
    }

    fn act(&mut self, i: usize, action: Action) -> Result<(), EngineError> {
        let record = self.records[i].clone();
        let swap = &record.swap;
        let (own_chain, own_contract, own_amount, other_contract, other_amount) = match swap.role {
            Role::Maker => (
                swap.offer.maker_chain,
                &swap.maker_contract,
                swap.maker_part,
                &swap.taker_contract,
                swap.taker_part,
            ),
            Role::Taker => (
                swap.offer.maker_chain.other(),
                &swap.taker_contract,
                swap.taker_part,
                &swap.maker_contract,
                swap.maker_part,
            ),
        };
        let (chain, tx, spend_fee) = match action {
            Action::Fund => match record.funding {
                Some(tx) => (own_chain, tx, None),
                None => {
                    // E2 (0017): parked awaiting the user's funding signature? Do nothing until they
                    // submit it via submit_signed_lock. Never rebuild a parked lock: a fresh
                    // walletcreatefundedpsbt could pick different inputs and strand the signature.
                    if record.pending_lock_psbt.is_some() {
                        return Ok(());
                    }
                    let other = &self.nodes[&own_chain.other()].rpc;
                    let lock_amount = self.lock_amount_override.unwrap_or(own_amount);
                    // The voluntary fee (design 0010, 0013): terms come from the offer, the address
                    // for the chain we lock, the amount from our role and what we lock. If the offer
                    // sets no fee address for our chain, we lock without a fee output. A leg below the
                    // minimum trade owes no fee (design 0013 / fee.rs semantics), so BelowMinimum means
                    // "no fee output" here too, not a failure: treating it as a failure stranded the
                    // first locker's coin for any leg in [min_swap, min_trade) with a fee address (#107).
                    // The counterparty's fee verification reaches the same conclusion (NotRequired).
                    let fee = match swap
                        .offer
                        .fee
                        .as_ref()
                        .and_then(|terms| terms.address(own_chain).map(|a| (terms, a)))
                    {
                        None => None,
                        Some((terms, fee_address)) => {
                            let dest =
                                FeeDest::parse(fee_address, self.nodes[&own_chain].network())?;
                            let rates = FeeRates {
                                maker_bps: terms.maker_bps,
                                taker_bps: terms.taker_bps,
                            };
                            fee_amount_or_none(rates, swap.role, lock_amount, self.min_trade_sat)
                                .map(|amount| (amount, dest))
                        }
                    };
                    // Tests only: a fee-cheating counterparty tampers with the owed fee output, so the
                    // honest party's on-chain fee verification can be exercised against a wrong or
                    // underpaid fee. Only applies when a fee is actually owed.
                    let fee = fee.map(|(amount, dest)| match &self.fee_tamper {
                        Some(FeeTamper::WrongAddress(addr)) => {
                            let wrong = FeeDest::parse(addr, self.nodes[&own_chain].network())
                                .expect("test fee_tamper address parses");
                            (amount, wrong)
                        }
                        Some(FeeTamper::Underpay(sat)) => (Amount::from_sat(*sat), dest),
                        None => (amount, dest),
                    });
                    match self.nodes[&own_chain].fund(
                        own_contract,
                        lock_amount,
                        self.config.fee_rate_sat_vb,
                        self.config.policy.funding_minconf(own_chain),
                        other,
                        fee.as_ref().map(|(a, dest)| (*a, dest)),
                    ) {
                        Ok((tx, fee_proof)) => {
                            self.records[i].funding = Some(tx.clone());
                            self.records[i].fee = fee_proof;
                            self.save(&self.records[i])?;
                            (own_chain, tx, None)
                        }
                        // E2 (0017): the user signs out of band. Park the unsigned PSBT (it has
                        // already passed the replay guard) and wait for submit_signed_lock; do not
                        // broadcast anything now.
                        Err(NodeError::AwaitingSignature { psbt }) => {
                            // Record the expected lock txid as a watch that outlives the prompt
                            // (design 0019), so a lock the user broadcasts, even after the swap later
                            // abandons, is still recognised and refunded. The watch horizon is stamped
                            // in advance() from the view height (consistent with the give-up check).
                            self.records[i].expected_lock_txid = Some(funding_psbt_txid(&psbt)?);
                            self.records[i].pending_lock_psbt = Some(psbt);
                            self.save(&self.records[i])?;
                            return Ok(());
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
            },
            Action::Claim { lock, preimage } => {
                let spend_chain = own_chain.other();
                if record.user_held {
                    // 0028: if the user already signed this claim and it still spends this lock,
                    // rebroadcast it rather than re-parking for a second signature (a race once the
                    // secret is public). A stale stored spend for a different outpoint (e.g. a dead
                    // refund after a role switch) does not match, so it is dropped and a fresh claim is
                    // parked below.
                    if let Some(tx) = reusable_spend(record.spent_tx.as_ref(), lock) {
                        self.backend(spend_chain).broadcast(tx)?;
                        return Ok(());
                    }
                    if record.spent_tx.is_some() {
                        self.records[i].spent_tx = None;
                        self.save(&self.records[i])?;
                    }
                    // 0027: do not sign; park the unsigned claim for the user to sign. Build once and
                    // keep it (the parked sighash stays stable across ticks); nothing is broadcast until
                    // submit_signed_spend. Fee it by the real signed vsize via the SAME rate_spend path
                    // as the local claim, estimated with a dummy-witness probe since a user-held spend
                    // cannot sign to measure.
                    if self.records[i].pending_spend.is_none() {
                        let probe = |fee: Amount| {
                            other_contract.claim_probe(&Spend {
                                outpoint: lock,
                                value: other_amount,
                                destination: record.claim_to.clone(),
                                fee,
                            })
                        };
                        let (_, fee) = self
                            .rate_spend(spend_chain, record.spend_fee_sat, probe)
                            .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?;
                        let spend = Spend {
                            outpoint: lock,
                            value: other_amount,
                            destination: record.claim_to.clone(),
                            fee,
                        };
                        let unsigned = other_contract
                            .claim_unsigned(&spend)
                            .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?;
                        self.records[i].pending_spend = Some(PendingSpend {
                            claim: true,
                            fee_sat: fee.to_sat(),
                            sighash: unsigned.sighash,
                        });
                        self.save(&self.records[i])?;
                    }
                    return Ok(());
                }
                // Local signing (not user-held): `decide` always supplies a preimage here, the maker's
                // own secret or the taker's secret learned from chain, so `None` would be a logic bug.
                let preimage = preimage.expect(
                    "a local-signing claim carries a preimage (own secret or learned secret)",
                );
                let key = self.keys.key(swap.key_index, Use::Claim);
                let secp = self.keys.secp();
                let build = |fee| {
                    let spend = Spend {
                        outpoint: lock,
                        value: other_amount,
                        destination: record.claim_to.clone(),
                        fee,
                    };
                    other_contract.claim(secp, &spend, &key, &preimage)
                };
                let (tx, fee) = self
                    .rate_spend(spend_chain, record.spend_fee_sat, build)
                    .map_err(|e| NodeError::Unexpected(format!("claim: {e:?}")))?;
                (spend_chain, tx, Some(fee.to_sat()))
            }
            Action::Refund { lock, value } => {
                if record.user_held {
                    // 0028: rebroadcast the user's already-signed refund if it still spends this lock,
                    // else drop a stale one (see the claim arm) and park a fresh refund below.
                    if let Some(tx) = reusable_spend(record.spent_tx.as_ref(), lock) {
                        self.backend(own_chain).broadcast(tx)?;
                        return Ok(());
                    }
                    if record.spent_tx.is_some() {
                        self.records[i].spent_tx = None;
                        self.save(&self.records[i])?;
                    }
                    // 0027: park the unsigned refund for the user to sign (see the claim arm), fee'd by
                    // the real signed vsize via rate_spend + a dummy-witness probe.
                    if self.records[i].pending_spend.is_none() {
                        let probe = |fee: Amount| {
                            own_contract.refund_probe(&Spend {
                                outpoint: lock,
                                value,
                                destination: record.refund_to.clone(),
                                fee,
                            })
                        };
                        let (_, fee) = self
                            .rate_spend(own_chain, record.spend_fee_sat, probe)
                            .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?;
                        let spend = Spend {
                            outpoint: lock,
                            value,
                            destination: record.refund_to.clone(),
                            fee,
                        };
                        let unsigned = own_contract
                            .refund_unsigned(&spend)
                            .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?;
                        self.records[i].pending_spend = Some(PendingSpend {
                            claim: false,
                            fee_sat: fee.to_sat(),
                            sighash: unsigned.sighash,
                        });
                        self.save(&self.records[i])?;
                    }
                    return Ok(());
                }
                let key = self.keys.key(swap.key_index, Use::Refund);
                let secp = self.keys.secp();
                let build = |fee| {
                    let spend = Spend {
                        outpoint: lock,
                        value,
                        destination: record.refund_to.clone(),
                        fee,
                    };
                    own_contract.refund(secp, &spend, &key)
                };
                let (tx, fee) = self
                    .rate_spend(own_chain, record.spend_fee_sat, build)
                    .map_err(|e| NodeError::Unexpected(format!("refund: {e:?}")))?;
                (own_chain, tx, Some(fee.to_sat()))
            }
        };
        if self.drop_broadcasts > 0 {
            self.drop_broadcasts -= 1;
            return Ok(());
        }
        self.backend(chain).broadcast(&tx)?;
        // Persist the chosen claim/refund fee only AFTER the broadcast is accepted (F6), so the stored
        // fee never diverges from the transaction actually in the mempool: a rejected bump leaves the
        // prior fee in place, and the next tick rebuilds the identical, already-accepted transaction.
        if let Some(fee) = spend_fee {
            if self.records[i].spend_fee_sat != Some(fee) {
                self.records[i].spend_fee_sat = Some(fee);
                self.save(&self.records[i])?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{fee_amount_or_none, State};
    use crate::fee::FeeRates;
    use crate::swap::Role;
    use bitcoin::Amount;

    #[test]
    fn a_leg_below_the_minimum_trade_owes_no_fee_output_107() {
        let rates = FeeRates {
            maker_bps: 20,
            taker_bps: 30,
        };
        let min_trade = 100_000;
        // Below the minimum trade: no fee output, on either role. Before #107 this returned an error
        // that the fund path turned into a hard failure, stranding the first locker's coin.
        assert_eq!(
            fee_amount_or_none(rates, Role::Maker, Amount::from_sat(50_000), min_trade),
            None
        );
        assert_eq!(
            fee_amount_or_none(rates, Role::Taker, Amount::from_sat(99_999), min_trade),
            None
        );
        // At or above the minimum trade: a fee is owed (floored), so an output is required.
        assert!(
            fee_amount_or_none(rates, Role::Maker, Amount::from_sat(100_000), min_trade).is_some()
        );
        assert!(
            fee_amount_or_none(rates, Role::Taker, Amount::from_sat(1_000_000), min_trade)
                .is_some()
        );
    }

    #[test]
    fn a_pre_m1_engine_state_still_loads() {
        // An engine.json written before the withdrawn set existed must still deserialize, with the
        // new field defaulting to empty (serde(default)).
        let old = r#"{"next_index":3,"own_offers":[],"seen_offers":[],"bids":[]}"#;
        let state: State = serde_json::from_str(old).unwrap();
        assert_eq!(state.next_index, 3);
        assert!(state.withdrawn.is_empty());
        assert!(
            state.seen_at.is_empty(),
            "seen_at defaults empty on an old state"
        );
    }

    #[test]
    fn a_pre_0027_engine_state_still_loads_and_commitments_round_trip() {
        use super::Commitment;
        use bitcoin::hashes::Hash;
        use bitcoin::PubkeyHash;
        // A state written before 0027 has no commitment_pool or bid_commitments; both default empty.
        let old = r#"{"next_index":3,"own_offers":[],"seen_offers":[],"bids":[]}"#;
        let state: State = serde_json::from_str(old).unwrap();
        assert!(state.commitment_pool.is_empty());
        assert!(state.bid_commitments.is_empty());
        // A state carrying a commitment (keyed by index) round-trips through save/load.
        let mut state = State {
            next_index: 5,
            ..Default::default()
        };
        state.commitment_pool.insert(
            5,
            Commitment {
                secret_hash: [7u8; 32],
                claim_pkh: PubkeyHash::from_byte_array([1u8; 20]),
                refund_pkh: PubkeyHash::from_byte_array([2u8; 20]),
            },
        );
        let back: State = serde_json::from_str(&serde_json::to_string(&state).unwrap()).unwrap();
        assert_eq!(back.next_index, 5);
        let c = back
            .commitment_pool
            .get(&5)
            .expect("commitment round-trips");
        assert_eq!(c.secret_hash, [7u8; 32]);
        assert_eq!(c.claim_pkh, PubkeyHash::from_byte_array([1u8; 20]));
    }

    #[test]
    fn reusable_spend_matches_only_the_actions_lock() {
        use super::reusable_spend;
        use bitcoin::hashes::Hash;
        use bitcoin::{
            absolute::LockTime, transaction::Version, OutPoint, ScriptBuf, Sequence, Transaction,
            TxIn, Txid, Witness,
        };
        let outpoint = |b: u8, vout: u32| OutPoint {
            txid: Txid::from_byte_array([b; 32]),
            vout,
        };
        let spend = |o: OutPoint| Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: o,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![],
        };
        let lock = outpoint(1, 0);
        // A stored spend of this lock is reusable; a spend of a different outpoint (e.g. a dead refund
        // after a role switch to a claim on the other chain) is NOT; and None is never reusable.
        let own = spend(lock);
        assert!(reusable_spend(Some(&own), lock).is_some());
        let stale = spend(outpoint(2, 1));
        assert!(reusable_spend(Some(&stale), lock).is_none());
        assert!(reusable_spend(None, lock).is_none());
    }

    #[test]
    fn prune_seen_ages_out_stale_and_stamps_legacy() {
        use super::{prune_seen, SEEN_OFFER_TTL_SECS};
        use crate::swap::{Chain, Offer};
        use bitcoin::Amount;
        let offer = |n: u8| Offer {
            id: [n; 16],
            maker_chain: Chain::Xbtc,
            maker_amount: Amount::from_sat(1000),
            taker_amount: Amount::from_sat(1000),
            min_maker_amount: Amount::ZERO,
            maker_lock_blocks: 40,
            taker_lock_blocks: 20,
            maker_lock_depth: 2,
            taker_lock_depth: 2,
            margin_blocks: 3,
            fee: None,
            valid_until: None,
        };
        let now = 1_000_000u64;
        let mut seen_offers = vec![offer(1), offer(2), offer(3)];
        let mut seen_at = vec![
            ([1u8; 16], now), // fresh
            ([2u8; 16], now - SEEN_OFFER_TTL_SECS - 1), // stale, must drop
                              // offer(3): no entry = legacy, stamped at now
        ];
        assert!(
            prune_seen(&mut seen_offers, &mut seen_at, now),
            "stale dropped = a change"
        );
        let ids: Vec<[u8; 16]> = seen_offers.iter().map(|o| o.id).collect();
        assert!(ids.contains(&[1u8; 16]) && !ids.contains(&[2u8; 16]) && ids.contains(&[3u8; 16]));
        // The legacy offer now carries a timestamp: a second prune at the same time is a no-op.
        assert!(!prune_seen(&mut seen_offers, &mut seen_at, now));
        // Everything ages out once past the TTL.
        assert!(prune_seen(
            &mut seen_offers,
            &mut seen_at,
            now + SEEN_OFFER_TTL_SECS + 1
        ));
        assert!(seen_offers.is_empty() && seen_at.is_empty());
    }

    #[test]
    fn touch_seen_refreshes_so_a_re_announced_offer_survives_its_first_seen_ttl() {
        // Regression: `seen_at` is a LAST-seen (freshness) stamp. An offer re-announced within the
        // window must survive a prune past its FIRST-seen + TTL; one not re-seen must age out. This
        // locks in the handle(Offer) refresh that `prune_seen` alone does not provide.
        use super::{prune_seen, touch_seen, SEEN_OFFER_TTL_SECS};
        use crate::swap::{Chain, Offer};
        use bitcoin::Amount;
        let offer = |n: u8| Offer {
            id: [n; 16],
            maker_chain: Chain::Xbtc,
            maker_amount: Amount::from_sat(1000),
            taker_amount: Amount::from_sat(1000),
            min_maker_amount: Amount::ZERO,
            maker_lock_blocks: 40,
            taker_lock_blocks: 20,
            maker_lock_depth: 2,
            taker_lock_depth: 2,
            margin_blocks: 3,
            fee: None,
            valid_until: None,
        };
        let t0 = 1_000_000u64;
        let mut seen_offers = vec![offer(1), offer(2)];
        let mut seen_at = Vec::new();
        touch_seen(&mut seen_at, [1u8; 16], t0); // both first seen at t0
        touch_seen(&mut seen_at, [2u8; 16], t0);
        // offer 1 is re-announced near the end of its window; offer 2 is never re-seen.
        touch_seen(&mut seen_at, [1u8; 16], t0 + SEEN_OFFER_TTL_SECS - 10);
        // Prune just past offer 1's FIRST-seen + TTL.
        prune_seen(&mut seen_offers, &mut seen_at, t0 + SEEN_OFFER_TTL_SECS + 5);
        let ids: Vec<[u8; 16]> = seen_offers.iter().map(|o| o.id).collect();
        assert!(
            ids.contains(&[1u8; 16]),
            "a re-announced offer must stay fresh past its first-seen TTL"
        );
        assert!(
            !ids.contains(&[2u8; 16]),
            "an offer not re-seen within the TTL must age out"
        );
        assert_eq!(
            seen_at
                .iter()
                .find(|(i, _)| *i == [1u8; 16])
                .map(|(_, t)| *t),
            Some(t0 + SEEN_OFFER_TTL_SECS - 10),
            "the stamp is the last-seen time, not the first-seen"
        );
    }
}

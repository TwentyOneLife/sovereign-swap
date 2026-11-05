//! `sovereign-swap-daemon`: the long-running client service (design 0009, M4a). It owns the engine
//! and the config and exposes a small local HTTP+JSON API on `127.0.0.1` for a GUI to drive. This
//! module is the API surface and the config; wiring every endpoint to a live engine (publishing to
//! relays, driving swaps) is the next M4a step, so offers and swaps here are an in-memory scaffold
//! with the real validation and auth already in place.
//!
//! Security posture, because this is an API a browser talks to:
//! - binds `127.0.0.1` only (never a routable address);
//! - every request needs the bearer token written to the data dir on first run (mode 600), checked
//!   in constant time, so another local process or a web page cannot drive the daemon;
//! - the request is size-capped and the body must parse as the expected JSON, or it is refused;
//! - there is no "move funds" or "freeze" route: the API starts and watches swaps, never seizes value.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hex::{Case, DisplayHex, FromHex};
use bitcoin::Amount;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::engine::{Config as EngineConfig, Engine};
use crate::envelope::Identity;
use crate::node::ChainNode;
use crate::policy::Policy;
use crate::routing::RelayTransport;
use crate::rpc::Client;
use crate::swap::{Chain as SwapChain, Offer as SwapOffer, Phase};
use crate::ws::WsConn;

/// How often the engine thread drives a swap forward when no command arrives.
const TICK_INTERVAL: Duration = Duration::from_secs(3);
/// Default per-leg timelocks for a new offer, in blocks (the engine clamps to policy regardless).
const MAKER_LOCK_BLOCKS: u16 = 40;
const TAKER_LOCK_BLOCKS: u16 = 20;

/// The largest request (headers + body) we read. Settings and offers are tiny; anything near this is
/// abuse, so we refuse it rather than grow a buffer.
const MAX_REQUEST_BYTES: usize = 64 * 1024;
/// Below this an amount is dust; an offer under it is refused.
const DUST_SAT: u64 = 10_000;
/// A sane band for a swap price, so a fat-fingered or hostile rate is caught before it is published.
const MIN_PRICE: f64 = 0.5;
const MAX_PRICE: f64 = 2.0;

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
        e
    }
}

/// A scaffold offer record. The live version is published to the relays and discovered from them;
/// here it is held in memory so the API is coherent and testable before the engine is wired.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Offer {
    pub id: String,
    pub sell_chain: Chain,
    pub amount_sat: u64,
    pub price: f64,
    pub min_amount_sat: u64,
}

/// What a `POST /offers` body must contain. Validated before an offer is created.
#[derive(Deserialize)]
struct NewOffer {
    sell_chain: Chain,
    amount_sat: u64,
    price: f64,
    min_amount_sat: u64,
}

impl NewOffer {
    fn validate(&self) -> Vec<String> {
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
    fn into_swap_offer(self, s: &Settings) -> SwapOffer {
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

struct DaemonState {
    settings: Settings,
    offers: Vec<Offer>,
}

pub struct Daemon {
    state: Arc<Mutex<DaemonState>>,
    token: String,
    data_dir: PathBuf,
    /// The channel to the engine thread, present once the engine is started from settings. Behind a
    /// Mutex because a configure can (re)start it.
    engine: Arc<Mutex<Option<Sender<EngineCmd>>>>,
    /// This node's long-term identity and per-connection routing key seeds, persisted so the identity
    /// is stable across restarts.
    identity_seed: [u8; 32],
    routing_seed: [u8; 32],
}

impl Daemon {
    /// Opens the daemon in `data_dir`: loads `settings.json` (or defaults), loads or creates the API
    /// token (`token`, mode 600).
    pub fn open(data_dir: &Path) -> std::io::Result<Daemon> {
        std::fs::create_dir_all(data_dir)?;
        let settings = match std::fs::read(data_dir.join("settings.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
            Err(_) => Settings::default(),
        };
        let token = load_or_make_token(data_dir)?;
        let daemon = Daemon {
            state: Arc::new(Mutex::new(DaemonState {
                settings,
                offers: Vec::new(),
            })),
            token,
            data_dir: data_dir.to_owned(),
            engine: Arc::new(Mutex::new(None)),
            identity_seed: load_or_make_seed(data_dir, "identity.seed")?,
            routing_seed: load_or_make_seed(data_dir, "routing.seed")?,
        };
        // If the saved settings are already complete, bring the engine up; otherwise it starts after
        // the first complete PUT /settings.
        let _ = daemon.start_engine();
        Ok(daemon)
    }

    /// Opens the engine from the current settings and spawns its thread. Returns an error string if
    /// the settings are incomplete or a node or relay cannot be reached. Idempotent-ish: a running
    /// engine is replaced (the old thread ends when its channel drops).
    pub fn start_engine(&self) -> Result<(), String> {
        let settings = self.state.lock().unwrap().settings.clone();
        let Some(relay) = settings.relays.first() else {
            return Err("no relay configured".to_owned());
        };
        // A wallet name unique to this daemon's identity, so two daemons sharing one pair of nodes
        // (as in tests, or a shared node setup) do not collide on the same wallet.
        let wallet = format!(
            "swap-{}",
            self.identity_seed[..4].to_hex_string(Case::Lower)
        );
        let open_node = |addr: &str, user: &str, pass: &str| {
            ChainNode::open(Client::new(addr, user, pass), &wallet).map_err(|e| format!("{e:?}"))
        };
        let btc = open_node(
            &settings.btc_node,
            &settings.btc_rpc_user,
            &settings.btc_rpc_pass,
        )?;
        let xbtc = open_node(
            &settings.xbtc_node,
            &settings.xbtc_rpc_user,
            &settings.xbtc_rpc_pass,
        )?;
        // Tor-first: an .onion relay is dialed through a local SOCKS5 proxy; a plain host is direct.
        let socks = relay
            .contains(".onion")
            .then(|| "127.0.0.1:9050".to_owned());
        let conn = WsConn::connect(relay, socks.as_deref()).map_err(|e| format!("relay: {e:?}"))?;
        let transport = RelayTransport::new(
            Identity::from_seed(&self.identity_seed),
            &self.routing_seed,
            conn,
        );
        let config = engine_config(&settings);
        let engine = Engine::open(&self.data_dir.join("engine"), btc, xbtc, transport, config)
            .map_err(|e| format!("engine: {e:?}"))?;

        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || run_engine(engine, rx));
        *self.engine.lock().unwrap() = Some(tx);
        Ok(())
    }

    /// Sends a command to the engine thread and waits for its reply. `Err` if the engine is not
    /// running or the thread is gone.
    fn engine_call<R>(&self, make: impl FnOnce(Sender<R>) -> EngineCmd) -> Result<R, String> {
        let guard = self.engine.lock().unwrap();
        let tx = guard.as_ref().ok_or("engine not running")?;
        let (reply_tx, reply_rx) = mpsc::channel();
        tx.send(make(reply_tx)).map_err(|_| "engine stopped")?;
        reply_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| "engine timed out".to_owned())
    }

    fn engine_running(&self) -> bool {
        self.engine.lock().unwrap().is_some()
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Binds and serves forever on `bind` (must be a loopback address). A thread per connection.
    pub fn serve(self, bind: &str) -> std::io::Result<()> {
        let listener = TcpListener::bind(bind)?;
        self.accept_loop(listener);
        Ok(())
    }

    /// Binds an ephemeral loopback port and serves in a background thread; for tests. Returns the
    /// bound address and the token a client must present.
    pub fn spawn(self) -> std::io::Result<(String, String)> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?.to_string();
        let token = self.token.clone();
        std::thread::spawn(move || self.accept_loop(listener));
        Ok((addr, token))
    }

    fn accept_loop(self, listener: TcpListener) {
        let me = Arc::new(self);
        for stream in listener.incoming().flatten() {
            let me = Arc::clone(&me);
            std::thread::spawn(move || me.serve_connection(stream));
        }
    }

    fn serve_connection(&self, mut stream: TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let (status, body) = match read_request(&mut stream) {
            Ok(req) => self.route(&req),
            Err(code) => (code, json!({"error": "bad request"})),
        };
        let body = body.to_string();
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\
             Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
            reason = reason(status),
            len = body.len(),
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    fn route(&self, req: &Request) -> (u16, Value) {
        // Auth first, on every route: a missing or wrong token is 401 before anything else happens.
        if !self.authorized(req) {
            return (401, json!({"error": "unauthorized"}));
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/status") => (200, self.status()),
            ("GET", "/settings") => (
                200,
                serde_json::to_value(&self.state.lock().unwrap().settings).unwrap(),
            ),
            ("PUT", "/settings") => self.put_settings(&req.body),
            ("GET", "/offers") => self.get_offers(),
            ("POST", "/offers") => self.post_offer(&req.body),
            ("GET", "/swaps") => self.get_swaps(),
            ("POST", p)
                if p.starts_with("/offers/")
                    && p.ends_with("/take")
                    && valid_id(offer_id_of(p)) =>
            {
                self.post_take(offer_id_of(p), &req.body)
            }
            // A bounded dynamic path. Kept strict so nothing is mistaken for a file to serve.
            ("GET", p) if p.starts_with("/swaps/") && valid_id(&p[7..]) => self.get_swap(&p[7..]),
            ("GET", p) if p.starts_with("/offers/") || p.starts_with("/swaps/") => {
                (404, json!({"error": "not found"}))
            }
            (_, _) => (404, json!({"error": "not found"})),
        }
    }

    fn authorized(&self, req: &Request) -> bool {
        match req.headers.get("authorization") {
            Some(h) => {
                let presented = h.strip_prefix("Bearer ").unwrap_or("");
                constant_time_eq(presented.as_bytes(), self.token.as_bytes())
            }
            None => false,
        }
    }

    fn status(&self) -> Value {
        let settings = self.state.lock().unwrap().settings.clone();
        let running = self.engine_running();
        let active = if running {
            self.engine_call(EngineCmd::Swaps)
                .map(|v: Vec<SwapView>| v.iter().filter(|s| s.is_active()).count())
                .unwrap_or(0)
        } else {
            0
        };
        json!({
            "btc_node": reachable(&settings.btc_node),
            "xbtc_node": reachable(&settings.xbtc_node),
            "relays": settings.relays.len(),
            "engine": running,
            "active_swaps": active,
        })
    }

    fn get_offers(&self) -> (u16, Value) {
        if !self.engine_running() {
            return (200, json!(self.state.lock().unwrap().offers));
        }
        match self.engine_call(EngineCmd::Offers) {
            Ok(offers) => (
                200,
                json!(offers.iter().map(offer_to_json).collect::<Vec<_>>()),
            ),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn get_swaps(&self) -> (u16, Value) {
        if !self.engine_running() {
            return (200, json!([]));
        }
        match self.engine_call(EngineCmd::Swaps) {
            Ok(swaps) => (
                200,
                json!(swaps.iter().map(SwapView::to_json).collect::<Vec<_>>()),
            ),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn get_swap(&self, id_hex: &str) -> (u16, Value) {
        let Ok(id) = <[u8; 16]>::from_hex(id_hex) else {
            return (404, json!({"error": "no such swap"}));
        };
        if !self.engine_running() {
            return (404, json!({"error": "no such swap"}));
        }
        match self.engine_call(EngineCmd::Swaps) {
            Ok(swaps) => match swaps.iter().find(|s| s.id == id) {
                Some(s) => (200, s.to_json()),
                None => (404, json!({"error": "no such swap"})),
            },
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn post_take(&self, offer_id_hex: &str, body: &[u8]) -> (u16, Value) {
        let Ok(offer_id) = <[u8; 16]>::from_hex(offer_id_hex) else {
            return (400, json!({"error": "bad offer id"}));
        };
        #[derive(Deserialize)]
        struct Take {
            amount_sat: u64,
        }
        let Ok(take) = serde_json::from_slice::<Take>(body) else {
            return (400, json!({"error": "take needs amount_sat"}));
        };
        if !self.engine_running() {
            return (503, json!({"error": "engine not running"}));
        }
        let maker_part = Amount::from_sat(take.amount_sat);
        match self.engine_call(move |reply| EngineCmd::Take {
            offer_id,
            maker_part,
            reply,
        }) {
            Ok(Ok(swap_id)) => (
                200,
                json!({ "swap_id": swap_id.to_hex_string(Case::Lower) }),
            ),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn put_settings(&self, body: &[u8]) -> (u16, Value) {
        let Ok(settings) = serde_json::from_slice::<Settings>(body) else {
            return (
                400,
                json!({"error": "settings must be a valid JSON object"}),
            );
        };
        let errors = settings.validate();
        if !errors.is_empty() {
            return (422, json!({"error": "invalid settings", "fields": errors}));
        }
        if self.save_settings(&settings).is_err() {
            return (500, json!({"error": "could not persist settings"}));
        }
        self.state.lock().unwrap().settings = settings;
        // Bring the engine up (or restart it) now the settings may be complete. A failure here just
        // means it is not running yet; the GUI learns that from GET /status, and the settings are
        // saved regardless.
        let _ = self.start_engine();
        (200, json!({"ok": true}))
    }

    fn post_offer(&self, body: &[u8]) -> (u16, Value) {
        let Ok(new) = serde_json::from_slice::<NewOffer>(body) else {
            return (400, json!({"error": "offer must be a valid JSON object"}));
        };
        let errors = new.validate();
        if !errors.is_empty() {
            return (422, json!({"error": "invalid offer", "fields": errors}));
        }
        if self.engine_running() {
            let offer = new.into_swap_offer(&self.state.lock().unwrap().settings);
            let id = offer.id.to_hex_string(Case::Lower);
            return match self.engine_call(move |reply| EngineCmd::Publish(offer, reply)) {
                Ok(Ok(())) => (200, json!({ "offer_id": id })),
                Ok(Err(e)) => (422, json!({ "error": e })),
                Err(e) => (503, json!({ "error": e })),
            };
        }
        // Scaffold path when no engine is configured: validate and remember, so the API is usable
        // and testable without live nodes.
        let id = random_hex(8);
        self.state.lock().unwrap().offers.push(Offer {
            id: id.clone(),
            sell_chain: new.sell_chain,
            amount_sat: new.amount_sat,
            price: new.price,
            min_amount_sat: new.min_amount_sat,
        });
        (200, json!({ "offer_id": id }))
    }

    fn save_settings(&self, settings: &Settings) -> std::io::Result<()> {
        std::fs::write(
            self.data_dir.join("settings.json"),
            serde_json::to_vec_pretty(settings).unwrap(),
        )
    }
}

/// A command to the engine thread. The engine never leaves that thread; only these messages cross it,
/// so none of the engine's internals need to be shared or `Send` across a lock.
enum EngineCmd {
    Publish(SwapOffer, Sender<Result<(), String>>),
    Offers(Sender<Vec<SwapOffer>>),
    Swaps(Sender<Vec<SwapView>>),
    Take {
        offer_id: [u8; 16],
        maker_part: Amount,
        reply: Sender<Result<[u8; 16], String>>,
    },
}

/// The slice of a swap the API exposes (id and phase); more detail follows as the GUI needs it.
pub struct SwapView {
    id: [u8; 16],
    phase: Phase,
}

impl SwapView {
    fn is_active(&self) -> bool {
        !matches!(self.phase, Phase::Done | Phase::Refunded | Phase::Abandoned)
    }

    fn to_json(&self) -> Value {
        json!({
            "id": self.id.to_hex_string(Case::Lower),
            "phase": format!("{:?}", self.phase).to_lowercase(),
        })
    }
}

/// Owns the engine, drives it forward on a timer, and serves commands. Ends when the daemon drops its
/// sender (all senders gone => `Disconnected`).
fn run_engine(mut engine: Engine<RelayTransport<WsConn>>, rx: Receiver<EngineCmd>) {
    loop {
        match rx.recv_timeout(TICK_INTERVAL) {
            Ok(cmd) => handle_engine_cmd(cmd, &mut engine),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
        let _ = engine.tick();
    }
}

fn handle_engine_cmd(cmd: EngineCmd, engine: &mut Engine<RelayTransport<WsConn>>) {
    match cmd {
        EngineCmd::Publish(offer, reply) => {
            let _ = reply.send(engine.publish(offer).map_err(|e| format!("{e:?}")));
        }
        EngineCmd::Offers(reply) => {
            let _ = reply.send(engine.seen_offers().to_vec());
        }
        EngineCmd::Swaps(reply) => {
            let views = engine
                .swaps()
                .map(|s| SwapView {
                    id: s.id,
                    phase: s.phase,
                })
                .collect();
            let _ = reply.send(views);
        }
        EngineCmd::Take {
            offer_id,
            maker_part,
            reply,
        } => {
            let found = engine
                .seen_offers()
                .iter()
                .find(|o| o.id == offer_id)
                .cloned();
            let res = match found {
                Some(o) => {
                    let id = random16();
                    engine
                        .bid(&o, maker_part, id)
                        .map(|_| id)
                        .map_err(|e| format!("{e:?}"))
                }
                None => Err("no such offer".to_owned()),
            };
            let _ = reply.send(res);
        }
    }
}

fn engine_config(s: &Settings) -> EngineConfig {
    let mut policy = Policy::standard();
    policy.funding_minconf_btc = s.btc_conf;
    policy.funding_minconf_xbtc = s.xbtc_conf;
    EngineConfig {
        spend_fee: Amount::from_sat(2_000),
        fee_rate_sat_vb: 2,
        policy,
    }
}

fn offer_to_json(o: &SwapOffer) -> Value {
    json!({
        "id": o.id.to_hex_string(Case::Lower),
        "sell_chain": chain_str(o.maker_chain),
        "amount_sat": o.maker_amount.to_sat(),
        "counter_amount_sat": o.taker_amount.to_sat(),
        "min_amount_sat": o.min_maker_amount.to_sat(),
        "maker_lock_blocks": o.maker_lock_blocks,
        "taker_lock_blocks": o.taker_lock_blocks,
    })
}

fn chain_str(c: SwapChain) -> &'static str {
    match c {
        SwapChain::Btc => "btc",
        SwapChain::Xbtc => "xbtc",
    }
}

/// Extracts `<id>` from `/offers/<id>/take`.
fn offer_id_of(path: &str) -> &str {
    path.strip_prefix("/offers/")
        .and_then(|r| r.strip_suffix("/take"))
        .unwrap_or("")
}

fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut b);
    }
    b
}

fn load_or_make_seed(data_dir: &Path, name: &str) -> std::io::Result<[u8; 32]> {
    let path = data_dir.join(name);
    if let Ok(hex) = std::fs::read_to_string(&path) {
        if let Ok(bytes) = <[u8; 32]>::from_hex(hex.trim()) {
            return Ok(bytes);
        }
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut seed)?;
    std::fs::write(&path, seed.to_hex_string(Case::Lower))?;
    set_owner_only(&path);
    Ok(seed)
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

struct Request {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

/// Reads one HTTP/1.1 request, size-capped. `Err(code)` is the status to answer with.
fn read_request(stream: &mut TcpStream) -> Result<Request, u16> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    // Read until the header terminator, bounded by the cap.
    let header_end = loop {
        if let Some(pos) = find(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_REQUEST_BYTES {
            return Err(413);
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(400),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(400),
        }
    };
    let head = std::str::from_utf8(&buf[..header_end]).map_err(|_| 400u16)?;
    let mut lines = head.split("\r\n");
    let mut parts = lines.next().unwrap_or("").split(' ');
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();
    if method.is_empty() || !path.starts_with('/') {
        return Err(400);
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    if content_len > MAX_REQUEST_BYTES {
        return Err(413);
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_len {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => body.extend_from_slice(&chunk[..n]),
            Err(_) => return Err(400),
        }
        if body.len() > MAX_REQUEST_BYTES {
            return Err(413);
        }
    }
    body.truncate(content_len);
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn load_or_make_token(data_dir: &Path) -> std::io::Result<String> {
    let path = data_dir.join("token");
    if let Ok(existing) = std::fs::read_to_string(&path) {
        let t = existing.trim().to_owned();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    let token = random_hex(32);
    std::fs::write(&path, &token)?;
    set_owner_only(&path);
    Ok(token)
}

#[cfg(unix)]
fn set_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_owner_only(_path: &Path) {}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    // Best-effort OS randomness; the token guards a loopback API, not a key.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    buf.to_hex_string(Case::Lower)
}

/// Compares in time independent of how many leading bytes match, so the token cannot be guessed by
/// timing. Unequal lengths still run a full pass over the presented bytes.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    for (i, &byte) in a.iter().enumerate() {
        diff |= byte ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
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

/// An id we will echo into a path or a response: hex-ish, bounded, no path tricks.
fn valid_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn reachable(host_port: &str) -> bool {
    use std::net::ToSocketAddrs;
    host_port
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .map(|addr| TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_ok())
        .unwrap_or(false)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        413 => "Payload Too Large",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        _ => "OK",
    }
}

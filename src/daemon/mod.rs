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

use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hex::{Case, DisplayHex, FromHex};
use bitcoin::Amount;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::engine::Engine;
use crate::envelope::Identity;
use crate::node::ChainNode;
use crate::routing::RelayTransport;
use crate::rpc::Client;
use crate::ws::WsConn;

/// How often the engine thread drives a swap forward when no command arrives.
mod engine;
mod types;
mod wire;

pub use engine::SwapView;
pub use types::{parse_btc_to_sats, Chain, Settings, Signer};

use engine::{engine_config, offer_to_json, run_engine, EngineCmd};
use types::{NewOffer, Offer};
use wire::{
    constant_time_eq, load_or_make_seed, load_or_make_token, offer_id_of, random_hex, reachable,
    read_request, reason, valid_id, Request,
};

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
    /// Server-Sent-Events subscribers (the GUI). The engine thread broadcasts phase changes and new
    /// offers here so the GUI updates live instead of polling.
    events: Arc<Mutex<Vec<Sender<String>>>>,
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
            events: Arc::new(Mutex::new(Vec::new())),
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
        let events = Arc::clone(&self.events);
        std::thread::spawn(move || run_engine(engine, rx, events));
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
        let req = match read_request(&mut stream) {
            Ok(req) => req,
            Err(code) => {
                return self.write_json(&mut stream, code, &json!({"error": "bad request"}))
            }
        };
        // The live event stream is a long-lived connection, not a single response.
        if req.method == "GET" && req.path == "/events" {
            if self.authorized(&req) {
                self.serve_events(stream);
            } else {
                self.write_json(&mut stream, 401, &json!({"error": "unauthorized"}));
            }
            return;
        }
        let (status, body) = self.route(&req);
        self.write_json(&mut stream, status, &body);
    }

    fn write_json(&self, stream: &mut TcpStream, status: u16, body: &Value) {
        let body = body.to_string();
        let resp = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\
             Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
            reason = reason(status),
            len = body.len(),
        );
        let _ = stream.write_all(resp.as_bytes());
    }

    /// Serves the live event stream (Server-Sent Events): headers, then one `data:` line per event
    /// the engine broadcasts, with a periodic keepalive. Returns (and the subscriber is pruned on the
    /// next broadcast) when the client disconnects.
    fn serve_events(&self, mut stream: TcpStream) {
        let headers =
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\n\
                       Connection: keep-alive\r\nX-Content-Type-Options: nosniff\r\n\r\n";
        if stream.write_all(headers.as_bytes()).is_err() {
            return;
        }
        let (tx, rx) = mpsc::channel::<String>();
        self.events.lock().unwrap().push(tx);
        let _ = stream.write_all(b": connected\n\n");
        loop {
            let frame = match rx.recv_timeout(Duration::from_secs(20)) {
                Ok(line) => format!("data: {line}\n\n"),
                Err(RecvTimeoutError::Timeout) => ": keepalive\n\n".to_owned(),
                Err(RecvTimeoutError::Disconnected) => return,
            };
            if stream.write_all(frame.as_bytes()).is_err() {
                return; // client gone; the broadcaster prunes our sender when its send next fails
            }
        }
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
        match self.engine_call(move |reply| EngineCmd::Detail(id, reply)) {
            Ok(Some(detail)) => (200, detail),
            Ok(None) => (404, json!({"error": "no such swap"})),
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

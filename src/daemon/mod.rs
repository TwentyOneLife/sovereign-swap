//! `sovereign-swap-daemon`: the long-running client service (design 0009, M4a). It owns the engine
//! and the config and exposes a small local HTTP+JSON API on `127.0.0.1` for a GUI to drive. This
//! module is the API surface and the config; every offer and swap it serves comes from the live
//! engine (publishing to and discovering from relays, driving swaps on the user's own nodes). The
//! daemon never fabricates data: until the user's nodes and a relay are configured and the engine
//! is running, the data endpoints return "engine not running" rather than empty or placeholder
//! results.
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
mod reference;
mod types;
mod wire;

pub use engine::SwapView;
pub use types::{parse_btc_to_sats, Chain, Settings, Signer};

use engine::{engine_config, offer_to_json, run_engine, EngineCmd};
use reference::Reference;
use types::NewOffer;
use wire::{
    constant_time_eq, load_or_make_seed, load_or_make_token, offer_id_of, reachable, read_request,
    reason, valid_id, Request,
};

/// The GUI (design 0009), embedded in the binary and served on the loopback API. `index.html` carries
/// a `__TOKEN__` placeholder the daemon fills with the API token before serving it.
const INDEX_HTML: &str = include_str!("../gui/index.html");
const APP_CSS: &str = include_str!("../gui/app.css");
const APP_JS: &str = include_str!("../gui/app.js");

struct DaemonState {
    settings: Settings,
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
    /// Optional external price reference (opt-in, over Tor).
    reference: Reference,
    /// Server-Sent-Events subscribers (the GUI). The engine thread broadcasts phase changes and new
    /// offers here so the GUI updates live instead of polling.
    events: Arc<Mutex<Vec<Sender<String>>>>,
    /// Optional web UI password (`SWAP_USERNAME`/`SWAP_PASSWORD`, set by the StartOS package). When
    /// present, the page and its assets (which carry the API token) are served only to a browser that
    /// passes HTTP Basic auth, so knowing the onion is no longer enough to reach the swaps.
    basic_auth: Option<(String, String)>,
    /// When set (`SWAP_CONFIG_LOCKED=1`, the StartOS package), node/relay config is owned by the
    /// package action: the web UI shows it read-only and `PUT /settings` is refused. This keeps the
    /// one config source authoritative and off the public page.
    config_locked: bool,
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
        let basic_auth = match (
            std::env::var("SWAP_USERNAME"),
            std::env::var("SWAP_PASSWORD"),
        ) {
            (Ok(u), Ok(p)) if !u.is_empty() && !p.is_empty() => Some((u, p)),
            _ => None,
        };
        let config_locked = std::env::var("SWAP_CONFIG_LOCKED").as_deref() == Ok("1");
        let daemon = Daemon {
            state: Arc::new(Mutex::new(DaemonState { settings })),
            token,
            data_dir: data_dir.to_owned(),
            engine: Arc::new(Mutex::new(None)),
            identity_seed: load_or_make_seed(data_dir, "identity.seed")?,
            routing_seed: load_or_make_seed(data_dir, "routing.seed")?,
            events: Arc::new(Mutex::new(Vec::new())),
            reference: Reference::default(),
            basic_auth,
            config_locked,
        };
        // If the saved settings are already complete, bring the engine up; otherwise it starts after
        // the first complete PUT /settings. A failure here is not fatal (the GUI learns it from GET
        // /status), but it is logged: a silently swallowed reason is very hard to diagnose in the
        // field, where the nodes or the relay may be the cause.
        if let Err(e) = daemon.start_engine() {
            eprintln!("engine not started on open: {e}");
        }
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
        // Tor-first: an .onion node or relay is dialed through the configured SOCKS5 proxy; a plain
        // host is direct. An https node is verified against its Root CA, an onion accepts its cert
        // (design 0011). All the rules are enforced in Client::connect.
        //
        // `SWAP_TOR_SOCKS`, when set, overrides the settings value: on StartOS the container has no
        // Tor at a fixed address, so the package resolves the proxy bridge address and injects it
        // here, and the user never has to guess it. The settings field stays the manual fallback.
        let tor_socks = std::env::var("SWAP_TOR_SOCKS")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| settings.tor_socks.clone());
        let open_node = |addr: &str, user: &str, pass: &str, ca: &str| {
            let socks = addr.contains(".onion").then_some(tor_socks.as_str());
            let ca = (!ca.trim().is_empty()).then_some(ca);
            let client = Client::connect(addr, user, pass, ca, socks)
                .map_err(|e| format!("node {addr}: {e:?}"))?;
            ChainNode::open(client, &wallet).map_err(|e| format!("{e:?}"))
        };
        let btc = open_node(
            &settings.btc_node,
            &settings.btc_rpc_user,
            &settings.btc_rpc_pass,
            &settings.btc_rpc_ca,
        )?;
        let xbtc = open_node(
            &settings.xbtc_node,
            &settings.xbtc_rpc_user,
            &settings.xbtc_rpc_pass,
            &settings.xbtc_rpc_ca,
        )?;
        let socks = relay.contains(".onion").then(|| tor_socks.to_owned());
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
        // Web UI password: when StartOS has set credentials, the page and its assets (which carry the
        // API token) are served only to a Basic-authenticated browser. The API and event stream stay
        // token-gated, and the token is never served without the password, so the whole site is behind
        // it. When no credentials are set (a plain non-StartOS daemon), the page is open as before.
        if let Some((user, pass)) = self.basic_auth.clone() {
            let is_page = req.method == "GET"
                && matches!(
                    req.path.as_str(),
                    "/" | "/index.html" | "/app.css" | "/app.js"
                );
            if is_page && !self.basic_ok(&req, &user, &pass) {
                return self.write_unauthorized_basic(&mut stream);
            }
        }
        // The live event stream is a long-lived connection, not a single response.
        if req.method == "GET" && req.path == "/events" {
            if self.authorized(&req) {
                self.serve_events(stream);
            } else {
                self.write_json(&mut stream, 401, &json!({"error": "unauthorized"}));
            }
            return;
        }
        // The GUI itself is served without the token (a cross-origin site cannot read the response,
        // so it cannot steal the token injected into the page); the API it then calls still needs it.
        if req.method == "GET" {
            match req.path.as_str() {
                "/" | "/index.html" => {
                    let page = INDEX_HTML.replace("__TOKEN__", &self.token);
                    return self.write_asset(
                        &mut stream,
                        "text/html; charset=utf-8",
                        page.as_bytes(),
                    );
                }
                "/app.css" => {
                    return self.write_asset(
                        &mut stream,
                        "text/css; charset=utf-8",
                        APP_CSS.as_bytes(),
                    )
                }
                "/app.js" => {
                    return self.write_asset(
                        &mut stream,
                        "application/javascript; charset=utf-8",
                        APP_JS.as_bytes(),
                    )
                }
                _ => {}
            }
        }
        let (status, body) = self.route(&req);
        self.write_json(&mut stream, status, &body);
    }

    fn write_asset(&self, stream: &mut TcpStream, content_type: &str, body: &[u8]) {
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n\
             Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(header.as_bytes());
        let _ = stream.write_all(body);
    }

    /// A 401 that makes the browser prompt for the web UI password (HTTP Basic).
    fn write_unauthorized_basic(&self, stream: &mut TcpStream) {
        let body = br#"{"error":"authentication required"}"#;
        let resp = format!(
            "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"sovereign-swap\", charset=\"UTF-8\"\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(resp.as_bytes());
        let _ = stream.write_all(body);
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
            ("GET", "/reference-rate") => self.reference_rate(),
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

    /// Whether the request carries the correct HTTP Basic credentials. Compared in constant time
    /// against the expected header, so neither the username nor the password leaks by timing.
    fn basic_ok(&self, req: &Request, user: &str, pass: &str) -> bool {
        match req.headers.get("authorization") {
            Some(h) => {
                let expected = format!(
                    "Basic {}",
                    crate::rpc::base64(format!("{user}:{pass}").as_bytes())
                );
                constant_time_eq(h.as_bytes(), expected.as_bytes())
            }
            None => false,
        }
    }

    /// The opt-in external price reference (nonkyc BTCB2/BTC, over Tor). `{enabled:false}` when off;
    /// a hint only, never a price the protocol relies on.
    fn reference_rate(&self) -> (u16, Value) {
        if !self.state.lock().unwrap().settings.price_reference {
            return (200, json!({ "enabled": false }));
        }
        match self.reference.get() {
            Ok(r) => (
                200,
                json!({
                    "enabled": true,
                    "rate": r.rate, "bid": r.bid, "ask": r.ask,
                    "source": "nonkyc BTCB2/BTC, over Tor",
                }),
            ),
            Err(e) => (200, json!({ "enabled": true, "error": e })),
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
            "config_locked": self.config_locked,
        })
    }

    /// The one response for every data path when no engine is running: the daemon never fabricates
    /// offers or swaps, so until the user's nodes are connected it says so plainly rather than
    /// returning empty or placeholder data (design 0009; all data comes from the live engine).
    fn not_running() -> (u16, Value) {
        (
            503,
            json!({ "error": "engine not running; connect your BTC and xBTC nodes in Settings" }),
        )
    }

    fn get_offers(&self) -> (u16, Value) {
        if !self.engine_running() {
            return Self::not_running();
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
            return Self::not_running();
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
            return Self::not_running();
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
            return Self::not_running();
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
        if self.config_locked {
            return (
                403,
                json!({"error": "configuration is managed by StartOS; edit it in Actions and Config"}),
            );
        }
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
        // saved regardless. Logged so the reason (a node or the relay) is visible in the service logs.
        if let Err(e) = self.start_engine() {
            eprintln!("engine not started after settings update: {e}");
        }
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
        if !self.engine_running() {
            return Self::not_running();
        }
        let offer = new.into_swap_offer(&self.state.lock().unwrap().settings);
        let id = offer.id.to_hex_string(Case::Lower);
        match self.engine_call(move |reply| EngineCmd::Publish(offer, reply)) {
            Ok(Ok(())) => (200, json!({ "offer_id": id })),
            Ok(Err(e)) => (422, json!({ "error": e })),
            Err(e) => (503, json!({ "error": e })),
        }
    }

    fn save_settings(&self, settings: &Settings) -> std::io::Result<()> {
        std::fs::write(
            self.data_dir.join("settings.json"),
            serde_json::to_vec_pretty(settings).unwrap(),
        )
    }
}
